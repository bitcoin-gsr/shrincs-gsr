#!/usr/bin/env python3
"""Differential tests for the stage-1 GSR WOTS+C verifier variants."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(ROOT / "impl"))

import shrincs  # noqa: E402
import stage1_wots_c_inline as stage1  # noqa: E402


class WotsCStage1Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bitcoin_util = Path(os.environ.get(
            "GSR_BITCOIN_UTIL",
            stage1.DEFAULT_CORE / "build" / "bin" / "bitcoin-util",
        ))
        if not cls.bitcoin_util.is_file():
            raise unittest.SkipTest(f"missing GSR evaluator: {cls.bitcoin_util}")

    def make_case(self, case: int) -> dict[str, bytes]:
        sk_seed = hashlib.sha256(b"stage1 sk" + bytes([case])).digest()[:16]
        pk_seed = hashlib.sha256(b"stage1 pk" + bytes([case])).digest()[:16]
        digest = hashlib.sha256(b"stage1 digest" + bytes([case])).digest()
        address = bytearray(22)
        address[0] = 20 + case
        address[1:9] = (1000 + case).to_bytes(8, "big")
        signature = shrincs.wots_c_sign(digest, sk_seed, pk_seed, bytearray(address))
        self.assertIsNotNone(signature)
        expected = shrincs.wots_c_pubkey_gen(sk_seed, pk_seed, bytearray(address))
        recovered = shrincs.wots_c_pubkey_from_sig(
            signature, digest, pk_seed, bytearray(address)
        )
        self.assertEqual(recovered, expected)
        return {
            "pk_seed": pk_seed,
            "digest": digest,
            "address": bytes(address),
            "signature": signature,
            "expected": expected,
        }

    def evaluate(
        self,
        case: dict[str, bytes],
        signature: bytes | None = None,
        *,
        static_macros: bool = False,
        nested_macros: bool = False,
    ) -> dict:
        script = stage1.build_verifier(
            case["pk_seed"], case["address"], case["expected"],
            static_macros=static_macros,
            nested_macros=nested_macros,
        )
        return stage1.run_evalscript(self.bitcoin_util, {
            "protocol": 1,
            "sigversion": "tapscript_v2",
            "script": bytes(script.raw).hex(),
            "stack": [(signature or case["signature"]).hex(), case["digest"].hex()],
            "varops_budget": 40_000_000_000,
        })

    def test_multiple_reference_cases(self) -> None:
        for static_macros in (False, True):
            for number in range(4):
                with self.subTest(macros=static_macros, case=number):
                    result = self.evaluate(
                        self.make_case(number),
                        static_macros=static_macros,
                    )
                    self.assertTrue(result["success"], result)

    def test_corrupted_chain_value_fails(self) -> None:
        case = self.make_case(0)
        corrupted = bytearray(case["signature"])
        corrupted[2 + 13 * 16 + 7] ^= 0x80
        for static_macros in (False, True):
            with self.subTest(macros=static_macros):
                self.assertFalse(self.evaluate(
                    case, bytes(corrupted), static_macros=static_macros,
                )["success"])

    def test_non_constant_sum_counter_fails(self) -> None:
        case = self.make_case(1)
        invalid_counter = next(
            counter
            for counter in range(1 << 16)
            if shrincs.wots_c_map_digest(
                case["pk_seed"], case["digest"], bytearray(case["address"]), counter
            ) is None
        )
        malformed = invalid_counter.to_bytes(2, "big") + case["signature"][2:]
        for static_macros in (False, True):
            with self.subTest(macros=static_macros):
                self.assertFalse(self.evaluate(
                    case, malformed, static_macros=static_macros,
                )["success"])

    def test_wrong_length_fails(self) -> None:
        case = self.make_case(2)
        for static_macros in (False, True):
            with self.subTest(macros=static_macros):
                self.assertFalse(self.evaluate(
                    case, case["signature"][:-1],
                    static_macros=static_macros,
                )["success"])

    def test_legacy_functions_are_not_current_macros(self) -> None:
        case = self.make_case(0)
        script = stage1.build_verifier(
            case["pk_seed"], case["address"], case["expected"],
            reusable_functions=True,
        )
        result = stage1.run_evalscript(self.bitcoin_util, {
            "protocol": 1,
            "sigversion": "tapscript_v2",
            "script": bytes(script.raw).hex(),
            "stack": [case["signature"].hex(), case["digest"].hex()],
            "varops_budget": 40_000_000_000,
        })
        self.assertFalse(result["success"])

    def test_nested_macro_definitions_precede_their_calls(self) -> None:
        case = self.make_case(0)
        hash_body = stage1.build_chain_hash_function(case["address"])
        walk_body = stage1.build_chain_walk_function(nested_macro=True)
        script = stage1.build_verifier(
            case["pk_seed"], case["address"], case["expected"],
            nested_macros=True,
        )
        prefix = (
            bytes([stage1.OP_MACRO]) + stage1.compact_size(len(hash_body.raw)) + hash_body.raw
            + bytes([stage1.OP_MACRO]) + stage1.compact_size(len(walk_body.raw)) + walk_body.raw
        )
        self.assertTrue(script.raw.startswith(prefix))
        self.assertEqual(walk_body.raw.count(bytes([stage1.OP_CALLMACRO, 0])), 15)

    def test_nested_macros_match_reference_and_reject_corruption(self) -> None:
        for number in range(4):
            case = self.make_case(number)
            with self.subTest(case=number):
                self.assertTrue(self.evaluate(case, nested_macros=True)["success"])
                corrupted = bytearray(case["signature"])
                corrupted[2 + 13 * 16 + 7] ^= 0x80
                self.assertFalse(self.evaluate(
                    case, bytes(corrupted), nested_macros=True,
                )["success"])


if __name__ == "__main__":
    unittest.main()
