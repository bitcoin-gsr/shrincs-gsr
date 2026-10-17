#!/usr/bin/env python3
"""Differential tests for fixed-depth FXMSS verifiers."""

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
import stage2_fxmss_fixed as stage2  # noqa: E402


class FxmssFixedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bitcoin_util = Path(os.environ.get(
            "GSR_BITCOIN_UTIL",
            stage2.DEFAULT_CORE / "build" / "bin" / "bitcoin-util",
        ))
        if not cls.bitcoin_util.is_file():
            raise unittest.SkipTest(f"missing GSR evaluator: {cls.bitcoin_util}")

    def make_case(
        self, case: int, *, depth: int = 4, leaf_index: int | None = None
    ) -> dict:
        if leaf_index is None:
            leaf_index = (5 + 3 * case) % (2**depth)
        leaf_height = shrincs.FXMSS_HEIGHT - depth
        sk_seed = hashlib.sha256(b"stage2 sk" + bytes([case])).digest()[:16]
        pk_seed = hashlib.sha256(b"stage2 pk" + bytes([case])).digest()[:16]
        digest = hashlib.sha256(b"stage2 digest" + bytes([case])).digest()
        signature = shrincs.fxmss_sign(
            digest, sk_seed, leaf_index, leaf_height, pk_seed, True, depth
        )
        self.assertIsNotNone(signature)
        root = shrincs.fxmss_node(
            sk_seed, 0, shrincs.FXMSS_HEIGHT, pk_seed, True, depth, bytearray(22)
        )
        recovered = shrincs.fxmss_pubkey_from_sig(
            leaf_index, leaf_height, signature, digest, pk_seed
        )
        self.assertEqual(recovered, root)
        return {
            "pk_seed": pk_seed,
            "digest": digest,
            "depth": depth,
            "leaf_index": leaf_index,
            "signature": signature,
            "root": root,
        }

    def evaluate(
        self,
        case: dict,
        *,
        static_macros: bool,
        nested_macros: bool = False,
        signature: bytes | None = None,
        root: bytes | None = None,
        leaf_index: bytes | None = None,
    ) -> dict:
        script = stage2.build_verifier(
            case["pk_seed"],
            case["depth"],
            root or case["root"],
            static_macros=static_macros,
            nested_macros=nested_macros,
        )
        return stage1.run_evalscript(self.bitcoin_util, {
            "protocol": 1,
            "sigversion": "tapscript_v2",
            "script": bytes(script.raw).hex(),
            "stack": [
                (signature or case["signature"]).hex(),
                case["digest"].hex(),
                (leaf_index or bytes([case["leaf_index"]])).hex(),
            ],
            "varops_budget": 40_000_000_000,
        })

    def test_reference_cases(self) -> None:
        for macros in (False, True):
            for number in range(4):
                with self.subTest(macros=macros, case=number):
                    result = self.evaluate(
                        self.make_case(number), static_macros=macros
                    )
                    self.assertTrue(result["success"], result)

    def test_multiple_leaf_positions_same_tree(self) -> None:
        for macros in (False, True):
            for leaf_index in (3, 12):
                with self.subTest(macros=macros, leaf_index=leaf_index):
                    result = self.evaluate(
                        self.make_case(7, leaf_index=leaf_index),
                        static_macros=macros,
                    )
                    self.assertTrue(result["success"], result)

    def test_corrupted_authentication_path_fails(self) -> None:
        case = self.make_case(0)
        corrupted = bytearray(case["signature"])
        corrupted[stage2.WOTS_SIGNATURE_BYTES + 7] ^= 1
        for macros in (False, True):
            with self.subTest(macros=macros):
                self.assertFalse(self.evaluate(
                    case,
                    static_macros=macros,
                    signature=bytes(corrupted),
                )["success"])

    def test_wrong_root_fails(self) -> None:
        case = self.make_case(1)
        wrong_root = bytes([case["root"][0] ^ 1]) + case["root"][1:]
        for macros in (False, True):
            with self.subTest(macros=macros):
                self.assertFalse(self.evaluate(
                    case, static_macros=macros, root=wrong_root
                )["success"])

    def test_wrong_length_fails(self) -> None:
        case = self.make_case(2)
        for macros in (False, True):
            with self.subTest(macros=macros):
                self.assertFalse(self.evaluate(
                    case,
                    static_macros=macros,
                    signature=case["signature"][:-1],
                )["success"])

    def test_leaf_index_must_be_one_byte(self) -> None:
        case = self.make_case(3)
        for macros in (False, True):
            with self.subTest(macros=macros):
                self.assertFalse(self.evaluate(
                    case,
                    static_macros=macros,
                    leaf_index=b"\x00" + bytes([case["leaf_index"]]),
                )["success"])

    def test_nested_macro_definitions_are_ordered(self) -> None:
        case = self.make_case(0)
        bodies = (
            stage1.build_chain_hash_function(None),
            stage1.build_chain_walk_function(nested_macro=True),
            stage2.build_merkle_hash_function(case["pk_seed"]),
        )
        script = stage2.build_verifier(
            case["pk_seed"], case["depth"], case["root"],
            nested_macros=True,
        )
        prefix = b"".join(
            bytes([stage1.OP_MACRO]) + stage1.compact_size(len(body.raw)) + body.raw
            for body in bodies
        )
        self.assertTrue(script.raw.startswith(prefix))
        self.assertEqual(bodies[1].raw.count(bytes([stage1.OP_CALLMACRO, 0])), 15)

    def test_nested_macros_match_reference_and_reject_corruption(self) -> None:
        for number in range(4):
            case = self.make_case(number)
            with self.subTest(case=number):
                self.assertTrue(self.evaluate(
                    case, static_macros=False, nested_macros=True,
                )["success"])
                corrupted = bytearray(case["signature"])
                corrupted[stage2.WOTS_SIGNATURE_BYTES + 7] ^= 1
                self.assertFalse(self.evaluate(
                    case, static_macros=False, nested_macros=True,
                    signature=bytes(corrupted),
                )["success"])


if __name__ == "__main__":
    unittest.main()
