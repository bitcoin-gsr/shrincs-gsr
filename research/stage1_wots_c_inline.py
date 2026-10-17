#!/usr/bin/env python3
"""Generate and validate stage-1 GSR WOTS+C verifier variants."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from collections import Counter


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORE = Path(os.environ.get(
    "GSR_CORE", ROOT.parents[1] / "core" / "gsr" / "gsr-full"
))
sys.path.insert(0, str(ROOT / "impl"))

import shrincs  # noqa: E402


OP_0 = 0x00
OP_1 = 0x51
OP_IF = 0x63
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_2DROP = 0x6D
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_ROT = 0x7B
OP_SWAP = 0x7C
OP_CAT = 0x7E
OP_SUBSTR = 0x7F
OP_LEFT = 0x80
OP_RIGHT = 0x81
OP_SIZE = 0x82
OP_AND = 0x84
OP_EQUAL = 0x87
OP_ADD = 0x93
OP_RSHIFT = 0x99
OP_NUMEQUALVERIFY = 0x9D
OP_NUMNOTEQUAL = 0x9E
OP_LESSTHAN = 0x9F
OP_SHA256 = 0xA8
OP_DEFINE = 0xBB
OP_INVOKE = 0xBC
OP_MACRO = OP_DEFINE
OP_CALLMACRO = OP_INVOKE
OP_MULTI = 0xBF

OP_NAMES = {
    OP_IF: "OP_IF",
    OP_ENDIF: "OP_ENDIF",
    OP_VERIFY: "OP_VERIFY",
    OP_TOALTSTACK: "OP_TOALTSTACK",
    OP_FROMALTSTACK: "OP_FROMALTSTACK",
    OP_2DROP: "OP_2DROP",
    OP_DROP: "OP_DROP",
    OP_DUP: "OP_DUP",
    OP_NIP: "OP_NIP",
    OP_PICK: "OP_PICK",
    OP_ROLL: "OP_ROLL",
    OP_ROT: "OP_ROT",
    OP_SWAP: "OP_SWAP",
    OP_CAT: "OP_CAT",
    OP_SUBSTR: "OP_SUBSTR",
    OP_LEFT: "OP_LEFT",
    OP_RIGHT: "OP_RIGHT",
    OP_SIZE: "OP_SIZE",
    OP_AND: "OP_AND",
    OP_EQUAL: "OP_EQUAL",
    OP_ADD: "OP_ADD",
    OP_RSHIFT: "OP_DOWNSHIFT",
    OP_NUMEQUALVERIFY: "OP_NUMEQUALVERIFY",
    OP_NUMNOTEQUAL: "OP_NUMNOTEQUAL",
    OP_LESSTHAN: "OP_LESSTHAN",
    OP_SHA256: "OP_SHA256",
    OP_DEFINE: "OP_DEFINE",
    OP_INVOKE: "OP_INVOKE",
    OP_MULTI: "OP_MULTI",
}


def unsigned_num(value: int) -> bytes:
    assert value >= 0
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def compact_size(value: int) -> bytes:
    assert value >= 0
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


class Script:
    def __init__(self) -> None:
        self.raw = bytearray()
        self.census: Counter[str] = Counter()
        self.function_census: Counter[str] = Counter()

    def op(self, opcode: int) -> None:
        self.raw.append(opcode)
        self.census[OP_NAMES[opcode]] += 1

    def push(self, value: bytes) -> None:
        size = len(value)
        if size == 0:
            self.raw.append(OP_0)
        elif size <= 75:
            self.raw.append(size)
        elif size <= 0xFF:
            self.raw.extend((0x4C, size))
        elif size <= 0xFFFF:
            self.raw.append(0x4D)
            self.raw.extend(size.to_bytes(2, "little"))
        else:
            self.raw.append(0x4E)
            self.raw.extend(size.to_bytes(4, "little"))
        self.raw.extend(value)
        self.census["PUSH"] += 1

    def num(self, value: int) -> None:
        if value == 0:
            self.raw.append(OP_0)
        elif 1 <= value <= 16:
            self.raw.append(OP_1 + value - 1)
        else:
            self.push(unsigned_num(value))
            return
        self.census["PUSH"] += 1

    def define_macro(self, body: Script) -> None:
        """Append a static definition; callers must place all definitions first."""
        self.raw.append(OP_MACRO)
        self.raw.extend(compact_size(len(body.raw)))
        self.raw.extend(body.raw)
        self.census["OP_MACRO"] += 1
        self.function_census.update(body.census)

    def call_macro(self, index: int) -> None:
        self.raw.append(OP_CALLMACRO)
        self.raw.extend(compact_size(index))
        self.census["OP_CALLMACRO"] += 1


def set_address(base: bytes, *, kind: int, chain: int = 0, step: int = 0) -> bytes:
    address = bytearray(base)
    address[9] = kind
    address[10:14] = bytes(4)
    address[14:18] = chain.to_bytes(4, "big")
    address[18:22] = step.to_bytes(4, "big")
    return bytes(address)


def address_suffix(*, kind: int, chain: int = 0, step: int = 0) -> bytes:
    """Return ADRS[9:22] for a separately supplied ADRS[:9]."""
    return (
        bytes([kind])
        + bytes(4)
        + chain.to_bytes(4, "big")
        + step.to_bytes(4, "big")
    )


def emit_hash_concat(script: Script, items: int) -> None:
    script.num(items)
    script.op(OP_MULTI)
    script.op(OP_CAT)
    script.op(OP_SHA256)


def build_chain_hash_function(base_address: bytes | None) -> Script:
    """Build chain,step-aware F(pk_seed, ADRS, node) for OP_INVOKE."""
    address_prefix = bytes([shrincs.SF_WOTS_C_HASH]) + bytes(4)
    if base_address is not None:
        address_prefix = base_address[:9] + address_prefix
    body = Script()

    # Input: node, one-byte chain index, one-byte step index. The shared
    # 64-byte SHA256 prefix lives on the altstack and is restored for the next call.
    body.op(OP_TOALTSTACK)
    body.push(address_prefix)
    body.num(1)
    body.op(OP_PICK)
    body.push(bytes(3))
    body.op(OP_SWAP)
    body.op(OP_CAT)
    body.op(OP_CAT)
    body.op(OP_FROMALTSTACK)
    body.push(bytes(3))
    body.op(OP_SWAP)
    body.op(OP_CAT)
    body.op(OP_CAT)
    body.op(OP_SWAP)
    body.op(OP_DROP)
    body.op(OP_FROMALTSTACK)
    body.op(OP_DUP)
    body.op(OP_TOALTSTACK)
    body.op(OP_ROT)
    body.op(OP_ROT)
    body.op(OP_SWAP)
    emit_hash_concat(body, 3)
    body.num(16)
    body.op(OP_LEFT)
    return body


def build_chain_walk_function(*, nested_macro: bool = False) -> Script:
    """Build a complete 15-step conditional WOTS+C chain walk."""
    body = Script()
    # Input: mapped index, one-byte chain index, current 16-byte node.
    for step in range(15):
        body.num(2)
        body.op(OP_PICK)
        body.num(step + 1)
        body.op(OP_LESSTHAN)
        body.op(OP_IF)
        body.num(1)
        body.op(OP_PICK)
        body.push(bytes([step]))
        if nested_macro:
            body.call_macro(0)
        else:
            body.num(1)
            body.op(OP_INVOKE)
        body.op(OP_ENDIF)
    body.op(OP_NIP)
    body.op(OP_NIP)
    return body


def build_static_chain_walk(base_address: bytes | None) -> Script:
    """Flatten the chain hash into a complete walk (nested calls are forbidden)."""
    hash_body = build_chain_hash_function(base_address)
    body = Script()
    for step in range(15):
        body.num(2)
        body.op(OP_PICK)
        body.num(step + 1)
        body.op(OP_LESSTHAN)
        body.op(OP_IF)
        body.num(1)
        body.op(OP_PICK)
        body.push(bytes([step]))
        body.raw.extend(hash_body.raw)
        body.census.update(hash_body.census)
        body.op(OP_ENDIF)
    body.op(OP_NIP)
    body.op(OP_NIP)
    return body


def build_recovery(
    pk_seed: bytes,
    base_address: bytes | None,
    *,
    reusable_functions: bool = False,
    static_macros: bool = False,
    nested_macros: bool = False,
    emit_macro_definition: bool = True,
    dynamic_address_prefix: bool = False,
) -> Script:
    """Build WOTS+C public-key recovery for signature,digest -> key.

    With ``dynamic_address_prefix``, the initial stack instead ends in a
    73-byte ``SHA256(pk_seed padding) || ADRS[:9]`` prefix.
    """
    assert len(pk_seed) == 16
    assert sum((reusable_functions, static_macros, nested_macros)) <= 1
    assert dynamic_address_prefix == (base_address is None)
    if base_address is not None:
        assert len(base_address) == 22
    prefix = pk_seed + bytes(48)
    script = Script()

    if static_macros and emit_macro_definition:
        script.define_macro(build_static_chain_walk(base_address))

    if nested_macros and emit_macro_definition:
        script.define_macro(build_chain_hash_function(base_address))
        script.define_macro(build_chain_walk_function(nested_macro=True))

    if reusable_functions:
        chain_hash = build_chain_hash_function(base_address)
        script.push(bytes(chain_hash.raw))
        script.num(1)
        script.op(OP_DEFINE)
        script.function_census.update(chain_hash.census)
        chain_walk = build_chain_walk_function()
        script.push(bytes(chain_walk.raw))
        script.num(2)
        script.op(OP_DEFINE)
        script.function_census.update(chain_walk.census)

    if dynamic_address_prefix:
        script.op(OP_TOALTSTACK)

    # Initial stack: [514-byte WOTS+C signature, 32-byte message digest].
    script.op(OP_SIZE)
    script.num(32)
    script.op(OP_NUMEQUALVERIFY)
    script.op(OP_SWAP)
    script.op(OP_SIZE)
    script.num(2 + shrincs.WOTS_C_CHAINS_SIZE)
    script.op(OP_NUMEQUALVERIFY)

    # Preserve the signature, then compute H_grind from the two-byte counter.
    if dynamic_address_prefix:
        script.op(OP_FROMALTSTACK)
        script.op(OP_DUP)
        script.op(OP_TOALTSTACK)
        script.op(OP_SWAP)
        script.op(OP_DUP)
        script.num(0)
        script.num(2)
        script.op(OP_SUBSTR)
        script.op(OP_SWAP)
        script.op(OP_TOALTSTACK)
        script.op(OP_TOALTSTACK)
        script.op(OP_SWAP)
        script.push(bytes([shrincs.SF_WOTS_C_GRIND]))
        script.op(OP_SWAP)
    else:
        script.op(OP_DUP)
        script.num(0)
        script.num(2)
        script.op(OP_SUBSTR)
        script.op(OP_SWAP)
        script.op(OP_TOALTSTACK)
        script.op(OP_TOALTSTACK)
        script.push(prefix)
        grind_address = bytearray(base_address)
        grind_address[9] = shrincs.SF_WOTS_C_GRIND
        script.push(bytes(grind_address[:10]))
        script.op(OP_ROT)
    script.push(bytes(4))
    script.op(OP_FROMALTSTACK)
    emit_hash_concat(script, 5)
    script.num(16)
    script.op(OP_LEFT)

    # Decode the 32 nibbles and enforce the WOTS+C constant sum.
    script.num(0)
    for byte_index in range(16):
        script.num(1)
        script.op(OP_PICK)
        script.num(byte_index)
        script.num(1)
        script.op(OP_SUBSTR)
        script.op(OP_DUP)
        script.num(4)
        script.op(OP_RSHIFT)
        script.op(OP_SWAP)
        script.push(b"\x0f")
        script.op(OP_AND)
        script.op(OP_ADD)
        script.op(OP_ADD)
    script.num(shrincs.WOTS_C_CONSTANT_SUM)
    script.op(OP_NUMEQUALVERIFY)

    # Recover every chain tip. The branch for step j executes iff index <= j.
    script.op(OP_FROMALTSTACK)
    if (reusable_functions or static_macros or nested_macros) and not dynamic_address_prefix:
        script.push(prefix)
        script.op(OP_TOALTSTACK)
    script.num(0)  # concatenated chain tips
    for chain in range(shrincs.WOTS_C_CHAIN_COUNT):
        script.num(2)
        script.op(OP_PICK)
        script.num(chain // 2)
        script.num(1)
        script.op(OP_SUBSTR)
        if chain % 2 == 0:
            script.num(4)
            script.op(OP_RSHIFT)
        else:
            script.push(b"\x0f")
            script.op(OP_AND)

        script.num(2)
        script.op(OP_PICK)
        script.num(2 + 16 * chain)
        script.num(16)
        script.op(OP_SUBSTR)

        if reusable_functions or static_macros or nested_macros:
            script.push(bytes([chain]))
            script.op(OP_SWAP)
            if static_macros:
                script.call_macro(0)
            elif nested_macros:
                script.call_macro(1)
            else:
                script.num(2)
                script.op(OP_INVOKE)
        else:
            for step in range(15):
                script.num(1)
                script.op(OP_PICK)
                script.num(step + 1)
                script.op(OP_LESSTHAN)
                script.op(OP_IF)
                if dynamic_address_prefix:
                    script.op(OP_FROMALTSTACK)
                    script.op(OP_DUP)
                    script.op(OP_TOALTSTACK)
                    script.push(address_suffix(
                        kind=shrincs.SF_WOTS_C_HASH,
                        chain=chain,
                        step=step,
                    ))
                else:
                    script.push(prefix)
                    script.push(set_address(
                        base_address,
                        kind=shrincs.SF_WOTS_C_HASH,
                        chain=chain,
                        step=step,
                    ))
                script.num(2)
                script.op(OP_PICK)
                emit_hash_concat(script, 3)
                script.num(16)
                script.op(OP_LEFT)
                script.op(OP_NIP)
                script.op(OP_ENDIF)

        if not (reusable_functions or static_macros or nested_macros):
            script.op(OP_NIP)
        script.op(OP_CAT)

    # T_sf hashes the 32 recovered chain tips into the WOTS+C public key.
    script.op(OP_TOALTSTACK)
    script.op(OP_2DROP)
    if reusable_functions or static_macros or nested_macros or dynamic_address_prefix:
        script.op(OP_FROMALTSTACK)
        if dynamic_address_prefix:
            script.push(address_suffix(kind=shrincs.SF_WOTS_C_PK))
        else:
            script.push(set_address(base_address, kind=shrincs.SF_WOTS_C_PK))
        script.op(OP_FROMALTSTACK)
        script.op(OP_ROT)
        script.op(OP_ROT)
        script.op(OP_SWAP)
    else:
        script.push(prefix)
        script.push(set_address(base_address, kind=shrincs.SF_WOTS_C_PK))
        script.op(OP_FROMALTSTACK)
    emit_hash_concat(script, 3)
    script.num(16)
    script.op(OP_LEFT)
    return script


def build_verifier(
    pk_seed: bytes,
    base_address: bytes,
    expected_key: bytes,
    *,
    reusable_functions: bool = False,
    static_macros: bool = False,
    nested_macros: bool = False,
) -> Script:
    """Build a WOTS+C verifier for signature,digest -> true."""
    assert len(expected_key) == 16
    script = build_recovery(
        pk_seed, base_address, reusable_functions=reusable_functions,
        static_macros=static_macros, nested_macros=nested_macros,
    )
    script.push(expected_key)
    script.op(OP_EQUAL)
    return script


def deterministic_reference_fixture() -> dict[str, bytes]:
    sk_seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pk_seed = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    message_digest = hashlib.sha256(b"SHRINCS GSR stage 1 WOTS+C").digest()
    address = bytearray(22)
    address[0] = 7
    address[1:9] = (5).to_bytes(8, "big")

    signature = shrincs.wots_c_sign(
        message_digest, sk_seed, pk_seed, bytearray(address)
    )
    assert signature is not None
    expected_key = shrincs.wots_c_pubkey_from_sig(
        signature, message_digest, pk_seed, bytearray(address)
    )
    assert expected_key is not None
    generated_key = shrincs.wots_c_pubkey_gen(
        sk_seed, pk_seed, bytearray(address)
    )
    assert expected_key == generated_key
    return {
        "pk_seed": pk_seed,
        "message_digest": message_digest,
        "address": bytes(address),
        "signature": signature,
        "expected_key": expected_key,
    }


def run_evalscript(bitcoin_util: Path, request: dict) -> dict:
    result = subprocess.run(
        [str(bitcoin_util), "evalscript"],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def load_core_framework(core: Path) -> dict:
    sys.path.insert(0, str(core / "test" / "functional"))
    from test_framework.key import compute_xonly_pubkey
    from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
    from test_framework.script import CScript, LEAF_VERSION_TAPSCRIPT_V2, taproot_construct

    return locals()


def build_transaction(
    core: Path,
    script_bytes: bytes,
    signature: bytes,
    digest: bytes,
    *additional_stack_items: bytes,
) -> dict:
    framework = load_core_framework(core)
    internal_key = framework["compute_xonly_pubkey"]((1).to_bytes(32, "big"))[0]
    script = framework["CScript"](script_bytes)
    tap = framework["taproot_construct"](
        internal_key,
        [("wots_c", script, framework["LEAF_VERSION_TAPSCRIPT_V2"])],
    )
    leaf = tap.leaves["wots_c"]
    control_block = bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch

    tx = framework["CTransaction"]()
    tx.vin = [framework["CTxIn"](framework["COutPoint"](1, 0), b"", 0xFFFFFFFD)]
    tx.vout = [framework["CTxOut"](9_000, tap.scriptPubKey)]
    tx.wit.vtxinwit = [framework["CTxInWitness"]()]
    tx.wit.vtxinwit[0].scriptWitness.stack = [
        signature, digest, *additional_stack_items, script_bytes, control_block
    ]
    return {
        "raw_hex": tx.serialize_with_witness().hex(),
        "raw_weight": tx.get_weight(),
        "spent_output": {
            "amount_sat": 10_000,
            "script_pubkey": bytes(tap.scriptPubKey).hex(),
        },
        "control_block": control_block.hex(),
    }


def git_revision(path: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, text=True,
        capture_output=True, check=True,
    ).stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=DEFAULT_CORE)
    parser.add_argument("--bitcoin-util", type=Path)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--variant", choices=("inline", "macros", "nested-macros"), default="inline")
    parser.add_argument("--artifact-tag", help="Distinct artifact name, e.g. inline-current")
    args = parser.parse_args()
    bitcoin_util = args.bitcoin_util or args.core / "build" / "bin" / "bitcoin-util"

    fixture = deterministic_reference_fixture()
    reusable_functions = args.variant == "functions"
    static_macros = args.variant == "macros"
    nested_macros = args.variant == "nested-macros"
    stage_name = (
        f"WOTS+C verification, {args.variant}"
    )
    file_stem = f"stage1-wots-c-{args.artifact_tag or args.variant}"
    script = build_verifier(
        fixture["pk_seed"], fixture["address"], fixture["expected_key"],
        reusable_functions=reusable_functions,
        static_macros=static_macros,
        nested_macros=nested_macros,
    )
    transaction = build_transaction(
        args.core, bytes(script.raw), fixture["signature"], fixture["message_digest"]
    )

    probe_request = {
        "protocol": 1,
        "sigversion": "tapscript_v2",
        "script": bytes(script.raw).hex(),
        "stack": [fixture["signature"].hex(), fixture["message_digest"].hex()],
        "varops_budget": 40_000_000_000,
    }
    probe = run_evalscript(bitcoin_util, probe_request)
    # Core's final clean-stack/truth check consumes the sole result.
    if not probe["success"] or probe["stack-after"]:
        raise RuntimeError(f"valid reference fixture failed in GSR: {probe}")
    consumed = probe_request["varops_budget"] - probe["varops-budget-remaining"]

    request = dict(probe_request)
    request["varops_budget"] = transaction["raw_weight"] * 10_000
    evaluation = run_evalscript(bitcoin_util, request)
    if not evaluation["success"] or evaluation["stack-after"]:
        raise RuntimeError(f"raw transaction does not fund valid execution: {evaluation}")
    if request["varops_budget"] - evaluation["varops-budget-remaining"] != consumed:
        raise RuntimeError("varops consumption changed with the funded budget")

    # A corrupted chain value must not reproduce the committed WOTS+C key.
    invalid_signature = bytearray(fixture["signature"])
    invalid_signature[2] ^= 1
    invalid_request = dict(request)
    invalid_request["stack"] = [invalid_signature.hex(), fixture["message_digest"].hex()]
    invalid = run_evalscript(bitcoin_util, invalid_request)
    if invalid["success"]:
        raise RuntimeError("corrupted WOTS+C signature unexpectedly succeeded")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    eval_path = args.output_dir / f"{file_stem}-eval.json"
    result_path = args.output_dir / f"{file_stem}.json"
    write_json(eval_path, request)
    write_json(result_path, {
        "stage": stage_name,
        "eval_fixture": str(eval_path.relative_to(ROOT)),
        "scheme_revision": git_revision(ROOT),
        "scheme_worktree_clean": not bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True,
            capture_output=True, check=True,
        ).stdout),
        "core_revision": git_revision(args.core),
        "core_worktree_clean": not bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=args.core, text=True,
            capture_output=True, check=True,
        ).stdout),
        "bitcoin_util": str(bitcoin_util.resolve()),
        "script_sha256": hashlib.sha256(script.raw).hexdigest(),
        "script_bytes": len(script.raw),
        "signature_bytes": len(fixture["signature"]),
        "message_digest": fixture["message_digest"].hex(),
        "pk_seed": fixture["pk_seed"].hex(),
        "address": fixture["address"].hex(),
        "expected_wots_c_key": fixture["expected_key"].hex(),
        "counter": int.from_bytes(fixture["signature"][:2], "big"),
        "opcode_census_serialized": dict(sorted(script.census.items())),
        "function_body_census": dict(sorted(script.function_census.items())),
        "macro_definitions": ([{
            "index": 0,
            "purpose": "complete WOTS+C chain walk",
            "body_bytes": len(build_static_chain_walk(fixture["address"]).raw),
            "call_sites": shrincs.WOTS_C_CHAIN_COUNT,
        }] if static_macros else [
            {
                "index": 0,
                "purpose": "WOTS+C chain hash",
                "body_bytes": len(build_chain_hash_function(fixture["address"]).raw),
                "executed_calls": 240,
            },
            {
                "index": 1,
                "purpose": "complete WOTS+C chain walk",
                "body_bytes": len(build_chain_walk_function(nested_macro=True).raw),
                "call_sites": shrincs.WOTS_C_CHAIN_COUNT,
            },
        ] if nested_macros else []),
        "uses_reusable_functions": reusable_functions,
        "uses_static_macros": static_macros,
        "uses_nested_macros": nested_macros,
        "evaluation": {
            "success": evaluation["success"],
            "varops": consumed,
            "budget": request["varops_budget"],
            "relative_varops_percent": 100 * consumed / request["varops_budget"],
            "invalid_signature_rejected": not invalid["success"],
        },
        "transaction": transaction,
        "padding_weight": 0,
        "funded_weight": transaction["raw_weight"],
        "block_weight_percent": 100 * transaction["raw_weight"] / 4_000_000,
    })
    print(json.dumps({
        "eval_fixture": str(eval_path),
        "result": str(result_path),
        "script_bytes": len(script.raw),
        "raw_weight": transaction["raw_weight"],
        "varops": consumed,
        "relative_varops_percent": 100 * consumed / request["varops_budget"],
    }, indent=2))


if __name__ == "__main__":
    main()
