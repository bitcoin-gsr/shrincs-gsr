#!/usr/bin/env python3
"""Generate and validate fixed-depth FXMSS verifier variants."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORE = Path(os.environ.get(
    "GSR_CORE", ROOT.parents[1] / "core" / "gsr" / "gsr-full"
))
sys.path.insert(0, str(ROOT / "impl"))
sys.path.insert(0, str(ROOT / "research"))

import shrincs  # noqa: E402
import stage1_wots_c_inline as stage1  # noqa: E402


TREE_DEPTH = 8
LEAF_INDEX = 0xAD
WOTS_SIGNATURE_BYTES = 2 + shrincs.WOTS_C_CHAINS_SIZE


def extend_script(destination: stage1.Script, source: stage1.Script) -> None:
    destination.raw.extend(source.raw)
    destination.census.update(source.census)
    destination.function_census.update(source.function_census)


def build_merkle_hash_function(pk_seed: bytes) -> stage1.Script:
    """Build H(pk_seed, address, left || right) for OP_INVOKE."""
    prefix = pk_seed + bytes(48)
    body = stage1.Script()
    # Input: concatenated children, 22-byte address.
    body.push(prefix)
    body.op(stage1.OP_ROT)
    body.op(stage1.OP_ROT)
    body.op(stage1.OP_SWAP)
    stage1.emit_hash_concat(body, 3)
    body.num(16)
    body.op(stage1.OP_LEFT)
    return body


def build_verifier(
    pk_seed: bytes,
    tree_depth: int,
    expected_root: bytes,
    *,
    reusable_functions: bool = False,
    static_macros: bool = False,
    nested_macros: bool = False,
) -> stage1.Script:
    """Build FXMSS verification for signature,digest,leaf_index -> true."""
    assert len(pk_seed) == 16
    assert 1 <= tree_depth <= 8
    assert len(expected_root) == 16
    assert sum((reusable_functions, static_macros, nested_macros)) <= 1

    leaf_height = shrincs.FXMSS_HEIGHT - tree_depth
    signature_bytes = WOTS_SIGNATURE_BYTES + 16 * tree_depth
    prefix = pk_seed + bytes(48)

    script = stage1.Script()
    if static_macros:
        script.define_macro(stage1.build_static_chain_walk(None))
        script.define_macro(build_merkle_hash_function(pk_seed))
    if nested_macros:
        script.define_macro(stage1.build_chain_hash_function(None))
        script.define_macro(stage1.build_chain_walk_function(nested_macro=True))
        script.define_macro(build_merkle_hash_function(pk_seed))

    # Initial stack: [FXMSS signature, 32-byte digest, one-byte leaf index].
    script.op(stage1.OP_SIZE)
    script.num(1)
    script.op(stage1.OP_NUMEQUALVERIFY)
    if tree_depth < 8:
        script.op(stage1.OP_DUP)
        script.num(2**tree_depth)
        script.op(stage1.OP_LESSTHAN)
        script.op(stage1.OP_VERIFY)
    script.op(stage1.OP_DUP)
    script.push(bytes([leaf_height]) + bytes(7))
    script.op(stage1.OP_SWAP)
    script.op(stage1.OP_CAT)

    # Split off the authentication path, preserving the leaf index and the
    # dynamic nine-byte keypair address prefix.
    script.num(3)
    script.op(stage1.OP_ROLL)
    script.op(stage1.OP_SIZE)
    script.num(signature_bytes)
    script.op(stage1.OP_NUMEQUALVERIFY)
    script.op(stage1.OP_DUP)
    script.num(WOTS_SIGNATURE_BYTES)
    script.num(16 * tree_depth)
    script.op(stage1.OP_SUBSTR)
    script.op(stage1.OP_TOALTSTACK)
    script.num(0)
    script.num(WOTS_SIGNATURE_BYTES)
    script.op(stage1.OP_SUBSTR)
    script.num(2)
    script.op(stage1.OP_ROLL)
    script.op(stage1.OP_TOALTSTACK)
    script.op(stage1.OP_SWAP)
    script.push(prefix)
    script.op(stage1.OP_SWAP)
    script.op(stage1.OP_CAT)
    script.op(stage1.OP_ROT)
    script.op(stage1.OP_SWAP)

    recovery = stage1.build_recovery(
        pk_seed,
        None,
        reusable_functions=reusable_functions,
        static_macros=static_macros,
        nested_macros=nested_macros,
        emit_macro_definition=False,
        dynamic_address_prefix=True,
    )
    extend_script(script, recovery)

    if reusable_functions:
        merkle_hash = build_merkle_hash_function(pk_seed)
        script.push(bytes(merkle_hash.raw))
        script.num(3)
        script.op(stage1.OP_DEFINE)
        script.function_census.update(merkle_hash.census)

    # Keep the authentication path and leaf index below the evolving node.
    script.op(stage1.OP_FROMALTSTACK)
    script.op(stage1.OP_FROMALTSTACK)
    script.op(stage1.OP_ROT)
    script.op(stage1.OP_ROT)
    script.op(stage1.OP_SWAP)
    for level in range(tree_depth):
        script.num(2)
        script.op(stage1.OP_PICK)
        script.num(16 * level)
        script.num(16)
        script.op(stage1.OP_SUBSTR)
        script.num(2)
        script.op(stage1.OP_PICK)
        if level:
            script.num(level)
            script.op(stage1.OP_RSHIFT)
        script.num(1)
        script.op(stage1.OP_AND)
        script.num(0)
        script.op(stage1.OP_NUMNOTEQUAL)
        script.op(stage1.OP_IF)
        script.op(stage1.OP_SWAP)
        script.op(stage1.OP_ENDIF)
        script.op(stage1.OP_CAT)

        # Construct the parent node's 22-byte address from the dynamic index.
        script.num(1)
        script.op(stage1.OP_PICK)
        script.num(level + 1)
        script.op(stage1.OP_RSHIFT)
        script.push(bytes(8))
        script.op(stage1.OP_SWAP)
        script.op(stage1.OP_CAT)
        script.num(8)
        script.op(stage1.OP_RIGHT)
        script.push(bytes([leaf_height + level + 1]))
        script.op(stage1.OP_SWAP)
        script.op(stage1.OP_CAT)
        script.push(bytes([shrincs.SF_FXMSS_TREE]) + bytes(12))
        script.op(stage1.OP_CAT)
        if reusable_functions or static_macros or nested_macros:
            if static_macros:
                script.call_macro(1)
            elif nested_macros:
                script.call_macro(2)
            else:
                script.num(3)
                script.op(stage1.OP_INVOKE)
        else:
            script.push(prefix)
            script.op(stage1.OP_ROT)
            script.op(stage1.OP_ROT)
            script.op(stage1.OP_SWAP)
            stage1.emit_hash_concat(script, 3)
            script.num(16)
            script.op(stage1.OP_LEFT)

    script.op(stage1.OP_NIP)
    script.op(stage1.OP_NIP)
    script.push(expected_root)
    script.op(stage1.OP_EQUAL)
    return script


def deterministic_reference_fixture() -> dict[str, bytes | int]:
    sk_seed = hashlib.sha256(b"SHRINCS GSR stage 2 secret seed").digest()[:16]
    pk_seed = hashlib.sha256(b"SHRINCS GSR stage 2 public seed").digest()[:16]
    message_digest = hashlib.sha256(b"SHRINCS GSR stage 2 FXMSS").digest()
    leaf_height = shrincs.FXMSS_HEIGHT - TREE_DEPTH
    signature = shrincs.fxmss_sign(
        message_digest,
        sk_seed,
        LEAF_INDEX,
        leaf_height,
        pk_seed,
        True,
        TREE_DEPTH,
    )
    assert signature is not None
    expected_root = shrincs.fxmss_node(
        sk_seed, 0, shrincs.FXMSS_HEIGHT, pk_seed, True, TREE_DEPTH, bytearray(22)
    )
    recovered_root = shrincs.fxmss_pubkey_from_sig(
        LEAF_INDEX, leaf_height, signature, message_digest, pk_seed
    )
    assert recovered_root == expected_root
    return {
        "pk_seed": pk_seed,
        "message_digest": message_digest,
        "leaf_index": LEAF_INDEX,
        "leaf_height": leaf_height,
        "tree_depth": TREE_DEPTH,
        "signature": signature,
        "expected_root": expected_root,
    }


def function_metadata(fixture: dict[str, bytes | int]) -> list[dict]:
    if not fixture:
        return []
    functions = (
        (1, "WOTS+C chain hash", stage1.build_chain_hash_function(None), 240),
        (2, "WOTS+C complete chain walk", stage1.build_chain_walk_function(), 32),
        (3, "FXMSS Merkle parent hash", build_merkle_hash_function(fixture["pk_seed"]), TREE_DEPTH),
    )
    return [
        {
            "id": identifier,
            "purpose": purpose,
            "body_bytes": len(body.raw),
            "executed_invocations": invocations,
            "serialized_opcode_census": dict(sorted(body.census.items())),
        }
        for identifier, purpose, body, invocations in functions
    ]


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
    file_stem = f"stage2-fxmss-depth{TREE_DEPTH}-{args.artifact_tag or args.variant}"
    script = build_verifier(
        fixture["pk_seed"],
        int(fixture["tree_depth"]),
        fixture["expected_root"],
        reusable_functions=reusable_functions,
        static_macros=static_macros,
        nested_macros=nested_macros,
    )
    transaction = stage1.build_transaction(
        args.core,
        bytes(script.raw),
        fixture["signature"],
        fixture["message_digest"],
        bytes([int(fixture["leaf_index"])]),
    )

    probe_request = {
        "protocol": 1,
        "sigversion": "tapscript_v2",
        "script": bytes(script.raw).hex(),
        "stack": [
            fixture["signature"].hex(),
            fixture["message_digest"].hex(),
            bytes([int(fixture["leaf_index"])]).hex(),
        ],
        "varops_budget": 40_000_000_000,
    }
    probe = stage1.run_evalscript(bitcoin_util, probe_request)
    if not probe["success"] or probe["stack-after"]:
        raise RuntimeError(f"valid FXMSS fixture failed in GSR: {probe}")
    consumed = probe_request["varops_budget"] - probe["varops-budget-remaining"]

    request = dict(probe_request)
    request["varops_budget"] = transaction["raw_weight"] * 10_000
    evaluation = stage1.run_evalscript(bitcoin_util, request)
    if not evaluation["success"] or evaluation["stack-after"]:
        raise RuntimeError(f"raw transaction does not fund valid execution: {evaluation}")
    if request["varops_budget"] - evaluation["varops-budget-remaining"] != consumed:
        raise RuntimeError("varops consumption changed with the funded budget")

    invalid_signature = bytearray(fixture["signature"])
    invalid_signature[WOTS_SIGNATURE_BYTES + 3] ^= 0x80
    invalid_request = dict(request)
    invalid_request["stack"] = [
        invalid_signature.hex(),
        fixture["message_digest"].hex(),
        bytes([int(fixture["leaf_index"])]).hex(),
    ]
    invalid = stage1.run_evalscript(bitcoin_util, invalid_request)
    if invalid["success"]:
        raise RuntimeError("corrupted FXMSS authentication path unexpectedly succeeded")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    eval_path = args.output_dir / f"{file_stem}-eval.json"
    result_path = args.output_dir / f"{file_stem}.json"
    stage1.write_json(eval_path, request)
    stage1.write_json(result_path, {
        "stage": f"FXMSS depth-{TREE_DEPTH}, {args.variant}",
        "eval_fixture": str(eval_path.relative_to(ROOT)),
        "scheme_revision": stage1.git_revision(ROOT),
        "scheme_worktree_clean": not bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True,
            capture_output=True, check=True,
        ).stdout),
        "core_revision": stage1.git_revision(args.core),
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
        "expected_fxmss_root": fixture["expected_root"].hex(),
        "tree_shape": "balanced",
        "tree_depth": TREE_DEPTH,
        "leaf_index": LEAF_INDEX,
        "leaf_height": fixture["leaf_height"],
        "opcode_census_serialized": dict(sorted(script.census.items())),
        "function_body_census": dict(sorted(script.function_census.items())),
        "function_definitions": function_metadata(fixture) if reusable_functions else [],
        "macro_definitions": ([
            {
                "index": 0,
                "purpose": "complete WOTS+C chain walk",
                "body_bytes": len(stage1.build_static_chain_walk(None).raw),
                "call_sites": shrincs.WOTS_C_CHAIN_COUNT,
            },
            {
                "index": 1,
                "purpose": "FXMSS Merkle parent hash",
                "body_bytes": len(build_merkle_hash_function(fixture["pk_seed"]).raw),
                "call_sites": TREE_DEPTH,
            },
        ] if static_macros else [
            {
                "index": 0,
                "purpose": "WOTS+C chain hash",
                "body_bytes": len(stage1.build_chain_hash_function(None).raw),
                "executed_calls": 240,
            },
            {
                "index": 1,
                "purpose": "complete WOTS+C chain walk",
                "body_bytes": len(stage1.build_chain_walk_function(nested_macro=True).raw),
                "call_sites": shrincs.WOTS_C_CHAIN_COUNT,
            },
            {
                "index": 2,
                "purpose": "FXMSS Merkle parent hash",
                "body_bytes": len(build_merkle_hash_function(fixture["pk_seed"]).raw),
                "call_sites": TREE_DEPTH,
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
            "invalid_authentication_path_rejected": not invalid["success"],
        },
        "transaction": transaction,
        "padding_weight": 0,
        "funded_weight": transaction["raw_weight"],
        "block_weight_percent": 100 * transaction["raw_weight"] / 4_000_000,
        "scope_limit": "Fixed depth; caller supplies leaf index and message digest.",
    })
    print(json.dumps({
        "eval_fixture": str(eval_path),
        "result": str(result_path),
        "script_bytes": len(script.raw),
        "signature_bytes": len(fixture["signature"]),
        "raw_weight": transaction["raw_weight"],
        "varops": consumed,
        "relative_varops_percent": 100 * consumed / request["varops_budget"],
    }, indent=2))


if __name__ == "__main__":
    main()
