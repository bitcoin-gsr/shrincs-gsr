#!/usr/bin/env python3
"""Build every GSR SHRINCS verifier variant, check it, and measure its spend.

For each variant this assembles the leaf script (with macros, and inline for
the unrolled size), evaluates the witness with `bitcoin-util evalscript` where
the script needs no transaction, then evaluates a complete one-input,
one-output spend with `txeval`, which runs Core's VerifyScript under the BIP 440
transaction budget. Each valid spend is checked against a corrupted signature,
and every OP_TX variant against the same witness in a different transaction.

    python3 gsr/measure.py --repeat 25   # writes gsr/results.json and gsr/results.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fixtures as fx  # noqa: E402
import verifiers as v  # noqa: E402
from asm import GSR_ROOT  # noqa: E402
from verifiers import ref  # noqa: E402

BITCOIN_UTIL = GSR_ROOT / "build" / "bitcoin" / "bin" / "bitcoin-util"
TXEVAL = HERE / "build" / "txeval"
OUTPUT_WEIGHT = 4 * 43  # an output paying to a 34-byte witness program, as P2TR and P2MR both are


def evalscript(script: bytes, stack: list[bytes]) -> dict:
    request = {"protocol": 1, "sigversion": "tapleaf_0xc2", "script": script.hex(),
               "stack": [s.hex() for s in stack], "varops_budget": 10 ** 12}
    out = subprocess.run([str(BITCOIN_UTIL), "evalscript"], input=json.dumps(request), capture_output=True,
                         text=True, check=True).stdout
    r = json.loads(out)
    r["varops"] = 10 ** 12 - r["varops-budget-remaining"]
    return r


def txeval(tx, spent, budget_override: int | None = None) -> dict:
    if not TXEVAL.exists():
        subprocess.run([str(HERE / "tools" / "build_txeval.sh")], check=True, capture_output=True)
    request = {"tx": tx.serialize_with_witness().hex(),
               "spent": [{"amount": o.nValue, "script_pubkey": bytes(o.scriptPubKey).hex()} for o in spent]}
    if budget_override is not None:
        request["budget_override"] = budget_override
    out = subprocess.run([str(TXEVAL)], input=json.dumps(request), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def corrupt(sig: bytes, at: int) -> bytes:
    bad = bytearray(sig)
    bad[at] ^= 1
    return bytes(bad)


class Variant:
    """One leaf script (in a tree of `leaves`) and a witness that should satisfy it."""

    def __init__(self, vid: str, stage: str, label: str, leaves: list, spend_leaf: int, stack=None,
                 sign=None, corrupt_at: int = 100, executed_steps: int | None = None, padded: bool = False) -> None:
        self.vid, self.stage, self.label, self.padded = vid, stage, label, padded
        self.leaves, self.spend_leaf, self.stack, self.sign = leaves, spend_leaf, stack, sign
        self.corrupt_at, self.executed_steps = corrupt_at, executed_steps


def build_variants(quick: bool) -> list[Variant]:
    out = []
    w = fx.wots_c_fixture()
    p1 = v.stage1(w["key"], w["address"], w["wots_pk"])
    out.append(Variant("1a", "1", "WOTS+C one-time signature, inline", [(p1, True)], 0, w["stack"]))
    out.append(Variant("1b", "1", "WOTS+C one-time signature, macros", [(p1, False)], 0, w["stack"]))

    f = fx.fxmss_fixture()
    p2 = v.stage2(f["key"], f["depth"])
    out.append(Variant("2a", "2", "FXMSS tree, fixed depth 8, inline", [(p2, True)], 0, f["stack"]))
    out.append(Variant("2b", "2", "FXMSS tree, fixed depth 8, macros", [(p2, False)], 0, f["stack"]))

    message = fx.digest("SHRINCS GSR message")
    # (variant, shape, key depth, verifier max depth, signature leaf depth, label)
    stateful = [
        ("3a", 0, 255, 255, 1, "SHRINCS stateful path: UXMSS-255 key, 1st signature (depth 1)"),
        ("3b", 1, 8, 8, 8, "SHRINCS stateful path: BXMSS-8 key (256 signatures)"),
        ("3c", 0, 20, 20, 20, "SHRINCS stateful path: depth-20 signature (UXMSS-20 key; = any BXMSS-20 signature)"),
        ("3d", 0, 255, 255, 64, "SHRINCS stateful path: UXMSS-255 key, depth 64"),
        ("3e", 0, 255, 255, 255, "SHRINCS stateful path: UXMSS-255 key, last signature (depth 255)"),
    ]
    if quick:
        stateful = stateful[1:2]
    for vid, shape, depth, max_depth, leaf_depth, label in stateful:
        _sk, pk = fx.shrincs_key(shape, depth)
        sig = fx.sign(message, shape, depth, fx.stateful_state(shape, depth, leaf_depth))
        p3 = v.stage3(fx.script_key(pk), max_depth)
        out.append(Variant(vid, "3", label, [(p3, False)], 0, [sig, message], corrupt_at=40))

    _sk, pk = fx.shrincs_key(1, 8)
    key = fx.script_key(pk)
    p4 = v.stage4(key)
    for i in range(1 if quick else 3):
        sig = fx.sign(message, 1, 8, None, opt_rand=fx.digest(f"opt_rand {i}")[:16])
        out.append(Variant(f"4{'abc'[i]}", "4", f"SHRINCS stateless path, signature {i + 1}", [(p4, False)], 0, [b"", sig, message],
                           corrupt_at=3000, executed_steps=stateless_steps(sig, message, pk), padded=True))

    # Stage 5: one output, two leaves (stateful and stateless), both rebuilding the message with OP_TX.
    leaves = [(v.stage3(key, 8, message="optx"), False), (v.stage4(key, message="optx"), False)]
    out.append(Variant("5a", "5", "SHRINCS, bound by OP_TX: stateful leaf (BXMSS-8 key)", leaves, 0,
                       sign=lambda m: [fx.sign(m, 1, 8, fx.stateful_state(1, 8, 8))], corrupt_at=40))
    out.append(Variant("5b", "5", "SHRINCS, bound by OP_TX: stateless leaf", leaves, 1,
                       sign=lambda m: [b"", fx.sign(m, 1, 8, None, opt_rand=fx.digest("opt_rand 0")[:16])],
                       corrupt_at=3000, padded=True))
    return out


def stateless_steps(sig: bytes, message: bytes, pk: bytes) -> int:
    """Executed WOTS-TW chain steps when verifying a stateless SHRINCS signature: 5 layers x (525 - sum of indexes)."""
    pk_seed, sl_root, sf_root = pk[:16], pk[16:32], pk[32:48]
    cmsg = bytes([0, len(v.CTX)]) + v.CTX + sf_root + message
    sphx = sig[1:]
    R = sphx[:16]
    fors_sig = sphx[16:16 + ref.FORS_SIGNATURE_SIZE]
    ht = sphx[16 + ref.FORS_SIGNATURE_SIZE:]
    fors_digest, tree, leaf = ref.slh_dsa_digest_message(R, pk_seed, sl_root, cmsg)
    adrs = bytearray(22)
    adrs[1:9] = tree.to_bytes(8, "big")
    adrs[10:14] = leaf.to_bytes(4, "big")
    node = ref.fors_pubkey_from_sig(fors_sig, fors_digest, pk_seed, adrs)
    steps = 0
    for j in range(ref.SPHX_LAYER_COUNT):
        indexes = ref.wots_tw_message_to_indexes(node)
        steps += sum(15 - i for i in indexes)
        adrs = bytearray(22)
        adrs[0] = j
        adrs[1:9] = tree.to_bytes(8, "big")
        node = ref.xmss_pubkey_from_sig(leaf, ht[j * 704:(j + 1) * 704], node, pk_seed, adrs)
        leaf, tree = tree % 512, tree >> 9
    assert node == sl_root
    return steps


def witness_size(stack: list[bytes]) -> int:
    """Serialized size of a witness stack: item count and length-prefixed items."""
    def compact(n: int) -> int:
        return 1 if n < 253 else 3 if n <= 0xFFFF else 5
    return compact(len(stack)) + sum(compact(len(x)) + len(x) for x in stack)


def measure(var: Variant, repeat: int) -> dict:
    scripts = [p.assemble(inline=inline) for p, inline in var.leaves]
    program, inline = var.leaves[var.spend_leaf]
    script = scripts[var.spend_leaf]
    unrolled = program.assemble(inline=True)
    tap = fx.leaf_tree(scripts)
    name = f"leaf{var.spend_leaf}"
    si = 1 if var.padded else 0  # witness position of the signature

    def with_sig(stack: list[bytes], sig: bytes) -> list[bytes]:
        return stack[:si] + [sig] + stack[si + 1:]

    if var.sign is None:
        stack = list(var.stack)
        standalone = evalscript(script, stack)
        assert standalone["success"], (var.vid, standalone["error"])
        assert not evalscript(script, with_sig(stack, corrupt(stack[si], var.corrupt_at)))["success"], var.vid
    else:
        tx, spent = fx.spend(tap, name, [b""])
        stack = var.sign(fx.optx_message(tx, spent, 0, tap.leaves[name].leaf_hash))
        standalone = None

    tx, spent = fx.spend(tap, name, stack)
    result = txeval(tx, spent)
    inp = result["inputs"][0]
    raw_weight, varops = result["weight"], inp["varops"]
    padding = 0
    if not inp["success"]:
        # Only a stateless spend may run out of budget: fill its padding item until it is funded.
        assert var.padded and inp["error"] == "Varops budget exceeded", (var.vid, inp["error"])
        unfunded = txeval(tx, spent, budget_override=10 ** 12)["inputs"][0]
        assert unfunded["success"], var.vid
        need = -(-(unfunded["varops"] - result["budget"]) // 10_000)
        while not inp["success"]:
            # The padding item is outside the OP_TX message, so the signature stays valid.
            stack = [bytes(need)] + stack[1:]
            tx, spent = fx.spend(tap, name, stack)
            result = txeval(tx, spent)
            inp = result["inputs"][0]
            need += 1
        padding = result["weight"] - raw_weight
        varops = inp["varops"]
    timing = txeval_timed(tx, spent, repeat) if repeat else None

    bad_tx, bad_spent = fx.spend(tap, name, with_sig(stack, corrupt(stack[si], var.corrupt_at)))
    bad = txeval(bad_tx, bad_spent)["inputs"][0]
    assert not bad["success"], var.vid
    checks = {"valid": True, "corrupted_signature_rejected": True, "corrupted_error": bad["error"]}
    if var.sign is not None:
        # The same witness in a transaction paying a different amount must fail.
        other, other_spent = fx.spend(tap, name, stack, amount_out=fx.AMOUNT - fx.FEE - 1)
        moved = txeval(other, other_spent)["inputs"][0]
        assert not moved["success"], var.vid
        checks["other_transaction_rejected"] = True
        checks["other_transaction_error"] = moved["error"]

    witness = tx.wit.vtxinwit[0].scriptWitness.stack
    weight, budget = result["weight"], result["budget"]
    return {
        "id": var.vid, "stage": var.stage, "label": var.label,
        "script_bytes": len(script), "unrolled_bytes": len(unrolled), "inline": inline,
        "unroll_varops": 0 if inline else program.unroll_charge(),
        "macros": {} if inline else program.macro_sizes(),
        "signature_bytes": len(stack[si]),
        "other_witness_bytes": sum(len(x) for k, x in enumerate(stack) if k != si),
        "control_block_bytes": len(witness[-1]),
        "witness_bytes": witness_size(witness),
        "tx_weight": weight, "tx_vsize": -(-weight // 4), "raw_tx_weight": raw_weight,
        "padding_weight": padding, "output_weight": OUTPUT_WEIGHT,
        "budget": budget, "varops": varops, "budget_percent": round(100 * varops / budget, 2),
        "standalone_varops": standalone["varops"] if standalone else None,
        "verify_us": timing,
        "executed_chain_steps": var.executed_steps,
        "checks": checks,
        "script_sha256": hashlib.sha256(script).hexdigest(),
        "tx_hex": tx.serialize_with_witness().hex(),
        "spent": [{"amount": o.nValue, "script_pubkey": bytes(o.scriptPubKey).hex()} for o in spent],
    }


def txeval_timed(tx, spent, repeat: int) -> float:
    request = {"tx": tx.serialize_with_witness().hex(), "repeat": repeat,
               "spent": [{"amount": o.nValue, "script_pubkey": bytes(o.scriptPubKey).hex()} for o in spent]}
    out = subprocess.run([str(TXEVAL)], input=json.dumps(request), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["inputs"][0]["median_us"]


def comparison(report: dict) -> str:
    """Full spend size of the GSR verifiers against a Schnorr key-path spend and against SHRINCS as a
    native opcode (the upstream draft's 0xC2 CHECKSIG: one leaf `<flag||pk 49 B> OP_CHECKSIG`)."""
    rows = {r["id"]: r for r in report["rows"]}
    tap = fx.leaf_tree([b"\x51"])
    schnorr, _ = fx.spend(tap, "leaf0", [])
    schnorr.wit.vtxinwit[0].scriptWitness.stack = [bytes(64)]
    native = fx.leaf_tree([bytes([49]) + bytes(49) + b"\xac"])

    def native_weight(sig_bytes: int) -> int:
        return fx.spend(native, "leaf0", [bytes(sig_bytes)])[0].get_weight()
    base = schnorr.get_weight()
    out = ["| spend | signature B | tx WU | vsize vB | against Schnorr |", "|---|---:|---:|---:|---:|"]
    for label, sig, weight in (
            ("Schnorr key path (P2TR, not post-quantum)", 64, base),
            ("SHRINCS stateful, native opcode", rows["5a"]["signature_bytes"], native_weight(rows["5a"]["signature_bytes"])),
            ("SHRINCS stateful, GSR Script (5a)", rows["5a"]["signature_bytes"], rows["5a"]["tx_weight"]),
            ("SHRINCS stateless, native opcode", rows["5b"]["signature_bytes"], native_weight(rows["5b"]["signature_bytes"])),
            ("SHRINCS stateless, GSR Script (5b)", rows["5b"]["signature_bytes"], rows["5b"]["tx_weight"])):
        out.append(f"| {label} | {sig:,} | {weight:,} | {-(-weight // 4):,} | {weight / base:.1f}× |")
    return "\n".join(out) + "\n"


def markdown(report: dict) -> str:
    """The spend table of a results report. A macro row and its inline row share one line, with the
    inline value in brackets where it differs; other rows give the inline script size only."""
    def fields(r: dict) -> list[str]:
        return [f"{r['script_bytes']:,}", f"{r['signature_bytes']:,}", f"{r['witness_bytes']:,}",
                f"{r['tx_weight']:,}", f"{r['tx_vsize']:,}", f"{r['varops'] / 1e6:.2f}M",
                f"{r['unroll_varops'] / 1e6:.2f}M", f"{r['budget_percent']:.1f}%", f"{r['padding_weight']}",
                f"{r['verify_us'] or 0:,.0f}"]

    lines = [f"Node {report['node']['repo']}@{report['node']['commit'][:10]} ({report['node']['branch']}), "
             f"SHRINCS {report['scheme_commit'][:10]}. Every variant locks into one 43-byte output "
             f"({OUTPUT_WEIGHT} WU, no varops); the table is the spend. Brackets: the inline form.", "",
             "| id | variant | script B (inline) | signature B | witness B | tx WU | vsize vB | varops | "
             "unroll charge | budget used | padding WU | verify µs |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    inline = {r["stage"]: r for r in report["rows"] if r["inline"]}
    for r in report["rows"]:
        if r["inline"]:
            continue
        cells = fields(r)
        vid, label = r["id"], r["label"]
        if r["stage"] in inline:
            vid, label = r["stage"], label.removesuffix(", macros")
            cells = [m if m == i else f"{m} ({i})" for m, i in zip(cells, fields(inline[r["stage"]]))]
        else:
            cells[0] += f" ({r['unrolled_bytes']:,})"
        lines.append(f"| {vid} | {label} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n\n" + comparison(report)


def git_rev(path: Path, *files: str) -> str:
    """HEAD of the repository at `path`, or the last commit that changed `files` there."""
    r = subprocess.run(["git", "log", "-1", "--format=%H", "HEAD", "--", *files], cwd=path, capture_output=True, text=True)
    return r.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="one variant per stage")
    parser.add_argument("--only", help="comma-separated variant ids")
    parser.add_argument("--repeat", type=int, default=0, help="time each spend's verification this many times")
    parser.add_argument("--table", action="store_true", help="only rewrite results.md from results.json")
    args = parser.parse_args()
    if args.table:
        (HERE / "results.md").write_text(markdown(json.loads((HERE / "results.json").read_text())))
        return
    variants = build_variants(args.quick)
    if args.only:
        keep = set(args.only.split(","))
        variants = [x for x in variants if x.vid in keep]
    rows = []
    for var in variants:
        row = measure(var, args.repeat)
        rows.append(row)
        print(f"{row['id']:3} {row['label']:58} script {row['script_bytes']:6} wit-sig {row['signature_bytes']:5} "
              f"tx {row['tx_weight']:6} WU  varops {row['varops']:11,}  {row['budget_percent']:6.2f}%  "
              f"pad {row['padding_weight']}  {row['verify_us'] or 0:8.0f} us", flush=True)
    report = {"node": {"repo": "jmoik/bitcoin", "branch": "gsr", "commit": git_rev(GSR_ROOT / "bitcoin")},
              "scheme_commit": git_rev(HERE.parent, "impl", "SHRINCS.md"), "ctx": v.CTX.decode(), "rows": rows}
    if not args.only and not args.quick:
        (HERE / "results.json").write_text(json.dumps(report, indent=1) + "\n")
        (HERE / "results.md").write_text(markdown(report))


if __name__ == "__main__":
    main()
