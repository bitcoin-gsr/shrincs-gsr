#!/usr/bin/env python3
"""Cost estimates for other post-quantum signatures as Tapleaf 0xC2 verifiers.

Nothing here is a complete verifier. Each estimate multiplies operation counts of the
scheme by unit costs measured on the node (`bitcoin-util evalscript`) with pieces of the
SHRINCS verifiers, or with small loop bodies written for the scheme:

    walk step / skip   SHRINCS chain step (one tweakable hash), from the hypertree LAYER macro
    layer              SHRINCS WOTS-TW + 9-level XMSS layer: fixed part and per chain step
    fors tree          SHRINCS FORS tree (a = 13): leaf + 13 levels
    xmss step / node   RFC 8391 WOTS+ chain step (PRF key, PRF mask, F) and RAND_HASH node
    lamport bit        one bit of a Lamport signature (hash the preimage, order, chain-hash)
    keccak-f           Keccak-f[1600] (keccak.py), 24 rounds
    falcon coeff       one coefficient: unpack, centre, square, add to the norm, pack 5 bytes
    mul 2560           a 2560 x 2560 byte multiplication (Kronecker product of two polynomials)

Transactions are priced like the measured ones: one input, one output, the leaf's message
from OP_TX (stage 5) and a single-leaf control block. A spend whose varops exceed its budget
(10,000 per weight unit - 500,000) is padded with witness bytes until it fits.

    python3 gsr/estimates.py      # prints and writes gsr/estimates.md
"""
from __future__ import annotations

import math
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fixtures as fx  # noqa: E402
import keccak  # noqa: E402
import measure as M  # noqa: E402
import verifiers as v  # noqa: E402
from asm import Program, be, hx, le  # noqa: E402
from verifiers import ref  # noqa: E402

TX_OVERHEAD = 378           # tx weight minus witness bytes of the measured 1-in-1-out spends
OPTX = (8, 19_540)          # script bytes and varops of the OP_TX message prologue (5a - 3b)
CONTROL_BLOCK = 34          # 33 bytes and its length prefix
rb = random.Random(2026).randbytes   # fixed inputs: the estimates are reproducible


def run(main: str, stack: list[bytes], macros=None) -> int:
    p = Program()
    if macros:
        macros(p)
    p.set_main(main)
    return M.evalscript(p.assemble(), stack)["varops"]


def delta(main: str, stack: list[bytes], tail: str, macros=None) -> int:
    return run(f"{main} {tail}", stack, macros) - run(tail, stack, macros)


def units() -> dict[str, float]:
    u: dict[str, float] = {}
    _sk, pk = fx.shrincs_key(ref.FXMSS_SHAPE_BALANCED, 8)
    key = fx.script_key(pk)

    def shrincs(p):
        v.common_macros(p, key)
        v.stateless_macros(p, key)

    # SHRINCS layer: fixed part and cost per executed chain step, fitted over random nodes
    hts = rb(ref.SPHX_XMSS_SIGNATURE_SIZE * ref.SPHX_LAYER_COUNT)
    pts = []
    for _ in range(8):
        node = rb(16)
        digits = [x for b in node for x in (b >> 4, b & 15)]
        cs = 480 - sum(digits)
        digits += [(cs >> 8) & 15, (cs >> 4) & 15, cs & 15]
        steps = sum(15 - d for d in digits)
        pts.append((steps, delta("@LAYER", [b"\x05", b"\x03", node, hts], "2DROP 2DROP 1", shrincs)))
    n = len(pts)
    sx, sy = sum(x for x, _ in pts), sum(y for _, y in pts)
    u["step"] = (n * sum(x * y for x, y in pts) - sx * sy) / (n * sum(x * x for x, _ in pts) - sx * sx)
    u["layer"] = sy / n - u["step"] * sx / n
    # one FORS tree (a = 13): a leaf and 13 levels, so one level is about a 14th
    stack = [b"", rb(17), bytes([136]), b"", rb(ref.FORS_SIGNATURE_SIZE)]
    pre = f"{hx(rb(78))} TOALTSTACK"
    u["fors_tree13"] = delta(f"{pre} @FORS_TREE", stack, "FROMALTSTACK DROP 2DROP 2DROP DROP 1", shrincs) - \
        delta(pre, stack, "FROMALTSTACK DROP 2DROP 2DROP DROP 1", shrincs)
    u["level"] = u["fors_tree13"] / (1 + ref.SPHX_FORS_HEIGHT)
    # SHRINCS chain walk, all 15 steps skipped
    u["walk_skip"] = delta("@WALK", [rb(82), rb(16), bytes([15])], "DROP 1", shrincs)

    # RFC 8391 WOTS+ chain: step j: KEY = PRF(ADRS j 0), BM = PRF(ADRS j 1), node' = F(KEY, node ^ BM);
    # [PS node c], PS = toByte(3, 32) || SEED || ADRS[:24]
    def xmss(p):
        p.macro("XWALK", " ".join(
            f"DUP 0NOTEQUAL IF 1SUB ELSE 2 PICK {be(j, 4)}00000000 CAT SHA256 3 PICK {be(j, 4)}00000001 CAT SHA256 "
            f"3 ROLL XOR CAT {hx(bytes(32))} SWAP CAT SHA256 SWAP ENDIF" for j in range(15)) + " DROP NIP")
    ps = bytes(31) + b"\x03" + rb(32 + 24)
    skip = delta("@XWALK", [ps, rb(32), bytes([15])], "DROP 1", xmss)
    full = delta("@XWALK", [ps, rb(32), b""], "DROP 1", xmss)
    u["xmss_walk_skip"], u["xmss_step"] = skip, (full - skip) / 15
    # RAND_HASH(L, R): KEY, BM0, BM1 = PRF(ADRS 0/1/2); SHA256(toByte(1, 32) || KEY || L^BM0 || R^BM1)
    tb1 = hx(bytes(31) + b"\x01")
    node = (f"2 PICK x00000000 CAT SHA256 3 PICK x00000001 CAT SHA256 3 ROLL XOR "
            f"3 PICK x00000002 CAT SHA256 3 ROLL XOR CAT CAT {tb1} SWAP CAT SHA256")
    u["xmss_node"] = delta(node, [ps, rb(32), rb(32)], "2DROP 1")

    # Lamport, one bit: [acc m item] item = preimage || other hash -> [acc' m']
    bit = ("DUP 16 LEFT SHA256 16 LEFT SWAP 16 RIGHT 2 PICK 1 AND 0NOTEQUAL IF SWAP ENDIF CAT "
           "ROT SWAP CAT SHA256 16 LEFT SWAP 1 RSHIFT")
    items = [rb(32) for _ in range(8)]
    u["lamport_bit"] = (delta(" ".join(["ROT " + bit] * 8), items + [rb(16), rb(32)],
                              "2DROP 1")) / 8

    # Keccak-f[1600] and a Falcon coefficient
    lanes = [int.from_bytes(rb(8), "little") for _ in range(25)]
    u["keccak_f"] = M.evalscript(keccak.program().assemble(), keccak.rows(lanes))["varops"]
    q = 12289
    coeff = (f"DUP 2 LEFT SWAP 16 RSHIFT SWAP DUP DUP 6145 LESSTHAN NOTIF {q} SWAP SUB ENDIF DUP MUL "
             f"4 ROLL ADD SWAP {le(1 << 40)} ADD 5 LEFT 3 ROLL SWAP CAT ROT ")
    chunk = b"".join((int.from_bytes(rb(2), "little") % q).to_bytes(2, "little") for _ in range(16))
    u["falcon_coeff"] = delta(coeff * 16, [b"", b"", chunk], "2DROP DROP 1") / 16   # into an 80-byte chunk
    u["cat_1280"] = delta("CAT", [rb(1280), rb(80)], "DROP 1")        # chunk onto a 2560-byte slot list
    u["mul2560"] = delta("MUL", [rb(2560), rb(2560)], "DROP 1")
    u["sha256_76"] = delta("SHA256", [rb(76)], "DROP 1")
    return u


def tx(sig_items: list[int], script: int, varops: float) -> dict:
    """Weight, padding and vsize of a spend with these witness items and leaf script size."""
    def item(n):
        return n + (1 if n < 253 else 3)
    witness = 1 + sum(item(n) for n in sig_items) + item(script) + CONTROL_BLOCK
    weight = TX_OVERHEAD + witness
    budget = 10_000 * weight - 500_000
    pad = max(0, math.ceil((varops - budget) / 10_000))
    if pad:
        pad += 3          # the padding item's own length prefix
    return {"sig": sum(sig_items), "script": script, "varops": varops, "weight": weight + pad, "pad": pad,
            "vsize": math.ceil((weight + pad) / 4), "share": varops / (10_000 * (weight + pad) - 500_000)}


def estimates(u: dict[str, float]) -> list[tuple[str, str, dict, str]]:
    rows = []
    # Lamport: 256 bits, preimages and hashes of 16 bytes, one witness item per bit
    var = OPTX[1] + 256 * u["lamport_bit"] + 20_000
    rows.append(("Lamport, 256 bits, n = 16", "1", tx([32] * 256, 200 + OPTX[0], var),
                 "256 items of preimage || other hash; cheap to verify, large"))

    # RFC 8391 XMSS-SHA2_10_256: n = 32, w = 16, 67 chains, h = 10
    chain_overhead = (u["layer"] - 9 * u["level"]) / 35 - u["walk_skip"]   # split, encode, CAT per chain (SHRINCS)
    for name, chains, n_hash, h in (("XMSS-SHA2_10_256 (RFC 8391)", 67, 32, 10),
                                    ("XMSS-SHA2_10_192 (SP 800-208)", 51, 24, 10)):
        len1 = chains - 3
        avg_steps, max_steps = len1 * 7.5 + 30, len1 * 15 + 30
        fixed = chains * (u["xmss_walk_skip"] + chain_overhead) + (chains - 1 + h) * (u["xmss_node"] + 10_000) \
            + OPTX[1] + 50_000
        sig = 4 + n_hash + chains * n_hash + h * n_hash
        avg = tx([sig], 1500, fixed + avg_steps * u["xmss_step"])
        worst = tx([sig], 1500, fixed + max_steps * u["xmss_step"])
        rows.append((name, "1,024", avg, f"worst case (all digits 0): {worst['varops'] / 1e6:.0f}M varops, "
                     f"{worst['vsize']:,} vB"))

    # SLH-DSA-SHA2-128s: n = 16, d = 7, h' = 9, k = 14, a = 12; same tweakable hash as SHRINCS
    steps_per_layer = 282   # measured average of the SHRINCS stateless signatures (WOTS-TW, 35 chains)
    var = 7 * (u["layer"] + steps_per_layer * u["step"]) + 14 * (u["fors_tree13"] - u["level"]) + OPTX[1] + 200_000
    rows.append(("SLH-DSA-SHA2-128s (FIPS 205)", "2^64", tx([7856], 1200, var),
                 "the SHRINCS stateless verifier with d = 7 layers and k = 14, a = 12 FORS trees"))

    # SLH-DSA-SHAKE-128s: one Keccak-f per tweakable hash call (T_len: 5, T_k: 2)
    calls = 14 * 13 + 2 + 7 * (steps_per_layer + 5 + 9)
    var = calls * u["keccak_f"]
    rows.append(("SLH-DSA-SHAKE-128s (FIPS 205)", "2^64", tx([7856], 2600, var),
                 f"{calls:,} Keccak-f calls; not a standard transaction"))

    # Falcon-512: hash-to-point, s2 (2 bytes per coefficient in the witness), h unpacked from 2 bytes
    # each in the script, s2*h by one Kronecker multiplication, s1 = c - s2*h mod q, the norm.
    # Loop bodies other than the measured s2 one are priced relative to it by their op counts.
    samples = 546          # expected 16-bit samples for 512 values below 5q
    c = u["falcon_coeff"]
    arith = (512 * c                            # s2: unpack, centre, square, add, pack into 5 bytes
             + 512 * 1.1 * c                    # s1: unpack a slot, (c - t) mod q, centre, square, add
             + 512 * 0.4 * c                    # h: unpack 2 bytes into a 5-byte slot
             + samples * 0.4 * c                # samples: 2 bytes, byte order, compare with 5q
             + 2 * 32 * u["cat_1280"]           # chunks of 16 slots joined, for s2 and h
             + u["mul2560"] + 200_000)          # product and negacyclic fold
    sig = 1 + 40 + 1024
    shake = 9 * u["keccak_f"]
    rows.append(("Falcon-512 (FN-DSA), SHAKE256", "2^64", tx([sig], 1024 + 2600, arith + shake + OPTX[1]),
                 f"9 Keccak-f = {shake / 1e6:.0f}M varops; arithmetic {arith / 1e6:.0f}M"))
    sha = math.ceil(2 * samples / 32) * (u["sha256_76"] + 3_000)
    rows.append(("Falcon-512, SHA-256 hash-to-point (non-standard)", "2^64",
                 tx([sig], 1024 + 1200, arith + sha + OPTX[1]),
                 f"35 SHA-256 calls replace SHAKE256; arithmetic {arith / 1e6:.0f}M"))
    return rows


def main() -> None:
    u = units()
    lines = ["Measured unit costs (varops):", ""]
    lines += [f"    {k:15} {val:12,.0f}" for k, val in u.items()]
    lines += ["", "| scheme | signatures | sig B | script B | varops | padding WU | tx WU | vsize vB | budget used | note |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for name, count, t, note in estimates(u):
        lines.append(f"| {name} | {count} | {t['sig']:,} | {t['script']:,} | {t['varops'] / 1e6:,.1f}M | {t['pad']:,} | "
                     f"{t['weight']:,} | {t['vsize']:,} | {100 * t['share']:.0f}% | {note} |")
    text = "\n".join(lines) + "\n"
    print(text, end="")
    (HERE / "estimates.md").write_text(text)


if __name__ == "__main__":
    main()
