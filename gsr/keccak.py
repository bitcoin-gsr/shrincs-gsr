#!/usr/bin/env python3
"""Keccak-f[1600] in Tapleaf 0xC2 Script, to price SHAKE-based schemes (Falcon, SLH-DSA-SHAKE).

Representation: the state is five 80-byte rows on the stack (row 0 deepest). Row y holds
lanes x = 0..4 as 16-byte blocks, each lane twice (lane || lane, little-endian). Bitwise
operations keep the doubled form, and a rotation of lane x by r is one shift of its row:
(row >> 128x + 64 - r) has the rotated lane in its low 8 bytes.

    python3 gsr/keccak.py      # checks the permutation against a reference and prints its cost
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from asm import Program, hx  # noqa: E402

RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
      0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
MASK64 = (1 << 64) - 1


def reference(lanes: list[int], rounds: int = 24) -> list[int]:
    """Keccak-f[1600] on 25 lanes, lane (x, y) at index x + 5y."""
    a = list(lanes)
    rot = lambda v, r: ((v << r) | (v >> (64 - r))) & MASK64 if r else v  # noqa: E731
    for rnd in range(rounds):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rot(a[x + 5 * y], RHO[x][y])
        a = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= RC[rnd]
    return a


def rows(lanes: list[int]) -> list[bytes]:
    """The five doubled rows of a state."""
    return [b"".join(lanes[x + 5 * y].to_bytes(8, "little") * 2 for x in range(5)) for y in range(5)]


def program(rounds: int = 24) -> Program:
    """[R0 R1 R2 R3 R4] -> [R0' .. R4']: `rounds` rounds of Keccak-f[1600]."""
    p = Program()
    low_halves = hx((b"\xff" * 8 + bytes(8)) * 5)
    # theta: C = R0^..^R4; D[x] = C[x-1] ^ rotl1(C[x+1]) from CC = C||C; every row ^= D
    p.macro("THETA", f"""
        DUP 2 PICK XOR 3 PICK XOR 4 PICK XOR 5 PICK XOR
        DUP CAT DUP 512 RSHIFT SWAP 191 RSHIFT XOR {low_halves} AND DUP 64 LSHIFT OR 80 LEFT
        TOALTSTACK""" + " 4 ROLL FROMALTSTACK DUP TOALTSTACK XOR" * 5 + " FROMALTSTACK DROP")
    # rho and pi: output row y' block x' = rotl(A[x][y], r) with y = x', y' = 2x + 3y; each input
    # row is copied for its lanes of rows 0..3 and consumed by its lane of row 4.
    out, stack = [], [f"R{y}" for y in range(5)]       # simulated stack, top last
    for y_out in range(5):
        for x_out in range(5):
            y = x_out
            x = next(x for x in range(5) if (2 * x + 3 * y) % 5 == y_out)
            depth = len(stack) - 1 - stack.index(f"R{y}")
            if y_out == 4:
                stack.remove(f"R{y}")
            stack.append("lane")
            if x_out:
                stack[-2:] = ["acc"]
            shift = 128 * x + 64 - RHO[x][y]
            out.append(f"{depth} {'ROLL' if y_out == 4 else 'PICK'} {shift} RSHIFT 8 LEFT DUP CAT" + (" CAT" if x_out else ""))
        stack[-1] = f"O{y_out}"
    assert stack == [f"O{y}" for y in range(5)], stack
    p.macro("RHOPI", " ".join(out))
    # chi on one row O: O ^ (~B1 & B2), B1 and B2 the row turned by one and two lanes
    p.macro("CHI", "DUP DUP CAT DUP 128 RSHIFT INVERT SWAP 256 RSHIFT AND XOR 80 LEFT")
    main = []
    for rnd in range(rounds):
        rc = hx(RC[rnd].to_bytes(8, "little") * 2)
        main.append(f"@THETA @RHOPI 4 ROLL @CHI {rc} XOR" + " 4 ROLL @CHI" * 4)
    p.set_main(" ".join(main))
    return p


def check_and_measure() -> None:
    import measure as M
    lanes = [int.from_bytes(os.urandom(8), "little") for _ in range(25)]
    for rounds in (1, 24):
        p = program(rounds)
        want = rows(reference(lanes, rounds))
        p2 = program(rounds)
        p2.set_main(" ".join(p2.main) + " " + " ".join(
            [f"{hx(want[4 - i])} EQUALVERIFY" for i in range(4)] + [f"{hx(want[0])} EQUAL"]))
        r = M.evalscript(p2.assemble(), rows(lanes))
        assert r["success"], (rounds, r["error"])
        cost = M.evalscript(program(rounds).assemble(), rows(lanes))["varops"]  # leaves 5 rows: fails, cost still counted
        print(f"Keccak-f[1600], {rounds:2} round(s): {cost:,} varops; script {len(program(rounds).assemble())} B "
              f"(macros), {len(program(rounds).assemble(inline=True))} B inline")
    # SHA3-256("") is one permutation of the padded block
    block = bytearray(200)
    block[0], block[135] = 0x06, 0x80
    out = reference([int.from_bytes(block[8 * i:8 * i + 8], "little") for i in range(25)])
    digest = b"".join(v.to_bytes(8, "little") for v in out)[:32]
    assert digest == hashlib.sha3_256(b"").digest()
    print("reference matches hashlib.sha3_256")


if __name__ == "__main__":
    check_and_measure()
