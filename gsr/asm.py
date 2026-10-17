"""A small text assembler for Tapleaf 0xC2 Script with static macros.

Source is whitespace-separated tokens; `#` starts a comment:

    DUP 16 LEFT        opcodes and decimal numbers (minimal pushes)
    x0011ff            a data push of these bytes
    @NAME              a reference to the macro NAME (OP_CALLMACRO)

A `Program` holds macro definitions in dependency order and a main script. It
assembles either with OP_MACRO declarations and OP_CALLMACRO references, or
inline, with every reference expanded in place. Both forms execute the same
instructions.
"""
from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

GSR_ROOT = Path(os.environ.get("GSR_ROOT", Path(__file__).resolve().parents[2] / "gsr-stark-verifier"))

# The push encoder of the GSR tools (minimal pushes, Tapleaf 0xC2 rules), loaded by path.
_spec = importlib.util.spec_from_file_location("gsr_tools", GSR_ROOT / "risc0-succinct" / "tools" / "gsr.py")
_gsr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gsr)
Script, compact = _gsr.Script, _gsr.compact

OPS = {
    "0": 0x00, "IF": 0x63, "NOTIF": 0x64, "ELSE": 0x67, "ENDIF": 0x68, "VERIFY": 0x69,
    "TOALTSTACK": 0x6B, "FROMALTSTACK": 0x6C, "2DROP": 0x6D, "2DUP": 0x6E, "3DUP": 0x6F,
    "2OVER": 0x70, "2SWAP": 0x72, "DEPTH": 0x74, "DROP": 0x75, "DUP": 0x76, "NIP": 0x77,
    "OVER": 0x78, "PICK": 0x79, "ROLL": 0x7A, "ROT": 0x7B, "SWAP": 0x7C, "TUCK": 0x7D,
    "CAT": 0x7E, "SUBSTR": 0x7F, "LEFT": 0x80, "RIGHT": 0x81, "SIZE": 0x82, "AND": 0x84,
    "OR": 0x85, "XOR": 0x86, "EQUAL": 0x87, "EQUALVERIFY": 0x88, "1ADD": 0x8B, "1SUB": 0x8C,
    "NOT": 0x91, "0NOTEQUAL": 0x92, "ADD": 0x93, "SUB": 0x94, "MUL": 0x95, "DIV": 0x96,
    "MOD": 0x97, "LSHIFT": 0x98, "RSHIFT": 0x99, "NUMEQUAL": 0x9C, "NUMEQUALVERIFY": 0x9D,
    "LESSTHAN": 0x9F, "GREATERTHAN": 0xA0, "LESSTHANOREQUAL": 0xA1, "MIN": 0xA3, "MAX": 0xA4,
    "WITHIN": 0xA5, "SHA256": 0xA8, "TX": 0xBF, "BYTEREV": 0xCF, "INVERT": 0x83, "2MUL": 0x8D, "2DIV": 0x8E,
}
OP_MACRO, OP_CALLMACRO = 0xD0, 0xD1


def tokens(text: str) -> list[str]:
    return re.sub(r"#[^\n]*", " ", text).split()


def be(value: int, width: int) -> str:
    """A data token pushing `value` as `width` big-endian bytes."""
    return "x" + value.to_bytes(width, "big").hex()


def le(value: int) -> str:
    """A data token pushing `value` as a minimal little-endian number (at least one byte)."""
    return "x" + value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little").hex()


def hx(data: bytes) -> str:
    return "x" + data.hex()


class Program:
    def __init__(self) -> None:
        self.macros: dict[str, list[str]] = {}
        self.main: list[str] = []

    def macro(self, name: str, text: str) -> None:
        assert name not in self.macros, name
        body = tokens(text)
        for t in body:
            if t.startswith("@"):
                assert t[1:] in self.macros, f"{name} references {t} before its definition"
        self.macros[name] = body

    def set_main(self, text: str) -> None:
        self.main = tokens(text)

    # assembly

    def _emit(self, toks: list[str], script: Script, inline: bool, index: dict[str, int]) -> None:
        for t in toks:
            if t.startswith("@"):
                name = t[1:]
                if inline:
                    self._emit(self.macros[name], script, inline, index)
                else:
                    script.code += bytes([OP_CALLMACRO]) + compact(index[name])
            elif t.startswith("x"):
                script.data(bytes.fromhex(t[1:]))
            elif re.fullmatch(r"\d+", t):
                script.int(int(t))
            else:
                script.code.append(OPS[t])

    def used_macros(self) -> list[str]:
        """Macros reachable from main, in definition order."""
        used: set[str] = set()

        def visit(toks: list[str]) -> None:
            for t in toks:
                if t.startswith("@") and t[1:] not in used:
                    used.add(t[1:])
                    visit(self.macros[t[1:]])
        visit(self.main)
        return [m for m in self.macros if m in used]

    def assemble(self, inline: bool = False) -> bytes:
        script = Script()
        if not inline:
            names = self.used_macros()
            index = {name: i for i, name in enumerate(names)}
            for name in names:
                body = Script()
                self._emit(self.macros[name], body, False, index)
                script.code += bytes([OP_MACRO]) + compact(len(body.code)) + body.code
        else:
            index = {}
        self._emit(self.main, script, inline, index)
        return bytes(script.code)

    def unroll_charge(self) -> int:
        """Varops the node charges before execution (BIP 441): 300 per substituted instruction and
        per visited reference, plus writing the unrolled script. Zero without declarations."""
        if not self.used_macros():
            return 0
        own = sum(1 for t in self.main if not t.startswith("@"))
        refs = total = 0

        def visit(toks: list[str]) -> None:
            nonlocal refs, total
            for t in toks:
                if t.startswith("@"):
                    refs += 1
                    visit(self.macros[t[1:]])
                else:
                    total += 1
        visit(self.main)
        length = len(self.assemble(inline=True))
        return 300 * (total - own + refs) + 800 + 7 * ((length + 7) // 8 * 8)

    def macro_sizes(self) -> dict[str, int]:
        names = self.used_macros()
        index = {name: i for i, name in enumerate(names)}
        sizes = {}
        for name in names:
            body = Script()
            self._emit(self.macros[name], body, False, index)
            sizes[name] = len(body.code)
        return sizes
