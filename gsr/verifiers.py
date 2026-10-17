"""SHRINCS verifiers in Tapleaf 0xC2 Script.

Every verifier is built from a handful of macros. Stack pictures list the
bottom on the left and the top on the right; `alt[...]` is the altstack.

    BE4/BE8/BE9   number -> 4/8/9-byte big-endian bytes
    WALK          the 15 conditional chain-hash steps of one Winternitz chain
    NIB           split the next digest byte into two chain indexes
    CHAIN         recover one chain tip (fetch its signature chunk, build its ADRS, WALK)
    FX_LEVEL      one FXMSS Merkle level (stateful ADRS layout)
    HT_LEVEL      one XMSS or FORS Merkle level (stateless ADRS layout, prefix on the altstack)
    FORS_TREE     one FORS tree: leaf hash and 13 levels
    LAYER         one hypertree layer: WOTS-TW recovery, T_sl and 9 levels

Macros only shorten the committed script; the unrolled script, and so the
execution, is the same as the inline form.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "impl"))

import shrincs as ref  # noqa: E402
from asm import Program, be, hx, le  # noqa: E402

BIG = 6000          # a SUBSTR length past the end of every value we slice
CTX = b"bitcoin-tx"  # the SHRINCS context used from stage 3 on

# OP_TX selector: COLLATE version, locktime, input count, output count; all inputs'
# outpoint, amount, scriptPubKey and sequence; all outputs; current input index,
# annex and tapleaf hash. The signed message is SHA256 of the collated bytes.
OPTX_SELECTOR = bytes([0x00, 0x57, 0x0B, 0x22, 0x2F, 0x03])


class Key:
    """The public values a verifier script commits to."""

    def __init__(self, pk_seed: bytes, sl_root: bytes = bytes(16), sf_root: bytes = bytes(16)) -> None:
        self.pk_seed, self.sl_root, self.sf_root = pk_seed, sl_root, sf_root
        self.p64 = pk_seed + bytes(48)


def rep(p: Program, name: str, n: int) -> str:
    """Tokens calling macro `name` n times, nesting groups of 4 (x4, x16, x64)."""
    out, size, level = [], 1, name
    digits = []
    while n:
        digits.append(n % 4)
        n //= 4
    for i, d in enumerate(digits):
        if i > 0:
            group = f"{name}_x{size}"
            if group not in p.macros:
                p.macro(group, f"@{level} " * 4)
            level = group
        out = [f"@{level}"] * d + out
        size *= 4
    return " ".join(out)


def split(n: int) -> str:
    """(s -- s[:n] s[n:])"""
    return f"DUP {n} LEFT SWAP {n} {BIG} SUBSTR"


def common_macros(p: Program, key: Key) -> None:
    p.macro("BE4", f"{le(1 << 32)} ADD 4 LEFT BYTEREV")
    p.macro("BE8", f"{le(1 << 64)} ADD 8 LEFT BYTEREV")
    p.macro("BE9", f"{le(1 << 72)} ADD 9 LEFT BYTEREV")

    # [P82 node c] -> [tip]  c counts the steps still to skip (the chain index); step j hashes
    # node' = SHA256(P82||BE4(j)||node)[:16] once c is 0, and otherwise decrements c.
    p.macro("WALK", " ".join(
        f"DUP 0NOTEQUAL IF 1SUB ELSE 2 PICK {be(j, 4)} CAT ROT CAT SHA256 16 LEFT SWAP ENDIF" for j in range(15))
        + " DROP NIP")
    # [sum D] -> [hi lo sum' D']  hi, lo: the two indexes of D[0]; sum' = sum + hi + lo; D' = D[1:]
    p.macro("NIB", "DUP 1 LEFT DUP 4 RSHIFT SWAP 15 AND 2DUP ADD 4 ROLL ADD 3 ROLL 1 64 SUBSTR")
    # [n tips cs] alt[P78] -> [tips' cs']  for the last chain i = |cs|/16 - 1:
    # P82 = P78||BE4(i), tip = WALK(n, cs[16i:]), tips' = tip||tips, cs' = cs[:16i]
    p.macro("CHAIN", """
        DUP 16 RIGHT SWAP SIZE 16 SUB TUCK LEFT SWAP  # [n tips chunk cs' off]  off = 16 i
        4 RSHIFT @BE4                                 # [n tips chunk cs' chain4]
        FROMALTSTACK DUP TOALTSTACK SWAP CAT          # [n tips chunk cs' P82]
        ROT 4 ROLL @WALK                              # [tips cs' tip]
        ROT CAT SWAP""")

    # [h pos node path] -> [h' pos' node' path']  one Merkle level: h' = h + 1, pos' = pos >> 1,
    # node' = H(ADRS, node||sib or sib||node by the low bit of pos), sib = path[:16], path' = path[16:]
    order = f"{split(16)} TOALTSTACK 2 PICK 1 AND 0NOTEQUAL IF SWAP ENDIF CAT ROT 1ADD ROT 1 RSHIFT"
    # FXMSS: ADRS = h'||BE8(pos')||0x12||0^12
    p.macro("FX_LEVEL", f"""
        {order}                                         # [pair h' pos'] alt[path']
        2DUP @BE8 CAT {hx(bytes([ref.SF_FXMSS_TREE]) + bytes(12))} CAT {hx(key.p64)} SWAP CAT
        3 ROLL CAT SHA256 16 LEFT FROMALTSTACK""")
    p.macro("CFX_LEVEL", "SIZE 0NOTEQUAL IF @FX_LEVEL ENDIF")
    # XMSS and FORS, alt[P78]: ADRS = P78||BE4(h')||BE4(pos')
    p.macro("HT_LEVEL", f"""
        {order}                                         # [pair h' pos'] alt[P78 path']
        2DUP SWAP 32 LSHIFT ADD @BE8 FROMALTSTACK FROMALTSTACK DUP TOALTSTACK
        ROT CAT 4 ROLL CAT SHA256 16 LEFT SWAP""")


def wots_recover(p: Program, chains: int) -> str:
    """[cs d] alt[P78] -> [tips]  for WOTS+C (32 chains, constant sum) or WOTS-TW (35, checksum)."""
    text = f"0 SWAP {rep(p, 'NIB', 16)} DROP"      # [cs n0..n31 sum]
    if chains == ref.WOTS_C_CHAIN_COUNT:
        text += f" {ref.WOTS_C_CONSTANT_SUM} NUMEQUALVERIFY"
    else:
        # checksum c = 480 - sum, written as three base-16 digits n32 n33 n34
        text += f" {ref.WOTS_TW_CHECKSUM_MAX} SWAP SUB DUP 8 RSHIFT OVER 4 RSHIFT 15 AND ROT 15 AND"
    return text + f" {chains} ROLL 0 SWAP {rep(p, 'CHAIN', chains)} DROP"


def wots_c_pk(p: Program) -> str:
    """[fx d] alt[P73] -> [auth pk]  fx = counter2||chains512||auth, d the 32-byte digest."""
    return f"""
        OVER 2 LEFT SWAP FROMALTSTACK DUP TOALTSTACK {hx(bytes([ref.SF_WOTS_C_GRIND]))} CAT SWAP CAT
        x00000000 CAT SWAP CAT SHA256 16 LEFT           # [fx g]  g = H_grind(digest, counter)
        SWAP DUP 2 {ref.WOTS_C_CHAINS_SIZE} SUBSTR SWAP {2 + ref.WOTS_C_CHAINS_SIZE} {BIG} SUBSTR
        ROT ROT SWAP                                    # [auth cs g]
        FROMALTSTACK DUP TOALTSTACK {hx(bytes([ref.SF_WOTS_C_HASH]) + bytes(4))} CAT TOALTSTACK
        {wots_recover(p, ref.WOTS_C_CHAIN_COUNT)}       # [auth tips]
        FROMALTSTACK DROP FROMALTSTACK DUP TOALTSTACK {hx(bytes([ref.SF_WOTS_C_PK]) + bytes(12))} CAT
        SWAP CAT SHA256 16 LEFT                         # [auth pk]  pk = T_sf(tips)
        """


# ---- stage 1: WOTS+C on a supplied digest, fixed address ----

def stage1(key: Key, address: bytes, wots_pk: bytes) -> Program:
    """[sig514 digest32] -> [true]"""
    p = Program()
    common_macros(p, key)
    p.set_main(f"""
        SIZE 32 NUMEQUALVERIFY SWAP SIZE {2 + ref.WOTS_C_CHAINS_SIZE} NUMEQUALVERIFY SWAP
        {hx(key.p64 + address[:9])} TOALTSTACK
        {wots_c_pk(p)} NIP {hx(wots_pk)} EQUAL""")
    return p


# ---- stage 2: FXMSS, fixed depth, dynamic leaf index byte ----

def stage2(key: Key, depth: int = 8) -> Program:
    """[fx digest32 leaf_index_byte] -> [true], fx = counter||chains||auth (16*depth)."""
    height = ref.FXMSS_HEIGHT - depth
    p = Program()
    common_macros(p, key)
    p.set_main(f"""
        SIZE 1 NUMEQUALVERIFY ROT SIZE {2 + ref.WOTS_C_CHAINS_SIZE + 16 * depth} NUMEQUALVERIFY
        ROT SIZE 32 NUMEQUALVERIFY                      # [idx fx d]
        2 PICK {hx(key.p64 + bytes([height]) + bytes(7))} SWAP CAT TOALTSTACK
        {wots_c_pk(p)}                                  # [idx auth pk]
        {hx(bytes([height]))} 3 ROLL ROT 3 ROLL         # [h idx pk auth]
        {rep(p, 'FX_LEVEL', depth)} DROP NIP NIP {hx(key.sf_root)} EQUAL""")
    return p


# ---- stage 3: complete stateful SHRINCS verification, depth 1..max_depth ----

def message_prologue(message: str) -> str:
    """Put the 32-byte message on the altstack: from the witness, or rebuilt with OP_TX."""
    if message == "witness":
        return "SIZE 32 NUMEQUALVERIFY TOALTSTACK"
    assert message == "optx"
    return f"{hx(OPTX_SELECTOR)} TX SHA256 TOALTSTACK"


def stage3(key: Key, max_depth: int, message: str = "witness") -> Program:
    """[sig M] (or [sig] with message='optx') -> [true] for any stateful SHRINCS signature."""
    assert 1 <= max_depth <= ref.FXMSS_HEIGHT
    bound_prefix = bytes([0, len(CTX)]) + CTX + key.sl_root
    p = Program()
    common_macros(p, key)
    p.set_main(f"""
        {message_prologue(message)}                     # [sig] alt[M]
        SIZE SWAP DUP 1 LEFT xff OVER SUB               # [L sig hb d]  d = 255 - leaf height
        DUP 1 {max_depth + 1} WITHIN VERIFY
        DUP 64 MIN DUP 7 ADD 3 RSHIFT                   # [L sig hb d m s]  s = index bytes
        ROT 4 LSHIFT OVER ADD {1 + 16 + 2 + ref.WOTS_C_CHAINS_SIZE} ADD 5 ROLL NUMEQUALVERIFY
        3 ROLL DUP 1 16 SUBSTR SWAP 17 {BIG} SUBSTR     # [hb m s R sig17]
        ROT 2DUP LEFT ROT ROT {BIG} SUBSTR              # [hb m R idxb fx]
        OVER BYTEREV 1 5 ROLL LSHIFT LESSTHAN VERIFY    # leaf index < 2^min(d, 64)
        SWAP x0000000000000000 SWAP CAT 8 RIGHT 3 PICK SWAP CAT   # [hb R fx a9]  a9 = ADRS[:9]
        2 PICK {hx(key.pk_seed + key.sf_root)} CAT OVER CAT {hx(bound_prefix)} CAT FROMALTSTACK CAT SHA256
        3 PICK {hx(key.pk_seed)} CAT SWAP CAT OVER CAT SHA256     # [hb R fx a9 digest]  H_msg_sf
        OVER {hx(key.p64)} SWAP CAT TOALTSTACK          # alt[P73]
        3 ROLL DROP ROT SWAP                            # [hb a9 fx digest]
        {wots_c_pk(p)}                                  # [hb a9 auth pk]
        ROT 1 8 SUBSTR BYTEREV ROT ROT SWAP             # [h pos pk auth]
        {rep(p, 'CFX_LEVEL', max_depth)} DROP NIP NIP {hx(key.sf_root)} EQUAL""")
    return p


# ---- stage 4: stateless SHRINCS (SLH-DSA with FORS and a 5-layer hypertree) ----

def stateless_macros(p: Program, key: Key) -> None:
    fors_auth = 16 * ref.SPHX_FORS_HEIGHT
    # [roots X sh base fsig] alt[P78f] -> [roots' X sh' base' fsig']  one FORS tree
    p.macro("FORS_TREE", f"""
        ROT 13 SUB ROT ROT {split(16)} {split(fors_auth)}   # [roots X sh base sk auth fs]
        5 PICK 5 PICK RSHIFT {le(2 ** ref.SPHX_FORS_HEIGHT - 1)} AND 4 PICK ADD   # [.. fs pos]
        DUP @BE4 x00000000 SWAP CAT FROMALTSTACK DUP TOALTSTACK SWAP CAT
        4 ROLL CAT SHA256 16 LEFT                       # [roots X sh base auth fs pos leaf]
        SWAP 0 SWAP ROT 4 ROLL                          # [.. fs 0 pos leaf auth]
        {rep(p, 'HT_LEVEL', ref.SPHX_FORS_HEIGHT)} DROP NIP NIP
        5 ROLL SWAP CAT 4 ROLL 4 ROLL 4 ROLL {le(2 ** ref.SPHX_FORS_HEIGHT)} ADD 4 ROLL""")
    xmss_size = ref.SPHX_XMSS_SIGNATURE_SIZE
    # [tree leaf node hts] -> [tree' leaf' root hts']  one hypertree layer, j = 5 - |hts|/704
    p.macro("LAYER", f"""
        SIZE {xmss_size} DIV {ref.SPHX_LAYER_COUNT} SWAP SUB 64 LSHIFT 4 PICK ADD @BE9
        {hx(key.p64)} SWAP CAT                          # [tree leaf node hts P73]
        SWAP {split(ref.WOTS_TW_CHAINS_SIZE)} {split(16 * ref.SPHX_XMSS_HEIGHT)}
        SWAP ROT 3 ROLL SWAP 4 ROLL                     # [tree leaf hts' auth P73 ws node]
        2 PICK {hx(bytes([ref.SL_WOTS_TW_HASH]))} CAT 6 PICK @BE4 CAT TOALTSTACK
        {wots_recover(p, ref.WOTS_TW_CHAIN_COUNT)} FROMALTSTACK DROP   # [tree leaf hts' auth P73 tips]
        OVER {hx(bytes([ref.SL_WOTS_TW_PK]))} CAT 5 PICK @BE4 CAT x0000000000000000 CAT
        SWAP CAT SHA256 16 LEFT                         # [.. auth P73 pk]  pk = T_sl(tips)
        SWAP {hx(bytes([ref.SL_XMSS_TREE]) + bytes(4))} CAT TOALTSTACK
        0 4 PICK ROT 3 ROLL                             # [tree leaf hts' 0 leaf pk auth]
        {rep(p, 'HT_LEVEL', ref.SPHX_XMSS_HEIGHT)} DROP NIP NIP FROMALTSTACK DROP
        3 ROLL DUP {le(2 ** ref.SPHX_XMSS_HEIGHT - 1)} AND SWAP {ref.SPHX_XMSS_HEIGHT} RSHIFT
        4 ROLL DROP SWAP ROT 3 ROLL""")


def stage4(key: Key, message: str = "witness") -> Program:
    """[pad sig5777 M] (or [pad sig] with message='optx') -> [true] for a stateless SHRINCS signature.

    `pad` is ignored: an empty item, or filler that adds the weight (and so the varops budget)
    a signature with many chain steps needs."""
    cmsg_prefix = bytes([0, len(CTX)]) + CTX + key.sf_root
    p = Program()
    common_macros(p, key)
    stateless_macros(p, key)
    fors_size = ref.FORS_SIGNATURE_SIZE
    p.set_main(f"""
        {message_prologue(message)}                     # [sig] alt[M]
        SIZE {ref.SHRINCS_SL_SIGNATURE_SIZE} NUMEQUALVERIFY DUP 1 LEFT xff EQUALVERIFY
        DUP 1 16 SUBSTR DUP {hx(key.pk_seed + key.sl_root)} CAT {hx(cmsg_prefix)} CAT FROMALTSTACK CAT SHA256
        SWAP {hx(key.pk_seed)} CAT SWAP CAT x00000000 CAT SHA256   # [sig digest]  H_msg_sl
        DUP 17 5 SUBSTR BYTEREV {le(2 ** ref.SPHX_TREE_INDEX_BITS - 1)} AND
        OVER 22 2 SUBSTR BYTEREV {le(2 ** ref.SPHX_XMSS_HEIGHT - 1)} AND
        ROT 17 LEFT BYTEREV                             # [sig tree leaf X]
        {hx(key.p64)} 3 PICK @BE9 CAT                   # [sig tree leaf X P73]
        DUP {hx(bytes([ref.SL_FORS_TREE]))} CAT 3 PICK @BE4 CAT TOALTSTACK   # alt[P78f]
        {hx(bytes([ref.SL_FORS_ROOTS]))} CAT 2 PICK @BE4 CAT x0000000000000000 CAT   # [sig tree leaf X Tk]
        4 ROLL DUP 17 {fors_size} SUBSTR SWAP {17 + fors_size} {BIG} SUBSTR
        ROT 3 ROLL 0 SWAP {13 * ref.SPHX_FORS_COUNT + 6} 0 6 ROLL   # [tree leaf hts Tk '' X 136 0 fsig]
        {rep(p, 'FORS_TREE', ref.SPHX_FORS_COUNT)}
        2DROP 2DROP CAT SHA256 16 LEFT FROMALTSTACK DROP SWAP      # [tree leaf fors_pk hts]
        {rep(p, 'LAYER', ref.SPHX_LAYER_COUNT)} DROP NIP NIP {hx(key.sl_root)} EQUAL NIP""")
    return p
