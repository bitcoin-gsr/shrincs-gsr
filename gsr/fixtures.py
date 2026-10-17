"""Deterministic keys, signatures and spending transactions for the GSR SHRINCS verifiers."""
from __future__ import annotations

import hashlib
import struct
import sys
from functools import lru_cache

import verifiers as v
from asm import GSR_ROOT
from verifiers import ref

sys.path.insert(0, str(GSR_ROOT / "bitcoin" / "test" / "functional"))

from test_framework.messages import (  # noqa: E402
    COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string, ser_uint256,
)
from test_framework.script import CScript, LEAF_VERSION_0XC2, taproot_construct  # noqa: E402

# BIP 341's provably unspendable internal key. A P2TR output key is still a curve
# point, so a quantum attacker could spend it through the key path (see README).
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
FUNDING_OUTPOINT = COutPoint(int.from_bytes(hashlib.sha256(b"shrincs-gsr funding").digest(), "little"), 0)
AMOUNT = 100_000
FEE = 5_000


def digest(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


# ---- stage 1 and 2: the fixtures of the earlier prototype ----

def wots_c_fixture() -> dict:
    sk_seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pk_seed = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    message = digest("SHRINCS GSR stage 1 WOTS+C")
    address = bytearray(22)
    address[0] = 7
    address[1:9] = (5).to_bytes(8, "big")
    sig = ref.wots_c_sign(message, sk_seed, pk_seed, bytearray(address))
    pk = ref.wots_c_pubkey_from_sig(sig, message, pk_seed, bytearray(address))
    assert pk == ref.wots_c_pubkey_gen(sk_seed, pk_seed, bytearray(address))
    return {"key": v.Key(pk_seed), "address": bytes(address), "wots_pk": pk, "stack": [sig, message]}


def fxmss_fixture(depth: int = 8, leaf_index: int = 0xAD) -> dict:
    sk_seed = hashlib.sha256(b"SHRINCS GSR stage 2 secret seed").digest()[:16]
    pk_seed = hashlib.sha256(b"SHRINCS GSR stage 2 public seed").digest()[:16]
    message = digest("SHRINCS GSR stage 2 FXMSS")
    height = ref.FXMSS_HEIGHT - depth
    sig = ref.fxmss_sign(message, sk_seed, leaf_index, height, pk_seed, True, depth)
    root = ref.fxmss_node(sk_seed, 0, ref.FXMSS_HEIGHT, pk_seed, True, depth, bytearray(22))
    assert ref.fxmss_pubkey_from_sig(leaf_index, height, sig, message, pk_seed) == root
    return {"key": v.Key(pk_seed, sf_root=root), "depth": depth, "stack": [sig, message, bytes([leaf_index])]}


# ---- stage 3 to 5: complete SHRINCS keys ----

@lru_cache(maxsize=None)
def shrincs_key(shape: int, depth: int) -> tuple[bytes, bytes]:
    """(secret key, public key) for an FXMSS structure (shape, depth); same seeds for every structure."""
    seed = hashlib.sha256(b"SHRINCS GSR secret key").digest() + hashlib.sha256(b"SHRINCS GSR seed 2").digest()[:16]
    return ref.shrincs_keygen(seed, bytes([shape, depth]))


def script_key(pk: bytes) -> v.Key:
    return v.Key(pk[:16], sl_root=pk[16:32], sf_root=pk[32:48])


def sign(message: bytes, shape: int, depth: int, state: int | None, opt_rand: bytes | None = None) -> bytes:
    sk, pk = shrincs_key(shape, depth)
    sig = ref.shrincs_sign(message, v.CTX, sk, state, opt_rand)
    assert ref.shrincs_verify(message, sig, v.CTX, pk)
    return sig


def stateful_state(shape: int, depth: int, leaf_depth: int) -> int:
    """A state counter whose leaf has the given depth."""
    if shape == ref.FXMSS_SHAPE_BALANCED:
        assert leaf_depth == depth
        return 0xAD % (2 ** depth)
    return leaf_depth - 1 if leaf_depth < depth else depth


# ---- transactions ----

def leaf_tree(scripts: list[bytes]) -> tuple:
    """A taptree with one 0xC2 leaf per script, under the NUMS internal key."""
    return taproot_construct(NUMS, [(f"leaf{i}", CScript(s), LEAF_VERSION_0XC2) for i, s in enumerate(scripts)])


def control_block(tap, name: str) -> bytes:
    leaf = tap.leaves[name]
    return bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def spend(tap, name: str, stack: list[bytes], *, outpoint: COutPoint = FUNDING_OUTPOINT,
          amount_out: int = AMOUNT - FEE) -> tuple[CTransaction, list[CTxOut]]:
    """A one-input, one-output spend of the leaf `name` (an output of AMOUNT), paying back to the same script."""
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(outpoint, b"", 0xFFFFFFFD)]
    tx.vout = [CTxOut(amount_out, tap.scriptPubKey)]
    tx.wit.vtxinwit = [CTxInWitness()]
    tx.wit.vtxinwit[0].scriptWitness.stack = [*stack, bytes(tap.leaves[name].script), control_block(tap, name)]
    return tx, [CTxOut(AMOUNT, tap.scriptPubKey)]


def optx_message(tx: CTransaction, spent: list[CTxOut], index: int, leaf_hash: bytes, annex: bytes = b"") -> bytes:
    """SHA256 of what `OPTX_SELECTOR` collates, as `op_tx.cpp` serializes it."""
    out = struct.pack("<III", tx.version, tx.nLockTime, len(tx.vin))
    for txin, prev in zip(tx.vin, spent):
        out += ser_uint256(txin.prevout.hash) + struct.pack("<IQ", txin.prevout.n, prev.nValue)
        out += ser_string(prev.scriptPubKey) + struct.pack("<I", txin.nSequence)
    out += struct.pack("<I", len(tx.vout))
    for o in tx.vout:
        out += struct.pack("<Q", o.nValue) + ser_string(o.scriptPubKey)
    out += struct.pack("<I", index) + ser_string(annex) + leaf_hash
    return hashlib.sha256(out).digest()
