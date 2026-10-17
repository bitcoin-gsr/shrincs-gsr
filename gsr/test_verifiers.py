#!/usr/bin/env python3
"""Differential tests: each GSR verifier accepts exactly what the SHRINCS reference accepts.

Valid vectors come from `impl/shrincs.py`; every corruption must be rejected by
both the reference and the script.

    python3 gsr/test_verifiers.py
"""
import hashlib
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fixtures as fx  # noqa: E402
import measure  # noqa: E402
import verifiers as v  # noqa: E402
from verifiers import ref  # noqa: E402


def flip(data: bytes, at: int) -> bytes:
    out = bytearray(data)
    out[at] ^= 0x01
    return bytes(out)


def accepts(script: bytes, stack: list[bytes]) -> bool:
    return measure.evalscript(script, stack)["success"]


class Stage1WotsC(unittest.TestCase):
    def test_vectors(self):
        for case in range(4):
            sk = hashlib.sha256(b"t1 sk" + bytes([case])).digest()[:16]
            pk_seed = hashlib.sha256(b"t1 pk" + bytes([case])).digest()[:16]
            msg = hashlib.sha256(b"t1 m" + bytes([case])).digest()
            adrs = bytearray(22)
            adrs[0], adrs[1:9] = 250 - case, (1000 + case).to_bytes(8, "big")
            sig = ref.wots_c_sign(msg, sk, pk_seed, bytearray(adrs))
            pk = ref.wots_c_pubkey_gen(sk, pk_seed, bytearray(adrs))
            script = v.stage1(v.Key(pk_seed), bytes(adrs), pk).assemble()
            self.assertTrue(accepts(script, [sig, msg]))
            for at in (0, 1, 2, 300, 513):  # counter, first and middle chains, last byte
                self.assertFalse(accepts(script, [flip(sig, at), msg]), at)
            self.assertFalse(accepts(script, [sig, flip(msg, 31)]))
            self.assertFalse(accepts(script, [sig[:-1], msg]))


class Stage2Fxmss(unittest.TestCase):
    def test_every_leaf_position_of_depth_4(self):
        depth = 4
        sk = hashlib.sha256(b"t2 sk").digest()[:16]
        pk_seed = hashlib.sha256(b"t2 pk").digest()[:16]
        root = ref.fxmss_node(sk, 0, ref.FXMSS_HEIGHT, pk_seed, True, depth, bytearray(22))
        script = v.stage2(v.Key(pk_seed, sf_root=root), depth).assemble()
        for leaf in range(2 ** depth):
            msg = hashlib.sha256(b"t2 m" + bytes([leaf])).digest()
            sig = ref.fxmss_sign(msg, sk, leaf, ref.FXMSS_HEIGHT - depth, pk_seed, True, depth)
            self.assertTrue(accepts(script, [sig, msg, bytes([leaf])]), leaf)
            self.assertFalse(accepts(script, [sig, msg, bytes([leaf ^ 1])]), leaf)
            self.assertFalse(accepts(script, [flip(sig, 2 + 512 + 16 * (leaf % depth)), msg, bytes([leaf])]))


class Stage3Stateful(unittest.TestCase):
    def check(self, shape, depth, max_depth, states):
        _sk, pk = fx.shrincs_key(shape, depth)
        script = v.stage3(fx.script_key(pk), max_depth).assemble()
        for state in states:
            msg = hashlib.sha256(b"t3" + bytes([shape, depth, state])).digest()
            sig = fx.sign(msg, shape, depth, state)
            self.assertTrue(accepts(script, [sig, msg]), (shape, depth, state))
            index_bytes = len(sig) - (1 + 16 + 2 + 512 + 16 * (255 - sig[0]))
            for at in (0, 1, 17, 17 + index_bytes, 17 + index_bytes + 2, len(sig) - 1):
                bad = flip(sig, at)
                self.assertFalse(ref.shrincs_verify(msg, bad, v.CTX, pk))
                self.assertFalse(accepts(script, [bad, msg]), (state, at))
            self.assertFalse(accepts(script, [sig, flip(msg, 0)]))
            self.assertFalse(accepts(script, [sig[:-16], msg]))

    def test_balanced_depth_8(self):
        self.check(ref.FXMSS_SHAPE_BALANCED, 8, 8, [0, 1, 0xAD, 255])

    def test_unbalanced_depth_20(self):
        self.check(ref.FXMSS_SHAPE_UNBALANCED, 20, 20, [0, 1, 7, 19, 20])

    def test_depth_beyond_verifier_rejected(self):
        _sk, pk = fx.shrincs_key(ref.FXMSS_SHAPE_UNBALANCED, 20)
        script = v.stage3(fx.script_key(pk), 8).assemble()
        msg = hashlib.sha256(b"t3 deep").digest()
        self.assertTrue(accepts(script, [fx.sign(msg, 0, 20, 7), msg]))       # depth 8
        self.assertFalse(accepts(script, [fx.sign(msg, 0, 20, 8), msg]))      # depth 9

    def test_stateless_signature_rejected(self):
        _sk, pk = fx.shrincs_key(ref.FXMSS_SHAPE_BALANCED, 8)
        script = v.stage3(fx.script_key(pk), 8).assemble()
        msg = hashlib.sha256(b"t3 sl").digest()
        self.assertFalse(accepts(script, [fx.sign(msg, 1, 8, None), msg]))


class Stage4Stateless(unittest.TestCase):
    def test_vectors(self):
        _sk, pk = fx.shrincs_key(ref.FXMSS_SHAPE_BALANCED, 8)
        script = v.stage4(fx.script_key(pk)).assemble()
        for case in range(2):
            msg = hashlib.sha256(b"t4" + bytes([case])).digest()
            sig = fx.sign(msg, 1, 8, None, opt_rand=hashlib.sha256(b"t4 r" + bytes([case])).digest()[:16])
            stack = [b"", sig, msg]
            self.assertTrue(accepts(script, stack), case)
            self.assertTrue(accepts(script, [bytes(300), sig, msg]))  # padding is ignored
            # R, a FORS secret, a FORS path node, WOTS-TW chains of layers 0 and 4, an XMSS path node
            for at in (1, 17, 17 + 16, 17 + 2240 + 3, 17 + 2240 + 4 * 704 + 100, 17 + 2240 + 560 + 5):
                bad = flip(sig, at)
                self.assertFalse(ref.shrincs_verify(msg, bad, v.CTX, pk))
                self.assertFalse(accepts(script, [b"", bad, msg]), (case, at))
            self.assertFalse(accepts(script, [b"", sig, flip(msg, 5)]))

    def test_stateful_signature_rejected(self):
        _sk, pk = fx.shrincs_key(ref.FXMSS_SHAPE_BALANCED, 8)
        script = v.stage4(fx.script_key(pk)).assemble()
        msg = hashlib.sha256(b"t4 sf").digest()
        self.assertFalse(accepts(script, [b"", fx.sign(msg, 1, 8, 3), msg]))


class Stage5Binding(unittest.TestCase):
    def test_signature_bound_to_its_transaction(self):
        _sk, pk = fx.shrincs_key(ref.FXMSS_SHAPE_BALANCED, 8)
        key = fx.script_key(pk)
        tap = fx.leaf_tree([v.stage3(key, 8, message="optx").assemble(), v.stage4(key, message="optx").assemble()])
        tx, spent = fx.spend(tap, "leaf0", [b""])
        sig = fx.sign(fx.optx_message(tx, spent, 0, tap.leaves["leaf0"].leaf_hash), 1, 8, 9)
        tx, spent = fx.spend(tap, "leaf0", [sig])
        self.assertTrue(measure.txeval(tx, spent)["inputs"][0]["success"])
        for changed in (fx.spend(tap, "leaf0", [sig], amount_out=fx.AMOUNT - fx.FEE - 1),
                        fx.spend(tap, "leaf0", [sig], outpoint=fx.COutPoint(fx.FUNDING_OUTPOINT.hash, 1))):
            self.assertFalse(measure.txeval(*changed)["inputs"][0]["success"])
        # A signature over the same transaction but for the other leaf's tapleaf hash fails here.
        other = fx.sign(fx.optx_message(tx, spent, 0, tap.leaves["leaf1"].leaf_hash), 1, 8, 9)
        self.assertFalse(measure.txeval(*fx.spend(tap, "leaf0", [other]))["inputs"][0]["success"])


if __name__ == "__main__":
    unittest.main()
