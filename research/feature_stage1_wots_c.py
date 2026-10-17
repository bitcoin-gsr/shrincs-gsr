#!/usr/bin/env python3
"""Consensus-spend check for a stage-1 WOTS+C verifier variant."""

from pathlib import Path
import os
import sys


ROOT = Path(__file__).resolve().parents[1]
CORE = Path(os.environ.get(
    "GSR_CORE", ROOT.parents[1] / "core" / "gsr" / "gsr-full"
))
sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(ROOT / "impl"))
sys.path.insert(0, str(CORE / "test" / "functional"))

from stage1_wots_c_inline import build_verifier, deterministic_reference_fixture
from test_framework.key import compute_xonly_pubkey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, LEAF_VERSION_TAPSCRIPT_V2, taproot_construct
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class Stage1WotsCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-vbparams=script_restoration:0:3999999999"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 432)
        assert node.getdeploymentinfo()["deployments"]["script_restoration"]["active"]

        fixture = deterministic_reference_fixture()
        variant = os.environ.get("SHRINCS_GSR_VARIANT", "inline")
        assert variant in ("inline", "macros", "nested-macros")
        script_bytes = bytes(build_verifier(
            fixture["pk_seed"], fixture["address"], fixture["expected_key"],
            static_macros=variant == "macros",
            nested_macros=variant == "nested-macros",
        ).raw)
        internal_key = compute_xonly_pubkey((1).to_bytes(32, "big"))[0]
        tap = taproot_construct(internal_key, [
            ("wots_c", CScript(script_bytes), LEAF_VERSION_TAPSCRIPT_V2),
        ])
        leaf = tap.leaves["wots_c"]
        control_block = bytes([leaf.version | tap.negflag]) + tap.internal_pubkey

        funded = wallet.send_to(
            from_node=node,
            scriptPubKey=tap.scriptPubKey,
            amount=1_000_000,
            fee=10_000,
        )
        self.generate(wallet, 1)

        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(int(funded["txid"], 16), funded["sent_vout"]))]
        spend.vout = [CTxOut(990_000, tap.scriptPubKey)]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [
            fixture["signature"],
            fixture["message_digest"],
            script_bytes,
            control_block,
        ]
        expected_weight = {"inline": 51_368, "macros": 2_922, "nested-macros": 2_294}[variant]
        assert_equal(spend.get_weight(), expected_weight)

        # Large Script witness items are currently nonstandard, so demonstrate
        # consensus acceptance by constructing a block containing the raw tx.
        result = self.generateblock(node, wallet.get_descriptor(), [spend.serialize().hex()])
        assert_equal(len(result["hash"]), 64)
        assert node.getrawtransaction(spend.txid_hex, True, result["hash"])["confirmations"] == 1


if __name__ == "__main__":
    Stage1WotsCTest(__file__).main()
