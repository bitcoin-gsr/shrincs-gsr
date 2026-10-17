#!/usr/bin/env python3
"""Spend every GSR SHRINCS verifier variant on regtest.

Each variant's output is funded, then spent with the measured witness through the
mempool and a mined block. Stateless spends whose signature needs more budget fill
their padding item. For the OP_TX leaves (stage 5), the witness of a confirmed spend
must fail for another output of the same script and for a different spending
transaction of the same output.

    python3 gsr/feature_shrincs_regtest.py --configfile=<gsr build>/test/config.ini
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fixtures as fx  # noqa: E402
import measure  # noqa: E402

from test_framework.messages import COutPoint  # noqa: E402
from test_framework.test_framework import BitcoinTestFramework  # noqa: E402
from test_framework.util import assert_equal  # noqa: E402
from test_framework.wallet import MiniWallet  # noqa: E402


class ShrincsRegtest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-vbparams=tapleaf_0xc2:0:3999999999"]]

    def fund(self, tap):
        funded = self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=tap.scriptPubKey, amount=fx.AMOUNT)
        self.generate(self.nodes[0], 1)
        return COutPoint(int(funded["txid"], 16), funded["sent_vout"])

    def witness_for(self, var, tap, name, outpoint):
        if var.sign is None:
            return list(var.stack)
        tx, spent = fx.spend(tap, name, [b""], outpoint=outpoint)
        return var.sign(fx.optx_message(tx, spent, 0, tap.leaves[name].leaf_hash))

    def funded_spend(self, var, tap, name, outpoint, stack):
        """The spend, with the padding item filled when the budget needs it."""
        tx, spent = fx.spend(tap, name, stack, outpoint=outpoint)
        if var.padded:
            unfunded = measure.txeval(tx, spent, budget_override=10 ** 12)["inputs"][0]
            assert unfunded["success"]
            pad = max(0, -(-(unfunded["varops"] - measure.txeval(tx, spent)["budget"]) // 10_000))
            while not measure.txeval(tx, spent)["inputs"][0]["success"]:
                stack = [bytes(pad)] + stack[1:]
                tx, spent = fx.spend(tap, name, stack, outpoint=outpoint)
                pad += 1
        return tx, stack

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 432)
        assert node.getdeploymentinfo()["deployments"]["tapleaf_0xc2"]["active"]

        for var in measure.build_variants(quick=False):
            scripts = [p.assemble(inline=inline) for p, inline in var.leaves]
            tap = fx.leaf_tree(scripts)
            name = f"leaf{var.spend_leaf}"
            outpoint = self.fund(tap)
            tx, stack = self.funded_spend(var, tap, name, outpoint, self.witness_for(var, tap, name, outpoint))
            result = node.testmempoolaccept([tx.serialize().hex()])[0]
            assert result["allowed"], (var.vid, result)
            node.sendrawtransaction(tx.serialize().hex())
            block = self.generate(node, 1)[0]
            assert_equal(node.getrawtransaction(tx.txid_hex, True, block)["confirmations"], 1)
            line = f"{var.vid}: confirmed, {tx.get_weight()} WU, padding item {len(stack[0]) if var.padded else '-'} B"

            if var.sign is not None:
                # Replays of the confirmed witness: on another output of the same script ...
                other = self.fund(tap)
                replay, _ = fx.spend(tap, name, stack, outpoint=other)
                r = node.testmempoolaccept([replay.serialize().hex()])[0]
                assert not r["allowed"], var.vid
                # ... and in a different spending transaction of a fresh output, signed for the first.
                third = self.fund(tap)
                signed, _ = self.funded_spend(var, tap, name, third, self.witness_for(var, tap, name, third))
                changed, _ = fx.spend(tap, name, signed.wit.vtxinwit[0].scriptWitness.stack[:-2], outpoint=third,
                                      amount_out=fx.AMOUNT - fx.FEE - 1)
                r2 = node.testmempoolaccept([changed.serialize().hex()])[0]
                assert not r2["allowed"], var.vid
                line += f"; replay rejected ({r['reject-reason']}), changed tx rejected ({r2['reject-reason']})"
            self.log.info(line)


if __name__ == "__main__":
    ShrincsRegtest(__file__).main()
