#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test for MiniMiner::DeleteAncestorPackage assertion failure with negative fees.

This test reproduces an assertion failure in MiniMiner::DeleteAncestorPackage
when a child transaction has a negative fee that causes its ancestor_fees to
be less than its parent's fee, while still passing SanityCheck.

Bug location: src/node/mini_miner.cpp (DeleteAncestorPackage)
    Assert(descendant->second.GetModFeesWithAncestors() >= anc->second.GetModifiedFee())

The assertion checks that when processing an ancestor, all its descendants have
ancestor_fees >= that ancestor's own fee. This can fail independently of SanityCheck
when the child has a negative fee.

Example:
    TX P (parent): modified_fee = +1000 sats (normal fee)
    TX C (child):  modified_fee = -500 sats (via prioritisetransaction)

    C's ancestor_fees = P.fee + C.fee = 1000 + (-500) = 500 sats

    SanityCheck: C.ancestor_fees >= C.own_fee -> 500 >= -500 -> TRUE (passes)
    DeleteAncestorPackage: C.ancestor_fees >= P.own_fee -> 500 >= 1000 -> FALSE (fails!)
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletMiniMinerDeleteAncestorPackageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-walletrbf=1",
            "-fallbackfee=0.0001",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Setup: Mine blocks to mature coinbase")
        self.generate(node, COINBASE_MATURITY + 10)

        self.log.info("Create wallet for testing")
        node.createwallet("test_wallet")
        wallet = node.get_wallet_rpc("test_wallet")

        # Fund the test wallet
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        funding_addr = wallet.getnewaddress()
        default_wallet.sendtoaddress(funding_addr, 10)
        self.generate(node, 1)

        self.log.info("Test: MiniMiner::DeleteAncestorPackage assertion with negative child fee")
        self.test_deleteancestorpackage_negative_child_fee(node, wallet)

    def test_deleteancestorpackage_negative_child_fee(self, node, wallet):
        """
        Trigger MiniMiner::DeleteAncestorPackage assertion failure.

        DeleteAncestorPackage fails when: descendant.ancestor_fees < ancestor.own_fee
        This can happen even when SanityCheck passes, if the child has a negative
        fee that reduces ancestor_fees below the parent's positive fee.

        We need:
        - child.ancestor_fees >= child.own_fee (SanityCheck passes)
        - child.ancestor_fees < parent.own_fee (DeleteAncestorPackage fails)
        """
        utxos = wallet.listunspent(minconf=1)
        assert_equal(len(utxos), 1)

        # Create parent transaction with higher fee
        self.log.info("Create parent transaction with higher fee")
        parent_addr = wallet.getnewaddress()
        parent_txid = wallet.sendtoaddress(
            address=parent_addr,
            amount=9,
            fee_rate=10,  # Higher fee rate to get a larger absolute fee
        )
        self.log.info(f"Parent tx: {parent_txid}")

        # Create child transaction
        self.log.info("Create child transaction")
        child_addr = wallet.getnewaddress()
        child_txid = wallet.sendtoaddress(
            address=child_addr,
            amount=8,
            fee_rate=1,
        )
        self.log.info(f"Child tx: {child_txid}")

        # Verify chain
        mempool = node.getrawmempool(verbose=True)
        assert parent_txid in mempool[child_txid]['depends']

        # Get parent's fee
        p_entry = node.getmempoolentry(parent_txid)
        parent_fee_sats = int(Decimal(str(p_entry['fees']['base'])) * 100_000_000)
        self.log.info(f"Parent fee: {parent_fee_sats} sats")

        # Make child fee negative enough that:
        # child.ancestor_fees < parent.fee (DeleteAncestorPackage fails)
        # but child.ancestor_fees >= child.own_fee (SanityCheck passes)
        #
        # child.ancestor_fees = parent.fee + child.fee
        # We want: child.own_fee <= child.ancestor_fees < parent.fee
        # So: child.own_fee <= parent.fee + child.own_fee < parent.fee
        # Which means: child.own_fee < 0 and |child.own_fee| < parent.fee
        #
        # If parent.fee = 1500 sats and we set child.fee = -1000 sats:
        # child.ancestor_fees = 1500 + (-1000) = 500 sats
        # SanityCheck: 500 >= -1000 ✓
        # DeleteAncestorPackage: 500 >= 1500 ✗
        c_entry = node.getmempoolentry(child_txid)
        child_base_fee_sats = int(Decimal(str(c_entry['fees']['base'])) * 100_000_000)

        # Make child fee negative: subtract more than the base fee but less than parent fee
        # We want final child.own_fee to be negative but > -parent.fee
        negative_delta = -(child_base_fee_sats + parent_fee_sats // 2)
        self.log.info(f"Apply negative fee delta ({negative_delta} sats) to child")
        node.prioritisetransaction(child_txid, 0, negative_delta)

        # Verify the fees
        p_entry = node.getmempoolentry(parent_txid)
        c_entry = node.getmempoolentry(child_txid)

        parent_fee = Decimal(str(p_entry['fees']['modified']))
        child_own_fee = Decimal(str(c_entry['fees']['modified']))
        child_ancestor_fee = Decimal(str(c_entry['fees']['ancestor']))

        self.log.info(f"Parent modified fee: {parent_fee} BTC ({int(parent_fee * 100_000_000)} sats)")
        self.log.info(f"Child modified fee: {child_own_fee} BTC ({int(child_own_fee * 100_000_000)} sats)")
        self.log.info(f"Child ancestor fee: {child_ancestor_fee} BTC ({int(child_ancestor_fee * 100_000_000)} sats)")

        # Verify bug conditions:
        # 1. SanityCheck should pass: child.ancestor_fees >= child.own_fee
        assert child_ancestor_fee >= child_own_fee, \
            f"SanityCheck should pass: ancestor_fees ({child_ancestor_fee}) >= own_fee ({child_own_fee})"

        # 2. DeleteAncestorPackage should fail: child.ancestor_fees < parent.own_fee
        assert child_ancestor_fee < parent_fee, \
            f"DeleteAncestorPackage condition: ancestor_fees ({child_ancestor_fee}) < parent.fee ({parent_fee})"

        self.log.info("Bug conditions verified:")
        self.log.info(f"  SanityCheck passes: {child_ancestor_fee} >= {child_own_fee}")
        self.log.info(f"  DeleteAncestorPackage fails: {child_ancestor_fee} < {parent_fee}")

        self.log.info("Trigger MiniMiner via sendtoaddress - should crash in DeleteAncestorPackage")
        dest_addr = wallet.getnewaddress()
        wallet.sendtoaddress(address=dest_addr, amount=7, fee_rate=10)


if __name__ == '__main__':
    WalletMiniMinerDeleteAncestorPackageTest(__file__).main()
