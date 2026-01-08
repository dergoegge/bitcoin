#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test for MiniMiner::SanityCheck assertion failure with negative fees.

This test reproduces an assertion failure in MiniMiner::SanityCheck when
ancestor transactions have very negative modified fees due to prioritisetransaction.

Bug location: src/node/mini_miner.cpp (SanityCheck)
    Assert(entry->second.GetModFeesWithAncestors() >= entry->second.GetModifiedFee())

The assertion expects that a transaction's ancestor fees (sum of all ancestors
including self) is always >= its own fee. This is violated when ancestors have
very negative fees that drag down the total below the transaction's own fee.

Example:
    TX A (grandparent): modified_fee = -2 BTC (via prioritisetransaction)
    TX B (parent):      modified_fee = +0.00001 BTC (normal fee)
    TX C (child):       modified_fee = +0.00001 BTC (normal fee)

    C's ancestor_fees = A.fee + B.fee + C.fee = -2 + 0.00001 + 0.00001 ~ -2 BTC
    SanityCheck: -2 BTC >= 0.00001 BTC -> FALSE!
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletMiniMinerSanityCheckTest(BitcoinTestFramework):
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

        self.log.info("Test: MiniMiner::SanityCheck assertion with negative ancestor fees")
        self.test_sanitycheck_negative_ancestor_fees(node, wallet)

    def test_sanitycheck_negative_ancestor_fees(self, node, wallet):
        """
        Trigger MiniMiner::SanityCheck assertion failure.

        SanityCheck fails when: entry.ancestor_fees < entry.own_fee
        This happens when an ancestor has very negative fees that drag down
        the total ancestor_fees below the descendant's own positive fee.
        """
        utxos = wallet.listunspent(minconf=1)
        assert_equal(len(utxos), 1)

        # Create parent transaction
        self.log.info("Create parent transaction")
        parent_addr = wallet.getnewaddress()
        parent_txid = wallet.sendtoaddress(
            address=parent_addr,
            amount=9,
            fee_rate=1,
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

        # Make parent fee very negative (-2 BTC)
        # This causes child.ancestor_fees to be negative while child.own_fee is positive
        negative_delta = -200_000_000  # -2 BTC
        self.log.info(f"Apply negative fee delta ({negative_delta} sats) to parent")
        node.prioritisetransaction(parent_txid, 0, negative_delta)

        # Log fees
        p_entry = node.getmempoolentry(parent_txid)
        c_entry = node.getmempoolentry(child_txid)
        self.log.info(f"Parent modified fee: {p_entry['fees']['modified']} BTC")
        self.log.info(f"Child own fee: {c_entry['fees']['base']} BTC")
        self.log.info(f"Child ancestor fee: {c_entry['fees']['ancestor']} BTC")

        # Verify the bug condition: child.ancestor_fees < child.own_fee
        child_ancestor_fee = Decimal(str(c_entry['fees']['ancestor']))
        child_own_fee = Decimal(str(c_entry['fees']['base']))
        assert child_ancestor_fee < child_own_fee, \
            f"SanityCheck condition: ancestor_fees ({child_ancestor_fee}) should be < own_fee ({child_own_fee})"

        self.log.info("Trigger MiniMiner via sendtoaddress - should crash in SanityCheck")
        dest_addr = wallet.getnewaddress()
        wallet.sendtoaddress(address=dest_addr, amount=7, fee_rate=10)


if __name__ == '__main__':
    WalletMiniMinerSanityCheckTest(__file__).main()
