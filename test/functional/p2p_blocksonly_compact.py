#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test p2p blocksonly mode & compact block relay"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    MSG_CMPCT_BLOCK,
    CInv,
    CBlockHeader,
    msg_block,
    msg_sendcmpct,
    msg_headers,
)

class P2PCompact(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_sendcmpct = []
        self.last_getdata = []

    def on_sendcmpct(self, message):
        self.last_sendcmpct.append(message)

    def on_getdata(self, message):
        self.last_getdata.append(message)

    def assert_last_sendcmpct(self, announce):
        assert len(self.last_sendcmpct) > 0
        assert_equal(self.last_sendcmpct[-1].announce, announce)

    def assert_last_getdata(self, type, hash):
        assert len(self.last_getdata) > 0
        assert len(self.last_getdata[-1].inv) == 1
        assert self.last_getdata[-1].inv[0] == CInv(type, hash)

class P2PBlocksOnlyCompact(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [["-blocksonly"], [], []]

    def setup_network(self):
        self.setup_nodes()
        self.sync_all()

    def build_block_on_tip(self):
        block = create_block(tmpl=self.nodes[2].getblocktemplate(NORMAL_GBT_REQUEST_PARAMS))
        add_witness_commitment(block)
        block.solve()
        self.nodes[2].submitblock(block.serialize().hex())
        return block

    def run_test(self):
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)

        # Generate somee blocks so all nodes are out of IBD.
        self.nodes[2].generate(10)
        self.sync_blocks()

        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(1, 2)

        p2p_conn_node0 = self.nodes[0].add_p2p_connection(P2PCompact())
        p2p_conn_node1 = self.nodes[1].add_p2p_connection(P2PCompact())
        assert_equal(p2p_conn_node0.message_count['sendcmpct'], 2)
        assert_equal(p2p_conn_node1.message_count['sendcmpct'], 2)
        p2p_conn_node0.send_and_ping(msg_sendcmpct(announce=False, version=2))
        p2p_conn_node1.send_and_ping(msg_sendcmpct(announce=False, version=2))

        # Topology:
        #   p2p_conn_node0 ---> node0         node1 <--- p2p_conn_node1
        #                              node2
        #
        # node2 produces blocks which get passed to node0 and node1
        # through the respective p2p connections.

        # Part 1: Test that blocksonly nodes do not request high bandwidth mode.

        block0 = self.build_block_on_tip()

        # A -blocksonly=0 node should request high bandwidth mode appon
        # receiving a new valid block at the tip.
        p2p_conn_node1.send_and_ping(msg_block(block0))
        assert_equal(int(self.nodes[1].getbestblockhash(), 16), block0.sha256)
        p2p_conn_node1.sync_with_ping()
        assert_equal(p2p_conn_node1.message_count['sendcmpct'], 3)
        p2p_conn_node1.assert_last_sendcmpct(True)

        # A -blocksonly=1 node should not request high bandwidth mode appon
        # receiving a new valid block at the tip.
        p2p_conn_node0.send_and_ping(msg_block(block0))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block0.sha256)
        p2p_conn_node0.sync_with_ping()
        assert_equal(p2p_conn_node0.message_count['sendcmpct'], 2)
        p2p_conn_node0.assert_last_sendcmpct(False)

        # Part 2: Test that blocksonly nodes send getdata(BLOCK) instead
        # of getdata(CMPCT) in low bandwidth mode.

        block1 = self.build_block_on_tip()

        p2p_conn_node0.send_and_ping(msg_headers(headers=[CBlockHeader(block1)]))
        p2p_conn_node0.sync_with_ping()
        p2p_conn_node0.assert_last_getdata(MSG_BLOCK | MSG_WITNESS_FLAG, block1.sha256)

        p2p_conn_node1.send_and_ping(msg_headers(headers=[CBlockHeader(block1)]))
        p2p_conn_node1.sync_with_ping()
        p2p_conn_node1.assert_last_getdata(MSG_CMPCT_BLOCK, block1.sha256)

if __name__ == '__main__':
    P2PBlocksOnlyCompact().main()
