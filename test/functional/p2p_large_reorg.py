#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time

from test_framework.blocktools import (create_block, create_coinbase)
from test_framework.messages import CInv, MSG_BLOCK
from test_framework.p2p import (
    P2PInterface,
    P2PDataStore,
    msg_headers,
    msg_block,
    msg_getdata,
    msg_getheaders,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class P2PLargeReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    # Build a chain of blocks on top of given one
    def build_chain(self, nblocks, prev_hash, prev_height, prev_median_time):
        blocks = []
        for _ in range(nblocks):
            coinbase = create_coinbase(prev_height + 1)
            block_time = prev_median_time + 1
            block = create_block(int(prev_hash, 16), coinbase, block_time)
            block.solve()

            blocks.append(block)
            prev_hash = block.hash
            prev_height += 1
            prev_median_time = block_time
        return blocks

    def run_test(self):

        # Mine 60 days worth of blocks
        self.log.info("mine 60 days worth of blocks")
        day = 60
        block_hashes = []
        while day > 0:
            self.nodes[0].setmocktime(int(time.time()) - day * 24 * 60 * 60)
            block_hashes += self.generatetoaddress(self.nodes[0], 50, self.nodes[0].get_deterministic_priv_key().address)
            day -= 1

        self.log.info("connecting and syncing node 0 and 1")
        self.connect_nodes(0, 1)
        self.sync_all()
        self.log.info(self.nodes[0].getbestblockhash())
        self.log.info(self.nodes[1].getbestblockhash())

        self.log.info("mining large fork")
        MAX_HEADERS_RESULTS = 2000 # As defined in net_processing.cpp
        MAX_BLOCKS_TO_ANNOUNCE = 8 # As defined in net_processing.cpp

        height = len(block_hashes) - MAX_HEADERS_RESULTS
        block_hash = block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        self.log.info("mining 2005 block reorg")
        new_blocks = self.build_chain(MAX_HEADERS_RESULTS + 5, block_hash, height, block_time)
        assert(len(new_blocks) % MAX_HEADERS_RESULTS <= MAX_BLOCKS_TO_ANNOUNCE)

        self.log.info("sending fork to node 0")
        node0 = self.nodes[0].add_p2p_connection(P2PDataStore())
        node0.send_blocks_and_test(blocks=new_blocks, node=self.nodes[0], force_send=False)

        self.sync_all()
        self.log.info(self.nodes[0].getbestblockhash())
        self.log.info(self.nodes[1].getbestblockhash())

if __name__ == '__main__':
    P2PLargeReorgTest().main()
