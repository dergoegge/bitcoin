#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -adversarial node capabilities.

A node started with -adversarial exposes the adv_* RPC namespace, turning it
into a programmable network adversary (open connections, send raw/malformed p2p
messages, construct adversarial blocks) plus a "chaoswallet" that builds
adversarial transactions. It also autonomously fuzzes outbound BIP152
compact-block relay (validated indirectly here: the node still functions).
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    p2p_port,
)


class AdversarialTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node0 is the adversary; node1 is a plain victim.
        self.extra_args = [["-adversarial"], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        adv = self.nodes[0]
        victim = self.nodes[1]

        self.test_gating(victim)
        self.test_sendblock_and_rawmessage(adv, victim)
        self.test_chaoswallet(adv)
        self.test_buildblock_controls(adv)
        self.test_generators(adv)

    def test_gating(self, victim):
        self.log.info("adv_* RPCs are unavailable without -adversarial")
        # Node-side adv_* commands are not even registered on a plain node.
        assert_raises_rpc_error(-32601, "Method not found", victim.adv_buildblock)
        # The chaoswallet RPCs are registered but refuse to run.
        assert_raises_rpc_error(-32601, "only available when the node is started with -adversarial", victim.adv_createchaostx)

    def test_sendblock_and_rawmessage(self, adv, victim):
        self.log.info("adv_connect / adv_sendblock / adv_sendrawmessage operate over the node's own p2p stack")
        # The framework connected node0<->node1; grab the peer id.
        peer_id = adv.getpeerinfo()[0]["id"]

        # Build a valid block on the shared genesis tip and deliver it to the
        # victim as a raw BLOCK message. The victim should accept it.
        block = adv.adv_buildblock(solve=True)
        assert block["solved"]
        assert_equal(adv.adv_sendblock(peer_id, block["hex"]), True)
        self.wait_until(lambda: victim.getbestblockhash() == block["hash"])
        assert_equal(victim.getblockcount(), 1)

        # A raw (here well-formed) p2p message can be pushed to the peer.
        assert_equal(adv.adv_sendrawmessage(peer_id, "ping", "0011223344556677"), True)

        # adv_connect opens an additional outbound connection to the victim.
        before = victim.getconnectioncount()
        info = adv.adv_connect(f"127.0.0.1:{p2p_port(1)}", "block-relay-only", False)
        assert_equal(info["connection_type"], "block-relay-only")
        self.wait_until(lambda: victim.getconnectioncount() > before)

    def test_chaoswallet(self, adv):
        self.log.info("chaoswallet builds adversarial transactions that reach adversarial blocks")
        # Mine coins on the adversary itself (do not rely on relay to the victim).
        addr = adv.getnewaddress()
        self.generatetoaddress(adv, 110, addr, sync_fun=self.no_op)

        # Track a wide range of script types so chaos outputs stay spendable.
        descriptors = adv.adv_chaoswallet_setup(5)
        assert_equal(len(descriptors), 6)
        assert any(d.startswith("wsh(multi(") for d in descriptors)
        assert any(d.startswith("tr(") for d in descriptors)

        # The node chooses everything itself (from /dev/urandom). The result may
        # be non-standard or (with e.g. SIGHASH_SINGLE) not fully signable, so we
        # only check that a transaction with inputs and outputs was produced.
        chaos = adv.adv_createchaostx()
        decoded = adv.decoderawtransaction(chaos["hex"])
        assert_greater_than(len(decoded["vin"]), 0)
        assert_greater_than(len(decoded["vout"]), 0)

        # A chaos transaction may be non-standard (e.g. zero fee) and thus never
        # enter a mempool, yet it must still be includable in an adversarial
        # block. Build a fully-signed (SIGHASH_ALL) one and mine it into a block.
        chaos = adv.adv_createchaostx({"sighash": "ALL"})
        assert chaos["complete"]
        height = adv.getblockcount()
        tip = adv.getbestblockhash()
        block = adv.adv_buildblock(prev=tip, txs=[chaos["hex"]], solve=True)
        assert_equal(adv.submitblock(block["hex"]), None)
        assert_equal(adv.getblockcount(), height + 1)
        # The (non-standard) chaos transaction is now confirmed in a block.
        assert chaos["txid"] in adv.getblock(block["hash"])["tx"]

    def test_generators(self, adv):
        self.log.info("autonomous generators (parameterless, /dev/urandom-driven) run against peers")
        # Make sure the adversary has at least one peer to target.
        if adv.getconnectioncount() == 0:
            adv.adv_connect(f"127.0.0.1:{p2p_port(1)}", "outbound-full-relay", False)
            self.wait_until(lambda: adv.getconnectioncount() > 0)

        generators = [
            "adv_gen_sendmessage", "adv_gen_inv", "adv_gen_getdata", "adv_gen_getaddr",
            "adv_gen_addr", "adv_gen_addrv2", "adv_gen_filterload", "adv_gen_filteradd",
            "adv_gen_filterclear", "adv_gen_cfilterquery", "adv_gen_compactblock",
            "adv_gen_blocktxn", "adv_gen_tx", "adv_gen_headers", "adv_gen_block",
            "adv_gen_addconnection",
        ]
        for name in generators:
            res = getattr(adv, name)()
            # Each generator returns {sent: bool, action: str} and must not raise.
            assert "action" in res, f"{name} -> {res}"
            assert isinstance(res["sent"], bool)

        # The node is still alive after all the adversarial traffic.
        assert_greater_than(adv.getblockcount(), 0)

    def test_buildblock_controls(self, adv):
        self.log.info("adv_buildblock exposes adversarial control over every field")
        # Overriding the merkle root yields a different (mutated) block.
        normal = adv.adv_buildblock(solve=False)
        mutated = adv.adv_buildblock(solve=False, merkle_root="00" * 32)
        assert normal["hash"] != mutated["hash"]

        # An explicit out-of-range prefill-free block builds without committing.
        no_commit = adv.adv_buildblock(commit=False, solve=False)
        assert_greater_than(len(no_commit["hex"]), 0)


if __name__ == "__main__":
    AdversarialTest(__file__).main()
