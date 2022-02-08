// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for denial-of-service detection/prevention code

#include <banman.h>
#include <chainparams.h>
#include <common/args.h>
#include <net.h>
#include <net_processing.h>
#include <pubkey.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <serialize.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <timedata.h>
#include <util/string.h>
#include <util/time.h>
#include <validation.h>

#include <array>
#include <stdint.h>

#include <boost/test/unit_test.hpp>

static CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

BOOST_FIXTURE_TEST_SUITE(denialofservice_tests, TestingSetup)

// Test eviction of an outbound peer whose chain never advances
// Mock a node connection, and use mocktime to simulate a peer
// which never sends any headers messages.  PeerLogic should
// decide to evict that outbound peer, after the appropriate timeouts.
// Note that we protect 4 outbound nodes from being subject to
// this logic; this test takes advantage of that protection only
// being applied to nodes which send headers with sufficient
// work.
BOOST_AUTO_TEST_CASE(outbound_slow_chain_eviction)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto evictionman = std::make_unique<EvictionManager>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS);
    auto connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, *evictionman);
    auto peerLogic = PeerManager::make(*connman, *m_node.addrman, *evictionman, nullptr,
                                       *m_node.chainman, *m_node.mempool, {});
    {
        // Disable inactivity checks for this test to avoid interference
        CConnman::Options opts;
        opts.m_peer_connect_timeout = 99999;
        opts.m_msgproc = peerLogic.get();
        connman->Init(opts);
    }

    PeerManager& peerman = *peerLogic;

    // Mock an outbound peer
    CAddress addr1(ip(0xa0b0c001), NODE_NONE);
    NodeId id{0};
    CNode dummyNode1{id++,
                     /*sock=*/nullptr,
                     addr1,
                     CAddress(),
                     /*addrNameIn=*/"",
                     ConnectionType::OUTBOUND_FULL_RELAY,
                     /*inbound_onion=*/false};

    connman->Handshake(
        /*node=*/dummyNode1,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);
    TestOnlyResetTimeData();

    // This test requires that we have a chain with non-zero work.
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip() != nullptr);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->nChainWork > 0);
    }

    // Test starts here
    BOOST_CHECK(peerman.SendMessages(&dummyNode1)); // should result in getheaders

    {
        LOCK(dummyNode1.cs_vSend);
        BOOST_CHECK(dummyNode1.vSendMsg.size() > 0);
        dummyNode1.vSendMsg.clear();
    }

    int64_t nStartTime = GetTime();
    // Wait 21 minutes
    SetMockTime(nStartTime+21*60);
    BOOST_CHECK(peerman.SendMessages(&dummyNode1)); // should result in getheaders
    {
        LOCK(dummyNode1.cs_vSend);
        BOOST_CHECK(dummyNode1.vSendMsg.size() > 0);
    }
    // Wait 3 more minutes
    SetMockTime(nStartTime+24*60);
    BOOST_CHECK(peerman.SendMessages(&dummyNode1)); // should result in disconnect
    BOOST_CHECK(dummyNode1.fDisconnect == true);

    peerman.FinalizeNode(dummyNode1);
}

BOOST_AUTO_TEST_CASE(peer_discouragement)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto banman = std::make_unique<BanMan>(m_args.GetDataDirBase() / "banlist", nullptr, DEFAULT_MISBEHAVING_BANTIME);
    auto evictionman = std::make_unique<EvictionManager>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS);
    auto connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, *evictionman);
    auto peerLogic = PeerManager::make(*connman, *m_node.addrman, *evictionman, banman.get(),
                                       *m_node.chainman, *m_node.mempool, {});

    CNetAddr tor_netaddr;
    BOOST_REQUIRE(
        tor_netaddr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    const CService tor_service{tor_netaddr, Params().GetDefaultPort()};

    const std::array<CAddress, 3> addr{CAddress{ip(0xa0b0c001), NODE_NONE},
                                       CAddress{ip(0xa0b0c002), NODE_NONE},
                                       CAddress{tor_service, NODE_NONE}};

    const CNetAddr other_addr{ip(0xa0b0ff01)}; // Not any of addr[].

    std::array<CNode*, 3> nodes;

    banman->ClearBanned();
    NodeId id{0};
    nodes[0] = new CNode{id++,
                         /*sock=*/nullptr,
                         addr[0],
                         CAddress(),
                         /*addrNameIn=*/"",
                         ConnectionType::INBOUND,
                         /*inbound_onion=*/false};
    nodes[0]->SetCommonVersion(PROTOCOL_VERSION);
    peerLogic->InitializeNode(*nodes[0], NODE_NETWORK);
    nodes[0]->fSuccessfullyConnected = true;
    connman->AddTestNode(*nodes[0]);
    peerLogic->UnitTestMisbehaving(nodes[0]->GetId(), DISCOURAGEMENT_THRESHOLD); // Should be discouraged
    BOOST_CHECK(peerLogic->SendMessages(nodes[0]));

    BOOST_CHECK(banman->IsDiscouraged(addr[0]));
    BOOST_CHECK(nodes[0]->fDisconnect);
    BOOST_CHECK(!banman->IsDiscouraged(other_addr)); // Different address, not discouraged

    nodes[1] = new CNode{id++,
                         /*sock=*/nullptr,
                         addr[1],
                         CAddress(),
                         /*addrNameIn=*/"",
                         ConnectionType::INBOUND,
                         /*inbound_onion=*/false};
    nodes[1]->SetCommonVersion(PROTOCOL_VERSION);
    peerLogic->InitializeNode(*nodes[1], NODE_NETWORK);
    nodes[1]->fSuccessfullyConnected = true;
    connman->AddTestNode(*nodes[1]);
    peerLogic->UnitTestMisbehaving(nodes[1]->GetId(), DISCOURAGEMENT_THRESHOLD - 1);
    BOOST_CHECK(peerLogic->SendMessages(nodes[1]));
    // [0] is still discouraged/disconnected.
    BOOST_CHECK(banman->IsDiscouraged(addr[0]));
    BOOST_CHECK(nodes[0]->fDisconnect);
    // [1] is not discouraged/disconnected yet.
    BOOST_CHECK(!banman->IsDiscouraged(addr[1]));
    BOOST_CHECK(!nodes[1]->fDisconnect);
    peerLogic->UnitTestMisbehaving(nodes[1]->GetId(), 1); // [1] reaches discouragement threshold
    BOOST_CHECK(peerLogic->SendMessages(nodes[1]));
    // Expect both [0] and [1] to be discouraged/disconnected now.
    BOOST_CHECK(banman->IsDiscouraged(addr[0]));
    BOOST_CHECK(nodes[0]->fDisconnect);
    BOOST_CHECK(banman->IsDiscouraged(addr[1]));
    BOOST_CHECK(nodes[1]->fDisconnect);

    // Make sure non-IP peers are discouraged and disconnected properly.

    nodes[2] = new CNode{id++,
                         /*sock=*/nullptr,
                         addr[2],
                         CAddress(),
                         /*addrNameIn=*/"",
                         ConnectionType::OUTBOUND_FULL_RELAY,
                         /*inbound_onion=*/false};
    nodes[2]->SetCommonVersion(PROTOCOL_VERSION);
    peerLogic->InitializeNode(*nodes[2], NODE_NETWORK);
    nodes[2]->fSuccessfullyConnected = true;
    connman->AddTestNode(*nodes[2]);
    peerLogic->UnitTestMisbehaving(nodes[2]->GetId(), DISCOURAGEMENT_THRESHOLD);
    BOOST_CHECK(peerLogic->SendMessages(nodes[2]));
    BOOST_CHECK(banman->IsDiscouraged(addr[0]));
    BOOST_CHECK(banman->IsDiscouraged(addr[1]));
    BOOST_CHECK(banman->IsDiscouraged(addr[2]));
    BOOST_CHECK(nodes[0]->fDisconnect);
    BOOST_CHECK(nodes[1]->fDisconnect);
    BOOST_CHECK(nodes[2]->fDisconnect);

    for (CNode* node : nodes) {
        peerLogic->FinalizeNode(*node);
    }
    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(DoS_bantime)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    auto banman = std::make_unique<BanMan>(m_args.GetDataDirBase() / "banlist", nullptr, DEFAULT_MISBEHAVING_BANTIME);
    auto evictionman = std::make_unique<EvictionManager>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS);
    auto connman = std::make_unique<CConnman>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, *evictionman);
    auto peerLogic = PeerManager::make(*connman, *m_node.addrman, *evictionman, banman.get(),
                                       *m_node.chainman, *m_node.mempool, {});

    banman->ClearBanned();
    int64_t nStartTime = GetTime();
    SetMockTime(nStartTime); // Overrides future calls to GetTime()

    CAddress addr(ip(0xa0b0c001), NODE_NONE);
    NodeId id{0};
    CNode dummyNode{id++,
                    /*sock=*/nullptr,
                    addr,
                    CAddress(),
                    /*addrNameIn=*/"",
                    ConnectionType::INBOUND,
                    /*inbound_onion=*/false};
    dummyNode.SetCommonVersion(PROTOCOL_VERSION);
    peerLogic->InitializeNode(dummyNode, NODE_NETWORK);
    dummyNode.fSuccessfullyConnected = true;

    peerLogic->UnitTestMisbehaving(dummyNode.GetId(), DISCOURAGEMENT_THRESHOLD);
    BOOST_CHECK(peerLogic->SendMessages(&dummyNode));
    BOOST_CHECK(banman->IsDiscouraged(addr));

    peerLogic->FinalizeNode(dummyNode);
}

BOOST_AUTO_TEST_SUITE_END()
