// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net.h>
#include <net_processing.h>
#include <protocol.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <timedata.h>

namespace {

class ConnectionsMockSetup : public TestingSetup
{
public:
    MockConnectionsInterface m_connman;

    ConnectionsMockSetup(const std::string& chain_name,
                         const std::vector<const char*>& extra_args)
        : TestingSetup(chain_name, extra_args)
    {
        m_node.peerman.reset(nullptr);
        m_node.peerman = PeerManager::make(m_connman, *m_node.addrman, *m_node.evictionman,
                                           m_node.banman.get(), *m_node.chainman,
                                           *m_node.mempool, false);
    }
};

ConnectionsMockSetup* g_setup;
void initialize()
{
    static auto testing_setup = MakeNoLogFileContext<ConnectionsMockSetup>(
        /*chain_name=*/CBaseChainParams::REGTEST,
        /*extra_args=*/{"-txreconciliation"});
    g_setup = testing_setup.get();
}

ConnectionContext ConsumeConnCtx(FuzzedDataProvider& fdp, NodeId id)
{
    const ConnectionType conn_type = fdp.PickValueInArray(ALL_CONNECTION_TYPES);
    return ConnectionContext{
        .id = id,
        .connected = GetTime<std::chrono::seconds>(),
        .permission_flags = ConsumeWeakEnum(fdp, ALL_NET_PERMISSION_FLAGS),
        .conn_type = conn_type,
        .is_inbound_onion = conn_type == ConnectionType::INBOUND ? fdp.ConsumeBool() : false,
    };
}

CSerializedNetMsg ConsumeVersionMsg(FuzzedDataProvider& fdp)
{
    CSerializedNetMsg msg;
    CallOneOf(
        fdp,
        [&msg, &fdp]() {
            msg.m_type = NetMsgType::VERSION;
            msg.data = ConsumeRandomLengthByteVector(fdp, /*max_length=*/1024);
        },
        [&msg]() {
            msg.m_type = NetMsgType::VERACK;
        },
        [&msg]() {
            msg.m_type = NetMsgType::WTXIDRELAY;
        },
        [&msg]() {
            msg.m_type = NetMsgType::SENDADDRV2;
        },
        [&msg]() {
            msg.m_type = NetMsgType::SENDHEADERS;
        },
        [&msg, &fdp]() {
            msg.m_type = NetMsgType::SENDCMPCT;
            msg.data = fdp.ConsumeBytes<uint8_t>(9);
        },
        [&msg, &fdp]() {
            msg.m_type = NetMsgType::SENDTXRCNCL;
            msg.data = fdp.ConsumeBytes<uint8_t>(12);
        });

    return msg;
}

} // namespace


FUZZ_TARGET_INIT(p2p_handshake, initialize)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    LOCK(NetEventsInterface::g_msgproc_mutex);

    MockConnectionsInterface& connman = g_setup->m_connman;
    PeerManager& peerman = *g_setup->m_node.peerman;

    auto num_conns{fuzzed_data_provider.ConsumeIntegralInRange<NodeId>(1, 8)};
    for (NodeId id = 0; id < num_conns; ++id) {
        auto& conn = connman.AddMockConnection(ConsumeConnCtx(fuzzed_data_provider, id));
        peerman.InitializeNode(conn, ServiceFlags{NODE_NETWORK | NODE_WITNESS});
    }

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        NodeId id{fuzzed_data_provider.ConsumeIntegralInRange<NodeId>(0, num_conns - 1)};
        auto& conn = connman.m_conns.at(id);

        conn.m_send_queue.emplace_back(ConsumeVersionMsg(fuzzed_data_provider));

        bool completed_handshake{conn.IsSuccessfullyConnected()};
        try {
            std::atomic_bool interrupt;
            peerman.ProcessMessages(&conn, interrupt);
        } catch (const std::ios_base::failure&) {
        }
        peerman.SendMessages(&conn);

        if (!completed_handshake && conn.IsSuccessfullyConnected()) {
            assert(!conn.MarkedForDisconnect());
            PeerStats stats;
            assert(peerman.GetPeerStats(conn.GetId(), stats));
            assert(stats.m_version >= MIN_PEER_PROTO_VERSION);

            assert(conn.m_message_types_received[NetMsgType::VERSION] == 1);
            assert(conn.m_message_types_received[NetMsgType::VERACK] == 1);

            assert(conn.m_message_types_received[NetMsgType::WTXIDRELAY] == stats.m_version >= WTXID_RELAY_VERSION);
            assert(conn.m_message_types_received[NetMsgType::SENDADDRV2] == stats.m_version >= WTXID_RELAY_VERSION);
            assert(conn.m_message_types_received[NetMsgType::SENDCMPCT] == stats.m_version >= SHORT_IDS_BLOCKS_VERSION);
            bool expect_feefiler{
                stats.m_version >= FEEFILTER_VERSION &&
                !conn.IsBlockOnlyConn() &&
                !conn.HasPermission(NetPermissionFlags::ForceRelay)};
            assert(conn.m_message_types_received[NetMsgType::FEEFILTER] == expect_feefiler);
            assert(conn.m_message_types_received["alert"] == stats.m_version <= SENDHEADERS_VERSION);
            bool expect_getaddr{!conn.IsBlockOnlyConn() && !conn.IsInboundConn()};
            assert(conn.m_message_types_received[NetMsgType::GETADDR] == expect_getaddr);
        }

        conn.m_received_messages.clear();
    }

    for (auto& [id, conn] : connman.m_conns) {
        peerman.FinalizeNode(conn);
    }

    // TODO add a reset method to the mock conn interface
    connman.m_conns.clear();
    connman.m_try_new_outbound = false;
    TestOnlyResetTimeData();
}
