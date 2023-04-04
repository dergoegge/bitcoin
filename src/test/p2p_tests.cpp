#include <banman.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/connection_types.h>
#include <node/connections.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <timedata.h>
#include <validation.h>

#include <deque>

#include <boost/test/unit_test.hpp>

void AdvanceMockTime(std::chrono::seconds secs)
{
    auto now{GetTime<std::chrono::seconds>()};
    SetMockTime(now + secs);
}

void ProcessAndSend(PeerManager& peerman, node::Connection& conn)
{
    LOCK(node::NetEventsInterface::g_msgproc_mutex);
    std::atomic<bool> interrupt;
    peerman.ProcessMessages(&conn, interrupt);
    peerman.SendMessages(&conn);
}

struct VersionMsg {
    int version{PROTOCOL_VERSION};
    int64_t time;
    ServiceFlags our_services{NODE_NETWORK | NODE_WITNESS};
    ServiceFlags their_services{NODE_NETWORK | NODE_WITNESS};
    uint64_t nonce;
    std::string sub_version{"mock"};
    int starting_height{1};
    bool tx_relay{true};

    SERIALIZE_METHODS(VersionMsg, obj)
    {
        READWRITE(obj.version,
                  Using<CustomUintFormatter<8>>(obj.our_services),
                  obj.time,
                  int64_t{},  // ignored service bits
                  CService{}, // dummy
                  int64_t{},  // ignored service bits
                  CService{}, // ignored
                  obj.nonce,
                  obj.sub_version,
                  obj.starting_height,
                  obj.tx_relay);
    }
};

MockConnection& AddMockConnectionAndHandshake(MockConnectionsInterface& connections, PeerManager& peerman, ConnectionContext&& conn_ctx)
{
    auto& conn = connections.AddMockConnection(std::move(conn_ctx));

    peerman.InitializeNode(conn, ServiceFlags{NODE_NETWORK | NODE_WITNESS});

    VersionMsg version_sent{};
    conn.m_send_queue.emplace_back(CSerializedNetMsg{CNetMsgMaker(0).Make(NetMsgType::VERSION, version_sent)});
    ProcessAndSend(peerman, conn);

    // Check for version and feature negotiation messages
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::VERSION], 1);
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::WTXIDRELAY], 1);
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::SENDADDRV2], 1);
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::VERACK], 1);

    BOOST_CHECK(conn.IsSuccessfullyConnected() == false);
    BOOST_CHECK(conn.MarkedForDisconnect() == false);

    conn.m_send_queue.emplace_back(CSerializedNetMsg{CNetMsgMaker(0).Make(NetMsgType::VERACK)});
    ProcessAndSend(peerman, conn);

    // Check for post handshake messages
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::SENDCMPCT], 1);
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::FEEFILTER], 1);

    // Handshake should be complete successfully
    BOOST_CHECK(conn.IsSuccessfullyConnected() == true);
    // Connection should not be marked for disconnection
    BOOST_CHECK(conn.MarkedForDisconnect() == false);

    // Sanity check some of the stats
    PeerStats stats;
    BOOST_CHECK(peerman.GetPeerStats(conn.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_version, version_sent.version);
    BOOST_CHECK_EQUAL(stats.m_relay_txs, version_sent.tx_relay);
    BOOST_CHECK_EQUAL(stats.m_clean_subversion, version_sent.sub_version);

    return conn;
}

BOOST_FIXTURE_TEST_SUITE(p2p, TestingSetup)


BOOST_AUTO_TEST_CASE(version_handshake)
{
    auto connman = std::make_unique<MockConnectionsInterface>();
    auto peerman = PeerManager::make(*connman, *m_node.addrman, *m_node.evictionman, nullptr,
                                     *m_node.chainman, *m_node.mempool, false);

    auto& outbound_conn = AddMockConnectionAndHandshake(*connman, *peerman,
                                                        ConnectionContext{
                                                            .id = 0,
                                                            .conn_type = ConnectionType::OUTBOUND_FULL_RELAY,
                                                        });
    BOOST_CHECK_EQUAL(outbound_conn.m_message_types_received[NetMsgType::GETADDR], 1);

    auto& inbound_conn = AddMockConnectionAndHandshake(*connman, *peerman,
                                                       ConnectionContext{
                                                           .id = 1,
                                                           .conn_type = ConnectionType::INBOUND,
                                                       });
    BOOST_CHECK_EQUAL(inbound_conn.m_message_types_received[NetMsgType::GETADDR], 0);

    peerman->FinalizeNode(outbound_conn);
    peerman->FinalizeNode(inbound_conn);

    TestOnlyResetTimeData();
}

BOOST_AUTO_TEST_CASE(pingpong)
{
    auto connman = std::make_unique<MockConnectionsInterface>();
    auto peerman = PeerManager::make(*connman, *m_node.addrman, *m_node.evictionman, nullptr,
                                     *m_node.chainman, *m_node.mempool, false);

    auto now{GetTime<std::chrono::seconds>()};
    SetMockTime(now);

    auto& conn = AddMockConnectionAndHandshake(*connman, *peerman,
                                               ConnectionContext{
                                                   .id = 0,
                                                   .conn_type = ConnectionType::OUTBOUND_FULL_RELAY,
                                               });

    auto check_ping_wait = [&conn, &peerman](std::chrono::microseconds wait) {
        PeerStats stats;
        BOOST_CHECK(peerman->GetPeerStats(conn.GetId(), stats));
        BOOST_CHECK(stats.m_ping_wait == wait);
    };

    BOOST_TEST_MESSAGE("Check that ping is sent after connection establishment");
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::PING], 1);
    AdvanceMockTime(3s);
    check_ping_wait(3s);

    BOOST_TEST_MESSAGE("Reply without nonce cancels ping");
    {
        ASSERT_DEBUG_LOG("pong peer=0: Short payload");
        conn.m_send_queue.emplace_back(CSerializedNetMsg{CNetMsgMaker(0).Make(NetMsgType::PONG)});
        ProcessAndSend(*peerman, conn);
    }
    check_ping_wait(0s);

    {
        BOOST_TEST_MESSAGE("Reply with wrong nonce does not cancel ping");
        ASSERT_DEBUG_LOG("pong peer=0: Unsolicited pong without ping, 0 expected, 0 received, 8 bytes");
        conn.m_send_queue.emplace_back(CSerializedNetMsg{CNetMsgMaker(0).Make(NetMsgType::PONG, uint64_t{0})});
        ProcessAndSend(*peerman, conn);
    }

    constexpr auto PING_INTERVAL{2min};
    AdvanceMockTime(PING_INTERVAL + 1s);

    {
        BOOST_TEST_MESSAGE("Reply with wrong nonce does not cancel ping");
        ASSERT_DEBUG_LOG("pong peer=0: Nonce mismatch");
        BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::PING], 1);
        ProcessAndSend(*peerman, conn);
        BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::PING], 2);

        auto& ping_msg = conn.m_received_messages.back();
        BOOST_CHECK_EQUAL(ping_msg.m_type, NetMsgType::PING);

        CDataStream stream{ping_msg.data, SER_NETWORK, PROTOCOL_VERSION};
        uint64_t nonce;
        stream >> nonce;

        AdvanceMockTime(9s);

        conn.m_send_queue.emplace_back(CSerializedNetMsg{CNetMsgMaker(0).Make(NetMsgType::PONG, nonce - 1)});
        ProcessAndSend(*peerman, conn);
        check_ping_wait(9s);
    }

    {
        BOOST_TEST_MESSAGE("Reply with zero nonce does cancel ping");
        ASSERT_DEBUG_LOG("pong peer=0: Nonce zero");
        conn.m_send_queue.emplace_back(CSerializedNetMsg{CNetMsgMaker(0).Make(NetMsgType::PONG, uint64_t{0})});
        ProcessAndSend(*peerman, conn);
        check_ping_wait(0s);
    }

    BOOST_TEST_MESSAGE("Check that peer is disconnected after ping timeout");
    AdvanceMockTime(PING_INTERVAL + 1s);
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::PING], 2);
    ProcessAndSend(*peerman, conn);
    BOOST_CHECK_EQUAL(conn.m_message_types_received[NetMsgType::PING], 3);

    constexpr auto TIMEOUT_INTERVAL{20min};
    AdvanceMockTime(TIMEOUT_INTERVAL + 1s);
    ProcessAndSend(*peerman, conn);
    BOOST_CHECK_EQUAL(conn.MarkedForDisconnect(), true);

    peerman->FinalizeNode(conn);
}

BOOST_AUTO_TEST_SUITE_END()
