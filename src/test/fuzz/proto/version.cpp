#include <src/libfuzzer/libfuzzer_macro.h>
#include <test/fuzz/proto/version.pb.h>

#include <net.h>
#include <net_processing.h>
#include <script/script.h>
#include <test/fuzz/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validation.h>
#include <validationinterface.h>

#include <iostream>

namespace {
const TestingSetup* g_setup;
} // namespace

// WHYYYYY
// const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
const std::function<void(const std::string&)> G_TEST_LOG_FUN;
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
    return 0;
}

ConnectionType ConvertConnType(const proto_fuzz::ConnectionType& type)
{
    switch (type) {
    case proto_fuzz::MANUAL:
        return ConnectionType::MANUAL;
    case proto_fuzz::BLOCK_RELAY:
        return ConnectionType::BLOCK_RELAY;
    case proto_fuzz::OUTBOUND_FULL_RELAY:
        return ConnectionType::OUTBOUND_FULL_RELAY;
    case proto_fuzz::INBOUND:
        return ConnectionType::OUTBOUND_FULL_RELAY;
    case proto_fuzz::INBOUND_ONION:
        return ConnectionType::INBOUND;
    case proto_fuzz::ADDR_FETCH:
        return ConnectionType::ADDR_FETCH;
    case proto_fuzz::FEELER:
        return ConnectionType::FEELER;
    }
}

NetPermissionFlags ConvertPermFlags(const proto_fuzz::NetPermissionFlags& flags)
{
    NetPermissionFlags perms{0};
    if (flags.addr()) perms = perms | NetPermissionFlags::Addr;
    if (flags.noban()) perms = perms | NetPermissionFlags::NoBan;
    if (flags.download()) perms = perms | NetPermissionFlags::Download;
    if (flags.relay()) perms = perms | NetPermissionFlags::Relay;
    if (flags.force_relay()) perms = perms | NetPermissionFlags::ForceRelay;
    if (flags.mempool()) perms = perms | NetPermissionFlags::Mempool;
    if (flags.implicit()) perms = perms | NetPermissionFlags::Implicit;
    if (flags.bloom_filter()) perms = perms | NetPermissionFlags::BloomFilter;
    return perms;
}

CNode& ConvertPeer(const proto_fuzz::Peer& peer, FuzzedDataProvider& sock_data_provider)
{
    CNodeOptions options;
    if (peer.has_perm_flags()) {
        options.permission_flags = ConvertPermFlags(peer.perm_flags());
    }
    if (peer.has_prefer_evict()) {
        options.prefer_evict = peer.prefer_evict();
    }

    CNode* node = new CNode{
        /*id=*/0,
        /*sock=*/std::make_shared<FuzzedSock>(sock_data_provider),
        /*addrIn=*/CAddress(),
        /*nKeyedNetGroupIn=*/peer.keyed_net_group(),
        /*nLocalHostNonceIn=*/peer.local_host_nonce(),
        /*addrBindIn=*/CAddress(),
        /*addrNameIn=*/"",
        /*conn_type_in=*/ConvertConnType(peer.conn_type()),
        /*inbound_onion=*/peer.conn_type() == proto_fuzz::INBOUND_ONION,
        std::move(options),
    };

    return *node;
}

ServiceFlags ConvertServiceFlags(const proto_fuzz::ServiceFlags& flags)
{
    uint64_t service_flags{0};
    if (flags.bloom()) service_flags |= NODE_BLOOM;
    if (flags.network()) service_flags |= NODE_NETWORK;
    if (flags.network_limited()) service_flags |= NODE_NETWORK_LIMITED;
    if (flags.compact_filters()) service_flags |= NODE_COMPACT_FILTERS;
    if (flags.witness()) service_flags |= NODE_WITNESS;

    return ServiceFlags{service_flags};
}

std::tuple<std::string, std::vector<uint8_t>> ConvertHandshakeMsg(const proto_fuzz::HandshakeMsg& msg)
{
    std::string type;
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    if (msg.has_version()) {
        type = NetMsgType::VERSION;
        stream << msg.version().version()
               << (uint64_t)ConvertServiceFlags(msg.version().services())
               << msg.version().time()
               << uint64_t{0}
               << CService()
               << uint64_t{0} << uint64_t{0} << uint64_t{0} << uint16_t{0}
               << msg.version().nonce()
               << msg.version().sub_version()
               << msg.version().starting_height()
               << msg.version().tx_relay();
    } else if (msg.has_send_cmpct()) {
        type = NetMsgType::SENDCMPCT;
        stream << msg.send_cmpct().high_bw()
               << msg.send_cmpct().version();
    } else if (msg.has_verack()) {
        type = NetMsgType::VERACK;
    } else if (msg.has_sendaddrv2()) {
        type = NetMsgType::SENDADDRV2;
    } else if (msg.has_sendtxrcncl()) {
        type = NetMsgType::SENDTXRCNCL;
        stream << msg.sendtxrcncl().version()
               << msg.sendtxrcncl().salt();
    } else if (msg.has_wtxidrelay()) {
        type = NetMsgType::WTXIDRELAY;
    }

    std::vector<uint8_t> data(stream.size());
    if (stream.size() > 0)
        std::memcpy(data.data(), (uint8_t*)stream.data(), stream.size());
    return {type, std::move(data)};
}

int64_t ClampTime(int64_t time)
{
    const auto* active_tip = WITH_LOCK(
        cs_main, return g_setup->m_node.chainman->ActiveChain().Tip());
    return std::min((int64_t)std::numeric_limits<decltype(active_tip->nTime)>::max(),
                    std::max(time, active_tip->GetMedianTimePast() + 1));
}

template <class Proto>
using PostProcessor =
    protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

static PostProcessor<proto_fuzz::HandshakeMsg> post_proc_atmp_mock_time = {
    [](proto_fuzz::HandshakeMsg* message, unsigned int seed) {
        // Make sure the atmp mock time lies between a sensible minimum and maximum.
        if (message->has_mock_time()) {
            message->set_mock_time(ClampTime(message->mock_time()));
        }
    }};

DEFINE_PROTO_FUZZER(const proto_fuzz::VersionHandshake& version_handshake)
{
    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(g_setup->m_node.connman.get());
    TestChainState& chainstate = *static_cast<TestChainState*>(&g_setup->m_node.chainman->ActiveChainstate());
    SetMockTime(1610000000); // any time to successfully reset ibd
    chainstate.ResetIbd();

    LOCK(NetEventsInterface::g_msgproc_mutex);

    FuzzedDataProvider sock_data_provider{
        (uint8_t*)version_handshake.peer().socket_data_provider().data(),
        version_handshake.peer().socket_data_provider().size()};
    auto& node = ConvertPeer(version_handshake.peer(), sock_data_provider);
    g_setup->m_node.peerman->InitializeNode(node, ConvertServiceFlags(version_handshake.our_flags()));
    connman.AddTestNode(node);

    for (const auto& msg : version_handshake.msgs()) {
        auto [type, bytes] = ConvertHandshakeMsg(msg);

        if (msg.has_mock_time()) {
            SetMockTime(msg.mock_time());
        }

        CSerializedNetMsg net_msg;
        net_msg.m_type = type;
        net_msg.data = std::move(bytes);

        (void)connman.ReceiveMsgFrom(node, net_msg);
        node.fPauseSend = false;

        try {
            connman.ProcessMessagesOnce(node);
        } catch (const std::ios_base::failure&) {
        }
        g_setup->m_node.peerman->SendMessages(&node);
    }

    g_setup->m_node.connman->StopNodes();
}
