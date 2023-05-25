#include <cstddef>
#include <cstdint>

#include <net_processing.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/snapshot_fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

static void SnapshotFuzzExample(snapshot_fuzz::Fuzz& fuzz)
{
    std::unique_ptr<TestChain100Setup> testing_setup = MakeNoLogFileContext<TestChain100Setup>();

    std::vector<uint256> coinbases;
    for (int i = 0; i < 200; ++i) {
        std::vector<CMutableTransaction> txs;
        CScript scriptPubKey;
        scriptPubKey << OP_TRUE;
        coinbases.push_back(testing_setup->CreateAndProcessBlock(txs, scriptPubKey).GetHash());
    }
    SyncWithValidationInterfaceQueue();

    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(testing_setup->m_node.connman.get());
    PeerManager& peerman = *static_cast<PeerManager*>(testing_setup->m_node.peerman.get());
    std::vector<CNode*> peers;

    FastRandomContext rnd{};

    NodeId id{0};
    std::vector<ConnectionType> connections = {};
    connections.resize(8, ConnectionType::OUTBOUND_FULL_RELAY);
    connections.resize(connections.size() + 2, ConnectionType::BLOCK_RELAY);
    connections.resize(connections.size() + 10, ConnectionType::INBOUND);
    connections.resize(connections.size() + 5, ConnectionType::MANUAL);

    LOCK(NetEventsInterface::g_msgproc_mutex);

    for (auto conn_type : connections) {
        CAddress addr{};
        peers.push_back(new CNode(id++, nullptr, addr, 0, 0, addr, "", conn_type, false));
        CNode& p2p_node = *peers.back();

        connman.Handshake(
            /*node=*/p2p_node,
            /*successfully_connected=*/true,
            /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
            /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
            /*version=*/PROTOCOL_VERSION,
            /*relay_txs=*/rnd.randbool());

        connman.AddTestNode(p2p_node);
    }

    // =====
    fuzz.run([&peers, &connman, &peerman](Span<const uint8_t> buffer) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

        while (fuzzed_data_provider.remaining_bytes()) {
            SetMockTime(ConsumeTime(fuzzed_data_provider));

            CSerializedNetMsg net_msg;
            net_msg.m_type = PickValue(fuzzed_data_provider, getAllNetMessageTypes());
            net_msg.data = ConsumeRandomLengthByteVector(fuzzed_data_provider);

            CNode& connection = *PickValue(fuzzed_data_provider, peers);

            (void)connman.ReceiveMsgFrom(connection, net_msg);
            connection.fPauseSend = false;

            try {
                connman.ProcessMessagesOnce(connection);
            } catch (const std::ios_base::failure&) {
            }
            peerman.SendMessages(&connection);
        }
    });
}

SNAPSHOT_FUZZ_TARGET(SnapshotFuzzExample)
