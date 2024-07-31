// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

#include <addrman.h>
#include <blockencodings.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <crypto/hex_base.h>
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <node/warnings.h>
#include <protocol.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/overloaded.h>
#include <util/time.h>
#include <validationinterface.h>

#include <ios>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <variant>
#include <vector>


#define DebugLog(...) \
    if (std::getenv("DEBUG")) fprintf(stdout, __VA_ARGS__);

namespace {

/** RAII helper for calling ConnmanTestMsg::StopNodes */
class ConnectionEnder
{
    ConnmanTestMsg& m_connman;

public:
    ConnectionEnder(ConnmanTestMsg& connman) : m_connman{connman} {}
    ~ConnectionEnder()
    {
        m_connman.StopNodes();
    }
};

class MessageCapturer
{
    std::map<std::string, std::deque<std::vector<uint8_t>>> m_received_msgs{};
    std::map<std::string, std::deque<std::vector<uint8_t>>> m_sent_msgs{};

    using CaptureFn = decltype(CaptureMessage);
    CaptureFn m_orig_capture;

public:
    MessageCapturer(const CNode& connection)
    {
        m_orig_capture = CaptureMessage;
        CaptureMessage = [&, this](const CAddress& addr,
                                   const std::string& msg_type,
                                   Span<const unsigned char> data,
                                   bool incoming) -> void {
            DebugLog("Captured message type=%s incoming=%d hex='%s' conn=%d\n",
                     msg_type.c_str(), incoming, HexStr(data).c_str(), addr.GetPort());

            if (addr.GetPort() != connection.GetId()) {
                return;
            }

            if (incoming) {
                this->m_received_msgs[msg_type].emplace_back(data.begin(), data.end());
            } else {
                this->m_sent_msgs[msg_type].emplace_back(data.begin(), data.end());
            }
        };
    }

    template <typename S>
    bool Received(S s)
    {
        return m_received_msgs.contains(s);
    }
    template <typename S>
    bool Sent(S s)
    {
        return m_sent_msgs.contains(s);
    }

    template <typename T, typename S>
    T PopSent(S s)
    {
        assert(!m_sent_msgs[s].empty());

        T t{};
        {
            DataStream stream{m_sent_msgs[s].front()};
            try {
                stream >> t;
            } catch (const std::ios_base::failure&) {
                fprintf(stderr, "Message sent by PeerManager did not deserialize!\n");
                abort();
            }
        }

        m_sent_msgs[s].pop_front();
        return t;
    }

    ~MessageCapturer()
    {
        CaptureMessage = m_orig_capture;
    }
};

// SendCmpctMsg encapsulates the contents of a "sendcmpct" message
struct SendCmpctMsg {
    bool hb_mode{};
    uint64_t version{};

    SERIALIZE_METHODS(SendCmpctMsg, obj) { READWRITE(obj.hb_mode, obj.version); }
};

// GetHeadersMsg encapsulates the contents of a "getheaders" message
struct GetHeadersMsg {
    CBlockLocator locator{};
    uint256 hash_stop{};

    SERIALIZE_METHODS(GetHeadersMsg, obj) { READWRITE(obj.locator, obj.hash_stop); }
};

class FuzzedHeaderAndShortIds : public CBlockHeaderAndShortTxIDs
{
public:
    FuzzedHeaderAndShortIds(FuzzedDataProvider& fuzzed_data_provider, const CBlock& block)
        : CBlockHeaderAndShortTxIDs{block, fuzzed_data_provider.ConsumeIntegral<uint64_t>()}
    {
        if (fuzzed_data_provider.ConsumeBool()) { // fuzz short ids
            auto shorttxids_ = shorttxids;
            shorttxids = ConsumeDeserializable<decltype(shorttxids_)>(fuzzed_data_provider).value_or(shorttxids_);
            for (auto& id : shorttxids) {
                // Fixup ids to be at most SHORTTXIDS_LENGTH bytes long to avoid
                // CustomUintFormatter from complaining.
                id &= (0xffffffffffffff >>
                       ((8 - CBlockHeaderAndShortTxIDs::SHORTTXIDS_LENGTH) * 8));
            }
        }
        if (fuzzed_data_provider.ConsumeBool()) { // fuzz prefilled txs
            // A offset of 0 really means 1, i.e. for [tx1, tx2, tx3] the offset
            // from tx1 to tx2 is 0 and the offset from tx1 to tx3 is 1.
            uint16_t offset_since_last_prefilled{0};
            for (size_t i = 1; i < block.vtx.size(); ++i) {
                if (fuzzed_data_provider.ConsumeBool()) {
                    // Add transactions from the block to `prefilledtxn`.
                    prefilledtxn.emplace_back(offset_since_last_prefilled, block.vtx[i]);
                    offset_since_last_prefilled = 0;
                    continue;
                }

                ++offset_since_last_prefilled;
            }
        }
    }
};

class FuzzedBlockTransactions : public BlockTransactions
{
public:
    FuzzedBlockTransactions(
        FuzzedDataProvider& fuzzed_data_provider,
        const CBlock& block,
        const std::vector<uint16_t>& indexes)
        : BlockTransactions{}
    {
        blockhash = block.GetHash();

        if (fuzzed_data_provider.ConsumeBool()) {
            // Consume all transactions from the fuzzed data provider
            std::vector<CTransactionRef> txn{};
            txn = ConsumeDeserializable<decltype(txn)>(
                      fuzzed_data_provider, TX_WITH_WITNESS)
                      .value_or(txn);
        } else {
            // Fill in the right transactions to respond with unless an index
            // is out of range for the announced block, in which case we
            // consume from the data provider.
            for (auto& index : indexes) {
                if (index >= block.vtx.size()) {
                    auto tx = ConsumeDeserializable<CTransactionRef>(
                        fuzzed_data_provider, TX_WITH_WITNESS);
                    if (tx) txn.push_back(*tx);
                } else {
                    txn.push_back(block.vtx[index]);
                }
            }
        }
    }
};

/** Helper for sending messages from a specific connection. */
void SendMessage(FuzzedDataProvider& fuzzed_data_provider,
                 ConnmanTestMsg& connman,
                 PeerManager& peerman,
                 CNode& connection,
                 CSerializedNetMsg&& msg)
    NO_THREAD_SAFETY_ANALYSIS
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);

    connman.FlushSendBuffer(connection);
    (void)connman.ReceiveMsgFrom(connection, std::move(msg));

    bool more_work{true};
    while (more_work) {
        connection.fPauseSend = false;

        try {
            more_work = connman.ProcessMessagesOnce(connection);
        } catch (const std::ios_base::failure&) {
        }
        peerman.SendMessages(&connection);
    }
};

class TestConnectionAddr : public CAddress
{
public:
    void SetPort(uint16_t port_) { this->port = port_; }
};

/** Consume a CNode* from the FuzzedDataProvider, that represents a connection
 * for compact block relay. */
CNode* ConsumeCompactBlockConnection(FuzzedDataProvider& fuzzed_data_provider,
                                     ConnmanTestMsg& connman,
                                     PeerManager& peerman,
                                     NodeId connection_id,
                                     const uint256& tip_hash) NO_THREAD_SAFETY_ANALYSIS
{
    AssertLockHeld(NetEventsInterface::g_msgproc_mutex);

    CAddress address = ConsumeAddress(fuzzed_data_provider);
    if (!address.IsValid()) return nullptr; // TODO subnet match issue
    // Set the port equal to the address so that we can distinguish between peer
    // in `MessageCapturer`.
    assert(connection_id <= std::numeric_limits<uint16_t>::max());
    static_cast<TestConnectionAddr*>(&address)->SetPort((uint16_t)connection_id);

    const uint64_t keyed_net_group = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    const uint64_t local_host_nonce = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    const CAddress addr_bind = ConsumeAddress(fuzzed_data_provider);
    const std::string addr_name = fuzzed_data_provider.ConsumeRandomLengthString(64);

    // We exclude feeler and addr fetch connections, because we would never
    // process any compact block messages from them.
    //
    // We also exlude manual connections as the current `CompactBlockStateMachine`
    // implementation will repsond to all getdata requests (the production
    // implementation will not respond if asked for an invalid block) and
    // therefore run into infinite request/reply loops with manual peers as they
    // don't get disconnected for sending invalid blocks.
    const ConnectionType conn_type = fuzzed_data_provider.PickValueInArray(
        {ConnectionType::INBOUND, ConnectionType::BLOCK_RELAY, ConnectionType::OUTBOUND_FULL_RELAY});
    const bool inbound_onion{conn_type == ConnectionType::INBOUND ? fuzzed_data_provider.ConsumeBool() : false};
    NetPermissionFlags permission_flags = ConsumeWeakEnum(fuzzed_data_provider, ALL_NET_PERMISSION_FLAGS);
    // Avoid the NoBan permission with the same reasoning as manual connection types (see comment above).
    using t = typename std::underlying_type<NetPermissionFlags>::type;
    permission_flags = static_cast<NetPermissionFlags>(
        static_cast<t>(permission_flags) & ~static_cast<t>(NetPermissionFlags::NoBan));

    auto connection = std::make_unique<CNode>(
        connection_id, /*sock=*/nullptr,
        address, keyed_net_group,
        local_host_nonce, addr_bind,
        addr_name, conn_type,
        inbound_onion,
        CNodeOptions{.permission_flags = permission_flags});

    connman.Handshake(*connection, true,
                      ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                      ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                      PROTOCOL_VERSION, true);
    if (!connection->fSuccessfullyConnected || connection->fDisconnect) return nullptr;
    connman.AddTestNode(*connection);

    // Send a "sendcmpct" message to let PeerManager know that this connection
    // speaks the compact block protocol.
    CSerializedNetMsg sendcmpct_msg;
    sendcmpct_msg.m_type = NetMsgType::SENDCMPCT;
    ParamsStream{VectorWriter{sendcmpct_msg.data, 0}, TX_WITH_WITNESS}
        << SendCmpctMsg{.hb_mode = fuzzed_data_provider.ConsumeBool(), .version = 2};
    SendMessage(
        fuzzed_data_provider, connman, peerman, *connection, std::move(sendcmpct_msg));

    // Announce `tip_hash`, so that the block availability for this connection
    // is correctly updated by PeerManager.
    std::vector<CInv> inv = {CInv{MSG_BLOCK, tip_hash}};
    CSerializedNetMsg inv_msg;
    inv_msg.m_type = NetMsgType::INV;
    ParamsStream{VectorWriter{inv_msg.data, 0}, TX_WITH_WITNESS} << inv;
    MessageCapturer msg_capture{*connection};
    SendMessage(
        fuzzed_data_provider, connman, peerman, *connection, std::move(inv_msg));
    // If the block availability was updated correctly, then PeerManager will
    // respond with a "sendheaders" message, indicating that the connection
    // should announce new blocks via "headers" messages.
    assert(msg_capture.Sent(NetMsgType::SENDHEADERS));

    return connection.release();
}


struct CompactBlockStateMachine {
    FuzzedDataProvider& m_fuzzed_data_provider;
    ChainstateManager& m_chainman;
    CNode& m_connection;
    bool m_high_bandwidth_mode_requested{false};

    const std::vector<CBlock> m_blocks;
    std::map<uint256, const CBlock*> m_block_index;
    const CBlock* m_tip{nullptr};

    // Initial high bandwidth mode announcement of the block.
    //
    // In low bandwidth mode a compact block will be requested in response to a
    // headers message.
    struct RelayCompactBlock {
        std::optional<uint256> requested;
    };

    struct RelayBlockTransactions {
        // A blocktxn message is only send in response to a getblocktxn message.
        // We store the requested transaction indexes from the getblocktxn in
        // `requested_indexes`.
        BlockTransactionsRequest request;
    };

    struct RelayHeaders {
        CBlockLocator request_locator;
    };

    struct RelayBlocks {
        // Block messages are send in response to a getdata(MSG_BLOCK) message.
        // We store the requested inventory from the getdata message in
        // `requested_inventory`.
        std::vector<CInv> requested_inventory;
    };

    // Next step in the state machine to execute.
    using StepVariant = std::variant<
        RelayCompactBlock,
        RelayBlockTransactions,
        RelayHeaders,
        RelayBlocks,
        std::monostate>;
    StepVariant m_step;

    void AssertBlockInventory(const std::vector<CInv>& inventory)
    {
        assert(!inventory.empty());
        for (const auto& inv : inventory) {
            assert(inv.IsMsgCmpctBlk() || inv.IsMsgWitnessBlk() || inv.IsMsgBlk());
            AssertExistsInIndex(inv.hash);
        }
    }

    void AssertExistsInIndex(const uint256& hash)
    {
        if (!m_block_index.contains(hash)) {
            fprintf(stderr, "%s does not exist in the block index!\n", hash.ToString().c_str());
            abort();
        }
    }

    // Send a message to `peerman` through the connection associated with the state machine.
    //
    // Returns true if the message caused the connection to be disconnected.
    bool SendMessage(ConnmanTestMsg& connman, PeerManager& peerman, CSerializedNetMsg&& msg)
    {
        ::SendMessage(
            m_fuzzed_data_provider, connman, peerman,
            m_connection, std::move(msg));

        if (m_connection.fDisconnect) {
            DebugLog("Last message caused a disconnect, entering final state!\n");
            m_step = std::monostate{};
            return true;
        }

        return false;
    }

    void AttemptToFillMempool(const std::vector<CTransactionRef>& txs)
    {
        if (!m_fuzzed_data_provider.ConsumeBool()) {
            return;
        }

        LOCK(cs_main);

        for (auto& tx : txs) {
            if (tx->IsCoinBase()) continue;
            if (!m_fuzzed_data_provider.ConsumeBool()) continue;
            // TODO send as tx message?
            const MempoolAcceptResult result = m_chainman.ProcessTransaction(tx, /*test_accept=*/false);
            DebugLog("PopulateMempool: mempool result: %s\n", result.m_state.ToString().c_str());
        }
    }

    void HandleSendCmpctMsg(const SendCmpctMsg& msg, const uint256& last_announced)
    {
        assert(msg.version == 2); // CMPCTBLOCKS_VERSION from net_processing.cpp
        m_high_bandwidth_mode_requested = msg.hb_mode;

        // We received a sendcmpct message in response, so the block we sent
        // must have been successfully relayed, although it might not be the
        // active tip if it was invalid.
        LOCK(cs_main);
        const CBlockIndex* index = Assert(m_chainman.m_blockman.LookupBlockIndex(last_announced));
        assert((index->nStatus & BLOCK_HAVE_DATA) != 0);
    }

    void Step(const RelayCompactBlock& relay_compact_block, ConnmanTestMsg& connman, PeerManager& peerman)
    {
        MessageCapturer msg_capture{m_connection};

        const CBlock* to_announce{nullptr};
        if (relay_compact_block.requested) {
            to_announce = m_block_index[*relay_compact_block.requested];
        } else {
            to_announce = &PickValue(m_fuzzed_data_provider, m_blocks);
        }

        FuzzedHeaderAndShortIds header_and_ids{m_fuzzed_data_provider, *to_announce};

        CSerializedNetMsg header_and_ids_msg;
        header_and_ids_msg.m_type = NetMsgType::CMPCTBLOCK;
        ParamsStream{VectorWriter{header_and_ids_msg.data, 0}, TX_WITH_WITNESS}
            << header_and_ids;

        AttemptToFillMempool(to_announce->vtx);

        if (SendMessage(connman, peerman, std::move(header_and_ids_msg))) return;

        // In response to a compact block message we expect a "getblocktxn",
        // "getheaders" or "getdata" in response. If the block is immediately
        // reconstructed and accepted we might also receive a "sendcmpct" indicating
        // the requested bandwidth mode for future announcements.

        if (msg_capture.Sent(NetMsgType::GETBLOCKTXN)) {
            auto request{msg_capture.PopSent<BlockTransactionsRequest>(NetMsgType::GETBLOCKTXN)};
            AssertExistsInIndex(request.blockhash);
            assert(request.blockhash == to_announce->GetHash());
            for (auto& index : request.indexes) {
                // Coinbase transaction should always be prefilled and never requested
                assert(index != 0);
                // Ensure the indexes PeerManager sends are in range for the announced block size
                assert(index >= 1 && index < header_and_ids.BlockTxCount());
            }

            m_step = RelayBlockTransactions{request};

        } else if (msg_capture.Sent(NetMsgType::GETHEADERS)) {
            auto getheaders{msg_capture.PopSent<GetHeadersMsg>(NetMsgType::GETHEADERS)};
            m_step = RelayHeaders{getheaders.locator};

        } else if (msg_capture.Sent(NetMsgType::GETDATA)) {
            auto requested_inventory{msg_capture.PopSent<std::vector<CInv>>(NetMsgType::GETDATA)};
            for (const auto& inv : requested_inventory) {
                assert(!inv.IsMsgCmpctBlk());
            }
            AssertBlockInventory(requested_inventory);
            m_step = RelayBlocks{requested_inventory};

        } else {
            // Nothing received or sendcmpct
            if (msg_capture.Sent(NetMsgType::SENDCMPCT)) {
                HandleSendCmpctMsg(msg_capture.PopSent<SendCmpctMsg>(NetMsgType::SENDCMPCT), to_announce->GetHash());
            }

            // TODO when does this happen? we don't want to get stuck in this step, so just bail
            m_step = std::monostate{};
        }
    }

    void Step(const RelayBlockTransactions& relay_block_transactions, ConnmanTestMsg& connman, PeerManager& peerman)
    {
        MessageCapturer msg_capture{m_connection};

        const CBlock& to_announce = *m_block_index[relay_block_transactions.request.blockhash];
        FuzzedBlockTransactions block_transactions{
            m_fuzzed_data_provider,
            to_announce,
            relay_block_transactions.request.indexes};
        CSerializedNetMsg block_transactions_msg;
        block_transactions_msg.m_type = NetMsgType::BLOCKTXN;
        ParamsStream{VectorWriter{block_transactions_msg.data, 0}, TX_WITH_WITNESS}
            << block_transactions;

        AttemptToFillMempool(block_transactions.txn);

        if (SendMessage(connman, peerman, std::move(block_transactions_msg))) return;

        if (msg_capture.Sent(NetMsgType::SENDCMPCT)) {
            HandleSendCmpctMsg(msg_capture.PopSent<SendCmpctMsg>(NetMsgType::SENDCMPCT), to_announce.GetHash());
            m_step = std::monostate{};

        } else if (msg_capture.Sent(NetMsgType::GETDATA)) {
            auto requested_inventory{msg_capture.PopSent<std::vector<CInv>>(NetMsgType::GETDATA)};
            AssertBlockInventory(requested_inventory);

            m_step = RelayBlocks{requested_inventory};
        } else {
            // Nothing received in response
            DebugLog("Nothing received after sending blocktxn, entering final state!\n");
            m_step = std::monostate{};
        }
    }

    void Step(const RelayHeaders& relay_headers, ConnmanTestMsg& connman, PeerManager& peerman)
    {
        MessageCapturer msg_capture{m_connection};

        // Figure out which headers to send
        uint256 last_hash{m_blocks.front().hashPrevBlock};
        for (auto& hash : relay_headers.request_locator.vHave) {
            if (m_block_index.contains(hash)) {
                last_hash = hash;
                break;
            }
        }

        std::vector<CBlock> headers;
        for (auto it = m_blocks.begin(); it != m_blocks.end(); ++it) {
            if (!headers.empty()) {
                if (m_fuzzed_data_provider.ConsumeBool()) {
                    // Only send connecting chains of headers
                    break;
                } else {
                    headers.emplace_back(CBlockHeader{*it});
                }
            } else if (it->hashPrevBlock == last_hash) {
                // Send at least this header and maybe more
                headers.emplace_back(CBlockHeader{*it});
            }
        }
        assert(!headers.empty());

        CSerializedNetMsg headers_msg;
        headers_msg.m_type = NetMsgType::HEADERS;
        ParamsStream{VectorWriter{headers_msg.data, 0}, TX_WITH_WITNESS} << headers;

        if (SendMessage(connman, peerman, std::move(headers_msg))) return;

        if (msg_capture.Sent(NetMsgType::GETHEADERS)) {
            auto getheaders{msg_capture.PopSent<GetHeadersMsg>(NetMsgType::GETHEADERS)};
            m_step = RelayHeaders{getheaders.locator};
        } else if (msg_capture.Sent(NetMsgType::GETDATA)) {
            auto requested_inventory{msg_capture.PopSent<std::vector<CInv>>(NetMsgType::GETDATA)};
            AssertBlockInventory(requested_inventory);

            if (requested_inventory.size() == 1 && requested_inventory[0].IsMsgCmpctBlk()) {
                m_step = RelayCompactBlock{requested_inventory[0].hash};
            } else {
                for (auto& inv : requested_inventory) {
                    // Only a getdata message with one inventory item is allowed to have compact block entries
                    assert(!inv.IsMsgCmpctBlk());
                }

                m_step = RelayBlocks{requested_inventory};
            }
        } else {
            m_step = std::monostate{};
        }
    }

    void Step(const RelayBlocks& relay_blocks, ConnmanTestMsg& connman, PeerManager& peerman)
    {
        assert(!relay_blocks.requested_inventory.empty());

        MessageCapturer msg_capture{m_connection};

        size_t to_relay{0};
        // Create the block message to relay
        CSerializedNetMsg block_msg;
        block_msg.m_type = NetMsgType::BLOCK;
        if (relay_blocks.requested_inventory.size() == 1 ||
            m_fuzzed_data_provider.ConsumeBool()) {
            // Relay the earliest block, i.e. the first block in the requested inventory
            ParamsStream{VectorWriter{block_msg.data, 0}, TX_WITH_WITNESS}
                << *m_block_index[relay_blocks.requested_inventory[0].hash];
        } else {
            // Relay one of the blocks that were requested before its parent
            to_relay = m_fuzzed_data_provider.ConsumeIntegralInRange<size_t>(
                1, relay_blocks.requested_inventory.size() - 1);
            DebugLog("relaying %zu/%zu from the inventory\n",
                     to_relay, relay_blocks.requested_inventory.size());
            AssertExistsInIndex(relay_blocks.requested_inventory[to_relay].hash);
            ParamsStream{VectorWriter{block_msg.data, 0}, TX_WITH_WITNESS}
                << *m_block_index[relay_blocks.requested_inventory[to_relay].hash];
        }

        std::vector<CInv> new_inventory{
            relay_blocks.requested_inventory.begin(),
            relay_blocks.requested_inventory.end()};
        new_inventory.erase(new_inventory.begin() + to_relay);

        AttemptToFillMempool(m_block_index[relay_blocks.requested_inventory[to_relay].hash]->vtx);

        if (SendMessage(connman, peerman, std::move(block_msg))) return;

        if (msg_capture.Sent(NetMsgType::SENDCMPCT)) {
            HandleSendCmpctMsg(msg_capture.PopSent<SendCmpctMsg>(NetMsgType::SENDCMPCT),
                               relay_blocks.requested_inventory[to_relay].hash);
            if (new_inventory.empty()) {
                m_step = std::monostate{};
            }

        } else {
            if (new_inventory.empty()) {
                m_step = std::monostate{};
            }
        }
        // TODO what about receiving getdata here?

        if (!new_inventory.empty()) {
            m_step = RelayBlocks{new_inventory};
        }
    }

public:
    CompactBlockStateMachine(
        FuzzedDataProvider& fuzzed_data_provider,
        ChainstateManager& chainman, CNode& connection,
        const std::vector<CBlock>& blocks, bool high_bandwidth_mode)
        : m_fuzzed_data_provider{fuzzed_data_provider},
          m_chainman{chainman},
          m_connection{connection},
          m_blocks{blocks.begin(), blocks.end()}
    {
        if (high_bandwidth_mode) {
            m_step = RelayCompactBlock{.requested = std::nullopt};
        } else {
            m_step = RelayHeaders{CBlockLocator{}};
        }

        for (const auto& block : m_blocks) {
            m_block_index.emplace(block.GetHash(), &block);
        }
        m_tip = &m_blocks.back();
    }

    CompactBlockStateMachine(const CompactBlockStateMachine&) = delete;

    // Advance the state machine by one step. Return std::nullopt if there are
    // more steps left to complete.
    struct StepResult {
        bool disconnected{false};
        bool high_bandwidth_mode_requested{false};
        uint256 block_hash{};
    };
    std::optional<StepResult> Step(ConnmanTestMsg& connman, PeerManager& peerman)
    {
        std::visit(
            util::Overloaded{
                [&](const RelayCompactBlock& initial_announcement) { Step(initial_announcement, connman, peerman); },
                [&](const RelayBlockTransactions& relay_block_transactions) { Step(relay_block_transactions, connman, peerman); },
                [&](const RelayHeaders& relay_headers) { Step(relay_headers, connman, peerman); },
                [&](const RelayBlocks& relay_blocks) { Step(relay_blocks, connman, peerman); },
                [&](const std::monostate& final_state) {}, // Ignore final state
            },
            m_step);
        if (std::holds_alternative<std::monostate>(m_step)) {
            return StepResult{
                .disconnected = m_connection.fDisconnect,
                .high_bandwidth_mode_requested = m_high_bandwidth_mode_requested,
                .block_hash = m_tip->GetHash(),
            };
        }

        return std::nullopt;
    }

    void StepUntilEnd(ConnmanTestMsg& connman, PeerManager& peerman)
    {
        constexpr int max_steps{1000};
        for (int i = 0; i < max_steps; ++i) {
            if (Step(connman, peerman)) {
                return;
            }
        }

        // If the state machine never reaches a final state, we're likely stuck
        // in an endless request/reply loop (which would indicate a bug in the
        // fuzz test or the net processing state machine).
        fprintf(stderr, "Compact block state machine never reached a final state!\n");
        abort();
    }
};


/** Create transactions for testing compact block relay. If
 * `should_add_to_mempool` is `true`, only some transactions are added to the
 * mempool, while others are returned for inclusion in a block to simulate
 * various compact block relay scenarios.
 *
 * At most 25 transactions are created with the following simple topology:
 *
 * ```
 *                       ┌─────┐
 *                ┌─────►│ tx1 │
 *                │      └─────┘
 *                │
 * ┌────────────┐ │      ┌─────┐
 * │ funding tx ├─┼─────►│ tx2 │
 * └────────────┘ │      └─────┘
 *                │
 *                │      ┌─────┐
 *                ├─────►│ tx3 │
 *                │      └─────┘
 *                │
 *                │
 *                └─────►  ...
 * ```
 *
 * The funding transaction spends from the yougest mature coinbase and has at
 * most 24 outputs, which may be spend by further transactions (tx1, ..., tx24).
 */
std::vector<CTransactionRef> PopulateMempool(
    TestChain100Setup& setup, FuzzedDataProvider& fuzzed_data_provider, int height)
{
    if (height < 100 || height > 200) {
        // We don't have a mature coinbase available if the tip height is <100 or >200
        return {};
    }

    // Get the youngest mature (i.e. spendable) coinbase transaction
    auto& mature_coinbase_tx{setup.m_coinbase_txns[height - COINBASE_MATURITY]};

    auto num_txs = fuzzed_data_provider.ConsumeIntegralInRange<uint64_t>(0, 24); // Avoid hitting too-long-mempool-chain
    if (num_txs == 0) return {};

    // Transaction spending from `mature_coinbase_tx` to create many outputs for
    // funding further transactions.
    CMutableTransaction funding_tx_mut;
    funding_tx_mut.version = 2;
    funding_tx_mut.vin.resize(1);
    funding_tx_mut.vin[0].prevout = COutPoint{mature_coinbase_tx->GetHash(), 0};
    funding_tx_mut.vin[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);

    for (uint32_t i = 0; i < num_txs; ++i) {
        CAmount value = mature_coinbase_tx->vout[0].nValue / num_txs;
        funding_tx_mut.vout.emplace_back(
            value / 2, // Use half the input value as fee
            P2WSH_OP_TRUE);
    }

    auto funding_tx = MakeTransactionRef(std::move(funding_tx_mut));
    std::vector<CTransactionRef> exported_txs = {funding_tx};

    for (uint32_t i = 0; i < num_txs; ++i) {
        CMutableTransaction tx_mut;
        tx_mut.version = 2;
        tx_mut.vin.resize(1);
        tx_mut.vin[0].prevout = COutPoint{funding_tx->GetHash(), i};
        tx_mut.vin[0].scriptWitness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
        tx_mut.vout.emplace_back(
            funding_tx->vout[i].nValue / 2, // Use half the input value as fee
            P2WSH_OP_TRUE);

        exported_txs.push_back(MakeTransactionRef(tx_mut));
    }

    return exported_txs;
}

} // namespace

FUZZ_TARGET(compact_block_state)
{
    SeedRandomForTest(SeedRand::ZEROS);

    TestChain100Setup test_setup{
        ChainType::REGTEST,
        TestOpts{
            .extra_args = {
                "-nodebuglogfile",
                "-capturemessages=1",
            },
            .op_true_coinbases = true,
        }};

    LOCK(NetEventsInterface::g_msgproc_mutex);

    ConnmanTestMsg& connman = static_cast<ConnmanTestMsg&>(*test_setup.m_node.connman);
    // Make sure connections are cleanup up whenever we return from the harness.
    ConnectionEnder connection_ender{connman};

    auto& chainman = static_cast<TestChainstateManager&>(*test_setup.m_node.chainman);
    // Set mocktime to the tip time (needed satisfy PeerManager::CanDirectFetch()).
    auto* tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());
    SetMockTime(tip->nTime);
    assert(!chainman.IsInitialBlockDownload());

    auto& peerman = *test_setup.m_node.peerman;
    test_setup.m_node.validation_signals->RegisterValidationInterface(&peerman);

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    std::map<NodeId, size_t> connections_id_map;
    std::vector<std::reference_wrapper<CNode>> connections;
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 8)
    {
        auto connection = ConsumeCompactBlockConnection(
            fuzzed_data_provider, connman, peerman, _count, tip->GetBlockHash());
        if (!connection) return;

        connections.push_back(*connection);
        connections_id_map.emplace(connection->GetId(), connections.size() - 1);
    }
    if (connections.empty()) return;

    DebugLog("New testcase\n");
    if (std::getenv("DEBUG")) LogInstance().m_print_to_console = true;

    std::map<NodeId, std::unique_ptr<CompactBlockStateMachine>> state_machines;

    // Create a chain that forks off somewhere on the current main chain and
    // create a `CompactBlockStateMachine` instance that attempts to relay that
    // chain through `connection`.
    auto create_new_state_machine = [&](CNode& connection, bool hb_mode) {
        // Length of the forked chain
        auto chain_length = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);
        // Number of blocks behind the tip to fork the chain from (it might "fork" from the tip)
        auto fork_depth = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, chain_length);

        CBlockHeader fork_point{};
        int tip_height{};
        {
            LOCK(cs_main);
            auto& chain = chainman.ActiveChain();
            fork_point = chain[chain.Height() - fork_depth]->GetBlockHeader();
            tip_height = chain.Height();
        }

        std::vector<CBlock> blocks_to_relay;
        for (size_t i = 0; i < chain_length; ++i) {
            int new_height = (tip_height - fork_depth) + i + 1;
            auto txs = PopulateMempool(
                test_setup, fuzzed_data_provider,
                /*height=*/new_height);

            CBlock new_block{fork_point};
            new_block.hashPrevBlock = fork_point.GetHash();
            new_block.nTime += 1;

            CMutableTransaction coinbase;
            coinbase.vin.resize(1);
            coinbase.vin[0].prevout.SetNull();
            coinbase.vout.resize(1);
            coinbase.vout[0].scriptPubKey = P2WSH_OP_TRUE;
            coinbase.vout[0].nValue = 1 * COIN;
            coinbase.vin[0].scriptSig = CScript() << new_height << OP_0;

            new_block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
            new_block.vtx.insert(new_block.vtx.begin(), txs.begin(), txs.end());

            new_block.hashMerkleRoot = BlockMerkleRoot(new_block);

            DebugLog("created height=%d %s: %s\n", new_height, new_block.GetHash().ToString().c_str(), new_block.ToString().c_str());
            blocks_to_relay.push_back(new_block);
            fork_point = new_block;
        }

        assert(!state_machines.contains(connection.GetId()));
        state_machines.emplace(
            connection.GetId(),
            std::make_unique<CompactBlockStateMachine>(
                fuzzed_data_provider, chainman, connection, blocks_to_relay,
                /*high_bandwidth_mode=*/hb_mode));
    };

    for (auto& connection : connections) {
        create_new_state_machine(connection, fuzzed_data_provider.ConsumeBool());
    }

    LIMITED_WHILE(!state_machines.empty(), 100)
    {
        // Let the fuzzer choose a state machine to step
        auto& pick = PickValue(fuzzed_data_provider, state_machines);
        NodeId connection_id = pick.first;
        auto& machine = pick.second;

        auto step_result = machine->Step(connman, peerman);
        if (!step_result) {
            // State machine has not reached a final state yet (i.e. disconnected
            // or finished relaying), so we continue.
            continue;
        }
        test_setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
        state_machines.erase(connection_id);

        if (step_result->disconnected) {
            // Connection was terminated (e.g. due to misbehavior), it would be
            // uninteresting to try and relay more blocks on it.
            continue;
        }

        if (WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash() != step_result->block_hash)) {
            // The attempt to relay the new chain was unsuccessful
            continue;
        }

        // The connection wasn't disconnected, create a new state machine for it
        assert(connections_id_map.contains(connection_id));
        create_new_state_machine(
            connections[connections_id_map[connection_id]],
            step_result->high_bandwidth_mode_requested);
    }

    // Make sure all machines step to the end
    for (auto& [id, machine] : state_machines) {
        machine->StepUntilEnd(connman, peerman);
    }

    test_setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
}
