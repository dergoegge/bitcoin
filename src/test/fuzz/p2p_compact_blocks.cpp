#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <kernel/chainparams.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <pow.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/snapshot_fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>

#include <validation.h>
#include <validationinterface.h>

#include <span.h>

static void p2p_compact_blocks(snapshot_fuzz::Fuzz& fuzz)
{
    TestingSetup testing_setup;

    ChainstateManager& chainman = *testing_setup.m_node.chainman;
    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(testing_setup.m_node.connman.get());
    PeerManager& peerman = *testing_setup.m_node.peerman;
    CTxMemPool& mempool = *testing_setup.m_node.mempool;

    auto SendMessage = [&](CNode& connection, CSerializedNetMsg&& msg) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        connman.FlushSendBuffer(connection);
        (void)connman.ReceiveMsgFrom(connection, std::move(msg));
        connection.fPauseSend = false;
        try {
            connman.ProcessMessagesOnce(connection);
        } catch (const std::ios_base::failure&) {
        }
        peerman.SendMessages(&connection);
    };

    // Setup initial state

    RegisterValidationInterface(&peerman);

    SetMockTime(Params().GenesisBlock().nTime);

    std::set<COutPoint> mature_coins;

    bool ignored;
    chainman.ProcessNewBlock(
        /*block=*/std::make_shared<CBlock>(Params().GenesisBlock()),
        /*force_processing=*/true,
        /*min_pow_checked=*/true,
        /*new_block=*/&ignored);

    std::shared_ptr<CBlock> current_block;
    std::vector<CBlock> sent_compact_blocks;

    LOCK(NetEventsInterface::g_msgproc_mutex);

    NodeId id{0};
    std::vector<CNode*> connections;
    for (auto conn_type : {ConnectionType::OUTBOUND_FULL_RELAY,
                           ConnectionType::BLOCK_RELAY,
                           ConnectionType::INBOUND}) {
        CAddress addr{};
        connections.push_back(new CNode(id++, nullptr, addr, 0, 0, addr, "", conn_type, false));
        CNode& p2p_node = *connections.back();

        connman.Handshake(
            /*node=*/p2p_node,
            /*successfully_connected=*/true,
            /*remote_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
            /*local_services=*/ServiceFlags(NODE_NETWORK | NODE_WITNESS),
            /*version=*/PROTOCOL_VERSION,
            /*relay_txs=*/true);

        connman.AddTestNode(p2p_node);
    }

    fuzz.run([&](Span<const uint8_t> buffer) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

        // Create a new transaction that spends from `mature_coins`
        auto create_tx = [&]() -> CTransactionRef {
            auto tx_opt{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS)};
            return MakeTransactionRef(tx_opt.value_or(CMutableTransaction{}));
        };

        // Submit a transaction to the mempool through the p2p interface.
        //
        // This is done so that the mempool potentially contains transactions
        // that we will also sent in a compact block.
        auto send_tx = [&]() {
            auto tx = create_tx();
            if (!tx) return;

            bool with_witness{fuzzed_data_provider.ConsumeBool()};
            CSerializedNetMsg msg = NetMsg::Make(NetMsgType::TX, with_witness ? TX_WITH_WITNESS(*tx) : TX_NO_WITNESS(*tx));
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));
        };

        // Either pick a transaction from the mempool or create a new
        // transaction and add it to the current block.
        auto add_tx = [&]() {
            if (!current_block) return;

            if (fuzzed_data_provider.ConsumeBool() && mempool.size() > 0) {
                auto all_entries = mempool.infoAll();
                auto entry = PickValue(fuzzed_data_provider, all_entries);
                current_block->vtx.push_back(entry.tx);
                return;
            }

            auto non_mempool_tx = create_tx();
            if (!non_mempool_tx) return;
            current_block->vtx.push_back(non_mempool_tx);
        };

        // Send the current block as a compact block. If the block was accepted
        // to the block index, we will remember having sent the compact block
        // in `sent_compact_blocks`.
        auto send_compact_block = [&]() {
            if (!current_block || current_block->vtx.empty()) return;
            auto index_size = chainman.m_blockman.m_block_index.size();

            std::optional<uint32_t> nBits;
            if (fuzzed_data_provider.ConsumeBool()) nBits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
            CBlockHeaderAndShortTxIDs cmpct_block{*current_block};

            CSerializedNetMsg msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpct_block);
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));

            if (chainman.m_blockman.m_block_index.size() > index_size) {
                sent_compact_blocks.push_back(*current_block);
            }
        };

        // Sent a blocktxn message for the current block or one of the
        // previously sent compact blocks
        auto send_block_txn = [&]() {
            if (!current_block) return;

            BlockTransactions block_txn{};
            if (sent_compact_blocks.empty()) {
                block_txn.blockhash = current_block->GetHash();
                block_txn.txn = current_block->vtx;
            } else {
                auto& block = PickValue(fuzzed_data_provider, sent_compact_blocks);
                block_txn.blockhash = block.GetHash();
                block_txn.txn = fuzzed_data_provider.ConsumeBool() ? block.vtx : current_block->vtx;
            }

            CSerializedNetMsg msg = NetMsg::Make(NetMsgType::BLOCKTXN, block_txn);
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));
        };

        // Send just the header of the current block
        auto send_header = [&]() {
            if (!current_block) return;

            CBlockHeader header{*current_block};
            CSerializedNetMsg msg =
                NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(std::vector<CBlock>{header}));
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));
        };

        // Send the current block in full
        auto send_block = [&]() {
            if (!current_block) return;

            CSerializedNetMsg msg = NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(*current_block));
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));
        };

        // Send an inv for the current block
        auto send_inv = [&]() {
            if (!current_block) return;

            // Either as full or compact block
            CInv inv{fuzzed_data_provider.PickValueInArray({MSG_BLOCK, MSG_CMPCT_BLOCK}), current_block->GetHash()};

            CSerializedNetMsg msg = NetMsg::Make(NetMsgType::INV, std::vector<CInv>{inv});
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));
        };

        // Change the current block
        auto new_block = [&]() {
            auto base = PickValue(fuzzed_data_provider, chainman.m_blockman.m_block_index).second.GetBlockHash();
            CBlockHeader header;
            header.hashPrevBlock = base;
            header.nBits = fuzzed_data_provider.ConsumeIntegral<decltype(header.nBits)>();
            header.nTime = fuzzed_data_provider.ConsumeIntegral<decltype(header.nTime)>();
            header.nNonce = fuzzed_data_provider.ConsumeIntegral<decltype(header.nNonce)>();
            header.nVersion = fuzzed_data_provider.ConsumeIntegral<decltype(header.nVersion)>();
            header.hashMerkleRoot = ConsumeUInt256(fuzzed_data_provider);
            current_block = std::make_shared<CBlock>(header);
            current_block->vtx.push_back(create_tx());
        };

        // Bump mocktime by 1s-5h
        auto bump_mocktime = [&]() {
            std::chrono::seconds advance_by{
                fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 60 * 60 * 5)};
            SetMockTime(GetMockTime() + advance_by);
        };

        auto send_sendcmpct = [&]() {
            CSerializedNetMsg msg =
                NetMsg::Make(NetMsgType::SENDCMPCT,
                             fuzzed_data_provider.ConsumeBool(), // high,low bandwidth
                             uint64_t{2}                         // compact block relay version
                );
            SendMessage(*PickValue(fuzzed_data_provider, connections), std::move(msg));
        };

        // Repeatedly call the actions from above in fuzzer chosen order.
        LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100)
        {
            CallOneOf(fuzzed_data_provider,
                      add_tx,
                      new_block,
                      bump_mocktime,
                      send_tx,
                      send_compact_block,
                      send_block_txn,
                      send_block,
                      send_header,
                      send_sendcmpct,
                      send_inv);
        }

        // Validation interface callbacks might have been scheduled, sync at the end.
        SyncWithValidationInterfaceQueue();
    });

    UnregisterValidationInterface(&peerman);
    TestOnlyResetTimeData();
    connman.StopNodes();
}

SNAPSHOT_FUZZ_TARGET(p2p_compact_blocks)
