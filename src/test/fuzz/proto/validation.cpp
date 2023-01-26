#include <src/libfuzzer/libfuzzer_macro.h>
#include <test/fuzz/proto/validation.pb.h>

#include <consensus/merkle.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
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

CTransactionRef ConvertTransaction(const validation_proto_fuzz::Transaction& proto_tx)
{
    CMutableTransaction mtx;
    mtx.nLockTime = proto_tx.lock_time();
    mtx.nVersion = proto_tx.version();

    for (const auto& proto_input : proto_tx.inputs()) {
        CTxIn input;
        input.nSequence = proto_input.sequence();
        // scriptWitness
        for (const auto& witness : proto_input.witness_stack()) {
            input.scriptWitness.stack.push_back({witness.begin(), witness.end()});
        }
        // scriptSig
        std::vector<uint8_t> script{proto_input.script_sig().raw().begin(),
                                    proto_input.script_sig().raw().end()};
        input.scriptSig = {script.begin(), script.end()};
        // prevout
        auto hex = proto_input.prev_out().txid();
        hex.resize(64);
        input.prevout.hash = uint256S(hex);
        input.prevout.n = proto_input.prev_out().n();

        mtx.vin.emplace_back(std::move(input));
    }

    for (const auto& proto_output : proto_tx.outputs()) {
        CTxOut output;
        output.nValue = proto_output.value();
        std::vector<uint8_t> script{proto_output.script_pub_key().raw().begin(),
                                    proto_output.script_pub_key().raw().end()};
        output.scriptPubKey = {script.begin(), script.end()};
        mtx.vout.emplace_back(std::move(output));
    }

    return MakeTransactionRef(mtx);
}

CBlockHeader ConvertHeader(const validation_proto_fuzz::BlockHeader& proto_header)
{
    CBlockHeader header;
    header.nVersion = proto_header.version();
    auto hex = proto_header.hash_prev_block();
    hex.resize(64);
    header.hashPrevBlock = uint256S(hex);
    hex = proto_header.merkle_root();
    hex.resize(64);
    header.hashMerkleRoot = uint256S(hex);
    header.nTime = proto_header.time();
    header.nBits = proto_header.bits();
    header.nNonce = proto_header.nonce();
    return header;
}

std::shared_ptr<CBlock> ConvertBlock(const validation_proto_fuzz::Block& block)
{
    auto block_ref = std::make_shared<CBlock>(ConvertHeader(block.header()));
    for (auto tx : block.transactions()) {
        block_ref->vtx.push_back(ConvertTransaction(tx));
    }
    return block_ref;
}

int64_t ClampTime(int64_t time)
{
    static const int64_t time_min{946684801};  // 2000-01-01T00:00:01Z
    static const int64_t time_max{4133980799}; // 2100-12-31T23:59:59Z
    return std::min(time_max,
                    std::max(time, time_min));
}

template <class Proto>
using PostProcessor =
    protobuf_mutator::libfuzzer::PostProcessorRegistration<Proto>;

static PostProcessor<validation_proto_fuzz::ValidationAction> clamp_action_mock_time = {
    [](validation_proto_fuzz::ValidationAction* message, unsigned int seed) {
        // Make sure the atmp mock time lies between a sensible minimum and maximum.
        if (message->has_mock_time()) {
            message->set_mock_time(ClampTime(message->mock_time()));
        }
    }};

static PostProcessor<validation_proto_fuzz::Transaction> set_txid = {
    [](validation_proto_fuzz::Transaction* message, unsigned int seed) {
        auto tx = ConvertTransaction(*message);
        message->set_txid(tx->GetHash().ToString());
        // TODO sometimes create coinbases, the fuzzer struggles with the commitment
    }};

static PostProcessor<validation_proto_fuzz::Block> block_hash_and_merkle = {
    [](validation_proto_fuzz::Block* message, unsigned int seed) {
        auto block = ConvertBlock(*message);
        auto mut_header = message->mutable_header();
        mut_header->set_hash(block->GetHash().ToString());
        mut_header->set_merkle_root(BlockMerkleRoot(*block).ToString());

        if (mut_header->hash_prev_block().size() != 64) {
            auto& genesis{Params().GenesisBlock()};
            mut_header->set_hash_prev_block(genesis.GetHash().ToString());

            mut_header->set_bits(genesis.nBits);
            mut_header->set_nonce(genesis.nNonce);
            mut_header->set_version(genesis.nVersion);
            mut_header->set_time(genesis.nTime + 1);
        }

        int max_tries{1000};
        while (!CheckProofOfWork(block->GetHash(), block->nBits, g_setup->m_node.chainman->GetConsensus()) && max_tries-- > 0) {
            ++block->nNonce;
        }

        mut_header->set_nonce(block->nNonce);
    }};

DEFINE_PROTO_FUZZER(const validation_proto_fuzz::FuzzValidation& fuzz_validation)
{
    SetMockTime(ClampTime(0));

    CTxMemPool tx_pool{CTxMemPool::Options{}};
    const CChainParams& params{Params()};
    ChainstateManager chainman{ChainstateManager::Options{
        .chainparams = params,
        .adjusted_time_callback = GetAdjustedTime,
    }};

    auto cache_sizes = node::CalculateCacheSizes(g_setup->m_args);
    chainman.m_blockman.m_block_tree_db = std::make_unique<CBlockTreeDB>(cache_sizes.block_tree_db, true);

    node::ChainstateLoadOptions options;
    options.mempool = &tx_pool;
    options.block_tree_db_in_memory = true;
    options.coins_db_in_memory = true;
    options.reindex = node::fReindex;
    options.reindex_chainstate = false;
    options.prune = node::fPruneMode;
    options.check_blocks = DEFAULT_CHECKBLOCKS;
    options.check_level = DEFAULT_CHECKLEVEL;
    auto [status, error] = LoadChainstate(chainman, cache_sizes, options);
    assert(status == node::ChainstateLoadStatus::SUCCESS);

    BlockValidationState state;
    assert(chainman.ActiveChainstate().ActivateBestChain(state));

    for (auto action : fuzz_validation.actions()) {
        if (action.has_mock_time()) {
            SetMockTime(action.mock_time());
        }

        if (action.has_process_new_block()) {
            bool new_block{false};
            (void)chainman.ProcessNewBlock(
                /*block=*/ConvertBlock(action.process_new_block().block()),
                /*force_processing=*/action.process_new_block().force(),
                /*min_pow_checked=*/action.process_new_block().min_pow_checked(),
                /*new_block=*/&new_block);
        } else if (action.has_process_new_headers()) {
            std::vector<CBlockHeader> headers;
            for (auto header : action.process_new_headers().headers()) {
                headers.push_back(ConvertHeader(header));
            }

            BlockValidationState state;
            (void)chainman.ProcessNewBlockHeaders(
                /*block=*/headers,
                /*min_pow_checked=*/action.process_new_headers().min_pow_checked(),
                /*state=*/state);
        } else if (action.has_process_transaction()) {
            LOCK(cs_main);
            (void)chainman.ProcessTransaction(
                /*tx=*/ConvertTransaction(action.process_transaction()),
                /*test_accept=*/false);
        }
    }

    assert(chainman.ActiveChain().Height() == 0);

    chainman.ActiveChainstate().CheckBlockIndex();
}
