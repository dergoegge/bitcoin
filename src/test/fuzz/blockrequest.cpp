#include "chain.h"
#include "test/fuzz/FuzzedDataProvider.h"
#include <blockencodings.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <node/blockrequest.h>
#include <node/blockstorage.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <chrono>
#include <cstdint>

namespace {
constexpr uint8_t MAX_BLOCKS{16};
constexpr uint8_t MAX_PEERS{16};

struct MockBlock {
    CBlockIndex index;
    CBlock block;
};

std::array<MockBlock, MAX_BLOCKS> BLOCK_INDEX;
std::array<std::chrono::microseconds, 256> DELAYS;

struct Initializer {
    Initializer()
    {
        uint256 prev_hash;
        for (uint8_t block_height = 0; block_height < MAX_BLOCKS; ++block_height) {
            // TODO: filling the blocks with transaction could help with
            // covering more logic in BlockRequestTracker.
            CBlock block;
            block.hashPrevBlock = prev_hash;
            block.nTime = block_height;
            block.nBits = 1;
            block.vtx.push_back(std::make_shared<CTransaction>(CMutableTransaction()));

            MockBlock& mock_block{BLOCK_INDEX[block_height]};
            mock_block.index = CBlockIndex(block);
            mock_block.block = block;
            mock_block.index.nHeight = block_height;

            uint256* hash = new uint256(block.GetHash());
            mock_block.index.phashBlock = hash;
            prev_hash = *hash;
        }

        int i = 0;
        // DELAYS[N] for N=0..15 is just N microseconds.
        for (; i < 16; ++i) {
            DELAYS[i] = std::chrono::microseconds{i};
        }
        // DELAYS[N] for N=16..127 has randomly-looking but roughly exponentially increasing values up to
        // 198.416453 seconds.
        for (; i < 128; ++i) {
            int diff_bits = ((i - 10) * 2) / 9;
            uint64_t diff = 1 + (CSipHasher(0, 0).Write(i).Finalize() >> (64 - diff_bits));
            DELAYS[i] = DELAYS[i - 1] + std::chrono::microseconds{diff};
        }
        // DELAYS[N] for N=128..255 are negative delays with the same magnitude as N=0..127.
        for (; i < 256; ++i) {
            DELAYS[i] = -DELAYS[255 - i];
        }
    }
    ~Initializer()
    {
        for (uint8_t block_height = 0; block_height < MAX_BLOCKS; ++block_height) {
            delete BLOCK_INDEX[block_height].index.phashBlock;
        }
    }
} g_initializer;

enum Action : uint8_t {
    ADVANCE_TIME,
    REQUEST,
    REQUEST_VIA_COMPACT,
    HANDLE_COMPACT_BLOCK,
    HANDLE_BLOCKTXN,
    FORGET_REQUEST,
    MAYBE_MARK_STALLER,
    FORGET_PEER,
    CONST_FUNCS,
};

class Tester
{
public:
    BlockRequestTracker block_tracker;

    Tester(const CTxMemPool& pool) : block_tracker(pool) {}

    std::chrono::microseconds now{244466666};

    void AdvanceTime(std::chrono::microseconds delay)
    {
        now += delay;
    }

    // TODO: implement dumb version of the block request tracker and
    // differently fuzz against that.
};

const TestingSetup* g_setup;
} // namespace

void initialize_blockrequest()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}


FUZZ_TARGET_INIT(blockrequest, initialize_blockrequest)
{
    Tester tester{*g_setup->m_node.mempool};

    // Decode the input as a sequence of instructions with parameters
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    while (fuzzed_data_provider.remaining_bytes()) {
        Action cmd{static_cast<Action>(fuzzed_data_provider.ConsumeIntegralInRange((int)ADVANCE_TIME, (int)CONST_FUNCS))};

        switch (cmd) {
        case ADVANCE_TIME:
            tester.AdvanceTime(fuzzed_data_provider.PickValueInArray(DELAYS));
            break;
        case REQUEST:
        case REQUEST_VIA_COMPACT: {
            const CBlockIndex& index{BLOCK_INDEX.at(fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_BLOCKS - 1)).index};
            tester.block_tracker.Request(
                fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1), index,
                tester.now);
        } break;
        case HANDLE_COMPACT_BLOCK: {
            const MockBlock& mock_block{BLOCK_INDEX[fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_BLOCKS - 1)]};
            CBlockHeaderAndShortTxIDs cmpctblock(mock_block.block);
            const auto& [result, txindexes] = tester.block_tracker.ReceiveCompactBlock(
                fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1),
                mock_block.index,
                fuzzed_data_provider.PickValueInArray(DELAYS),
                cmpctblock, {});
            assert(result == CompactBlockResult::SUCCESS || txindexes.empty());
        } break;
        case HANDLE_BLOCKTXN: {
            BlockTransactions blocktxn;
            blocktxn.blockhash = BLOCK_INDEX[fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_BLOCKS - 1)].index.GetBlockHash();
            const auto& [result, block] = tester.block_tracker.ReceiveBlockTxn(
                fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1), blocktxn);
            assert(result == BlockTxnResult::SUCCESS || block == nullptr);
        } break;
        case FORGET_REQUEST:
            tester.block_tracker.ForgetRequest(
                BLOCK_INDEX[fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_BLOCKS - 1)].index.GetBlockHash(), tester.now);
            break;
        case MAYBE_MARK_STALLER:
            tester.block_tracker.MaybeMarkStaller(
                fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1), tester.now);
            break;
        case FORGET_PEER:
            tester.block_tracker.ForgetPeer(fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1));
            break;

        case CONST_FUNCS: {
            NodeId peer{fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1)};
            const CBlockIndex& index{BLOCK_INDEX[fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_BLOCKS - 1)].index};
            ChainstateManager& chainman{*Assert(g_setup->m_node.chainman)};
            tester.block_tracker.CheckBlockDownloadTimeout(peer, chainman.GetParams().GetConsensus(), tester.now);
            tester.block_tracker.GetInFlightHeights(peer);
            tester.block_tracker.GetNumBlocksInFlight();
            tester.block_tracker.GetNumBlocksInFlight(peer);
            tester.block_tracker.IsOnlyRequest(index.GetBlockHash());
            tester.block_tracker.IsRequested(index.GetBlockHash());
            tester.block_tracker.IsRequested(index.GetBlockHash(), peer);
            tester.block_tracker.CheckPeerStallingTimeout(peer, tester.now);
        } break;
        }
    }
}
