#include "chain.h"
#include <algorithm>
#include <blockencodings.h>
#include <consensus/merkle.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <node/blockrequest.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

#include <chrono>
#include <cstdint>
#include <variant>
#include <vector>

namespace {
constexpr uint8_t MAX_PEERS{16};

std::array<std::chrono::microseconds, 256> DELAYS;

struct Initializer {
    Initializer()
    {
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
} g_initializer;

class Tester
{
private:
    //! Block request module under test
    BlockRequestTracker m_blockrequest;

    //! Mock time for the test
    std::chrono::microseconds m_now{244466666};

    // NodeId -> (block hash -> requested via compact)
    std::map<NodeId, std::map<uint256, bool>> m_requests_by_peer;
    std::set<uint256> m_requests_by_hash;

    // Fake block index per target execution
    struct Block {
        CBlock block;
        CBlockIndex index;
    };
    std::list<Block> m_blocks;

    const Block& GetBlock(size_t index) const
    {
        assert(index < m_blocks.size());
        auto it{m_blocks.begin()};
        std::advance(it, index);
        return *it;
    }

    void TweakAndAcceptBlock(CBlock& block)
    {
        // Connect to m_blocks tip
        block.hashPrevBlock =
            m_blocks.size() > 0 ?
                m_blocks.back().block.GetHash() :
                uint256{};
        // Adjust merkle root
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Adjust PoW
        LIMITED_WHILE(!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()), 1000)
        {
            ++block.nNonce;
        }

        Block block_entry{.block = block, .index = CBlockIndex(block)};
        block_entry.index.phashBlock = new uint256{block.GetHash()};
        block_entry.index.nHeight = m_blocks.size();
        m_blocks.emplace_back(std::move(block_entry));
    }

    void MarkAsRequested(NodeId peer, const CBlockIndex& index,
                         bool via_compact_block)
    {
        if (auto it = m_requests_by_peer.find(peer); it != m_requests_by_peer.end()) {
            auto& hashes{it->second};
            assert(hashes.count(index.GetBlockHash()) == 0 ||
                   // Regular requests can be upgraded to be requested via a compact block
                   (hashes.at(index.GetBlockHash()) == false && via_compact_block));
            hashes.emplace(index.GetBlockHash(), via_compact_block);
        } else {
            std::map<uint256, bool> hashes;
            hashes.emplace(index.GetBlockHash(), via_compact_block);
            m_requests_by_peer.emplace(peer, std::move(hashes));
        }

        // Delete request by other peer
        for (auto& [id, hashes] : m_requests_by_peer) {
            if (id == peer) continue;
            if (hashes.erase(index.GetBlockHash()) > 0) break;
        }

        // Hash might already exist in m_requests_by_hash
        m_requests_by_hash.insert(index.GetBlockHash());
    }

    std::optional<NodeId> GetRequestingPeer(const uint256& hash)
    {
        // Find the peer that requested the block
        std::optional<NodeId> peer;
        for (auto& [peer_id, hashes] : m_requests_by_peer) {
            if (hashes.count(hash) > 0) {
                peer = peer_id;
                break;
            }
        }

        return peer;
    }

    /** Assert that a block is not requested via compact block by `peer`. */
    void AssertNotRequestedViaCompact(const uint256& hash, NodeId peer) const
    {
        if (auto it{m_requests_by_peer.find(peer)}; it != m_requests_by_peer.end()) {
            assert(it->second.count(hash) == 0 ||
                   it->second.at(hash) == false);
        }
        // TODO check the block request module
    }

    /** Assert that a block is not requested by any peer. */
    void AssertNotRequested(const uint256& hash) const
    {
        assert(!m_blockrequest.IsRequested(hash));
        assert(m_requests_by_hash.count(hash) == 0);

        // Block can only be requested by one peer
        for (auto& [peer_id, hashes] : m_requests_by_peer) {
            assert(hashes.count(hash) == 0);
        }
    }

    /** Assert that a block is requested by `peer`. */
    void AssertRequested(const uint256& hash, NodeId peer) const
    {
        assert(m_blockrequest.IsRequested(hash));
        assert(m_blockrequest.IsRequested(hash, /*requested_by=*/peer));
        assert(m_requests_by_hash.count(hash) > 0);
        assert(m_requests_by_peer.count(peer) > 0);
        assert(m_requests_by_peer.at(peer).count(hash) > 0);

        // Block can only be requested by one peer
        for (auto& [peer_id, hashes] : m_requests_by_peer) {
            if (peer != peer_id) {
                assert(hashes.count(hash) == 0);
            }
        }
    }

public:
    Tester(const CTxMemPool& pool) : m_blockrequest(pool) {}
    ~Tester()
    {
        for (Block& block : m_blocks) {
            delete block.index.phashBlock;
        }
    }

    int NumBlocks() const
    {
        return m_blocks.size();
    }

    void AdvanceTime(std::chrono::microseconds delay)
    {
        m_now += delay;
    }

    void Request(NodeId peer, int block_index)
    {
        const CBlockIndex& index{GetBlock(block_index).index};
        auto result{m_blockrequest.Request(peer, index, m_now)};
        switch (result) {
        case BlockRequestResult::ALREADY_REQUESTED_VIA_COMPACT: [[fallthrough]];
        case BlockRequestResult::ALREADY_REQUESTED:
            assert(m_requests_by_hash.count(index.GetBlockHash()) > 0);
            break;
        case BlockRequestResult::SUCCESS:
            MarkAsRequested(peer, index, /*via_compact_block=*/false);
            break;
        }
    }

    void ReceiveCompactBlock(NodeId peer, std::variant<CBlock, int> new_block_or_index)
    {
        const Block* block{nullptr};
        if (std::holds_alternative<CBlock>(new_block_or_index)) {
            TweakAndAcceptBlock(std::get<CBlock>(new_block_or_index));
            block = &m_blocks.back();
        } else if (std::holds_alternative<int>(new_block_or_index)) {
            block = &GetBlock(std::get<int>(new_block_or_index));
        }
        assert(block);

        CBlockHeaderAndShortTxIDs cmpctblock(block->block);

        const auto& [result, txindexes] = m_blockrequest.ReceiveCompactBlock(
            peer, block->index, m_now, cmpctblock, {});
        assert(result == CompactBlockResult::SUCCESS || txindexes.empty());

        switch (result) {
        case CompactBlockResult::MISBEHAVING: [[fallthrough]];
        case CompactBlockResult::SHORT_ID_COLLISION: [[fallthrough]];
        case CompactBlockResult::SUCCESS:
            MarkAsRequested(peer, block->index, /*via_compact_block=*/true);
            break;
        case CompactBlockResult::ALREADY_REQUESTED:
            assert(m_requests_by_hash.count(block->index.GetBlockHash()) > 0);
            break;
        }
    }

    void ReceiveBlockTxn(NodeId peer, int block_index)
    {
        const Block& block_entry{GetBlock(block_index)};
        BlockTransactions blocktxn;
        blocktxn.blockhash = block_entry.index.GetBlockHash();
        blocktxn.txn = block_entry.block.vtx;
        // TODO dont always send all txs
        std::copy(block_entry.block.vtx.begin() + 1,
                  block_entry.block.vtx.end(),
                  std::back_inserter(blocktxn.txn));

        const auto& [result, block] = m_blockrequest.ReceiveBlockTxn(peer, blocktxn);
        assert(result == BlockTxnResult::SUCCESS || block == nullptr);

        switch (result) {
        case BlockTxnResult::MISBEHAVING:
            m_requests_by_peer.at(peer)[block_entry.index.GetBlockHash()] = false;
            break;
        case BlockTxnResult::SHORT_ID_COLLISION:
            m_requests_by_peer.at(peer)[block_entry.index.GetBlockHash()] = false;
            break;
        case BlockTxnResult::NOT_REQUESTED:
            AssertNotRequestedViaCompact(block_entry.index.GetBlockHash(), peer);
            break;
        case BlockTxnResult::SUCCESS:
            AssertRequested(block_entry.index.GetBlockHash(), peer);
            assert(block);
            m_requests_by_peer.at(peer)[block_entry.index.GetBlockHash()] = false;
            break;
        }
    }

    void ForgetRequest(int block_index)
    {
        const CBlockIndex& index{GetBlock(block_index).index};

        if (auto peer = GetRequestingPeer(index.GetBlockHash()); peer) {
            AssertRequested(index.GetBlockHash(), *peer);

            m_requests_by_peer.at(*peer).erase(index.GetBlockHash());
        } else {
            AssertNotRequested(index.GetBlockHash());
        }

        bool forgot{m_blockrequest.ForgetRequest(
            index.GetBlockHash(), m_now)};
        auto num_removed{m_requests_by_hash.erase(index.GetBlockHash())};

        assert((forgot && num_removed > 0) ||
               (!forgot && num_removed == 0));

        AssertNotRequested(index.GetBlockHash());
    }

    void MaybeMarkStaller(NodeId peer)
    {
        m_blockrequest.MaybeMarkStaller(peer, m_now);
    }

    void ForgetPeer(NodeId peer)
    {
        std::map<uint256, bool> hashes;
        if (auto it = m_requests_by_peer.find(peer); it != m_requests_by_peer.end()) {
            hashes = it->second;
        }

        for (const auto& [hash, via_compact] : hashes) {
            AssertRequested(hash, peer);
            auto erased{m_requests_by_hash.erase(hash)};
            assert(erased > 0);
        }

        auto num_removed{m_requests_by_peer.erase(peer)};
        bool forgot{m_blockrequest.ForgetPeer(peer)};
        assert((forgot && num_removed == 1) ||
               (!forgot && num_removed == 0));

        for (const auto& [hash, via_compact] : hashes) {
            AssertNotRequested(hash);
        }
    }

    void Check()
    {
    }
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
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    Tester tester{*g_setup->m_node.mempool};

    while (fuzzed_data_provider.remaining_bytes()) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                tester.AdvanceTime(fuzzed_data_provider.PickValueInArray(DELAYS));
            },
            [&] {
                if (tester.NumBlocks() == 0) return;
                tester.Request(fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1),
                               fuzzed_data_provider.ConsumeIntegralInRange(0, tester.NumBlocks() - 1));
            },
            [&] {
                std::variant<CBlock, int> block_or_index;
                bool deser_block{fuzzed_data_provider.ConsumeBool()};
                if (deser_block || tester.NumBlocks() == 0) {
                    auto block{ConsumeDeserializable<CBlock>(fuzzed_data_provider)};
                    if (!block || block->vtx.size() == 0) {
                        return;
                    }

                    block_or_index = *block;
                } else {
                    assert(tester.NumBlocks() > 0);
                    block_or_index =
                        fuzzed_data_provider.ConsumeIntegralInRange(0, tester.NumBlocks() - 1);
                }

                tester.ReceiveCompactBlock(
                    fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1),
                    block_or_index);
            },
            [&] {
                if (tester.NumBlocks() == 0) return;
                tester.ReceiveBlockTxn(
                    fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1),
                    fuzzed_data_provider.ConsumeIntegralInRange(0, tester.NumBlocks() - 1));
            },
            [&] {
                if (tester.NumBlocks() == 0) return;
                tester.ForgetRequest(
                    fuzzed_data_provider.ConsumeIntegralInRange(0, tester.NumBlocks() - 1));
            },
            [&] {
                tester.MaybeMarkStaller(
                    fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1));
            },
            [&] {
                tester.ForgetPeer(fuzzed_data_provider.ConsumeIntegralInRange(0, MAX_PEERS - 1));
            });
    }

    tester.Check();
}
