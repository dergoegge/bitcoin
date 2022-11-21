#ifndef BITCOIN_BLOCKREQUEST_IMPL_H
#define BITCOIN_BLOCKREQUEST_IMPL_H

#include <primitives/transaction.h>
#include <sync.h>
#include <uint256.h>

#include <chrono>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>


typedef int64_t NodeId;

class BlockTransactions;
class CBlock;
class CBlockHeaderAndShortTxIDs;
class CBlockIndex;
class CTxMemPool;
class PartiallyDownloadedBlock;

enum class BlockRequestResult;
enum class CompactBlockResult;
enum class BlockTxnResult;

namespace Consensus {
struct Params;
};

/** Blocks that are in flight, and that are in the queue to be downloaded. */
struct QueuedBlock {
    /** BlockIndex. We must have this since we only request blocks when we've already validated the header. */
    const CBlockIndex* index;
    /** Optional, used for CMPCTBLOCK downloads */
    std::unique_ptr<PartiallyDownloadedBlock> partial_block;
};

struct BlockSupplier {
    int num_blocks_in_flight{0};
    std::list<QueuedBlock> blocks_in_flight;

    std::optional<std::chrono::microseconds> stalling_since;
    std::optional<std::chrono::microseconds> downloading_since;
};

class BlockRequestTrackerImpl
{
private:
    const CTxMemPool& m_mempool;

    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>> m_blocks_in_flight;

    std::unordered_map<NodeId, BlockSupplier> m_block_suppliers;

    uint64_t m_peers_downloading_from{0};

    bool ForgetRequestInternal(const uint256& block_hash, std::chrono::microseconds now);

    BlockRequestResult Request(NodeId id, const CBlockIndex& index,
                               std::chrono::microseconds now,
                               bool via_compact_block);

public:
    BlockRequestTrackerImpl(const CTxMemPool& mempool) : m_mempool(mempool) {}

    BlockRequestResult Request(NodeId id, const CBlockIndex& index,
                               std::chrono::microseconds now);

    std::pair<CompactBlockResult, std::vector<uint16_t>>
    ReceiveCompactBlock(NodeId id, const CBlockIndex& index,
                        std::chrono::microseconds now,
                        const CBlockHeaderAndShortTxIDs& cmpctblock,
                        const std::vector<std::pair<uint256, CTransactionRef>>& extra_txs);

    std::pair<BlockTxnResult, std::unique_ptr<CBlock>>
    ReceiveBlockTxn(NodeId id, const BlockTransactions& block_txn);

    bool ForgetRequest(const uint256& block_hash, std::chrono::microseconds now);

    size_t GetNumBlocksInFlight() const;
    size_t GetNumBlocksInFlight(NodeId id) const;

    bool IsOnlyRequest(const uint256& block_hash) const;

    std::optional<NodeId> IsRequested(const uint256& block_hash,
                                      std::optional<NodeId> requested_by) const;

    bool MaybeMarkStaller(NodeId id, std::chrono::microseconds now);
    bool CheckPeerStallingTimeout(NodeId id, std::chrono::microseconds now) const;
    std::optional<uint256> CheckBlockDownloadTimeout(NodeId id,
                                                     const Consensus::Params& consensus_params,
                                                     std::chrono::microseconds now) const;

    std::vector<int> GetInFlightHeights(NodeId id) const;

    bool ForgetPeer(NodeId id);
};

#endif
