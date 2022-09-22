#ifndef BITCOIN_BLOCKREQUEST_H
#define BITCOIN_BLOCKREQUEST_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <chrono>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

typedef int64_t NodeId;

class CBlock;
class BlockTransactions;
class CBlockIndex;
class CBlockHeaderAndShortTxIDs;
class BlockRequestTrackerImpl;
class CTxMemPool;

namespace Consensus {
struct Params;
};

/** Result enum for compact block processing by the block request module. */
enum class BlockRequestResult {
    SUCCESS,
    ALREADY_REQUESTED,
    ALREADY_REQUESTED_VIA_COMPACT,
};

/** Result enum for compact block processing by the block request module. */
enum class CompactBlockResult {
    //! Compact block was successfully processed and the block is now marked as
    //! requested via compact block.
    SUCCESS,
    //! Block was already marked as requested.
    ALREADY_REQUESTED,
    //! Compact block
    MISBEHAVING,
    //!
    SHORT_ID_COLLISION,
};

enum class BlockTxnResult {
    SUCCESS,
    NOT_REQUESTED,
    MISBEHAVING,
    SHORT_ID_COLLISION,
};

class BlockRequestTracker
{
private:
    std::unique_ptr<BlockRequestTrackerImpl> m_impl;

public:
    BlockRequestTracker(const CTxMemPool& mempool);
    ~BlockRequestTracker();

    BlockRequestResult Request(NodeId id, const CBlockIndex& index, std::chrono::microseconds now);

    std::pair<CompactBlockResult, std::vector<uint16_t>>
    ReceiveCompactBlock(NodeId id, const CBlockIndex& index,
                        std::chrono::microseconds now,
                        const CBlockHeaderAndShortTxIDs& cmpctblock,
                        const std::vector<std::pair<uint256, CTransactionRef>>& extra_txs);

    std::pair<BlockTxnResult, std::unique_ptr<CBlock>>
    ReceiveBlockTxn(NodeId id, const BlockTransactions& block_txn);

    void ForgetRequest(const uint256& block_hash, std::chrono::microseconds now);

    size_t GetNumBlocksInFlight() const;
    size_t GetNumBlocksInFlight(NodeId id) const;

    bool IsOnlyRequest(const uint256& block_hash) const;

    std::optional<NodeId> IsRequested(const uint256& block_hash,
                                      std::optional<NodeId> requested_by = std::nullopt) const;

    bool MaybeMarkStaller(NodeId id, std::chrono::microseconds now);
    bool CheckPeerStallingTimeout(NodeId id, std::chrono::microseconds now) const;
    std::optional<uint256> CheckBlockDownloadTimeout(NodeId id,
                                                     const Consensus::Params& consensus_params,
                                                     std::chrono::microseconds now) const;

    std::vector<int> GetInFlightHeights(NodeId id) const;

    void ForgetPeer(NodeId id);
};

#endif
