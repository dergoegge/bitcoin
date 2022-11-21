#include <blockencodings.h>
#include <chain.h>
#include <consensus/params.h>
#include <logging.h>
#include <node/blockrequest.h>
#include <node/blockrequest_impl.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>

/** Time during which a peer must stall block download progress before being disconnected. */
static constexpr auto BLOCK_STALLING_TIMEOUT{2s};
/** Block download timeout base, expressed in multiples of the block interval (i.e. 10 min) */
static constexpr double BLOCK_DOWNLOAD_TIMEOUT_BASE = 1;
/** Additional block download timeout per parallel downloading peer (i.e. 5 min) */
static constexpr double BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 0.5;

bool BlockRequestTrackerImpl::ForgetRequestInternal(const uint256& block_hash, std::chrono::microseconds now)
{
    auto it{m_blocks_in_flight.find(block_hash)};
    if (it == m_blocks_in_flight.end()) {
        // Block was not requested
        return false;
    }

    auto [node_id, list_it] = it->second;

    auto supplier_it{m_block_suppliers.find(node_id)};
    if (supplier_it == m_block_suppliers.end()) {
        return false;
    }
    BlockSupplier& supplier{supplier_it->second};

    if (supplier.blocks_in_flight.begin() == list_it) {
        // First block on the queue was received, update the start download time for the next one
        supplier.downloading_since = std::max(supplier.downloading_since.value_or(now), now);
    }
    supplier.blocks_in_flight.erase(list_it);

    supplier.num_blocks_in_flight--;
    if (supplier.num_blocks_in_flight == 0) {
        // Last validated block on the queue was received.
        --m_peers_downloading_from;
    }
    supplier.stalling_since = std::nullopt;

    m_blocks_in_flight.erase(it);

    return true;
}

BlockRequestResult BlockRequestTrackerImpl::Request(NodeId id, const CBlockIndex& index, std::chrono::microseconds now, bool via_compact_block)
{
    const uint256& hash{index.GetBlockHash()};

    // Short-circuit most stuff in case it is from the same node
    auto in_flight_it{m_blocks_in_flight.find(hash)};
    if (in_flight_it != m_blocks_in_flight.end() && in_flight_it->second.first == id) {
        if (via_compact_block) {
            QueuedBlock& queued_block{*in_flight_it->second.second};
            if (!queued_block.partial_block) {
                return BlockRequestResult::SUCCESS;
            } else {
                return BlockRequestResult::ALREADY_REQUESTED_VIA_COMPACT;
            }
        }

        return BlockRequestResult::ALREADY_REQUESTED;
    }

    // Make sure it's not listed somewhere already.
    ForgetRequestInternal(hash, now);

    BlockSupplier& supplier{m_block_suppliers.emplace(std::make_pair(id, BlockSupplier{})).first->second};

    QueuedBlock queued_block{
        .index = &index,
        .partial_block = nullptr,
    };
    auto it{supplier.blocks_in_flight.emplace(supplier.blocks_in_flight.end(), std::move(queued_block))};

    supplier.num_blocks_in_flight++;
    if (supplier.num_blocks_in_flight == 1) {
        // We're starting a block download (batch) from this peer.
        supplier.downloading_since = now;
        ++m_peers_downloading_from;
    }

    m_blocks_in_flight.insert(std::make_pair(hash, std::make_pair(id, it)));

    return BlockRequestResult::SUCCESS;
}

BlockRequestResult BlockRequestTrackerImpl::Request(NodeId id, const CBlockIndex& index, std::chrono::microseconds now)
{
    return Request(id, index, now, /*via_compact_block=*/false);
}

std::pair<CompactBlockResult, std::vector<uint16_t>>
BlockRequestTrackerImpl::ReceiveCompactBlock(NodeId id, const CBlockIndex& index,
                                             std::chrono::microseconds now,
                                             const CBlockHeaderAndShortTxIDs& cmpctblock,
                                             const std::vector<std::pair<uint256, CTransactionRef>>& extra_txs)
{
    auto request_result{Request(id, index, now, /*via_compact_block=*/true)};
    if (request_result != BlockRequestResult::SUCCESS) {
        return {CompactBlockResult::ALREADY_REQUESTED, {}};
    }

    const uint256 block_hash{cmpctblock.header.GetHash()};

    auto in_flight_it{m_blocks_in_flight.find(block_hash)};
    Assert(in_flight_it != m_blocks_in_flight.end());
    QueuedBlock& queued_block{*in_flight_it->second.second};

    queued_block.partial_block.reset(new PartiallyDownloadedBlock());
    switch (queued_block.partial_block->InitData(m_mempool, cmpctblock, extra_txs)) {
    case READ_STATUS_INVALID:
        return {CompactBlockResult::MISBEHAVING, {}};
    case READ_STATUS_FAILED:
        return {CompactBlockResult::SHORT_ID_COLLISION, {}};
    case READ_STATUS_CHECKBLOCK_FAILED:
    case READ_STATUS_OK:
        std::vector<uint16_t> tx_indexes;
        for (size_t i = 0; i < cmpctblock.BlockTxCount(); ++i) {
            if (!queued_block.partial_block->IsTxAvailable(i)) {
                tx_indexes.push_back(i);
            }
        }
        return {CompactBlockResult::SUCCESS, tx_indexes};
    }
}

std::pair<BlockTxnResult, std::unique_ptr<CBlock>> BlockRequestTrackerImpl::ReceiveBlockTxn(NodeId id, const BlockTransactions& block_txn)
{
    auto in_flight_it{m_blocks_in_flight.find(block_txn.blockhash)};
    if (in_flight_it == m_blocks_in_flight.end()) {
        return {BlockTxnResult::NOT_REQUESTED, nullptr};
    }

    auto& [node_id, queued_block] = in_flight_it->second;

    if (!queued_block->partial_block || node_id != id) {
        return {BlockTxnResult::NOT_REQUESTED, nullptr};
    }

    auto block{std::make_unique<CBlock>()};
    auto fillblock_result{queued_block->partial_block->FillBlock(*block, block_txn.txn)};
    queued_block->partial_block.reset(nullptr);
    switch (fillblock_result) {
    case READ_STATUS_INVALID:
        return {BlockTxnResult::MISBEHAVING, nullptr};
    case READ_STATUS_FAILED:
        return {BlockTxnResult::SHORT_ID_COLLISION, nullptr};
    case READ_STATUS_CHECKBLOCK_FAILED:
    case READ_STATUS_OK:
        // Block is either okay, or possibly we received
        // READ_STATUS_CHECKBLOCK_FAILED.
        // Note that CheckBlock can only fail for one of a few reasons:
        // 1. bad-proof-of-work (impossible here, because we've already
        //    accepted the header)
        // 2. merkleroot doesn't match the transactions given (already
        //    caught in FillBlock with READ_STATUS_FAILED, so
        //    impossible here)
        // 3. the block is otherwise invalid (eg invalid coinbase,
        //    block is too big, too many legacy sigops, etc).
        // So if CheckBlock failed, #3 is the only possibility.
        // Under BIP 152, we don't discourage the peer unless proof of work is
        // invalid (we don't require all the stateless checks to have
        // been run).  This is handled below, so just treat this as
        // though the block was successfully read, and rely on the
        // handling in ProcessNewBlock to ensure the block index is
        // updated, etc.
        return {BlockTxnResult::SUCCESS, std::move(block)};
    }
}

bool BlockRequestTrackerImpl::ForgetRequest(const uint256& block_hash, std::chrono::microseconds now)
{
    return ForgetRequestInternal(block_hash, now);
}

size_t BlockRequestTrackerImpl::GetNumBlocksInFlight() const
{
    return m_blocks_in_flight.size();
}

size_t BlockRequestTrackerImpl::GetNumBlocksInFlight(NodeId id) const
{
    auto supplier_it{m_block_suppliers.find(id)};
    if (supplier_it == m_block_suppliers.end()) {
        return 0;
    }

    const BlockSupplier& supplier{supplier_it->second};
    return supplier.blocks_in_flight.size();
}

bool BlockRequestTrackerImpl::IsOnlyRequest(const uint256& block_hash) const
{
    return m_blocks_in_flight.count(block_hash) == m_blocks_in_flight.size();
}

std::optional<NodeId> BlockRequestTrackerImpl::IsRequested(const uint256& block_hash, std::optional<NodeId> requested_by) const
{
    auto it{m_blocks_in_flight.find(block_hash)};
    if (it == m_blocks_in_flight.end()) {
        // Block was not requested
        return {};
    }

    auto [node_id, _] = it->second;
    if (requested_by.has_value() && requested_by != node_id) {
        return {};
    }

    return node_id;
}

bool BlockRequestTrackerImpl::MaybeMarkStaller(NodeId id, std::chrono::microseconds now)
{
    auto supplier_it{m_block_suppliers.find(id)};
    if (supplier_it == m_block_suppliers.end()) {
        return false;
    }

    BlockSupplier& supplier{supplier_it->second};
    if (!supplier.stalling_since) {
        supplier.stalling_since = now;
        return true;
    }

    return false;
}

bool BlockRequestTrackerImpl::CheckPeerStallingTimeout(NodeId id, std::chrono::microseconds now) const
{
    auto supplier_it{m_block_suppliers.find(id)};
    if (supplier_it == m_block_suppliers.end()) {
        return false;
    }

    const BlockSupplier& supplier{supplier_it->second};

    return supplier.stalling_since.has_value() &&
           supplier.stalling_since < now - BLOCK_STALLING_TIMEOUT;
}

std::optional<uint256> BlockRequestTrackerImpl::CheckBlockDownloadTimeout(NodeId id, const Consensus::Params& consensus_params, std::chrono::microseconds now) const
{
    auto supplier_it{m_block_suppliers.find(id)};
    if (supplier_it == m_block_suppliers.end()) {
        return {};
    }

    const BlockSupplier& supplier{supplier_it->second};
    if (supplier.blocks_in_flight.size() == 0) {
        return {};
    }

    assert(m_peers_downloading_from > 0);
    int other_peers_with_validated_downloads = m_peers_downloading_from - 1;
    auto timeout{std::chrono::seconds{consensus_params.nPowTargetSpacing} *
                 (BLOCK_DOWNLOAD_TIMEOUT_BASE +
                  BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * other_peers_with_validated_downloads)};

    if (now > Assume(supplier.downloading_since).value() + timeout) {
        const auto& queued_block{supplier.blocks_in_flight.front()};
        return queued_block.index->GetBlockHash();
    }

    return {};
}

std::vector<int> BlockRequestTrackerImpl::GetInFlightHeights(NodeId id) const
{
    auto supplier_it{m_block_suppliers.find(id)};
    if (supplier_it == m_block_suppliers.end()) {
        return {};
    }

    std::vector<int> heights;
    for (const QueuedBlock& queued_block : supplier_it->second.blocks_in_flight) {
        heights.push_back(Assert(queued_block.index)->nHeight);
    }

    return heights;
}

bool BlockRequestTrackerImpl::ForgetPeer(NodeId id)
{
    auto supplier_it{m_block_suppliers.find(id)};
    if (supplier_it == m_block_suppliers.end()) {
        return false;
    }

    for (auto& queued_block : supplier_it->second.blocks_in_flight) {
        m_blocks_in_flight.erase(queued_block.index->GetBlockHash());
    }

    m_block_suppliers.erase(supplier_it);

    return true;
}

BlockRequestTracker::BlockRequestTracker(const CTxMemPool& mempool) : m_impl{std::make_unique<BlockRequestTrackerImpl>(mempool)} {}
BlockRequestTracker::~BlockRequestTracker() {}

BlockRequestResult BlockRequestTracker::Request(NodeId id, const CBlockIndex& index, std::chrono::microseconds now)
{
    return m_impl->Request(id, index, now);
}

std::pair<CompactBlockResult, std::vector<uint16_t>>
BlockRequestTracker::ReceiveCompactBlock(NodeId id, const CBlockIndex& index,
                                         std::chrono::microseconds now,
                                         const CBlockHeaderAndShortTxIDs& cmpctblock,
                                         const std::vector<std::pair<uint256, CTransactionRef>>& extra_txs)
{
    return m_impl->ReceiveCompactBlock(id, index, now, cmpctblock, extra_txs);
}

std::pair<BlockTxnResult, std::unique_ptr<CBlock>>
BlockRequestTracker::ReceiveBlockTxn(NodeId id, const BlockTransactions& block_txn)
{
    return m_impl->ReceiveBlockTxn(id, block_txn);
}

bool BlockRequestTracker::ForgetRequest(const uint256& block_hash, std::chrono::microseconds now)
{
    return m_impl->ForgetRequest(block_hash, now);
}

size_t BlockRequestTracker::GetNumBlocksInFlight() const
{
    return m_impl->GetNumBlocksInFlight();
}

size_t BlockRequestTracker::GetNumBlocksInFlight(NodeId id) const
{
    return m_impl->GetNumBlocksInFlight(id);
}

bool BlockRequestTracker::IsOnlyRequest(const uint256& block_hash) const
{
    return m_impl->IsOnlyRequest(block_hash);
}

std::optional<NodeId> BlockRequestTracker::IsRequested(const uint256& block_hash,
                                                       std::optional<NodeId> id) const
{
    return m_impl->IsRequested(block_hash, id);
}

bool BlockRequestTracker::MaybeMarkStaller(NodeId id, std::chrono::microseconds now)
{
    return m_impl->MaybeMarkStaller(id, now);
}

bool BlockRequestTracker::CheckPeerStallingTimeout(NodeId id, std::chrono::microseconds now) const
{
    return m_impl->CheckPeerStallingTimeout(id, now);
}

std::optional<uint256> BlockRequestTracker::CheckBlockDownloadTimeout(NodeId id,
                                                                      const Consensus::Params& consensus_params,
                                                                      std::chrono::microseconds now) const
{
    return m_impl->CheckBlockDownloadTimeout(id, consensus_params, now);
}

std::vector<int> BlockRequestTracker::GetInFlightHeights(NodeId id) const
{
    return m_impl->GetInFlightHeights(id);
}

bool BlockRequestTracker::ForgetPeer(NodeId id)
{
    return m_impl->ForgetPeer(id);
}
