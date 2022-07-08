// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_EVICTION_H
#define BITCOIN_NODE_EVICTION_H

#include <node/connection_types.h>
#include <net_permissions.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

typedef int64_t NodeId;

class EvictionManagerImpl;

class EvictionManager
{
private:
    const std::unique_ptr<EvictionManagerImpl> m_impl;

public:
    explicit EvictionManager();
    ~EvictionManager();

    void AddCandidate(NodeId id, std::chrono::seconds connected,
                      uint64_t keyed_net_group, bool prefer_evict,
                      bool is_local, Network network,
                      bool noban, ConnectionType conn_type);
    bool RemoveCandidate(NodeId id);

    /**
     * Select an inbound peer to evict after filtering out (protecting) peers having
     * distinct, difficult-to-forge characteristics. The protection logic picks out
     * fixed numbers of desirable peers per various criteria, followed by (mostly)
     * ratios of desirable or disadvantaged peers. If any eviction candidates
     * remain, the selection logic chooses a peer to evict.
     */
    [[nodiscard]] std::optional<NodeId> SelectNodeToEvict() const;

    /** A ping-pong round trip has completed successfully. Update minimum ping time. */
    void UpdateMinPingTime(NodeId id, std::chrono::microseconds ping_time);
    std::optional<std::chrono::microseconds> GetMinPingTime(NodeId id) const;

    /** A new valid block was received. Update the candidates last block time. */
    void UpdateLastBlockTime(NodeId id, std::chrono::seconds block_time);
    std::optional<std::chrono::seconds> GetLastBlockTime(NodeId id) const;

    /** A new valid transaction was received. Update the candidates last tx time. */
    void UpdateLastTxTime(NodeId id, std::chrono::seconds tx_time);
    std::optional<std::chrono::seconds> GetLastTxTime(NodeId id) const;

    /** Update the candidates relevant services flag. */
    void UpdateRelevantServices(NodeId id, bool has_relevant_flags);

    /** Update the candidates bloom filter loaded flag. */
    void UpdateLoadedBloomFilter(NodeId id, bool bloom_filter_loaded);

    /** Set the candidates tx relay status to true. */
    void UpdateRelayTxs(NodeId id);

    /** Update the candidates number of blocks in flight. */
    void AddBlockInFlight(NodeId id);
    void RemoveBlockInFlight(NodeId id);

    /** Update timestamp of last block announcement. */
    void UpdateLastBlockAnnounceTime(NodeId id, std::chrono::seconds last_block_announcement);
    std::optional<std::chrono::seconds> GetLastBlockAnnounceTime(NodeId id) const;
};


#endif // BITCOIN_NODE_EVICTION_H
