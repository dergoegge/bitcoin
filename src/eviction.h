// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVICTION_H
#define BITCOIN_EVICTION_H

#include <connection_types.h>
#include <netaddress.h>
#include <net_permissions.h>
#include <sync.h>

#include <chrono>
#include <cstdint>
#include <map>

typedef int64_t NodeId;

struct NodeEvictionCandidate
{
    NodeId id;
    std::chrono::seconds m_connected;
    std::chrono::microseconds m_min_ping_time;
    std::chrono::seconds m_last_block_time;
    std::chrono::seconds m_last_tx_time;
    bool fRelevantServices;
    bool m_relay_txs;
    bool fBloomFilter;
    uint64_t nKeyedNetGroup;
    bool prefer_evict;
    bool m_is_local;
    Network m_network;
    NetPermissionFlags m_flags;
    bool m_is_inbound;
    bool fSuccessfullyConnected;
    int nBlocksInFlight;
    int64_t m_last_block_announcement;
    bool m_slow_chain_protected;
    ConnectionType m_conn_type;
};

/**
 * Select an inbound peer to evict after filtering out (protecting) peers having
 * distinct, difficult-to-forge characteristics. The protection logic picks out
 * fixed numbers of desirable peers per various criteria, followed by (mostly)
 * ratios of desirable or disadvantaged peers. If any eviction candidates
 * remain, the selection logic chooses a peer to evict.
 */
[[nodiscard]] std::optional<NodeId> SelectIncomingNodeToEvict(std::vector<NodeEvictionCandidate>&& vEvictionCandidates);

/** Protect desirable or disadvantaged inbound peers from eviction by ratio.
 *
 * This function protects half of the peers which have been connected the
 * longest, to replicate the non-eviction implicit behavior and preclude attacks
 * that start later.
 *
 * Half of these protected spots (1/4 of the total) are reserved for the
 * following categories of peers, sorted by longest uptime, even if they're not
 * longest uptime overall:
 *
 * - onion peers connected via our tor control service
 *
 * - localhost peers, as manually configured hidden services not using
 *   `-bind=addr[:port]=onion` will not be detected as inbound onion connections
 *
 * - I2P peers
 *
 * - CJDNS peers
 *
 * This helps protect these privacy network peers, which tend to be otherwise
 * disadvantaged under our eviction criteria for their higher min ping times
 * relative to IPv4/IPv6 peers, and favorise the diversity of peer connections.
 */
void ProtectEvictionCandidatesByRatio(std::vector<NodeEvictionCandidate>& vEvictionCandidates);

class Evictor
{
    mutable Mutex m_candidates_mutex;
    std::map<NodeId, NodeEvictionCandidate> m_candidates GUARDED_BY(m_candidates_mutex);
    int m_max_outbound_block_relay;
    int m_max_outbound_full_relay;

public:

    Evictor(int max_outbound_block_relay, int max_outbound_full_relay) : m_max_outbound_block_relay(max_outbound_block_relay), m_max_outbound_full_relay(max_outbound_full_relay){}
    void AddCandidate(NodeEvictionCandidate candidate);
    bool RemoveCandidate(NodeId id);
    [[nodiscard]] std::optional<NodeId> SelectIncomingNodeToEvict() const;
    std::optional<NodeId> EvictExtraBlockOutboundPeers(std::chrono::seconds time_in_seconds);
    std::optional<NodeId> EvictExtraFullOutboundPeers(std::chrono::seconds time_in_seconds);

    /** A ping-pong round trip has completed successfully. Update minimum ping time. */
    void UpdateMinPingTime(NodeId id, std::chrono::microseconds ping_time);

    void UpdateLatestBlockTime(NodeId id, std::chrono::seconds time);

    void UpdateLatestTxTime(NodeId id, std::chrono::seconds time);

    void UpdateRelevantServices(NodeId id, bool relevant);

    void UpdateRelaysTxs(NodeId id, bool relay);

    void UpdateLoadedBloomFilter(NodeId id, bool loaded);

    void UpdateSuccessfullyConnected(NodeId id, bool connected);

    void UpdateBlocksInFlight(NodeId id, bool add);

    void UpdateLastBlockAnnouncementTime(NodeId id, int64_t time);

    void UpdateSlowChainProtected(NodeId id, bool is_protected);
};

#endif // BITCOIN_EVICTION_H
