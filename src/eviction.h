// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVICTION_H
#define BITCOIN_EVICTION_H

#include <connection_types.h>
#include <net_permissions.h>

#include <chrono>
#include <cstdint>

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

class EvictorImpl;

class Evictor
{
protected:
    const std::unique_ptr<EvictorImpl> m_impl;

public:
    explicit Evictor(int max_outbound_block_relay, int max_outbound_full_relay);
	~Evictor();

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
