// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <eviction.h>
#include <logging.h>
#include <util/time.h>

/** Minimum time an outbound-peer-eviction candidate must be connected for, in order to evict, in seconds */
static constexpr std::chrono::seconds MINIMUM_CONNECT_TIME{30};

static bool ReverseCompareNodeMinPingTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    return a.m_min_ping_time > b.m_min_ping_time;
}

static bool ReverseCompareNodeTimeConnected(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    return a.m_connected > b.m_connected;
}

static bool CompareNetGroupKeyed(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b) {
    return a.nKeyedNetGroup < b.nKeyedNetGroup;
}

static bool CompareNodeBlockTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    // There is a fall-through here because it is common for a node to have many peers which have not yet relayed a block.
    if (a.m_last_block_time != b.m_last_block_time) return a.m_last_block_time < b.m_last_block_time;
    if (a.fRelevantServices != b.fRelevantServices) return b.fRelevantServices;
    return a.m_connected > b.m_connected;
}

static bool CompareNodeTXTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    // There is a fall-through here because it is common for a node to have more than a few peers that have not yet relayed txn.
    if (a.m_last_tx_time != b.m_last_tx_time) return a.m_last_tx_time < b.m_last_tx_time;
    if (a.m_relay_txs != b.m_relay_txs) return b.m_relay_txs;
    if (a.fBloomFilter != b.fBloomFilter) return a.fBloomFilter;
    return a.m_connected > b.m_connected;
}

// Pick out the potential block-relay only peers, and sort them by last block time.
static bool CompareNodeBlockRelayOnlyTime(const NodeEvictionCandidate &a, const NodeEvictionCandidate &b)
{
    if (a.m_relay_txs != b.m_relay_txs) return a.m_relay_txs;
    if (a.m_last_block_time != b.m_last_block_time) return a.m_last_block_time < b.m_last_block_time;
    if (a.fRelevantServices != b.fRelevantServices) return b.fRelevantServices;
    return a.m_connected > b.m_connected;
}

/**
 * Sort eviction candidates by network/localhost and connection uptime.
 * Candidates near the beginning are more likely to be evicted, and those
 * near the end are more likely to be protected, e.g. less likely to be evicted.
 * - First, nodes that are not `is_local` and that do not belong to `network`,
 *   sorted by increasing uptime (from most recently connected to connected longer).
 * - Then, nodes that are `is_local` or belong to `network`, sorted by increasing uptime.
 */
struct CompareNodeNetworkTime {
    const bool m_is_local;
    const Network m_network;
    CompareNodeNetworkTime(bool is_local, Network network) : m_is_local(is_local), m_network(network) {}
    bool operator()(const NodeEvictionCandidate& a, const NodeEvictionCandidate& b) const
    {
        if (m_is_local && a.m_is_local != b.m_is_local) return b.m_is_local;
        if ((a.m_network == m_network) != (b.m_network == m_network)) return b.m_network == m_network;
        return a.m_connected > b.m_connected;
    };
};

//! Sort an array by the specified comparator, then erase the last K elements where predicate is true.
template <typename T, typename Comparator>
static void EraseLastKElements(
    std::vector<T>& elements, Comparator comparator, size_t k,
    std::function<bool(const NodeEvictionCandidate&)> predicate = [](const NodeEvictionCandidate& n) { return true; })
{
    std::sort(elements.begin(), elements.end(), comparator);
    size_t eraseSize = std::min(k, elements.size());
    elements.erase(std::remove_if(elements.end() - eraseSize, elements.end(), predicate), elements.end());
}

void ProtectNoBanConnections(std::vector<NodeEvictionCandidate>& eviction_candidates)
{
        eviction_candidates.erase(std::remove_if(eviction_candidates.begin(),eviction_candidates.end(),
                                  [](NodeEvictionCandidate &n){return (n.m_flags & NetPermissionFlags::NoBan) == NetPermissionFlags::NoBan;}),eviction_candidates.end());
}

void ProtectOutboundConnections(std::vector<NodeEvictionCandidate>& eviction_candidates)
{
        eviction_candidates.erase(std::remove_if(eviction_candidates.begin(),eviction_candidates.end(),
                                  [](NodeEvictionCandidate const &n){return !n.m_is_inbound;}),eviction_candidates.end());
}

void ProtectEvictionCandidatesByRatio(std::vector<NodeEvictionCandidate>& eviction_candidates)
{
    // Protect the half of the remaining nodes which have been connected the longest.
    // This replicates the non-eviction implicit behavior, and precludes attacks that start later.
    // To favorise the diversity of our peer connections, reserve up to half of these protected
    // spots for Tor/onion, localhost, I2P, and CJDNS peers, even if they're not longest uptime
    // overall. This helps protect these higher-latency peers that tend to be otherwise
    // disadvantaged under our eviction criteria.
    const size_t initial_size = eviction_candidates.size();
    const size_t total_protect_size{initial_size / 2};

    // Disadvantaged networks to protect. In the case of equal counts, earlier array members
    // have the first opportunity to recover unused slots from the previous iteration.
    struct Net { bool is_local; Network id; size_t count; };
    std::array<Net, 4> networks{
        {{false, NET_CJDNS, 0}, {false, NET_I2P, 0}, {/*localhost=*/true, NET_MAX, 0}, {false, NET_ONION, 0}}};

    // Count and store the number of eviction candidates per network.
    for (Net& n : networks) {
        n.count = std::count_if(eviction_candidates.cbegin(), eviction_candidates.cend(),
                                [&n](const NodeEvictionCandidate& c) {
                                    return n.is_local ? c.m_is_local : c.m_network == n.id;
                                });
    }
    // Sort `networks` by ascending candidate count, to give networks having fewer candidates
    // the first opportunity to recover unused protected slots from the previous iteration.
    std::stable_sort(networks.begin(), networks.end(), [](Net a, Net b) { return a.count < b.count; });

    // Protect up to 25% of the eviction candidates by disadvantaged network.
    const size_t max_protect_by_network{total_protect_size / 2};
    size_t num_protected{0};

    while (num_protected < max_protect_by_network) {
        // Count the number of disadvantaged networks from which we have peers to protect.
        auto num_networks = std::count_if(networks.begin(), networks.end(), [](const Net& n) { return n.count; });
        if (num_networks == 0) {
            break;
        }
        const size_t disadvantaged_to_protect{max_protect_by_network - num_protected};
        const size_t protect_per_network{std::max(disadvantaged_to_protect / num_networks, static_cast<size_t>(1))};
        // Early exit flag if there are no remaining candidates by disadvantaged network.
        bool protected_at_least_one{false};

        for (Net& n : networks) {
            if (n.count == 0) continue;
            const size_t before = eviction_candidates.size();
            EraseLastKElements(eviction_candidates, CompareNodeNetworkTime(n.is_local, n.id),
                               protect_per_network, [&n](const NodeEvictionCandidate& c) {
                                   return n.is_local ? c.m_is_local : c.m_network == n.id;
                               });
            const size_t after = eviction_candidates.size();
            if (before > after) {
                protected_at_least_one = true;
                const size_t delta{before - after};
                num_protected += delta;
                if (num_protected >= max_protect_by_network) {
                    break;
                }
                n.count -= delta;
            }
        }
        if (!protected_at_least_one) {
            break;
        }
    }

    // Calculate how many we removed, and update our total number of peers that
    // we want to protect based on uptime accordingly.
    assert(num_protected == initial_size - eviction_candidates.size());
    const size_t remaining_to_protect{total_protect_size - num_protected};
    EraseLastKElements(eviction_candidates, ReverseCompareNodeTimeConnected, remaining_to_protect);
}

[[nodiscard]] std::optional<NodeId> SelectIncomingNodeToEvict(std::vector<NodeEvictionCandidate>&& vEvictionCandidates)
{
    // Protect connections with certain characteristics

    // Protect all nodes with the NoBan permission
    ProtectNoBanConnections(vEvictionCandidates);

    // Protect all outgoing nodes
    ProtectOutboundConnections(vEvictionCandidates);

    // Deterministically select 4 peers to protect by netgroup.
    // An attacker cannot predict which netgroups will be protected
    EraseLastKElements(vEvictionCandidates, CompareNetGroupKeyed, 4);
    // Protect the 8 nodes with the lowest minimum ping time.
    // An attacker cannot manipulate this metric without physically moving nodes closer to the target.
    EraseLastKElements(vEvictionCandidates, ReverseCompareNodeMinPingTime, 8);
    // Protect 4 nodes that most recently sent us novel transactions accepted into our mempool.
    // An attacker cannot manipulate this metric without performing useful work.
    EraseLastKElements(vEvictionCandidates, CompareNodeTXTime, 4);
    // Protect up to 8 non-tx-relay peers that have sent us novel blocks.
    EraseLastKElements(vEvictionCandidates, CompareNodeBlockRelayOnlyTime, 8,
                       [](const NodeEvictionCandidate& n) { return !n.m_relay_txs && n.fRelevantServices; });

    // Protect 4 nodes that most recently sent us novel blocks.
    // An attacker cannot manipulate this metric without performing useful work.
    EraseLastKElements(vEvictionCandidates, CompareNodeBlockTime, 4);

    // Protect some of the remaining eviction candidates by ratios of desirable
    // or disadvantaged characteristics.
    ProtectEvictionCandidatesByRatio(vEvictionCandidates);

    if (vEvictionCandidates.empty()) return std::nullopt;

    // If any remaining peers are preferred for eviction consider only them.
    // This happens after the other preferences since if a peer is really the best by other criteria (esp relaying blocks)
    //  then we probably don't want to evict it no matter what.
    if (std::any_of(vEvictionCandidates.begin(),vEvictionCandidates.end(),[](NodeEvictionCandidate const &n){return n.prefer_evict;})) {
        vEvictionCandidates.erase(std::remove_if(vEvictionCandidates.begin(),vEvictionCandidates.end(),
                                  [](NodeEvictionCandidate const &n){return !n.prefer_evict;}),vEvictionCandidates.end());
    }

    // Identify the network group with the most connections and youngest member.
    // (vEvictionCandidates is already sorted by reverse connect time)
    uint64_t naMostConnections;
    unsigned int nMostConnections = 0;
    std::chrono::seconds nMostConnectionsTime{0};
    std::map<uint64_t, std::vector<NodeEvictionCandidate> > mapNetGroupNodes;
    for (const NodeEvictionCandidate &node : vEvictionCandidates) {
        std::vector<NodeEvictionCandidate> &group = mapNetGroupNodes[node.nKeyedNetGroup];
        group.push_back(node);
        const auto grouptime{group[0].m_connected};

        if (group.size() > nMostConnections || (group.size() == nMostConnections && grouptime > nMostConnectionsTime)) {
            nMostConnections = group.size();
            nMostConnectionsTime = grouptime;
            naMostConnections = node.nKeyedNetGroup;
        }
    }

    // Reduce to the network group with the most connections
    vEvictionCandidates = std::move(mapNetGroupNodes[naMostConnections]);

    // Disconnect from the network group with the most connections
    return vEvictionCandidates.front().id;
}

void Evictor::AddCandidate(NodeEvictionCandidate candidate)
{
    LOCK(m_candidates_mutex);
    m_candidates.emplace_hint(m_candidates.end(), candidate.id, std::move(candidate));
}

bool Evictor::RemoveCandidate(NodeId id)
{
    LOCK(m_candidates_mutex);
    return m_candidates.erase(id) != 0;
}

void Evictor::UpdateMinPingTime(NodeId id, std::chrono::microseconds ping_time)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.m_min_ping_time = std::min(it->second.m_min_ping_time, ping_time);
    }
}

void Evictor::UpdateLatestBlockTime(NodeId id, std::chrono::seconds time)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.m_last_block_time = time;
    }
}

void Evictor::UpdateLatestTxTime(NodeId id, std::chrono::seconds time)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.m_last_tx_time = time;
    }
}
void Evictor::UpdateRelevantServices(NodeId id, bool relevant)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.fRelevantServices = relevant;
    }
}

void Evictor::UpdateRelaysTxs(NodeId id, bool relay)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.m_relay_txs = relay;
    }
}

void Evictor::UpdateLoadedBloomFilter(NodeId id, bool loaded)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.fBloomFilter = loaded;
    }
}

void Evictor::UpdateSuccessfullyConnected(NodeId id, bool connected)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.fSuccessfullyConnected = connected;
    }
}

void Evictor::UpdateBlocksInFlight(NodeId id, bool add)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.nBlocksInFlight += add ? 1 : -1;
    }
}

void Evictor::UpdateLastBlockAnnouncementTime(NodeId id, int64_t time)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.m_last_block_announcement = time;
    }
}

void Evictor::UpdateSlowChainProtected(NodeId id, bool is_protected)
{
    LOCK(m_candidates_mutex);
    if (const auto& it = m_candidates.find(id); it != m_candidates.end()) {
        it->second.m_slow_chain_protected = is_protected;
    }
}

std::optional<NodeId> Evictor::SelectIncomingNodeToEvict() const
{
    std::vector<NodeEvictionCandidate> candidates;
    {
        LOCK(m_candidates_mutex);
        for (const auto& it : m_candidates) {
            candidates.push_back(it.second);
        }
    }
    return ::SelectIncomingNodeToEvict(std::move(candidates));
}


std::optional<NodeId> Evictor::EvictExtraBlockOutboundPeers(std::chrono::seconds time_in_seconds)
{
    LOCK(m_candidates_mutex);
    int block_relay_peers = 0;
    for (const auto& [id, candidate] : m_candidates) {
        if (candidate.fSuccessfullyConnected && candidate.m_conn_type == ConnectionType::BLOCK_RELAY) {
            ++block_relay_peers;
        }
    }

    // If we have any extra block-relay-only peers, disconnect the youngest unless
    // it's given us a block -- in which case, compare with the second-youngest, and
    // out of those two, disconnect the peer who least recently gave us a block.
    // The youngest block-relay-only peer would be the extra peer we connected
    // to temporarily in order to sync our tip; see net.cpp.
    // Note that we use higher nodeid as a measure for most recent connection.
    if (block_relay_peers - m_max_outbound_block_relay > 0) {
        std::pair<NodeId, std::chrono::seconds> youngest_peer{-1, 0}, next_youngest_peer{-1, 0};

        for (const auto& [id, candidate] : m_candidates) {
            if (candidate.m_conn_type != ConnectionType::BLOCK_RELAY) continue;
            if (candidate.id > youngest_peer.first) {
                next_youngest_peer = youngest_peer;
                youngest_peer.first = candidate.id;
                youngest_peer.second = candidate.m_last_block_time;
            }
        }
        NodeId to_disconnect = youngest_peer.first;
        if (youngest_peer.second > next_youngest_peer.second) {
            // Our newest block-relay-only peer gave us a block more recently;
            // disconnect our second youngest.
            to_disconnect = next_youngest_peer.first;
        }
        if (const auto it = m_candidates.find(to_disconnect); it != m_candidates.end()) {
            const auto& [id, candidate] = *it;
            // Make sure we're not getting a block right now, and that
            // we've been connected long enough for this eviction to happen
            // at all.
            // Note that we only request blocks from a peer if we learn of a
            // valid headers chain with at least as much work as our tip.
            if (time_in_seconds - candidate.m_last_block_time >= MINIMUM_CONNECT_TIME && candidate.nBlocksInFlight == 0) {
                LogPrint(BCLog::NET, "disconnecting extra block-relay-only peer=%d (last block received at time %d)\n", id, count_seconds(candidate.m_last_block_time));
                return id;
            } else {
                LogPrint(BCLog::NET, "keeping block-relay-only peer=%d chosen for eviction (connect time: %d, blocks_in_flight: %d)\n",
                    id, count_seconds(candidate.m_connected), candidate.nBlocksInFlight);
            }
        }
    }
    return {};
}

std::optional<NodeId> Evictor::EvictExtraFullOutboundPeers(std::chrono::seconds time_in_seconds)
{
    LOCK(m_candidates_mutex);
    // Check whether we have too many outbound-full-relay peers
    int full_relay_peers = 0;
    for (const auto& [id, candidate] : m_candidates) {
        if (candidate.fSuccessfullyConnected && candidate.m_conn_type == ConnectionType::OUTBOUND_FULL_RELAY) {
            ++full_relay_peers;
        }
    }
    if (full_relay_peers - m_max_outbound_full_relay > 0) {
        // If we have more outbound-full-relay peers than we target, disconnect one.
        // Pick the outbound-full-relay peer that least recently announced
        // us a new block, with ties broken by choosing the more recent
        // connection (higher node id)
        NodeId worst_peer = -1;
        int64_t oldest_block_announcement = std::numeric_limits<int64_t>::max();

        for (const auto& [id, candidate] : m_candidates) {

            // Only consider outbound-full-relay peers that are not already
            // marked for disconnection
            if (candidate.m_conn_type != ConnectionType::OUTBOUND_FULL_RELAY) continue;
            // Don't evict our protected peers
            if (candidate.m_slow_chain_protected) continue;
            if (candidate.m_last_block_announcement < oldest_block_announcement || (candidate.m_last_block_announcement == oldest_block_announcement && id > worst_peer)) {
                worst_peer = id;
                oldest_block_announcement = candidate.m_last_block_announcement;
            }
        }
        if (worst_peer != -1) {
            if (const auto it = m_candidates.find(worst_peer); it != m_candidates.end()) {
                const auto& [id, candidate] = *it;
                // Only disconnect a peer that has been connected to us for
                // some reasonable fraction of our check-frequency, to give
                // it time for new information to have arrived.
                // Also don't disconnect any peer we're trying to download a
                // block from.
                if (time_in_seconds - candidate.m_connected > MINIMUM_CONNECT_TIME && candidate.nBlocksInFlight == 0) {
                    LogPrint(BCLog::NET, "disconnecting extra outbound peer=%d (last block announcement received at time %d)\n", id, oldest_block_announcement);
                    return worst_peer;
                } else {
                    LogPrint(BCLog::NET, "keeping outbound peer=%d chosen for eviction (connect time: %d, blocks_in_flight: %d)\n", id, count_seconds(candidate.m_connected), candidate.nBlocksInFlight);
                }
            }
        }
    }
    return {};
}
