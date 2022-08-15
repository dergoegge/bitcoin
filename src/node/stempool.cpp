#include <node/stempool.h>
#include <sync.h>
#include <uint256.h>
#include <util/hasher.h>
#include <util/time.h>

#include <unordered_map>
#include <vector>

static constexpr auto STEMPOOL_REBROADCAST_INTERVAL{30s};
static constexpr auto STEMPOOL_EXPIRY{10min};
static constexpr auto STEMPOOL_MAX_TXS_PER_BROADCAST{16};

struct StempoolEntry {
    CTransactionRef tx{nullptr};
    NodeSeconds last_broadcast{0s};
    NodeSeconds added{0s};
    NodeId last_node{0};
};

class DandelionStempoolImpl
{
private:
    mutable Mutex m_stempool_mutex;

    using StempoolMap = std::unordered_map<uint256, StempoolEntry, SaltedTxidHasher>;
    StempoolMap m_entries;

public:
    void Add(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_stempool_mutex)
    {
        LOCK(m_stempool_mutex);
        auto [it, inserted] = m_entries.emplace(tx->GetWitnessHash(), StempoolEntry{tx, NodeSeconds{0s}, Now<NodeSeconds>()});
        if (!inserted) {
            it->second.added = Now<NodeSeconds>();
        }
    }

    bool Remove(const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_stempool_mutex)
    {
        LOCK(m_stempool_mutex);
        return m_entries.erase(wtxid) > 0;
    }

    const CTransactionRef Get(const uint256& wtxid, NodeId node_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_stempool_mutex)
    {
        LOCK(m_stempool_mutex);

        if (auto it = m_entries.find(wtxid); it != m_entries.end() && it->second.last_node == node_id) {
            return it->second.tx;
        }

        return nullptr;
    }

    std::vector<CTransactionRef> GetPackage(const CTransactionRef& tx) const EXCLUSIVE_LOCKS_REQUIRED(!m_stempool_mutex)
    {
        LOCK(m_stempool_mutex);

        if (auto it = m_entries.find(tx->GetWitnessHash()); it != m_entries.end()) {
            // Collect all parent transactions from the stempool.
            std::map<uint256, CTransactionRef> parents;
            for (const CTxIn& in : tx->vin) {
                if (auto it = m_entries.find(in.prevout.hash); it != m_entries.end()) {
                    const StempoolEntry& entry{it->second};
                    parents.emplace(entry.tx->GetWitnessHash(), entry.tx);
                }
            }

            std::vector<CTransactionRef> pkg;
            for (auto& [_, parent_tx] : parents) {
                pkg.push_back(parent_tx);
            }
            pkg.push_back(it->second.tx);

            return pkg;
        }

        // The transaction is not part of the stempool, so we can't return
        // a package for it.
        return {};
    }

    [[nodiscard]] StempoolBroadcastResult GetBroadcastCandidates() EXCLUSIVE_LOCKS_REQUIRED(!m_stempool_mutex)
    {
        LOCK(m_stempool_mutex);

        StempoolBroadcastResult result;
        auto now{Now<NodeSeconds>()};

        for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
            StempoolEntry& entry{it->second};

            if (now > entry.added + STEMPOOL_EXPIRY) {
                // This entry expired, remove it from the stempool.
                result.expired.push_back(entry.tx);
                it = m_entries.erase(it);
                continue;
            }

            if (result.broadcast.size() < STEMPOOL_MAX_TXS_PER_BROADCAST &&
                now > entry.last_broadcast + STEMPOOL_REBROADCAST_INTERVAL) {
                // This entry is ready for broadcast.
                result.broadcast.push_back(entry.tx);
            }
        }

        return result;
    }

    void Broadcast(uint256 wtxid, NodeId node_id) EXCLUSIVE_LOCKS_REQUIRED(!m_stempool_mutex)
    {
        LOCK(m_stempool_mutex);

        if (auto it = m_entries.find(wtxid); it != m_entries.end()) {
            it->second.last_broadcast = Now<NodeSeconds>();
            it->second.last_node = node_id;
        }
    }
};

DandelionStempool::DandelionStempool() : m_impl{std::make_unique<DandelionStempoolImpl>()} {}
DandelionStempool::~DandelionStempool() {}

void DandelionStempool::Add(const CTransactionRef& tx)
{
    m_impl->Add(tx);
}

bool DandelionStempool::Remove(const uint256& wtxid)
{
    return m_impl->Remove(wtxid);
}

const CTransactionRef DandelionStempool::Get(const uint256& wtxid, NodeId node_id) const
{
    return m_impl->Get(wtxid, node_id);
}

std::vector<CTransactionRef> DandelionStempool::GetPackage(const CTransactionRef& tx) const
{
    return m_impl->GetPackage(tx);
}

StempoolBroadcastResult DandelionStempool::GetBroadcastCandidates()
{
    return m_impl->GetBroadcastCandidates();
}

void DandelionStempool::Broadcast(uint256 wtxid, NodeId node_id)
{
    m_impl->Broadcast(wtxid, node_id);
}
