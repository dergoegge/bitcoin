#ifndef BITCOIN_STEMPOOL_H
#define BITCOIN_STEMPOOL_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <vector>

class DandelionStempoolImpl;
typedef int64_t NodeId;

struct StempoolBroadcastResult {
    std::vector<CTransactionRef> broadcast;
    std::vector<CTransactionRef> expired;
};

class DandelionStempool
{
private:
    std::unique_ptr<DandelionStempoolImpl> m_impl;

public:
    DandelionStempool();
    DandelionStempool(DandelionStempool&) = delete;
    DandelionStempool(DandelionStempool&&) = delete;
    ~DandelionStempool();

    void Add(const CTransactionRef& tx);
    bool Remove(const uint256& wtxid);
    const CTransactionRef Get(const uint256& wtxid, NodeId node_id) const;

    /** Find all parents for a given child tx and return the package of child
     * and parent transactions.*/
    std::vector<CTransactionRef> GetPackage(const CTransactionRef& tx) const;

    [[nodiscard]] StempoolBroadcastResult GetBroadcastCandidates();

    void Broadcast(uint256 wtxid, NodeId node_id);
};

#endif
