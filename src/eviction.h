// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVICTION_H
#define BITCOIN_EVICTION_H

#include <netaddress.h>

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
};

#endif // BITCOIN_EVICTION_H
