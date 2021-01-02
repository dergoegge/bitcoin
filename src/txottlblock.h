#ifndef BITCOIN_TXOTTLBLOCK_H
#define BITCOIN_TXOTTLBLOCK_H

#include <chain.h>
#include <flatfile.h>
#include <map>
#include <primitives/transaction.h>
#include <sstream>
#include <unordered_map>

struct TxoTtl {
    uint32_t m_index;
    uint32_t m_value;

    TxoTtl() : m_index(0), m_value(0) {}
    TxoTtl(uint32_t index, uint32_t value) : m_index(index), m_value(value) {}

    SERIALIZE_METHODS(TxoTtl, obj)
    {
        READWRITE(obj.m_value);
    }
};

class TxoTtlBlock
{
private:
    std::unordered_map<int, std::vector<TxoTtl>> m_ttlmap;
    void Unserialize(int height, const std::vector<uint8_t>& bytes);

public:
    TxoTtlBlock() {}
    TxoTtlBlock(int height, const std::vector<uint8_t>& bytes)
    {
        assert(bytes.size() % 4 == 0);
        Unserialize(height, bytes);
    }

    std::vector<TxoTtl>& GetTtls(int height);

    bool ForEachHeight(std::function<bool(const int, const std::vector<TxoTtl>&)>) const;
};
#endif
