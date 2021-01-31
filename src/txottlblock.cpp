#include <txottlblock.h>

void TxoTtlBlock::Unserialize(int height, const std::vector<uint8_t>& bytes)
{
    for (uint32_t pos = 0; pos < bytes.size() / 4; ++pos) {
        m_ttlmap[height].push_back(TxoTtl{pos, ReadLE32(bytes.data() + pos * 4)});
    }
}

std::vector<TxoTtl>& TxoTtlBlock::GetTtls(int height)
{
    return m_ttlmap[height];
}

bool TxoTtlBlock::ForEachHeight(std::function<bool(const int, const std::vector<TxoTtl>&)> func) const
{
    auto it = m_ttlmap.begin();
    while (it != m_ttlmap.end()) {
        if (!func(it->first, it->second)) return false;
        ++it;
    }
    return true;
}

