#ifndef BITCOIN_INDEX_TXOTTLINDEX_H
#define BITCOIN_INDEX_TXOTTLINDEX_H

#include <chain.h>
#include <flatfile.h>
#include <index/base.h>
#include <txottlblock.h>

/**
 * TxoTtlIndex is used to store and retrieve transaction output live times (blocks until spend) for
 * a range of blocks by height. 
 */
class TxoTtlIndex : public BaseIndex
{
private:
    std::unique_ptr<BaseIndex::DB> m_db;

    FlatFilePos m_next_ttlblock_pos;
    std::unique_ptr<FlatFileSeq> m_ttlblock_fileseq;

    bool ReadRawTxoTtlBlockFromDisk(int height, std::vector<uint8_t>& raw_block) const;
    bool ReadTxoTtlBlockFromDisk(int height, TxoTtlBlock& ttl_block) const;
    bool WriteTxoTtlBlockToDisk(const TxoTtlBlock& ttl_block);

    size_t AllocateForNextTtlBlock(int n_ttls);

protected:
    bool Init() override;

    bool CommitInternal(CDBBatch& batch) override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "txottlindex"; }

public:
    explicit TxoTtlIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    /** Lookup and return ttl blocks for the given block range. */
    bool LookupTtlBlocks(int start_height, CBlockIndex& stop_index, std::vector<TxoTtlBlock>& ttl_blocks) const;
};

extern std::unique_ptr<TxoTtlIndex> g_txottlindex;

#endif
