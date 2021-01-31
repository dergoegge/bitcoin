#ifndef BITCOIN_INDEX_BLOCKPROOFINDEX_H
#define BITCOIN_INDEX_BLOCKPROOFINDEX_H

#include <chain.h>
#include <flatfile.h>
#include <index/base.h>
#include <utreexo.h>

/**
 * BlockProofIndex is used to store and retrieve utxo set inclusion proofs for the inputs of blocks by height.
 * The proofs are stored in flatfiles.
 */
class BlockProofIndex : public BaseIndex
{
private:
    std::unique_ptr<BaseIndex::DB> m_db;
    FlatFilePos m_next_proof_pos, m_next_undo_pos;
    std::unique_ptr<FlatFileSeq> m_proof_fileseq, m_undo_fileseq;

    std::unique_ptr<utreexo::RamForest> m_forest;
    std::unique_ptr<utreexo::Pollard> m_pollard;

protected:
    size_t WriteProofToDisk(FlatFilePos& pos, const utreexo::BatchProof& proof);

    size_t WriteUndoBatchToDisk(FlatFilePos& pos, const utreexo::UndoBatch& undo);

    bool LookupUndoBatch(int height, utreexo::UndoBatch& undo) const;

    bool Init() override;

    bool CommitInternal(CDBBatch& batch) override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "blockproofindex"; }

public:
    explicit BlockProofIndex(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    bool LookupBlockProof(int height, utreexo::BatchProof& proof) const;
};

extern std::unique_ptr<BlockProofIndex> g_blockproofindex;

#endif
