#ifndef BITCOIN_INDEX_BLOCKPROOFINDEX_H
#define BITCOIN_INDEX_BLOCKPROOFINDEX_H

#include <chain.h>
#include <flatfile.h>
#include <index/base.h>
#include <utreexo.h>
#include <utreexoutils.h>

/**
 * The BlockProofIndex is used to generate and serve utreexo UTXO set inclusion
 * proofs.
 *
 * The index stores the proofs in sequenced flat files named `proof_*` and undo
 * data used to revert changes to the utreexo forest in case of reorgs in
 * sequenced flat files named `undo_*`.
 *
 * The index's level DB stores flat file positions, proof and undo data sizes as
 * well as the accumulator roots for each block.
 */
class BlockProofIndex : public BaseIndex
{
private:
    std::unique_ptr<BaseIndex::DB> m_db;
    FlatFilePos m_next_proof_pos, m_next_undo_pos;
    std::unique_ptr<FlatFileSeq> m_proof_fileseq, m_undo_fileseq;

    Mutex m_forest_mutex;
    std::unique_ptr<utreexo::RamForest> m_forest GUARDED_BY(m_forest_mutex);

    std::unique_ptr<utreexo::Pollard> m_pollard;

protected:
    size_t WriteProofToDisk(FlatFilePos& pos,
                            const UtxoSetInclusionProof& proof);

    size_t WriteUndoBatchToDisk(FlatFilePos& pos,
                                const utreexo::UndoBatch& undo);

    bool LookupUndoBatch(int height, utreexo::UndoBatch& undo) const;

    bool Init() override;

    bool CommitInternal(CDBBatch& batch) override;

    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip,
                const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override;

    const char* GetName() const override { return "blockproofindex"; }

public:
    explicit BlockProofIndex(size_t n_cache_size, bool f_memory = false,
                             bool f_wipe = false);

    bool LookupBlockProof(int height, UtxoSetInclusionProof& proof) const;
    bool LookupRawBlockProof(const CBlockIndex* index,
                             std::vector<uint8_t>& proof_bytes) const;

    /**
     * ComputeProofForLeaves computes a inclusion proof for a set of leaves.
     *
     * NOTE: we can only produce proofs for leaves at the tip because we only
     * have the full forest at the tip.
     *
     * TODO: we could consider allowing the forest to rollback a certain number
     * of blocks to be able to produce proofs for past blocks.
     */
    bool ComputeProofForLeaves(const CBlockIndex* expected_tip,
                               const std::vector<UtreexoLeafData>&& leaves,
                               UtxoSetInclusionProof& proof);
};

extern std::unique_ptr<BlockProofIndex> g_blockproofindex;

#endif
