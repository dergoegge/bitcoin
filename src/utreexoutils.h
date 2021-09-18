#ifndef BITCOIN_UTIL_UTREEXO_H
#define BITCOIN_UTIL_UTREEXO_H

#include <chain.h>
#include <coins.h>
#include <logging.h>
#include <primitives/block.h>
#include <serialize.h>
#include <utreexo.h>
#include <vector>

/**
 * Utreexo/Accumulator helpers and utility functions are defined here.
 * I was unsure where to place these and put them temporarily here.
 * TODO: Try to find suitable places for these utilities.
 */

/**
 * UtreexoLeafData holds the data that an element in the UTXO set
 * accumulator commits to.
 *
 * Included: 
 *   - Outpoint of the UTXO
 *   - Blockhash of the block in which the UTXO was created
 *   - Coin
 */
class UtreexoLeafData
{
private:
    friend class UtxoSetInclusionProof;

    COutPoint m_outpoint;
    uint256 m_blockhash;

public:
    Coin m_coin;

    UtreexoLeafData() {}
    UtreexoLeafData(const COutPoint& outpoint, const uint256& blockhash, const Coin& coin)
        : m_outpoint(outpoint), m_blockhash(blockhash), m_coin(coin) {}

    bool Reconstruct(const CChain& chain, const CTxIn& in, const Coin& coin)
    {
        m_outpoint = in.prevout;

        const CBlockIndex* index = chain[coin.nHeight];
        if (!index) {
            // Could not find the block hash for a coin.
            return false;
        }
        m_blockhash = index->GetBlockHash();

        m_coin = coin;
        return true;
    }

    template <typename Stream>
    void SerializeHash(Stream& s) const
    {
        ::Serialize(s, m_outpoint);
        ::Serialize(s, m_blockhash);
        uint32_t code = (m_coin.nHeight << 1) + m_coin.fCoinBase;
        ::Serialize(s, code);
        ::Serialize(s, m_coin.out.nValue);
        ::Serialize(s, m_coin.out.scriptPubKey);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (s.GetType() & SER_GETHASH) {
            SerializeHash(s);
            return;
        }

        ::Serialize(s, ReconstructableCoin(m_coin));
    }
};

void ComputeBlockSkipLists(const CBlock& block,
                           std::vector<int>& in_skip,
                           std::vector<int>& out_skip);

void GetNewLeavesFromBlock(const CBlock& block, int height,
                           const std::vector<int>& out_skip,
                           std::vector<UtreexoLeafData>& elements);

bool ReconstructLeavesFromTransactions(const CChain& chain,
                                       const std::vector<CTransactionRef>& transactions,
                                       const std::vector<ReconstructableCoin>& coins,
                                       const std::vector<int> in_skip,
                                       bool skip_coins,
                                       std::vector<UtreexoLeafData>& elements);

void SortTargetHashes(const utreexo::BatchProof& proof,
                      const std::vector<utreexo::Hash>& target_hashes,
                      std::vector<utreexo::Hash>& sorted_target_hashes);


/**
 * UtxoSetInclusionProof holds UTXO set accumualator elements and their inclusion proofs.
 */
class UtxoSetInclusionProof
{
private:
    //! The elements for which inclusion in the accumulator is proven.
    //!
    //! For blocks:
    //!   There is one element for each input in a block that
    //!   is not spending an output from the same block.
    //!
    //! For transactions:
    //!   There is one element for each input in the transaction.
    std::vector<UtreexoLeafData> m_leaves;
    std::vector<ReconstructableCoin> m_coins;

    //! The UTXO set inclusion proof for m_leaves.
    utreexo::BatchProof m_proof;

public:
    UtxoSetInclusionProof() {}
    UtxoSetInclusionProof(const std::vector<UtreexoLeafData>&& elements,
                          const utreexo::BatchProof&& proof)
        : m_leaves(std::move(elements)), m_proof(std::move(proof)) {}

    void FillCoinsView(CCoinsViewCache& view);

    const utreexo::BatchProof& GetProof() const { return m_proof; }
    utreexo::BatchProof& GetProof() { return m_proof; }
    const std::vector<UtreexoLeafData>& GetLeaves() const { return m_leaves; }
    std::vector<UtreexoLeafData>& GetLeaves() { return m_leaves; }
    const std::vector<ReconstructableCoin>& GetCoins() const { return m_coins; }
    std::vector<ReconstructableCoin>& GetCoins() { return m_coins; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        assert(m_coins.size() == 0);
        ::Serialize(s, m_leaves);
        std::vector<uint8_t> proof_bytes;
        m_proof.Serialize(proof_bytes);
        ::Serialize(s, proof_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, m_coins);
        std::vector<uint8_t> proof_bytes;
        ::Unserialize(s, proof_bytes);
        if (!m_proof.Unserialize(proof_bytes)) {
            throw std::ios_base::failure("UtxoSetInclusionProof: could not unserialize the batch proof.");
        }
    }
};

#endif
