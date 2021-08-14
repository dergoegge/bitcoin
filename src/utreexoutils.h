#ifndef BITCOIN_UTIL_UTREEXO_H
#define BITCOIN_UTIL_UTREEXO_H

#include <consensus/amount.h>
#include <hash.h>
#include <logging.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>
#include <utreexo.h>
#include <vector>

class CBlock;
class COutPoint;
class CTxIn;
class Coin;
class CChain;
class CCoinsViewCache;
class ReconstructableCoin;
class CTransaction;
typedef std::shared_ptr<const CTransaction> CTransactionRef;

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

    enum OutputType : uint8_t {
        OTHER = 0,
        P2PKH = 1,
        P2SH = 2,
        P2WPKH = 3,
        P2WSH = 4,
    };

    // COutPoint
    uint256 m_txid;
    uint32_t m_out;

    uint256 m_blockhash;

    // Coin
    CAmount m_amount;
    CScript m_script_pubkey;
    uint32_t m_height : 31;
    uint32_t m_is_coinbase : 1;

    uint8_t m_type{OTHER};

    bool m_is_reconstructed{false};

    // Reconstruct scriptPubKey from the spending input.
    CScript ReconstructP2PKH(const CTxIn& in) const;
    CScript ReconstructP2SH(const CTxIn& in) const;
    CScript ReconstructP2WPKH(const CTxIn& in) const;
    CScript ReconstructP2WSH(const CTxIn& in) const;

public:
    UtreexoLeafData() {}
    UtreexoLeafData(const COutPoint& outpoint, const uint256& blockhash,
                    const Coin& coin);
    UtreexoLeafData(const Coin& coin);

    void GetOutPoint(COutPoint& outpoint) const;

    void FillCoinsView(CCoinsViewCache& view) const;

    bool Reconstruct(const CChain& chain, const CTxIn& in);

    template <typename Stream>
    void SerializeHash(Stream& s) const
    {
        ::Serialize(s, m_txid);
        ::Serialize(s, m_out);
        ::Serialize(s, m_blockhash);
        uint32_t code = (m_height << 1) + m_is_coinbase;
        ::Serialize(s, code);
        ::Serialize(s, m_amount);
        ::Serialize(s, m_script_pubkey);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (s.GetType() & SER_GETHASH) {
            SerializeHash(s);
            return;
        }

        ::Serialize(s, m_type);
        uint32_t code = (m_height << 1) + m_is_coinbase;
        ::Serialize(s, code);
        ::Serialize(s, m_amount);

        if (m_type == OTHER) {
            ::Serialize(s, m_script_pubkey);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, m_type);

        uint32_t code{0};
        ::Unserialize(s, code);
        m_height = code >> 1;
        m_is_coinbase = code & 1;

        ::Unserialize(s, m_amount);

        if (m_type == OTHER) {
            ::Unserialize(s, m_script_pubkey);
        }
    }
};
/**
 * A Block can have outputs that get spend within the same block.
 * We do not want to add these outputs to the accumualator and
 * skip them instead. The same goes for inputs that reference an
 * output from the same block.
 *
 * ComputeBlockSkipLists computes the list of inputs and and outputs
 * that are involved in same block spends.
 */
void ComputeBlockSkipLists(const CBlock& block, std::vector<int>& in_skip,
                           std::vector<int>& out_skip);

/**
 * GetNewLeavesFromBlock figures out which outputs from the block
 * should be added to the accumulator. These are all outputs besides
 * besides unspendable ones and outputs that get spend in the same block.
 */
void GetNewLeavesFromBlock(const CBlock& block, int height,
                           const std::vector<int>& out_skip,
                           std::vector<UtreexoLeafData>& elements);

/**
 * The utreexo accumualator needs the hashes of the leaves to be sorted
 * for verification and deletion. They need to be sorted in the order in
 * which they were added to the accumualator. (accumualator-order)
 *
 * When we reconstruct leaves from a list of transactions we get the
 * leaves in the order in which they appeared in the transactions.
 * (transaction-order)
 *
 * SortTargetHashes sorts a list of leaf hashes into accumualator-order.
 */
void SortTargetHashes(const utreexo::BatchProof& proof,
                      const std::vector<utreexo::Hash>& target_hashes,
                      std::vector<utreexo::Hash>& sorted_target_hashes);


void ComputeLeafHashes(const std::vector<UtreexoLeafData>& leaves, std::vector<utreexo::Hash>& hashes);

/**
 * UtxoSetInclusionProof holds UTXO set accumualator elements and their
 * inclusion proofs.
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

    //! The UTXO set inclusion proof for m_leaves.
    utreexo::BatchProof m_proof;

public:
    UtxoSetInclusionProof() {}
    UtxoSetInclusionProof(const std::vector<UtreexoLeafData>&& elements,
                          const utreexo::BatchProof&& proof);
    ~UtxoSetInclusionProof() {}

    void FillCoinsView(CCoinsViewCache& view);

    bool ReconstructLeaves(const CChain& chain,
                           const std::vector<CTransactionRef>& transactions,
                           const std::vector<int> in_skip);

    bool ReconstructLeaves(const CChain& chain,
                           const std::vector<CTransactionRef>& transactions,
                           const std::vector<Coin>& coins,
                           const std::vector<int>& in_skip);


    void SetProof(const utreexo::BatchProof& proof)
    {
        m_proof = proof;
    }

    const utreexo::BatchProof& GetProof() const { return m_proof; }
    const std::vector<UtreexoLeafData>& GetLeaves() const { return m_leaves; }
    std::vector<UtreexoLeafData>& GetLeaves() { return m_leaves; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, m_leaves);
        std::vector<uint8_t> proof_bytes;
        m_proof.Serialize(proof_bytes);
        ::Serialize(s, proof_bytes);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, m_leaves);
        std::vector<uint8_t> proof_bytes;
        ::Unserialize(s, proof_bytes);
        if (!m_proof.Unserialize(proof_bytes)) {
            throw std::ios_base::failure("UtxoSetInclusionProof: could not "
                                         "unserialize the batch proof.");
        }
    }
};

#endif
