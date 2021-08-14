#include <chain.h>
#include <coins.h>
#include <functional>
#include <logging.h>
#include <primitives/block.h>
#include <utreexoutils.h>

UtreexoLeaf::UtreexoLeaf(const COutPoint& outpoint, const uint256& blockhash,
                         const Coin& coin) : UtreexoLeaf(coin)
{
    m_txid = outpoint.hash;
    m_out = outpoint.n;
    m_blockhash = blockhash;
}

UtreexoLeaf::UtreexoLeaf(const Coin& coin)
{
    m_amount = coin.out.nValue;
    m_script_pubkey = coin.out.scriptPubKey;
    m_height = coin.nHeight;
    m_is_coinbase = coin.fCoinBase;

    if (m_script_pubkey.IsPayToPubkeyHash()) {
        m_type = P2PKH;
    } else if (m_script_pubkey.IsPayToScriptHash()) {
        m_type = P2SH;
    } else if (m_script_pubkey.IsPayToWitnessPubkeyHash()) {
        m_type = P2WPKH;
    } else if (m_script_pubkey.IsPayToWitnessScriptHash()) {
        m_type = P2WSH;
    }
}

CScript UtreexoLeaf::ReconstructP2PKH(const CTxIn& in) const
{
    opcodetype op;
    std::vector<unsigned char> pubkey;
    CScript::const_iterator it = in.scriptSig.begin();
    while (it != in.scriptSig.end()) {
        in.scriptSig.GetOp(it, op, pubkey);
        if (pubkey.size() == 20) break;
    }
    if (!pubkey.empty()) {
        uint160 pubkey_hash = Hash160(pubkey);
        return CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey_hash) << OP_EQUALVERIFY << OP_CHECKSIG;
    }
    return CScript();
}

CScript UtreexoLeaf::ReconstructP2SH(const CTxIn& in) const
{
    opcodetype op;
    std::vector<unsigned char> redeem;
    CScript::const_iterator it = in.scriptSig.begin();
    while (it != in.scriptSig.end()) {
        in.scriptSig.GetOp(it, op, redeem);
        if (redeem.size() == 20) break;
    }
    uint160 scriptHash = Hash160(redeem);
    return CScript() << OP_HASH160 << ToByteVector(scriptHash) << OP_EQUAL;
}

CScript UtreexoLeaf::ReconstructP2WPKH(const CTxIn& in) const
{
    const auto& prog = in.scriptWitness.stack.back();
    uint160 scriptHash = Hash160(prog);
    return CScript() << OP_0 << ToByteVector(scriptHash);
}

CScript UtreexoLeaf::ReconstructP2WSH(const CTxIn& in) const
{
    const auto& prog = in.scriptWitness.stack.back();
    uint256 scriptHash;
    CSHA256().Write(prog.data(), prog.size()).Finalize(scriptHash.begin());
    return CScript() << OP_0 << ToByteVector(scriptHash);
}

void UtreexoLeaf::GetOutPoint(COutPoint& outpoint) const
{
    outpoint = COutPoint{m_txid, m_out};
}

void UtreexoLeaf::FillCoinsView(CCoinsViewCache& view) const
{
    Coin coin(CTxOut(m_amount, m_script_pubkey), m_height, m_is_coinbase);
    view.AddCoin(COutPoint{m_txid, m_out}, std::move(coin), false);
}

bool UtreexoLeaf::Reconstruct(const CChain& chain, const CTxIn& in)
{
    m_txid = in.prevout.hash;
    m_out = in.prevout.n;

    const CBlockIndex* index = chain[m_height];
    if (!index) {
        return false;
    }
    m_blockhash = index->GetBlockHash();

    switch (m_type) {
    case OTHER:
        break;
    case P2PKH:
        m_script_pubkey = ReconstructP2PKH(in);
        break;
    case P2SH:
        m_script_pubkey = ReconstructP2SH(in);
        break;
    case P2WPKH:
        m_script_pubkey = ReconstructP2WPKH(in);
        break;
    case P2WSH:
        m_script_pubkey = ReconstructP2WSH(in);
        break;
    }

    m_is_reconstructed = true;

    return true;
}

UtxoSetInclusionProof::UtxoSetInclusionProof(const std::vector<UtreexoLeaf>&& elements,
                                             const utreexo::BatchProof<utreexo::Hash>&& proof)
{
    m_leaves = std::move(elements);
    m_proof = std::move(proof);
}

void UtxoSetInclusionProof::FillCoinsView(CCoinsViewCache& view)
{
    for (const UtreexoLeaf& leaf : m_leaves) {
        leaf.FillCoinsView(view);
    }
}

bool UtxoSetInclusionProof::ReconstructLeaves(const CChain& chain,
                                              const std::vector<CTransactionRef>& transactions,
                                              const std::vector<int> in_skip)
{
    uint32_t input_counter = 0;
    auto in_skip_it = in_skip.begin();
    auto leaf_it = m_leaves.begin();

    for (const CTransactionRef& tx : transactions) {
        if (tx->IsCoinBase()) {
            input_counter += tx->vin.size();
            continue;
        }

        for (uint32_t i = 0; i < tx->vin.size(); ++i) {
            // Inputs from the input skip list get skipped.
            if (in_skip_it != in_skip.end() &&
                (uint32_t)*in_skip_it == input_counter + i) {
                ++in_skip_it;
                continue;
            }

            if (leaf_it == m_leaves.end()) {
                return false;
            }

            // Reconstruct the scriptPubKey from the input if needed.
            if (!leaf_it->Reconstruct(chain, tx->vin[i])) {
                return false;
            }
            ++leaf_it;
        }
        input_counter += tx->vin.size();
    }

    return true;
}

bool UtxoSetInclusionProof::ReconstructLeaves(const CChain& chain,
                                              const std::vector<CTransactionRef>& transactions,
                                              const std::vector<Coin>& coins,
                                              const std::vector<int>& in_skip)
{
    uint32_t input_counter = 0;
    auto in_skip_it = in_skip.begin();
    auto coin_it = coins.begin();

    for (const CTransactionRef& tx : transactions) {
        if (tx->IsCoinBase()) {
            input_counter += tx->vin.size();
            continue;
        }

        for (uint32_t i = 0; i < tx->vin.size(); ++i) {
            // Inputs from the input skip list get skipped.
            if (in_skip_it != in_skip.end() &&
                (uint32_t)*in_skip_it == input_counter + i) {
                ++in_skip_it;
                ++coin_it;
                continue;
            }

            if (coin_it == coins.end()) {
                return false;
            }

            UtreexoLeaf leaf(*coin_it);
            if (!leaf.Reconstruct(chain, tx->vin[i])) {
                return false;
            }

            m_leaves.push_back(leaf);
            ++coin_it;
        }
        input_counter += tx->vin.size();
    }

    return true;
}

void ComputeLeafHashes(const std::vector<UtreexoLeaf>& leaves, std::vector<utreexo::Hash>& hashes)
{
    for (const UtreexoLeaf& leaf_data : leaves) {
        CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
        writer << leaf_data;
        hashes.push_back(writer.GetHash256());
    }
}

void ComputeBlockSkipLists(const CBlock& block, std::vector<int>& in_skip,
                           std::vector<int>& out_skip)
{
    uint32_t input_index = 0;
    std::unordered_map<COutPoint, int, SaltedOutpointHasher> input_map;

    for (const CTransactionRef& tx : block.vtx) {
        if (tx->IsCoinBase()) {
            input_index += tx->vin.size();
            continue;
        }

        for (size_t i = 0; i < tx->vin.size(); ++i) {
            input_map[tx->vin[i].prevout] = input_index;
            ++input_index;
        }
    }

    uint32_t output_index = 0;
    for (const CTransactionRef& tx : block.vtx) {
        if (tx->IsCoinBase()) {
            output_index += tx->vout.size();
            continue;
        }

        for (uint32_t i = 0; i < tx->vout.size(); ++i) {
            auto it = input_map.find(COutPoint{tx->GetHash(), i});
            if (it != input_map.end()) {
                in_skip.push_back(it->second);
                out_skip.push_back(output_index);
            }

            ++output_index;
        }
    }

    std::sort(in_skip.begin(), in_skip.end());
}

void GetNewLeavesFromBlock(const CBlock& block, int height,
                           const std::vector<int>& out_skip,
                           std::vector<UtreexoLeaf>& leaves)
{
    auto out_skip_it = out_skip.begin();

    uint32_t output_counter = 0;
    for (const CTransactionRef& tx : block.vtx) {
        for (uint32_t i = 0; i < tx->vout.size(); ++i) {
            // Outputs from the output skip list get skipped.
            if (out_skip_it != out_skip.end() &&
                (uint32_t)*out_skip_it++ == output_counter + i) {
                ++out_skip_it;
                continue;
            }

            // We only add spendable outputs to the accumulator.
            if (!tx->vout[i].scriptPubKey.IsUnspendable()) {
                UtreexoLeaf leaf(
                    COutPoint{tx->GetHash(), i}, block.GetHash(),
                    Coin{tx->vout[i], height, tx->IsCoinBase()});

                leaves.push_back(leaf);
            }
        }
        output_counter += tx->vout.size();
    }
}

void SortTargetHashes(const utreexo::BatchProof<utreexo::Hash>& proof,
                      const std::vector<utreexo::Hash>& target_hashes,
                      std::vector<utreexo::Hash>& sorted_target_hashes)
{
    std::unordered_map<uint64_t, std::reference_wrapper<const utreexo::Hash>>
        hash_map;

    auto targets = proof.GetTargets();
    for (uint32_t i = 0; i < targets.size(); ++i) {
        hash_map.emplace(targets[i], std::cref(target_hashes.at(i)));
    }

    for (const uint64_t& pos : proof.GetSortedTargets()) {
        sorted_target_hashes.push_back(hash_map.at(pos));
    }
}

