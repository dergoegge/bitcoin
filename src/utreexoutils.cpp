#include <chain.h>
#include <functional>
#include <logging.h>
#include <primitives/block.h>
#include <utreexoutils.h>

bool UtreexoLeafData::Reconstruct(const CChain& chain, const CTxIn& in, const Coin& coin)
{
    m_outpoint = in.prevout;

    const CBlockIndex* index = chain[coin.nHeight];
    if (!index) {
        return false;
    }
    m_blockhash = index->GetBlockHash();

    m_coin = coin;
    return true;
}

void UtxoSetInclusionProof::FillCoinsView(CCoinsViewCache& view)
{
    for (const UtreexoLeafData& leaf : m_leaves) {
        Coin copy = leaf.m_coin;
        view.AddCoin(leaf.m_outpoint, std::move(copy), false);
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
                           std::vector<UtreexoLeafData>& leaves)
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
                UtreexoLeafData leaf(
                    COutPoint{tx->GetHash(), i}, block.GetHash(),
                    Coin{tx->vout[i], height, tx->IsCoinBase()});

                leaves.push_back(leaf);
            }
        }
        output_counter += tx->vout.size();
    }
}

bool ReconstructLeavesFromTransactions(
    const CChain& chain, const std::vector<CTransactionRef>& transactions,
    const std::vector<ReconstructableCoin>& coins,
    const std::vector<int> in_skip, bool skip_coins,
    std::vector<UtreexoLeafData>& leaves)
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
                if (skip_coins) ++coin_it;
                continue;
            }

            if (coin_it == coins.end()) {
                return false;
            }

            // Reconstruct the scriptPubKey from the input if needed.
            Coin coin = coin_it->Reconstruct(tx->vin[i]);

            // Lookup the block hash for this leaf.
            const CBlockIndex* index = chain[coin.nHeight];
            if (!index) {
                return false;
            }

            leaves.emplace_back(tx->vin[i].prevout, index->GetBlockHash(),
                                coin);
            ++coin_it;
        }
        input_counter += tx->vin.size();
    }

    return true;
}

void SortTargetHashes(const utreexo::BatchProof& proof,
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

