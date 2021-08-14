#include <logging.h>
#include <utreexoutils.h>

void UtxoSetInclusionProof::FillCoinsView(CCoinsViewCache& view)
{
    for (const UtreexoLeafData& leaf : m_leaves) {
        Coin copy = leaf.m_coin;
        view.AddCoin(leaf.m_outpoint, std::move(copy), false);
    }
}

void ComputeBlockSkipLists(const CBlock& block,
                           std::vector<int>& in_skip,
                           std::vector<int>& out_skip)
{
    uint32_t input_index = 0;
    std::unordered_map<COutPoint, int, SaltedOutpointHasher> input_map;
    for (const CTransactionRef& tx : block.vtx) {
        if (tx->IsCoinBase()) {
            ++input_index;
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
    int output_index = 0;
    uint32_t out_skip_index = 0;
    for (const CTransactionRef& tx : block.vtx) {
        for (uint32_t i = 0; i < tx->vout.size(); ++i) {
            if (out_skip_index < out_skip.size() &&
                out_skip[out_skip_index] == output_index) {
                ++out_skip_index;
                ++output_index;
                continue;
            }

            UtreexoLeafData leaf(COutPoint{tx->GetHash(), i},
                                 block.GetHash(),
                                 Coin{tx->vout[i], height, tx->IsCoinBase()});

            leaves.push_back(leaf);

            ++output_index;
        }
    }
}

bool ReconstructLeavesFromTransactions(const CChain& chain,
                                       const std::vector<CTransactionRef>& transactions,
                                       const std::vector<ReconstructableCoin>& coins,
                                       const std::vector<int> in_skip,
                                       bool skip_coins,
                                       std::vector<UtreexoLeafData>& leaves)
{
    int input_index = 0;
    uint32_t in_skip_index = 0;
    auto coin_it = coins.begin();

    for (const CTransactionRef& tx : transactions) {
        if (tx->IsCoinBase()) {
            input_index += tx->vin.size();
            continue;
        }

        for (const CTxIn& input : tx->vin) {
            if (in_skip_index < in_skip.size() &&
                in_skip[in_skip_index] == input_index) {
                ++in_skip_index;
                ++input_index;
                if (skip_coins) ++coin_it;
                continue;
            }

            if (coin_it == coins.end()) {
                return false;
            }

            Coin coin = coin_it->Reconstruct(input);
            UtreexoLeafData leaf;
            if (!leaf.Reconstruct(chain, input, coin)) {
                // Could not reconstruct leaf data.
                return false;
            }
            leaves.push_back(leaf);

            ++input_index;
            ++coin_it;
        }
    }

    return true;
}

void SortTargetHashes(const utreexo::BatchProof& proof,
                      const std::vector<utreexo::Hash>& target_hashes,
                      std::vector<utreexo::Hash>& sorted_target_hashes)
{
    std::unordered_map<uint64_t, utreexo::Hash> hash_map;
    auto targets = proof.GetTargets();
    for (int i = 0; i < targets.size(); ++i) {
        hash_map[targets[i]] = target_hashes[i];
    }

    auto sorted_targets = proof.GetSortedTargets();
    for (uint64_t& pos : sorted_targets) {
        sorted_target_hashes.push_back(hash_map[pos]);
    }
}

