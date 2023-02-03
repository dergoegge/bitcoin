#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>

#include <node/mini_miner.h>
#include <primitives/transaction.h>
#include <txmempool.h>

#include <vector>

FUZZ_TARGET(mini_miner)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    CTxMemPool pool{CTxMemPool::Options{}};
    std::vector<COutPoint> outpoints;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100)
    {
        auto tx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
        if (!tx) {
            break;
        }

        if (fuzzed_data_provider.ConsumeBool() && !tx->vout.empty()) {
            outpoints.push_back(COutPoint{tx->GetHash(),
                                          (uint32_t)fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, tx->vout.size())});
        } else {
            auto outpoint = ConsumeDeserializable<COutPoint>(fuzzed_data_provider);
            if (outpoint) outpoints.push_back(*outpoint);
        }

        pool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, CTransaction{*tx}));
    }

    node::MiniMiner mini_miner{pool, outpoints};
    mini_miner.CalculateBumpFees(CFeeRate{fuzzed_data_provider.ConsumeIntegral<uint64_t>()});
}
