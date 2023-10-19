#include <chainparams.h>
#include <coins.h>
#include <inttypes.h>
#include <kernel/coinstats.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <txdb.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>

namespace {
void initialize_coinstats_hash()
{
    SelectParams(ChainType::MAIN);
}

using UtxoMap = std::map<uint32_t, Coin>;

bool NotEqual(std::string reason)
{
    //std::cout << reason << std::endl;
    return false;
}
bool ContentEqual(const UtxoMap& map1, const UtxoMap& map2)
{
    if (map1.size() != map2.size()) return NotEqual("different sizes");

    for (const auto& [key, coin1] : map1) {
        auto it = map2.find(key);
        if (it == map2.end()) return NotEqual("not the same keys");

        Coin coin2 = it->second;
        if (coin2.out != coin1.out) return NotEqual("outs not the same");
        if (coin2.nHeight != coin1.nHeight) return NotEqual("heights not the same");
        if (coin2.fCoinBase != coin1.fCoinBase) return NotEqual("fCoinBase not the same");
    }

    return true;
}
} // namespace

FUZZ_TARGET(coinstats_hash, .init = initialize_coinstats_hash)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    auto outputs1 = ConsumeDeserializable<UtxoMap>(fuzzed_data_provider);
    if (!outputs1) return;
    auto outputs2 = ConsumeDeserializable<UtxoMap>(fuzzed_data_provider);
    if (!outputs2) return;

    HashWriter hasher1, hasher2;

    kernel::ApplyHash(hasher1, uint256{}, *outputs1);
    kernel::ApplyHash(hasher2, uint256{}, *outputs2);

    if (ContentEqual(*outputs1, *outputs2)) {
        assert(hasher1.GetHash() == hasher2.GetHash());
    } else {
        assert(hasher1.GetHash() != hasher2.GetHash());
    }
}
