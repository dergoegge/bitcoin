// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/overflow.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

void initialize_pow()
{
    SelectParams(ChainType::MAIN);
}

FUZZ_TARGET(pow_transition, .init = initialize_pow)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const Consensus::Params& consensus_params{Params().GetConsensus()};
    std::vector<std::unique_ptr<CBlockIndex>> blocks;

    const uint32_t old_time{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    const uint32_t new_time{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    const int32_t version{fuzzed_data_provider.ConsumeIntegral<int32_t>()};
    uint32_t nbits{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};

    const arith_uint256 pow_limit = UintToArith256(consensus_params.powLimit);
    arith_uint256 old_target;
    old_target.SetCompact(nbits);
    if (old_target > pow_limit) {
        nbits = pow_limit.GetCompact();
    }
    // Create one difficulty adjustment period worth of headers
    for (int height = 0; height < consensus_params.DifficultyAdjustmentInterval(); ++height) {
        CBlockHeader header;
        header.nVersion = version;
        header.nTime = old_time;
        header.nBits = nbits;
        if (height == consensus_params.DifficultyAdjustmentInterval() - 1) {
            header.nTime = new_time;
        }
        auto current_block{std::make_unique<CBlockIndex>(header)};
        current_block->pprev = blocks.empty() ? nullptr : blocks.back().get();
        current_block->nHeight = height;
        blocks.emplace_back(std::move(current_block));
    }
    auto last_block{blocks.back().get()};
    unsigned int new_nbits{GetNextWorkRequired(last_block, nullptr, consensus_params)};
    Assert(PermittedDifficultyTransition(consensus_params, last_block->nHeight + 1, last_block->nBits, new_nbits));
}
