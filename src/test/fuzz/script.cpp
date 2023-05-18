// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <compressor.h>
#include <core_io.h>
#include <core_memusage.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <univalue.h>
#include <util/chaintype.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <bitset>

void initialize_script()
{
    SelectParams(ChainType::REGTEST);
}

FUZZ_TARGET_INIT(script, initialize_script)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const CScript script{ConsumeScript(fuzzed_data_provider)};

    CompressedScript compressed;
    if (CompressScript(script, compressed)) {
        const unsigned int size = compressed[0];
        compressed.erase(compressed.begin());
        assert(size <= 5);
        CScript decompressed_script;
        const bool ok = DecompressScript(decompressed_script, size, compressed);
        assert(ok);
        assert(script == decompressed_script);
    }

    TxoutType which_type;
    bool is_standard_ret = IsStandard(script, std::nullopt, which_type);
    if (!is_standard_ret) {
        assert(which_type == TxoutType::NONSTANDARD ||
               which_type == TxoutType::NULL_DATA ||
               which_type == TxoutType::MULTISIG);
    }
    if (which_type == TxoutType::NONSTANDARD) {
        assert(!is_standard_ret);
    }
    if (which_type == TxoutType::NULL_DATA) {
        assert(script.IsUnspendable());
    }
    if (script.IsUnspendable()) {
        assert(which_type == TxoutType::NULL_DATA ||
               which_type == TxoutType::NONSTANDARD);
    }

    CTxDestination address;
    bool extract_destination_ret = ExtractDestination(script, address);
    if (!extract_destination_ret) {
        assert(which_type == TxoutType::PUBKEY ||
               which_type == TxoutType::NONSTANDARD ||
               which_type == TxoutType::NULL_DATA ||
               which_type == TxoutType::MULTISIG);
    }
    if (which_type == TxoutType::NONSTANDARD ||
        which_type == TxoutType::NULL_DATA ||
        which_type == TxoutType::MULTISIG) {
        assert(!extract_destination_ret);
    }

    const FlatSigningProvider signing_provider;
    (void)InferDescriptor(script, signing_provider);
    (void)IsSegWitOutput(signing_provider, script);

    (void)RecursiveDynamicUsage(script);

    std::vector<std::vector<unsigned char>> solutions;
    (void)Solver(script, solutions);

    (void)script.HasValidOps();
    (void)script.IsPayToScriptHash();
    (void)script.IsPayToWitnessScriptHash();
    (void)script.IsPushOnly();
    (void)script.GetSigOpCount(/* fAccurate= */ false);

    {
        const std::vector<uint8_t> bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider);
        CompressedScript compressed_script;
        compressed_script.assign(bytes.begin(), bytes.end());
        // DecompressScript(..., ..., bytes) is not guaranteed to be defined if the bytes vector is too short
        if (compressed_script.size() >= 32) {
            CScript decompressed_script;
            DecompressScript(decompressed_script, fuzzed_data_provider.ConsumeIntegral<unsigned int>(), compressed_script);
        }
    }

    const std::optional<CScript> other_script = ConsumeDeserializable<CScript>(fuzzed_data_provider);
    if (other_script) {
        {
            CScript script_mut{script};
            (void)FindAndDelete(script_mut, *other_script);
        }
        const std::vector<std::string> random_string_vector = ConsumeRandomLengthStringVector(fuzzed_data_provider);
        const uint32_t u32{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
        const uint32_t flags{u32 | SCRIPT_VERIFY_P2SH};
        {
            CScriptWitness wit;
            for (const auto& s : random_string_vector) {
                wit.stack.emplace_back(s.begin(), s.end());
            }
            (void)CountWitnessSigOps(script, *other_script, &wit, flags);
            wit.SetNull();
        }
    }

    (void)GetOpName(ConsumeOpcodeType(fuzzed_data_provider));
    (void)ScriptErrorString(static_cast<ScriptError>(fuzzed_data_provider.ConsumeIntegralInRange<int>(0, SCRIPT_ERR_ERROR_COUNT)));

    {
        const std::vector<uint8_t> bytes = ConsumeRandomLengthByteVector(fuzzed_data_provider);
        CScript append_script{bytes.begin(), bytes.end()};
        append_script << fuzzed_data_provider.ConsumeIntegral<int64_t>();
        append_script << ConsumeOpcodeType(fuzzed_data_provider);
        append_script << CScriptNum{fuzzed_data_provider.ConsumeIntegral<int64_t>()};
        append_script << ConsumeRandomLengthByteVector(fuzzed_data_provider);
    }

    {
        const CTxDestination tx_destination_1{
            fuzzed_data_provider.ConsumeBool() ?
                DecodeDestination(fuzzed_data_provider.ConsumeRandomLengthString()) :
                ConsumeTxDestination(fuzzed_data_provider)};
        const CTxDestination tx_destination_2{ConsumeTxDestination(fuzzed_data_provider)};
        const std::string encoded_dest{EncodeDestination(tx_destination_1)};
        const UniValue json_dest{DescribeAddress(tx_destination_1)};
        Assert(tx_destination_1 == DecodeDestination(encoded_dest));
        (void)GetKeyForDestination(/*store=*/{}, tx_destination_1);
        const CScript dest{GetScriptForDestination(tx_destination_1)};
        const bool valid{IsValidDestination(tx_destination_1)};
        Assert(dest.empty() != valid);

        Assert(valid == IsValidDestinationString(encoded_dest));

        (void)(tx_destination_1 < tx_destination_2);
        if (tx_destination_1 == tx_destination_2) {
            Assert(encoded_dest == EncodeDestination(tx_destination_2));
            Assert(json_dest.write() == DescribeAddress(tx_destination_2).write());
            Assert(dest == GetScriptForDestination(tx_destination_2));
        }
    }
}

void DebugPrint(const CScript& script, SigVersion sig_ver, std::pair<uint32_t, uint32_t> flags,
                std::pair<bool, bool> oks, std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> stacks)
{
    std::cout << "script: " << ScriptToAsmStr(script) << std::endl;
    std::cout << "flags0=" << std::bitset<32>(flags.first) << " flags1=" << std::bitset<32>(flags.second) << std::endl;
    std::cout << "ok0=" << oks.first << " ok1=" << oks.second << std::endl;
    std::cout << "sig_ver=" << (int)sig_ver << std::endl;

    std::cout << "begin stack0:" << std::endl;
    for (auto& elem : stacks.first) {
        std::cout << "-> "
                  << "'" << HexStr(elem) << "'" << std::endl;
    }
    std::cout << "end stack0" << std::endl;

    std::cout << "begin stack1:" << std::endl;
    for (auto& elem : stacks.second) {
        std::cout << "-> "
                  << "'" << HexStr(elem) << "'" << std::endl;
    }
    std::cout << "end stack1" << std::endl;
}

class SigChecker : public BaseSignatureChecker
{
    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey,
                             const CScript& scriptCode, SigVersion sigversion) const override
    {
        CSipHasher hasher{0, 0};
        return hasher.Write(scriptSig.data(), scriptSig.size())
                   .Write(vchPubKey.data(), vchPubKey.size())
                   .Finalize() &
               1;
    }

    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey,
                               SigVersion sigversion, ScriptExecutionData& execdata,
                               ScriptError* serror = nullptr) const override
    {
        CSipHasher hasher{0, 0};
        return hasher.Write(sig.data(), sig.size())
                   .Write(pubkey.data(), pubkey.size())
                   .Finalize() &
               1;
    }

    bool CheckLockTime(const CScriptNum& nLockTime) const override { return nLockTime.GetInt64() & 1; }
    bool CheckSequence(const CScriptNum& nSequence) const override { return nSequence.GetInt64() & 1; }
};

FUZZ_TARGET(script_stack_compare)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    int64_t tapscript_validation_weight_left{fuzzed_data_provider.ConsumeIntegral<int64_t>()};

    uint32_t flags{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    uint32_t flags_to_reduce{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    uint32_t flags_ = flags & ~flags_to_reduce;

    auto script_bytes = fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();
    CScript script{script_bytes.cbegin(), script_bytes.cend()};

    for (auto sig_ver : {SigVersion::BASE, SigVersion::WITNESS_V0, SigVersion::TAPSCRIPT}) {
        std::vector<std::vector<uint8_t>> stack;
        ScriptExecutionData execdata;
        execdata.m_validation_weight_left_init = true;
        execdata.m_validation_weight_left = tapscript_validation_weight_left;
        bool ok = EvalScript(stack, script, flags, SigChecker(), sig_ver, execdata);

        std::vector<std::vector<uint8_t>> stack_;
        ScriptExecutionData execdata_;
        execdata_.m_validation_weight_left_init = true;
        execdata_.m_validation_weight_left = tapscript_validation_weight_left;
        bool ok_ = EvalScript(stack_, script, flags_, SigChecker(), sig_ver, execdata_);

        if (!(!ok || ok_)) {
            // If script was valid under `flags` it should also be valid under `flags & ~(1 << flag_to_reduce)`.
            DebugPrint(script, sig_ver, {flags, flags_}, {ok, ok_}, {stack, stack_});
            abort();
        }

        // Stacks will only be equal if both scripts are valid.
        if (!ok || !ok_) continue;

        CSipHasher hasher{0, 0}, hasher_{0, 0};
        for (auto& elem : stack) {
            hasher.Write(elem.data(), elem.size());
        }
        for (auto& elem : stack_) {
            hasher_.Write(elem.data(), elem.size());
        }

        auto stack_hash{hasher.Finalize()};
        auto stack_hash_{hasher_.Finalize()};
        if (stack_hash != stack_hash_) {
            // If script was valid under both sets of flags, then the stacks should be the same.
            DebugPrint(script, sig_ver, {flags, flags_}, {ok, ok_}, {stack, stack_});
            abort();
        }
    }
}

