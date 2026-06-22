// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// "chaoswallet": adversarial transaction construction in the wallet, mirroring
// the transaction-generation capabilities of the fuzzamoto IR
// (https://github.com/dergoegge/fuzzamoto).
//
// Two ideas drive the design:
//
//  * The node makes its own random choices, reading them directly from
//    /dev/urandom on every draw (UrandomSource, NOT FastRandomContext). A
//    deterministic hypervisor / coverage-guided fuzzer (e.g. antithesis) that
//    controls the entropy device therefore drives the construction of every
//    adversarial transaction. The RPC caller may pin individual fields, but is
//    not required to specify anything.
//
//  * The wallet tracks a wide variety of output script types (p2pkh, p2sh,
//    p2wpkh, p2wsh, p2tr, p2pk, multisig, ...) so the adversarial transactions
//    it produces remain spendable by the wallet and can be chained. The four
//    native descriptor-wallet output types are tracked out of the box;
//    adv_chaoswallet_setup imports descriptors for the remaining exotic types.
//
// The adv_* RPCs are only usable when the node was started with -adversarial.

#include <addresstype.h>
#include <coins.h>
#include <common/args.h>
#include <common/urandom.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coinselection.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <array>
#include <map>
#include <string>
#include <vector>

namespace wallet {

//! Throw unless the node was started with -adversarial.
static void EnsureAdversarialEnabled()
{
    if (!gArgs.GetBoolArg("-adversarial", DEFAULT_ADVERSARIAL)) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "chaoswallet RPCs are only available when the node is started with -adversarial");
    }
}

//! A random BIP32 extended private key string, derived from /dev/urandom.
static std::string RandomXprv(UrandomSource& rng)
{
    const std::vector<unsigned char> seed{rng.randbytes(32)};
    CExtKey master;
    master.SetSeed(std::as_bytes(std::span{seed}));
    return EncodeExtKey(master);
}

//! Parse and import a ranged descriptor so the wallet tracks (and can spend) the
//! script type it describes.
static void ImportChaosDescriptor(CWallet& wallet, const std::string& desc_str, int32_t range_end)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    FlatSigningProvider keys;
    std::string error;
    auto parsed{Parse(desc_str, keys, error, /*require_checksum=*/false)};
    if (parsed.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("chaos descriptor parse failed (%s): %s", desc_str, error));
    }
    WalletDescriptor w_desc(std::move(parsed.at(0)), /*creation_time=*/1, /*range_start=*/0, range_end, /*next_index=*/0);
    auto res{wallet.AddWalletDescriptor(w_desc, keys, /*label=*/"chaos", /*internal=*/false)};
    if (!res) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("could not add chaos descriptor '%s': %s", desc_str, util::ErrorString(res).original));
    }
    res->get().TopUp(range_end);
}

RPCMethod adv_chaoswallet_setup()
{
    return RPCMethod{
        "adv_chaoswallet_setup",
        "Import descriptors for a wide range of script types so the wallet tracks (and can later\n"
        "spend) outputs of each type produced by adv_createchaostx. The four native descriptor-wallet\n"
        "types (legacy/p2sh-segwit/p2wpkh/p2tr) are already tracked; this adds p2pk, p2wsh,\n"
        "p2sh-p2wsh and multisig (in p2wsh and p2sh). Fresh spendable keys are generated from\n"
        "/dev/urandom. Requires -adversarial.\n",
        {
            {"range", RPCArg::Type::NUM, RPCArg::Default{100}, "Number of scripts to pre-derive (track) per imported descriptor."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "The descriptors that were imported",
            {
                {RPCResult::Type::STR, "", "An imported descriptor"},
            }},
        RPCExamples{HelpExampleCli("adv_chaoswallet_setup", "") + HelpExampleRpc("adv_chaoswallet_setup", "")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            EnsureAdversarialEnabled();
            std::shared_ptr<CWallet> const pwallet{GetWalletForJSONRPCRequest(request)};
            if (!pwallet) return UniValue::VNULL;
            if (!pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "chaoswallet requires a descriptor wallet");
            }
            const int32_t range_end{request.params[0].isNull() ? 100 : static_cast<int32_t>(request.params[0].getInt<int64_t>())};

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);
            UrandomSource rng;

            // One fresh xprv per key slot so we never collide with existing wallet keys.
            const auto k = [&] { return RandomXprv(rng); };
            const std::vector<std::string> descriptors{
                strprintf("pk(%s/*)", k()),
                strprintf("wsh(pk(%s/*))", k()),
                strprintf("sh(wsh(pk(%s/*)))", k()),
                strprintf("wsh(multi(1,%s/*,%s/*))", k(), k()),
                strprintf("sh(multi(1,%s/*,%s/*))", k(), k()),
                // Taproot with a script-path leaf: the wallet tracks and can spend
                // both the key path and the script path (matches fuzzamoto BuildTaprootTree).
                strprintf("tr(%s/*,pk(%s/*))", k(), k()),
            };

            UniValue imported(UniValue::VARR);
            for (const std::string& desc : descriptors) {
                ImportChaosDescriptor(*pwallet, desc, range_end);
                imported.push_back(desc);
            }
            return imported;
        },
    };
}

//! Pick a scriptPubKey for a chaos output. Roughly half the time a fresh
//! destination of a random native output type is used; otherwise a random
//! already-tracked script is reused (covering the exotic types imported by
//! adv_chaoswallet_setup). Either way the wallet tracks the result.
//! A random public key derived from /dev/urandom.
static CPubKey RandomPubKey(UrandomSource& rng)
{
    CKey key;
    for (int attempt = 0; attempt < 8; ++attempt) {
        const auto bytes{rng.randbytes(32)};
        key.Set(bytes.begin(), bytes.end(), /*fCompressedIn=*/true);
        if (key.IsValid()) return key.GetPubKey();
    }
    // Extremely unlikely; fall back to a fixed key.
    std::vector<unsigned char> ones(32, 0x01);
    key.Set(ones.begin(), ones.end(), true);
    return key.GetPubKey();
}

//! One of the fuzzamoto tx output script types (rng.gen_range(0..8) in tx.rs).
//! These mirror the IR exactly and are intentionally not wallet-tracked.
static CScript RandomAdversarialScript(UrandomSource& rng)
{
    switch (rng.randrange(8)) {
    case 0: { // raw P2WSH wrapping a trivial OP_TRUE witness script
        const CScript inner{CScript() << OP_TRUE};
        return GetScriptForDestination(WitnessV0ScriptHash{inner});
    }
    case 1: // pay-to-anchor
        return GetScriptForDestination(PayToAnchor{});
    case 2: { // OP_RETURN with random data (kept under MAX_SCRIPT_SIZE so it stays block-valid)
        return CScript() << OP_RETURN << rng.randbytes(static_cast<size_t>(rng.randrange(8000)));
    }
    case 3: { // P2SH wrapping a trivial OP_TRUE redeem script
        const CScript inner{CScript() << OP_TRUE};
        return GetScriptForDestination(ScriptHash{inner});
    }
    case 4: // P2PK
        return CScript() << ToByteVector(RandomPubKey(rng)) << OP_CHECKSIG;
    case 5: // P2PKH
        return GetScriptForDestination(PKHash{RandomPubKey(rng)});
    case 6: // P2WPKH
        return GetScriptForDestination(WitnessV0KeyHash{RandomPubKey(rng)});
    default: { // P2TR via a taproot tree (fuzzamoto BuildTaprootTree): key-path only,
               // or, half the time, with one script-path leaf.
        const XOnlyPubKey internal{RandomPubKey(rng)};
        TaprootBuilder builder;
        if (rng.randbool()) {
            const CScript leaf{CScript() << ToByteVector(RandomPubKey(rng)) << OP_CHECKSIG};
            builder.Add(/*depth=*/0, leaf, TAPROOT_LEAF_TAPSCRIPT);
        }
        builder.Finalize(internal);
        return GetScriptForDestination(builder.GetOutput());
    }
    }
}

//! Pick a scriptPubKey for a chaos output. Half the time an IR-style adversarial
//! script of a random type is emitted (matching fuzzamoto's 8 output types);
//! otherwise a wallet-tracked script is used so the output stays spendable and
//! chaos transactions can be chained.
static CScript ChaosOutputScript(CWallet& wallet, UrandomSource& rng, std::vector<CScript>& tracked_cache)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (tracked_cache.empty()) {
        for (ScriptPubKeyMan* spk : wallet.GetAllScriptPubKeyMans()) {
            for (const CScript& s : spk->GetScriptPubKeys()) tracked_cache.push_back(s);
        }
    }

    if (rng.randbool()) {
        return RandomAdversarialScript(rng);
    }
    // Tracked path: a fresh native destination or a reused tracked script.
    if (tracked_cache.empty() || rng.randbool()) {
        static constexpr std::array kTypes{OutputType::LEGACY, OutputType::P2SH_SEGWIT, OutputType::BECH32, OutputType::BECH32M};
        const OutputType type{kTypes[rng.randrange(kTypes.size())]};
        if (auto dest{wallet.GetNewDestination(type, "chaos")}) {
            return GetScriptForDestination(*dest);
        }
    }
    if (!tracked_cache.empty()) {
        return tracked_cache[rng.randrange(tracked_cache.size())];
    }
    return CScript() << OP_TRUE;
}

//! Adversarially mutate witnesses post-signing (fuzzamoto WitnessGenerator /
//! TaprootTxoUseAnnex): with low probability append a random witness item or a
//! BIP341 annex (0x50-prefixed). These invalidate the input on purpose.
static void MaybeMutateWitnesses(CMutableTransaction& mtx, UrandomSource& rng)
{
    for (CTxIn& in : mtx.vin) {
        if (rng.randrange(8) == 0) {
            in.scriptWitness.stack.push_back(rng.randbytes(static_cast<size_t>(rng.randrange(40))));
        }
        if (rng.randrange(8) == 0) {
            std::vector<unsigned char> annex{0x50};
            const auto extra{rng.randbytes(static_cast<size_t>(rng.randrange(64)))};
            annex.insert(annex.end(), extra.begin(), extra.end());
            in.scriptWitness.stack.push_back(std::move(annex));
        }
    }
}

//! Random sighash type (incl. ANYONECANPAY variants) drawn from /dev/urandom.
static int RandomSighash(UrandomSource& rng)
{
    static constexpr std::array<int, 7> kTypes{
        SIGHASH_DEFAULT,
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    };
    return kTypes[rng.randrange(kTypes.size())];
}

RPCMethod adv_createchaostx()
{
    return RPCMethod{
        "adv_createchaostx",
        "Build an adversarial transaction from the wallet's spendable coins (chaoswallet).\n"
        "By default the node chooses everything itself (version, locktime, input/output counts,\n"
        "per-input sequences, output script types and the signing sighash type), reading each\n"
        "choice directly from /dev/urandom so an external fuzzer (e.g. antithesis) drives it. Any\n"
        "field may be pinned via options. Outputs pay to wallet-tracked scripts so the resulting\n"
        "transaction stays spendable and adversarial transactions can be chained. The transaction is\n"
        "returned as hex and is NOT broadcast; deliver it with adv_sendrawmessage (msg_type \"tx\")\n"
        "or sendrawtransaction. Requires -adversarial.\n",
        {
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional overrides; any omitted field is chosen randomly from /dev/urandom.",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "Transaction version."},
                    {"locktime", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "Transaction nLockTime."},
                    {"num_inputs", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "Number of wallet coins to spend."},
                    {"num_outputs", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "Number of outputs to create."},
                    {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"random per input"}, "Fixed nSequence applied to every input."},
                    {"sign", RPCArg::Type::BOOL, RPCArg::Default{true}, "Sign the inputs with the wallet."},
                    {"sighash", RPCArg::Type::STR, RPCArg::DefaultHint{"random"}, "Signature hash type (DEFAULT, ALL, NONE, SINGLE, optionally |ANYONECANPAY)."},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The serialized transaction."},
                {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                {RPCResult::Type::BOOL, "complete", "Whether all inputs were fully signed."},
            }},
        RPCExamples{
            HelpExampleCli("adv_createchaostx", "") + HelpExampleCli("adv_createchaostx", "'{\"num_outputs\": 5}'") + HelpExampleRpc("adv_createchaostx", "{}")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            EnsureAdversarialEnabled();
            std::shared_ptr<CWallet> const pwallet{GetWalletForJSONRPCRequest(request)};
            if (!pwallet) return UniValue::VNULL;

            const UniValue options{request.params[0].isNull() ? UniValue{UniValue::VOBJ} : request.params[0].get_obj()};
            const auto has = [&](const char* key) { return options.exists(key); };

            UrandomSource rng;

            CMutableTransaction mtx;
            mtx.version = has("version") ? static_cast<uint32_t>(options["version"].getInt<int64_t>())
                                         // Mostly 1..3, occasionally a wild value.
                                         : (rng.randrange(4) ? static_cast<uint32_t>(rng.randrange(3) + 1) : rng.rand32());
            // Default to a consensus-final transaction so it can be mined into an
            // adversarial block even though it may be non-standard. A caller can set
            // locktime/sequence explicitly to build intentionally non-final txs.
            mtx.nLockTime = has("locktime") ? static_cast<uint32_t>(options["locktime"].getInt<int64_t>()) : 0u;
            const bool fixed_seq{has("sequence")};
            const uint32_t seq_value{fixed_seq ? static_cast<uint32_t>(options["sequence"].getInt<int64_t>()) : 0};
            const bool sign{has("sign") ? options["sign"].get_bool() : true};
            const int sighash{has("sighash") ? ParseSighashString(options["sighash"]).value_or(SIGHASH_DEFAULT) : RandomSighash(rng)};

            LOCK(pwallet->cs_wallet);

            // Select inputs from the wallet's spendable coins.
            CoinsResult available{AvailableCoins(*pwallet)};
            std::vector<COutput> all{available.All()};
            if (all.empty()) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "wallet has no spendable coins");

            int num_inputs{has("num_inputs") ? static_cast<int>(options["num_inputs"].getInt<int64_t>())
                                             : static_cast<int>(rng.randrange(std::min<size_t>(all.size(), 4)) + 1)};
            num_inputs = std::clamp<int>(num_inputs, 1, static_cast<int>(all.size()));

            // Shuffle-by-selection: pick distinct random coins.
            std::map<COutPoint, Coin> coins;
            CAmount total_in{0};
            const int height{pwallet->GetLastBlockHeight()};
            for (int i = 0; i < num_inputs; ++i) {
                const size_t pick{static_cast<size_t>(rng.randrange(all.size()))};
                const COutput out{all[pick]};
                all.erase(all.begin() + pick);
                // Set the BIP68 disable bit so a v2+ transaction is not held back by a
                // relative timelock; combined with nLockTime==0 this keeps the tx final.
                const uint32_t seq{fixed_seq ? seq_value : (0x80000000u | (rng.rand32() & 0x7fffffffu))};
                mtx.vin.emplace_back(out.outpoint, CScript(), seq);
                coins[out.outpoint] = Coin(out.txout, height, /*coinbase=*/false);
                total_in += out.txout.nValue;
                if (all.empty()) break;
            }

            // Create outputs paying to wallet-tracked scripts (so they stay spendable).
            int num_outputs{has("num_outputs") ? static_cast<int>(options["num_outputs"].getInt<int64_t>())
                                               : static_cast<int>(rng.randrange(4) + 1)};
            num_outputs = std::max(1, num_outputs);
            std::vector<CScript> tracked_cache;
            const CAmount per{total_in / num_outputs};
            for (int i = 0; i < num_outputs; ++i) {
                const CAmount amount{i == num_outputs - 1 ? total_in - per * (num_outputs - 1) : per};
                mtx.vout.emplace_back(amount, ChaosOutputScript(*pwallet, rng, tracked_cache));
            }

            bool complete{true};
            if (sign) {
                EnsureWalletIsUnlocked(*pwallet);
                std::map<int, bilingual_str> input_errors;
                complete = pwallet->SignTransaction(mtx, coins, sighash, input_errors);
                // Low-probability adversarial witness/annex mutation (invalidates the
                // affected input on purpose). Skipped when the caller pins a sighash,
                // so adv_createchaostx({"sighash":...}) stays block-includable.
                if (!has("sighash")) MaybeMutateWitnesses(mtx, rng);
            }

            UniValue result{UniValue::VOBJ};
            result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            result.pushKV("txid", mtx.GetHash().GetHex());
            result.pushKV("complete", complete);
            return result;
        },
    };
}

} // namespace wallet
