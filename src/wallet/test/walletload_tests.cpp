// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <script/descriptor.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_AUTO_TEST_SUITE(walletload_tests)

class DummyDescriptor final : public Descriptor {
private:
    std::string desc;
public:
    explicit DummyDescriptor(const std::string& descriptor) : desc(descriptor) {};
    ~DummyDescriptor() = default;

    std::string ToString(bool compat_format) const override { return desc; }
    std::optional<OutputType> GetOutputType() const override { return OutputType::UNKNOWN; }

    bool IsRange() const override { return false; }
    bool IsSolvable() const override { return false; }
    bool IsSingleType() const override { return true; }
    bool HavePrivateKeys(const SigningProvider&) const override { return false; }
    bool ToPrivateString(const SigningProvider& provider, std::string& out) const override { return false; }
    bool ToNormalizedString(const SigningProvider& provider, std::string& out, const DescriptorCache* cache = nullptr) const override { return false; }
    bool Expand(int pos, const SigningProvider& provider, std::vector<CScript>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override { return false; };
    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<CScript>& output_scripts, FlatSigningProvider& out) const override { return false; }
    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override {}
    std::optional<int64_t> ScriptSize() const override { return {}; }
    std::optional<int64_t> MaxSatisfactionWeight(bool) const override { return {}; }
    std::optional<int64_t> MaxSatisfactionElems() const override { return {}; }
    void GetPubKeys(std::set<CPubKey>& pubkeys, std::set<CExtPubKey>& ext_pubs) const override {}
    bool HasScripts() const override { return true; }
    std::vector<std::string> Warnings() const override { return {}; }
    uint32_t GetMaxKeyExpr() const override { return 0; }
    size_t GetKeyCount() const override { return 0; }
    bool CanSelfExpand() const final { return false; }
};

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptors, TestingSetup)
{
    bilingual_str _error;
    std::vector<bilingual_str> _warnings;
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    {
        // Write unknown active descriptor
        WalletBatch batch(*database);
        std::string unknown_desc = "trx(tpubD6NzVbkrYhZ4Y4S7m6Y5s9GD8FqEMBy56AGphZXuagajudVZEnYyBahZMgHNCTJc2at82YX6s8JiL1Lohu5A3v1Ur76qguNH4QVQ7qYrBQx/86'/1'/0'/0/*)#8pn8tzdt";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(unknown_desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256(), wallet_descriptor));
        BOOST_CHECK(batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(OutputType::UNKNOWN), uint256(), false));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::UNKNOWN_DESCRIPTOR);
    }

    // Test 2
    // Now write a valid descriptor with an invalid ID.
    // As the software produces another ID for the descriptor, the loading process must be aborted.
    database = CreateMockableWalletDatabase();

    // Verify the error
    bool found = false;
    DebugLogHelper logHelper("The descriptor ID calculated by the wallet differs from the one in DB", [&](const std::string* s) {
        found = true;
        return false;
    });

    {
        // Write valid descriptor with invalid ID
        WalletBatch batch(*database);
        std::string desc = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu";
        WalletDescriptor wallet_descriptor(std::make_shared<DummyDescriptor>(desc), 0, 0, 0, 0);
        BOOST_CHECK(batch.WriteDescriptor(uint256::ONE, wallet_descriptor));
    }

    {
        // Now try to load the wallet and verify the error.
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(_error, _warnings), DBErrors::CORRUPT);
        BOOST_CHECK(found); // The error must be logged
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_load_descriptor_cache_invalid_xpub_size, TestingSetup)
{
    // A descriptor cache record stores a serialized extended public key whose length is
    // expected to be exactly BIP32_EXTKEY_SIZE. CExtPubKey::Decode() reads that fixed
    // number of bytes, so a record encoding a shorter xpub would make the loader read
    // past the end of the deserialized buffer. Check that such a record is rejected as
    // database corruption instead.
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // A valid ranged descriptor. Its ID is computed the same way the loader recomputes it,
    // so the descriptor record loads successfully and the loader goes on to read the cache.
    const std::string desc_str = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu";
    FlatSigningProvider keys;
    std::string parse_error;
    std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, parse_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(descs.size() == 1, parse_error);
    std::shared_ptr<Descriptor> descriptor = std::move(descs.at(0));
    const uint256 desc_id = DescriptorID(*descriptor);

    // Build a fresh database holding the descriptor plus a single malformed cache record
    // (one byte short of BIP32_EXTKEY_SIZE) for the given cache type.
    auto make_db_with_short_cache_xpub = [&](const std::string& cache_type) {
        std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
        {
            WalletBatch batch(*database);
            WalletDescriptor wallet_descriptor(descriptor, 0, 0, 0, 0);
            BOOST_CHECK(batch.WriteDescriptor(desc_id, wallet_descriptor));
        }
        // The cache value is serialized as a vector, so the loader resizes ser_xpub to this
        // (too short) length before decoding. The key layout matches the parent cache record
        // written by WalletBatch::WriteDescriptorParentCache()/WriteDescriptorLastHardenedCache().
        const std::vector<unsigned char> short_xpub(BIP32_EXTKEY_SIZE - 1, 0);
        std::unique_ptr<DatabaseBatch> raw = database->MakeBatch();
        BOOST_CHECK(raw->Write(std::make_pair(std::make_pair(cache_type, desc_id), uint32_t{0}), short_xpub));
        return database;
    };

    // Parent/derived descriptor cache record.
    {
        std::unique_ptr<WalletDatabase> database = make_db_with_short_cache_xpub("walletdescriptorcache");
        bool found = false;
        DebugLogHelper log_helper("descriptor cache xpub has invalid size", [&](const std::string* s) {
            found = true;
            return false;
        });
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::CORRUPT);
        BOOST_CHECK(found);
    }

    // Last hardened descriptor cache record.
    {
        std::unique_ptr<WalletDatabase> database = make_db_with_short_cache_xpub("walletdescriptorlhcache");
        bool found = false;
        DebugLogHelper log_helper("descriptor last hardened cache xpub has invalid size", [&](const std::string* s) {
            found = true;
            return false;
        });
        const std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(database)));
        BOOST_CHECK_EQUAL(wallet->PopulateWalletFromDB(error, warnings), DBErrors::CORRUPT);
        BOOST_CHECK(found);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
