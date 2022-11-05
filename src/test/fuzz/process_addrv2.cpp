// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <chainparams.h>
#include <consensus/consensus.h>
#include <crypto/sha3.h>
#include <net.h>
#include <net_processing.h>
#include <protocol.h>
#include <scheduler.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <validationinterface.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iosfwd>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {
const TestingSetup* g_setup;

namespace torv3 {
// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135
static constexpr size_t CHECKSUM_LEN = 2;
static const unsigned char VERSION[] = {3};

static void Checksum(Span<const uint8_t> addr_pubkey, uint8_t (&checksum)[CHECKSUM_LEN])
{
    // TORv3 CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    static const unsigned char prefix[] = ".onion checksum";
    static constexpr size_t prefix_len = 15;

    SHA3_256 hasher;

    hasher.Write(Span{prefix}.first(prefix_len));
    hasher.Write(addr_pubkey);
    hasher.Write(VERSION);

    uint8_t checksum_full[SHA3_256::OUTPUT_SIZE];

    hasher.Finalize(checksum_full);

    memcpy(checksum, checksum_full, sizeof(checksum));
}

}; // namespace torv3
} // namespace


void initialize_process_addrv2()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
    SyncWithValidationInterfaceQueue();
}

template <typename Stream>
class AddrV2Input : public FuzzInput<Stream, /*with_rest=*/true>
{
public:
    virtual ~AddrV2Input() {}

    std::vector<CAddress> m_addrs;

    void Init(FastRandomContext& rnd) override
    {
        m_addrs.clear();
        m_addrs.push_back(CAddress{});
    }

    void MutateAddr(FastRandomContext& rnd, CAddress& addr)
    {
        // Mutate addr type
        Network network{addr.GetNetwork()};
        network = static_cast<Network>(MutateValue(static_cast<int>(network)) % (int)NET_MAX);
        auto addr_bytes{addr.GetAddrBytes()};

        CNetAddr net_addr;
        switch (network) {
        case NET_CJDNS:
        case NET_I2P:
        case NET_INTERNAL:
        case NET_UNROUTABLE:
        case NET_IPV4: {
            network = NET_IPV4;
            addr_bytes.resize(ADDR_IPV4_SIZE);
            LLVMFuzzerMutate(addr_bytes.data(), addr_bytes.size(), ADDR_IPV4_SIZE);
            in_addr v4{};
            v4.s_addr = ReadBE32(addr_bytes.data());
            net_addr = CNetAddr{v4};
            break;
        }
        case NET_IPV6: {
            addr_bytes.resize(ADDR_IPV6_SIZE);
            LLVMFuzzerMutate(addr_bytes.data(), addr_bytes.size(), ADDR_IPV6_SIZE);
            in6_addr v6{};
            std::memcpy(v6.s6_addr, addr_bytes.data(), ADDR_IPV6_SIZE);
            net_addr = CNetAddr{v6, 0};
            break;
        }
        case NET_ONION: {
            auto random_pub_key{rnd.randbytes(ADDR_TORV3_SIZE)};
            uint8_t check_sum[torv3::CHECKSUM_LEN];
            torv3::Checksum({random_pub_key.data(), random_pub_key.size()}, check_sum);

            std::vector<uint8_t> onion_addr;
            onion_addr.insert(onion_addr.end(), random_pub_key.begin(), random_pub_key.end());
            onion_addr.push_back(check_sum[0]);
            onion_addr.push_back(check_sum[1]);
            onion_addr.push_back(3);

            auto encoded{EncodeBase32({onion_addr.data(), onion_addr.size()})};
            encoded += ".onion";
            net_addr.SetSpecial(encoded);
            break;
        }
        case NET_MAX: break;
        }

        addr.SetIP(net_addr);
    }

    void Mutate(FastRandomContext& rnd) override
    {
        switch (rnd.rand32() % 3) {
        case 0: {
            CAddress addr{};
            MutateAddr(rnd, addr);
            m_addrs.push_back(addr);
            break;
        }
        case 1:
            // Mutate an addr;
            {
                if (m_addrs.size() < 1) break;
                uint64_t i{rnd.randrange(m_addrs.size())};

                switch (rnd.rand32() % 4) {
                case 0:
                    m_addrs[i].nServices = MutateValue(m_addrs[i].nServices);
                    break;
                case 1:
                    m_addrs[i].nTime = MutateValue(m_addrs[i].nTime);
                    break;
                case 2:
                    m_addrs[i].SetPort(MutateValue(m_addrs[i].GetPort()));
                    break;
                case 3: {
                    MutateAddr(rnd, m_addrs[i]);
                    break;
                }
                default: assert(false);
                }
            }
            break;
        case 2:
            // Shuffle addrs;
            Shuffle(m_addrs.begin(), m_addrs.end(), rnd);
            break;
        }
    }

    std::string ToString() const override
    {
        std::string out = "Addrv2Input:\n";
        for (const CAddress& addr : m_addrs) {
            out += addr.ToString();
            out += " | nServices: ";
            auto services{serviceFlagsToStr(addr.nServices)};
            for (auto& service : services) {
                out += service + ",";
            }
            // out += " | nTime: " + addr.nTime;
            out += "\n";
        }

        return out;
    }

    void Serialize(Stream& s) const override
    {
        s << m_addrs;
    }

    void Unserialize(Stream& s) override
    {
        m_addrs.clear();
        s >> m_addrs;
    }
};

std::string AddrV2InputToString(const FuzzBufferType& buffer)
{
    auto input{ReadFuzzInput<AddrV2Input>(buffer, PROTOCOL_VERSION | ADDRV2_FORMAT)};
    if (!input) {
        return "could not read input";
    }

    return input->ToStringFull();
}

size_t AddrV2InputMutator(uint8_t* data, size_t size, size_t max_size, unsigned int seed)
{
    return FuzzInputMutator<AddrV2Input, SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT>(data, size, max_size, seed);
}

FUZZ_TARGET_INIT_WITH_CUSTOM_MUTATOR(process_addrv2, initialize_process_addrv2, AddrV2InputMutator, AddrV2InputToString)
{
    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(g_setup->m_node.connman.get());
    TestChainState& chainstate = *static_cast<TestChainState*>(&g_setup->m_node.chainman->ActiveChainstate());
    SetMockTime(1610000000); // any time to successfully reset ibd
    chainstate.ResetIbd();

    auto input{ReadFuzzInput<AddrV2Input>(buffer, PROTOCOL_VERSION | ADDRV2_FORMAT)};
    if (!input) {
        return;
    }

    FuzzedDataProvider fuzzed_data_provider{input->GetDataProviderForRest()};

    LOCK(NetEventsInterface::g_msgproc_mutex);

    CNode& p2p_node = *ConsumeNodeAsUniquePtr(fuzzed_data_provider).release();
    connman.AddTestNode(p2p_node);
    FillNode(fuzzed_data_provider, connman, p2p_node);

    const auto mock_time = ConsumeTime(fuzzed_data_provider);
    SetMockTime(mock_time);

    CDataStream p2p_stream{SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT};
    p2p_stream << input->m_addrs;

    try {
        g_setup->m_node.peerman->ProcessMessage(p2p_node, "addrv2", p2p_stream,
                                                GetTime<std::chrono::microseconds>(), std::atomic<bool>{false});
    } catch (const std::ios_base::failure&) {
    }

    g_setup->m_node.peerman->SendMessages(&p2p_node);
    SyncWithValidationInterfaceQueue();
    g_setup->m_node.connman->StopNodes();
}
