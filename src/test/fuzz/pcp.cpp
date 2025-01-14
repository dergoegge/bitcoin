#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>

#include <util/pcp.h>

FUZZ_TARGET(pcp_request_port_map)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    SetMockTime(ConsumeTime(fuzzed_data_provider));

    auto CreateSockOrig = CreateSock;
    CreateSock = [&fuzzed_data_provider](int, int, int) {
        return std::make_unique<FuzzedSock>(fuzzed_data_provider);
    };

    PCPMappingNonce nonce{};
    CNetAddr gateway{};
    CNetAddr bind{};
    auto port = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
    auto lifetime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

    PCPRequestPortMap(nonce, gateway, bind, port, lifetime, 3, std::chrono::milliseconds{10});

    CreateSock = CreateSockOrig;
}

FUZZ_TARGET(natpmp_request_port_map)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    SetMockTime(ConsumeTime(fuzzed_data_provider));

    auto CreateSockOrig = CreateSock;
    CreateSock = [&fuzzed_data_provider](int, int, int) {
        return std::make_unique<FuzzedSock>(fuzzed_data_provider);
    };

    CNetAddr gateway{};
    auto port = fuzzed_data_provider.ConsumeIntegral<uint16_t>();
    auto lifetime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

    NATPMPRequestPortMap(gateway, port, lifetime, 3, std::chrono::milliseconds{10});

    CreateSock = CreateSockOrig;
}
