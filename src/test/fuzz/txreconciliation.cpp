#include <net.h>
#include <node/txreconciliation.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <limits>
#include <set>
#include <vector>

static constexpr int MAX_PEERS = 16;
static std::array<uint256, 64> WTXIDS;
static_assert(WTXIDS.size() <= std::numeric_limits<uint8_t>::max());
std::array<std::chrono::microseconds, 256> DELAYS;

static void initialize_txrecon_fuzz()
{
    for (size_t i = 0; i < WTXIDS.size(); ++i) {
        WTXIDS[i] = uint256{(uint8_t)i};
    }

    int i = 0;
    // DELAYS[N] for N=0..15 is just N microseconds.
    for (; i < 16; ++i) {
        DELAYS[i] = std::chrono::microseconds{i};
    }
    // DELAYS[N] for N=16..127 has randomly-looking but roughly exponentially increasing values up to
    // 198.416453 seconds.
    for (; i < 128; ++i) {
        int diff_bits = ((i - 10) * 2) / 9;
        uint64_t diff = 1 + (CSipHasher(0, 0).Write(i).Finalize() >> (64 - diff_bits));
        DELAYS[i] = DELAYS[i - 1] + std::chrono::microseconds{diff};
    }
    // DELAYS[N] for N=128..255 are negative delays with the same magnitude as N=0..127.
    for (; i < 256; ++i) {
        DELAYS[i] = -DELAYS[255 - i];
    }
}

uint256 ConsumeWtxid(FuzzedDataProvider& fuzzed_data_provider)
{
    return fuzzed_data_provider.PickValueInArray(WTXIDS);
}

NodeId ConsumeNodeId(FuzzedDataProvider& fuzzed_data_provider)
{
    return fuzzed_data_provider.ConsumeIntegralInRange<NodeId>(0, MAX_PEERS);
}

class TxReconTester
{
public:
    TxReconciliationTracker tracker;

    std::chrono::microseconds now{244466666};

    std::set<NodeId> pre_registered_peers;
    std::set<NodeId> registered_peers;
    std::map<NodeId, std::set<uint256>> local_sets;

    TxReconTester(uint32_t version)
        : tracker{/*recon_version=*/version} {}

    void AdvanceTime(std::chrono::microseconds delay)
    {
        now += delay;
    }

    void PreRegisterPeer(NodeId peer_id)
    {
        if (pre_registered_peers.count(peer_id) > 0) return;
        pre_registered_peers.insert(peer_id);
        tracker.PreRegisterPeer(peer_id);
    }
    void RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                      uint32_t peer_recon_version, uint64_t remote_salt)
    {
        switch (tracker.RegisterPeer(peer_id, is_peer_inbound, peer_recon_version, remote_salt)) {
        case ReconciliationRegisterResult::ALREADY_REGISTERED:
            assert(registered_peers.count(peer_id) > 0);
            break;
        case ReconciliationRegisterResult::NOT_FOUND:
            assert(pre_registered_peers.count(peer_id) == 0);
            assert(registered_peers.count(peer_id) == 0);
            break;
        case ReconciliationRegisterResult::PROTOCOL_VIOLATION:
            break;
        case ReconciliationRegisterResult::SUCCESS:
            assert(pre_registered_peers.count(peer_id) > 0);
            registered_peers.insert(peer_id);
            break;
        }
    }

    void ForgetPeer(NodeId peer_id)
    {
        assert(tracker.IsPeerRegistered(peer_id) == registered_peers.count(peer_id) > 0);
        tracker.ForgetPeer(peer_id);
        pre_registered_peers.erase(peer_id);
        registered_peers.erase(peer_id);
        local_sets.erase(peer_id);
    }

    void AddToSet(NodeId peer_id, const std::vector<uint256>& txs_to_reconcile)
    {
        if (registered_peers.count(peer_id) == 0 || txs_to_reconcile.empty()) return;

        assert(tracker.IsPeerRegistered(peer_id));

        // All already existing txids must also be in the oracle set.
        for (auto id : txs_to_reconcile) {
            bool already_in_set{tracker.IsAlreadyInPeerSet(peer_id, id)};
            assert(already_in_set == local_sets[peer_id].count(id) > 0);
        }

        tracker.AddToSet(peer_id, txs_to_reconcile);

        // TODO it would be nicer if AddToSet returned the number of added txids.
        for (auto id : txs_to_reconcile) {
            bool already_in_set{tracker.IsAlreadyInPeerSet(peer_id, id)};
            assert(already_in_set);
            local_sets[peer_id].insert(id);
        }
    }
    void TryRemovingFromSet(NodeId peer_id, const uint256& wtxid_to_remove)
    {
        if (registered_peers.count(peer_id) == 0) return;

        bool was_in_set{tracker.IsAlreadyInPeerSet(peer_id, wtxid_to_remove)};
        tracker.TryRemovingFromSet(peer_id, wtxid_to_remove);
        // Can't be in set afterwards
        assert(!tracker.IsAlreadyInPeerSet(peer_id, wtxid_to_remove));
        // If the txid was removed then it must be in the oracle set
        bool removed_from_oracle{local_sets[peer_id].erase(wtxid_to_remove) > 0};
        assert(!was_in_set || removed_from_oracle);
    }

    void MaybeRequestReconciliation(NodeId peer_id)
    {
        // TODO could also verify reconcil interval
        if (auto result = tracker.MaybeRequestReconciliation(peer_id, now)) {
            const auto& [set_size, _] = *result;
            assert(set_size == local_sets[peer_id].size());
        } else {
            // TODO this happens if the peer is not registered, we dont
            // initiate reconcils or the phase is not NONE???.
            // assert(registered_peers.count(peer_id) == 0);
            // assert(!tracker.IsPeerRegistered(peer_id));
        }
    }

    void ShouldFloodTo(NodeId peer_id, const uint256& wtxid) const
    {
        // TODO keep track of stats and check in the end that we didnt flood to
        // too many peers.
        tracker.ShouldFloodTo(peer_id, wtxid);
    }
};

FUZZ_TARGET_INIT(txrecon, initialize_txrecon_fuzz)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    TxReconTester tester{/*version=*/fuzzed_data_provider.ConsumeIntegral<uint32_t>()};

    while (fuzzed_data_provider.remaining_bytes()) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                tester.AdvanceTime(fuzzed_data_provider.PickValueInArray(DELAYS));
            },
            [&] {
                tester.PreRegisterPeer(ConsumeNodeId(fuzzed_data_provider));
            },
            [&] {
                tester.RegisterPeer(
                    ConsumeNodeId(fuzzed_data_provider),
                    fuzzed_data_provider.ConsumeBool(),
                    fuzzed_data_provider.ConsumeIntegral<uint32_t>(),
                    fuzzed_data_provider.ConsumeIntegral<uint64_t>());
            },
            [&] {
                tester.ForgetPeer(ConsumeNodeId(fuzzed_data_provider));
            },
            [&] {
                std::vector<uint256> wtxids_to_add;
                for (int i = 0; i < fuzzed_data_provider.ConsumeIntegralInRange<int>(0, WTXIDS.size()); ++i) {
                    wtxids_to_add.push_back(ConsumeWtxid(fuzzed_data_provider));
                }
                tester.AddToSet(ConsumeNodeId(fuzzed_data_provider), wtxids_to_add);
            },
            [&] {
                tester.TryRemovingFromSet(ConsumeNodeId(fuzzed_data_provider), ConsumeWtxid(fuzzed_data_provider));
            },
            [&] {
                tester.MaybeRequestReconciliation(ConsumeNodeId(fuzzed_data_provider));
            },
            [&] {
                tester.ShouldFloodTo(ConsumeNodeId(fuzzed_data_provider), ConsumeWtxid(fuzzed_data_provider));
            });
    }
}
