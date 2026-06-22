// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The "adv_*" RPC namespace turns a node into a programmable network adversary
// for full-system / antithesis style testing. It mirrors the capabilities of
// the fuzzamoto IR (https://github.com/dergoegge/fuzzamoto): open arbitrary
// connections, send raw/malformed p2p messages over the node's own p2p stack
// and construct adversarial blocks. Adversarial transaction construction lives
// in the wallet ("chaoswallet").
//
// These commands are only registered when the node is started with
// -adversarial and must never be reachable on a node connected to mainnet
// peers: they allow attacking the network the node is part of.

#include <addrman.h>
#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <common/urandom.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <net.h>
#include <netaddress.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <validation.h>
#include <versionbits.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <netinet/in.h>
#include <optional>
#include <set>
#include <vector>

using node::NodeContext;

static RPCMethod adv_connect()
{
    return RPCMethod{
        "adv_connect",
        "Open an outbound connection to a node of a chosen connection type.\n"
        "Unlike the test-only `addconnection`, this works on any chain and is gated by -adversarial.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The IP address and port to connect to."},
            {"connection_type", RPCArg::Type::STR, RPCArg::Default{"outbound-full-relay"}, "Type of connection to open (\"outbound-full-relay\", \"block-relay-only\", \"addr-fetch\" or \"feeler\")."},
            {"v2transport", RPCArg::Type::BOOL, RPCArg::Default{false}, "Attempt to connect using the BIP324 v2 transport protocol."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Address of the newly added connection."},
                {RPCResult::Type::STR, "connection_type", "Type of connection opened."},
            }},
        RPCExamples{
            HelpExampleCli("adv_connect", "\"192.168.0.6:8333\" \"outbound-full-relay\" true") + HelpExampleRpc("adv_connect", "\"192.168.0.6:8333\", \"outbound-full-relay\", true")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const std::string address{request.params[0].get_str()};
            auto conn_type_in{util::TrimStringView(self.Arg<std::string_view>("connection_type"))};
            ConnectionType conn_type{};
            if (conn_type_in == "outbound-full-relay") {
                conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
            } else if (conn_type_in == "block-relay-only") {
                conn_type = ConnectionType::BLOCK_RELAY;
            } else if (conn_type_in == "addr-fetch") {
                conn_type = ConnectionType::ADDR_FETCH;
            } else if (conn_type_in == "feeler") {
                conn_type = ConnectionType::FEELER;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, self.ToString());
            }
            const bool use_v2transport{self.Arg<bool>("v2transport")};

            NodeContext& node = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node);

            if (use_v2transport && !(connman.GetLocalServices() & NODE_P2P_V2)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Error: Adding v2transport connections requires -v2transport init flag to be set.");
            }

            if (!connman.AddConnection(address, conn_type, use_v2transport)) {
                throw JSONRPCError(RPC_CLIENT_NODE_CAPACITY_REACHED, "Error: Already at capacity for specified connection type.");
            }

            UniValue info(UniValue::VOBJ);
            info.pushKV("address", address);
            info.pushKV("connection_type", std::string{conn_type_in});
            return info;
        },
    };
}

static RPCMethod adv_disconnect()
{
    return RPCMethod{
        "adv_disconnect",
        "Immediately disconnect a peer by node id.\n",
        {
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to disconnect (see getpeerinfo for node ids)."},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the peer was found and disconnected."},
        RPCExamples{HelpExampleCli("adv_disconnect", "0") + HelpExampleRpc("adv_disconnect", "0")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const NodeId peer_id{request.params[0].getInt<int64_t>()};
            NodeContext& node = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node);
            return connman.DisconnectNode(peer_id);
        },
    };
}

static RPCMethod adv_sendrawmessage()
{
    return RPCMethod{
        "adv_sendrawmessage",
        "Send a raw (possibly malformed) p2p message to a peer over the node's own p2p stack.\n"
        "The message header is generated; the body is sent verbatim, so arbitrary/invalid payloads are possible.\n",
        {
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to send the message to."},
            {"msg_type", RPCArg::Type::STR, RPCArg::Optional::NO, strprintf("The message type (maximum length %i). May be a non-existent type.", CMessageHeader::MESSAGE_TYPE_SIZE)},
            {"msg", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "The serialized message body in hex, without a message header."},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the message was queued for the peer."},
        RPCExamples{
            HelpExampleCli("adv_sendrawmessage", "0 \"addr\" \"ffffff\"") + HelpExampleRpc("adv_sendrawmessage", "0, \"addr\", \"ffffff\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const NodeId peer_id{request.params[0].getInt<int64_t>()};
            const auto msg_type{self.Arg<std::string_view>("msg_type")};
            if (msg_type.size() > CMessageHeader::MESSAGE_TYPE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Error: msg_type too long, max length is %i", CMessageHeader::MESSAGE_TYPE_SIZE));
            }
            auto msg{TryParseHex<unsigned char>(self.Arg<std::string_view>("msg"))};
            if (!msg.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Error parsing input for msg");
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node);

            CSerializedNetMsg msg_ser;
            msg_ser.data = std::move(msg.value());
            msg_ser.m_type = msg_type;

            const bool success = connman.ForNode(peer_id, [&](CNode* pnode) {
                connman.PushMessage(pnode, std::move(msg_ser));
                return true;
            });
            return success;
        },
    };
}

//! Parse a compact difficulty target ("nbits") given as 4 hex bytes, e.g. "207fffff".
static uint32_t ParseCompactBits(std::string_view hex)
{
    const auto bytes{TryParseHex<uint8_t>(hex)};
    if (!bytes || bytes->size() != 4) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "nbits must be exactly 4 hex bytes (e.g. \"207fffff\")");
    }
    const auto& b{*bytes};
    return (uint32_t{b[0]} << 24) | (uint32_t{b[1]} << 16) | (uint32_t{b[2]} << 8) | uint32_t{b[3]};
}

static RPCMethod adv_buildblock()
{
    return RPCMethod{
        "adv_buildblock",
        "Construct a block with full adversarial control over every field and return it as hex.\n"
        "Every parameter is optional and defaults to a value that extends the active tip; override\n"
        "fields to build invalid/adversarial blocks (bad proof-of-work, wrong merkle root, oversized\n"
        "coinbase, out-of-order transactions, ...). The block is NOT submitted; pair with adv_sendblock\n"
        "to deliver it to a peer or submitblock to process it locally.\n",
        {
            {"prev", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"active tip"}, "Hash of the previous block to build on."},
            {"version", RPCArg::Type::NUM, RPCArg::DefaultHint{"0x20000000"}, "Block version (nVersion)."},
            {"time", RPCArg::Type::NUM, RPCArg::DefaultHint{"prev time + 1"}, "Block timestamp (nTime)."},
            {"nbits", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"next required work"}, "Compact difficulty target as 4 hex bytes."},
            {"nonce", RPCArg::Type::NUM, RPCArg::Default{0}, "Block nonce. Ignored if solve=true."},
            {"coinbase", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"auto (pays OP_TRUE)"}, "Raw coinbase transaction in hex."},
            {"txs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Additional raw transactions in hex, appended after the coinbase.",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                }},
            {"merkle_root", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"computed"}, "Override hashMerkleRoot (to build a block with an invalid merkle root)."},
            {"commit", RPCArg::Type::BOOL, RPCArg::Default{true}, "Add/refresh the segwit witness commitment in the coinbase."},
            {"solve", RPCArg::Type::BOOL, RPCArg::Default{true}, "Grind the nonce until the proof-of-work is valid."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "The block hash."},
                {RPCResult::Type::STR_HEX, "hex", "The serialized block."},
                {RPCResult::Type::BOOL, "solved", "Whether the block has a valid proof-of-work."},
            }},
        RPCExamples{
            HelpExampleCli("adv_buildblock", "'{\"solve\": false, \"nonce\": 0}'") + HelpExampleRpc("adv_buildblock", "{\"solve\": false}")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const Consensus::Params& consensus{chainman.GetConsensus()};

            auto prev_arg{self.MaybeArg<std::string_view>("prev")};
            auto version_arg{self.MaybeArg<int64_t>("version")};
            auto time_arg{self.MaybeArg<int64_t>("time")};
            auto nbits_arg{self.MaybeArg<std::string_view>("nbits")};
            const uint64_t nonce_arg{self.Arg<uint64_t>("nonce")};
            auto coinbase_arg{self.MaybeArg<std::string_view>("coinbase")};
            auto merkle_arg{self.MaybeArg<std::string_view>("merkle_root")};
            const bool commit{self.Arg<bool>("commit")};
            const bool solve{self.Arg<bool>("solve")};

            CBlock block;
            const CBlockIndex* prev_index{nullptr};
            {
                LOCK(cs_main);
                if (prev_arg) {
                    const uint256 prev_hash{ParseHashV(request.params[0], "prev")};
                    prev_index = chainman.m_blockman.LookupBlockIndex(prev_hash);
                    if (!prev_index) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "prev block not found");
                    }
                } else {
                    prev_index = chainman.ActiveChain().Tip();
                    if (!prev_index) throw JSONRPCError(RPC_INTERNAL_ERROR, "No active chain tip");
                }

                block.hashPrevBlock = prev_index->GetBlockHash();
                block.nVersion = version_arg ? static_cast<int32_t>(*version_arg) : VERSIONBITS_TOP_BITS;
                block.nTime = time_arg ? static_cast<uint32_t>(*time_arg) : static_cast<uint32_t>(prev_index->nTime + 1);
                block.nBits = nbits_arg ? ParseCompactBits(*nbits_arg) : GetNextWorkRequired(prev_index, &block, consensus);
                block.nNonce = static_cast<uint32_t>(nonce_arg);
            }

            const int height{prev_index->nHeight + 1};

            // Coinbase: use the supplied one, or build a minimal BIP34-compliant coinbase paying to OP_TRUE.
            CMutableTransaction coinbase;
            if (coinbase_arg) {
                if (!DecodeHexTx(coinbase, std::string{*coinbase_arg})) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "coinbase decode failed");
                }
            } else {
                coinbase.vin.resize(1);
                coinbase.vin[0].prevout.SetNull();
                coinbase.vin[0].scriptSig = CScript() << height << OP_0;
                coinbase.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
                // Witness reserved value, required for the segwit commitment.
                coinbase.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
                coinbase.vout.resize(1);
                coinbase.vout[0].nValue = GetBlockSubsidy(height, consensus);
                coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
            }
            block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

            if (!request.params[6].isNull()) {
                for (const UniValue& rawtx : request.params[6].get_array().getValues()) {
                    CMutableTransaction mtx;
                    if (!DecodeHexTx(mtx, rawtx.get_str())) {
                        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("tx decode failed for %s", rawtx.get_str()));
                    }
                    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
                }
            }

            if (commit) {
                LOCK(cs_main);
                chainman.GenerateCoinbaseCommitment(block, prev_index);
            }

            if (merkle_arg) {
                block.hashMerkleRoot = ParseHashV(request.params[7], "merkle_root");
            } else {
                block.hashMerkleRoot = BlockMerkleRoot(block);
            }

            if (solve) {
                while (block.nNonce < std::numeric_limits<uint32_t>::max() &&
                       !CheckProofOfWork(block.GetHash(), block.nBits, consensus) &&
                       !chainman.m_interrupt) {
                    ++block.nNonce;
                }
            }

            DataStream ss;
            ss << TX_WITH_WITNESS(block);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hash", block.GetHash().GetHex());
            result.pushKV("hex", HexStr(ss));
            result.pushKV("solved", CheckProofOfWork(block.GetHash(), block.nBits, consensus));
            return result;
        },
    };
}

static RPCMethod adv_sendblock()
{
    return RPCMethod{
        "adv_sendblock",
        "Send a serialized block to a peer as a `block` message over the node's own p2p stack.\n"
        "The block is sent verbatim and is not validated locally, so invalid blocks can be delivered.\n",
        {
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to send the block to."},
            {"block", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The serialized block in hex (e.g. from adv_buildblock)."},
            {"with_witness", RPCArg::Type::BOOL, RPCArg::Default{true}, "Serialize the block with witness data. Set false to strip witnesses."},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the block was queued for the peer."},
        RPCExamples{HelpExampleCli("adv_sendblock", "0 \"<blockhex>\"") + HelpExampleRpc("adv_sendblock", "0, \"<blockhex>\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const NodeId peer_id{request.params[0].getInt<int64_t>()};
            CBlock block;
            if (!DecodeHexBlk(block, request.params[1].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "block decode failed");
            }
            const bool with_witness{self.Arg<bool>("with_witness")};

            DataStream ss;
            if (with_witness) {
                ss << TX_WITH_WITNESS(block);
            } else {
                ss << TX_NO_WITNESS(block);
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node);

            CSerializedNetMsg msg;
            msg.m_type = NetMsgType::BLOCK;
            msg.data.resize(ss.size());
            std::memcpy(msg.data.data(), ss.data(), ss.size());

            const bool success = connman.ForNode(peer_id, [&](CNode* pnode) {
                connman.PushMessage(pnode, std::move(msg));
                return true;
            });
            return success;
        },
    };
}

// ---------------------------------------------------------------------------
// Autonomous generators
//
// Each generator is a parameterless RPC that ports the decision logic of the
// corresponding fuzzamoto IR generator into the node. Every random choice is
// read directly from /dev/urandom (UrandomSource), so a fuzzer controlling the
// entropy device (antithesis) drives the construction; the RPC is only the
// trigger. Generators use the node's own context (peers, chain, mempool,
// addrman) and send over the node's own p2p stack.
// ---------------------------------------------------------------------------

namespace {
//! A compact block with an adversarial prefill set / short ids (see fuzzamoto's
//! CompactBlockGenerator). Reused by the compact-block generator below.
class AdvCompactBlock : public CBlockHeaderAndShortTxIDs
{
public:
    AdvCompactBlock(const CBlock& block, uint64_t custom_nonce, UrandomSource& rng)
        : CBlockHeaderAndShortTxIDs(block, custom_nonce)
    {
        const size_t n{block.vtx.size()};
        std::set<uint16_t> prefill;
        const size_t num_prefill{static_cast<size_t>(rng.randrange(n + 1))};
        for (size_t i = 0; i < num_prefill; ++i) prefill.insert(static_cast<uint16_t>(rng.randrange(n)));
        prefilledtxn.clear();
        shorttxids.clear();
        int32_t last{-1};
        for (size_t i = 0; i < n; ++i) {
            if (prefill.contains(static_cast<uint16_t>(i))) {
                prefilledtxn.push_back(PrefilledTransaction{static_cast<uint16_t>(static_cast<int32_t>(i) - last - 1), block.vtx[i]});
                last = static_cast<int32_t>(i);
            } else {
                uint64_t id{GetShortID(block.vtx[i]->GetWitnessHash())};
                if (rng.randrange(8) == 0) id ^= (rng.rand64() & 0xffffffffffffULL);
                shorttxids.push_back(id);
            }
        }
    }
};
} // namespace

//! Result helper.
static UniValue AdvResult(bool sent, std::string_view what)
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("sent", sent);
    r.pushKV("action", std::string{what});
    return r;
}

//! Collect the ids of all currently connected peers.
static std::vector<NodeId> ConnectedPeers(CConnman& connman)
{
    std::vector<NodeId> ids;
    connman.ForEachNode([&ids](CNode* n) { ids.push_back(n->GetId()); });
    return ids;
}

//! Push a freshly serialized message body to a random connected peer.
static bool PushRandom(CConnman& connman, UrandomSource& rng, const std::string& type, DataStream&& ss)
{
    const std::vector<NodeId> peers{ConnectedPeers(connman)};
    if (peers.empty()) return false;
    const NodeId id{peers[rng.randrange(peers.size())]};
    CSerializedNetMsg msg;
    msg.m_type = type;
    msg.data.resize(ss.size());
    if (!ss.empty()) std::memcpy(msg.data.data(), ss.data(), ss.size());
    return connman.ForNode(id, [&](CNode* n) {
        connman.PushMessage(n, std::move(msg));
        return true;
    });
}

//! Random byte buffer with a fuzzing-friendly length distribution.
static std::vector<unsigned char> RandomBytes(UrandomSource& rng, size_t cap)
{
    static constexpr std::array<size_t, 6> kSmall{0, 1, 2, 4, 8, 32};
    size_t len{rng.randrange(10) == 0 ? static_cast<size_t>(rng.randrange(cap + 1)) : kSmall[rng.randrange(kSmall.size())]};
    if (len > cap) len = cap;
    return rng.randbytes(len);
}

//! A random block index on the active chain (nullptr if the chain is empty).
static const CBlockIndex* RandomBlockIndex(ChainstateManager& chainman, UrandomSource& rng) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const CChain& chain{chainman.ActiveChain()};
    const int height{chain.Height()};
    if (height < 0) return nullptr;
    return chain[static_cast<int>(rng.randrange(static_cast<uint64_t>(height) + 1))];
}

//! Build a random IPv4/IPv6 CAddress with random services/port/time.
static CAddress RandomAddress(UrandomSource& rng)
{
    CNetAddr net;
    if (rng.randbool()) {
        struct in_addr v4 {};
        v4.s_addr = rng.rand32();
        net = CNetAddr{v4};
    } else {
        struct in6_addr v6 {};
        const auto bytes{rng.randbytes(16)};
        std::memcpy(&v6, bytes.data(), 16);
        net = CNetAddr{v6};
    }
    CAddress addr{CService{net, rng.rand16()}, static_cast<ServiceFlags>(rng.rand64())};
    addr.nTime = NodeSeconds{std::chrono::seconds{rng.rand32()}};
    return addr;
}

// ---- Generator bodies -----------------------------------------------------

static UniValue GenSendMessage(NodeContext& node, UrandomSource& rng)
{
    // SendMessageGenerator: random peer, random message type, random payload.
    static const std::array<const char*, 38> kTypes{
        "version", "verack", "addr", "addrv2", "sendaddrv2", "inv", "getdata", "notfound",
        "getblocks", "getheaders", "mempool", "tx", "block", "headers", "sendheaders",
        "getaddr", "ping", "pong", "merkleblock", "filterload", "filteradd", "filterclear",
        "getcfilters", "cfilter", "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt",
        "sendcmpct", "cmpctblock", "getblocktxn", "blocktxn", "feefilter", "wtxidrelay",
        "sendtxrcncl", "reqtxrcncl", "sketch", "reconcildiff"};
    const std::string type{kTypes[rng.randrange(kTypes.size())]};
    DataStream ss;
    for (unsigned char b : RandomBytes(rng, 1024)) ss << b;
    return AdvResult(PushRandom(EnsureConnman(node), rng, type, std::move(ss)), "sendmessage:" + type);
}

//! Shared inventory builder for inv / getdata.
static DataStream BuildRandomInventory(NodeContext& node, UrandomSource& rng)
{
    std::vector<CInv> inv;
    const CTxMemPool* mempool{node.mempool.get()};
    if (mempool) {
        for (const auto& info : mempool->infoAll()) {
            if (rng.randbool()) continue;
            static constexpr std::array<uint32_t, 3> kTx{MSG_TX, MSG_WTX, MSG_WITNESS_TX};
            const uint32_t t{kTx[rng.randrange(kTx.size())]};
            inv.emplace_back(t, t == MSG_WTX ? info.tx->GetWitnessHash().ToUint256() : info.tx->GetHash().ToUint256());
            if (inv.size() >= 50) break;
        }
    }
    ChainstateManager& chainman{EnsureChainman(node)};
    {
        LOCK(cs_main);
        for (int i = 0; i < 8; ++i) {
            const CBlockIndex* pindex{RandomBlockIndex(chainman, rng)};
            if (!pindex) break;
            static constexpr std::array<uint32_t, 4> kBlk{MSG_BLOCK, MSG_WITNESS_BLOCK, MSG_FILTERED_BLOCK, MSG_CMPCT_BLOCK};
            inv.emplace_back(kBlk[rng.randrange(kBlk.size())], pindex->GetBlockHash());
        }
    }
    DataStream ss;
    ss << inv;
    return ss;
}

static UniValue GenSendInv(NodeContext& node, UrandomSource& rng)
{
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::INV, BuildRandomInventory(node, rng)), "inv");
}

static UniValue GenSendGetData(NodeContext& node, UrandomSource& rng)
{
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::GETDATA, BuildRandomInventory(node, rng)), "getdata");
}

static UniValue GenGetAddr(NodeContext& node, UrandomSource& rng)
{
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::GETADDR, DataStream{}), "getaddr");
}

static UniValue GenSendAddr(NodeContext& node, UrandomSource& rng, bool v2)
{
    std::vector<CAddress> addrs;
    const size_t count{static_cast<size_t>(rng.randrange(1000) + 1)};
    for (size_t i = 0; i < count; ++i) addrs.push_back(RandomAddress(rng));
    DataStream ss;
    if (v2) {
        ss << CAddress::V2_NETWORK(addrs);
    } else {
        ss << CAddress::V1_NETWORK(addrs);
    }
    return AdvResult(PushRandom(EnsureConnman(node), rng, v2 ? NetMsgType::ADDRV2 : NetMsgType::ADDR, std::move(ss)), v2 ? "addrv2" : "addr");
}

static UniValue GenFilterLoad(NodeContext& node, UrandomSource& rng)
{
    // init_filter: random size, optional random bytes, random hashfuncs/tweak/flags.
    const size_t size{static_cast<size_t>(rng.randrange(36000))};
    std::vector<unsigned char> filter(size, 0);
    if (rng.randbool() && size) filter = rng.randbytes(size);
    const uint32_t hash_funcs{static_cast<uint32_t>(rng.randrange(50) + 1)};
    const uint32_t tweak{rng.rand32()};
    const uint8_t flags{static_cast<uint8_t>(rng.randrange(3))};
    DataStream ss;
    ss << filter << hash_funcs << tweak << flags;
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::FILTERLOAD, std::move(ss)), "filterload");
}

static UniValue GenFilterAdd(NodeContext& node, UrandomSource& rng)
{
    DataStream ss;
    ss << RandomBytes(rng, 520);
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::FILTERADD, std::move(ss)), "filteradd");
}

static UniValue GenFilterClear(NodeContext& node, UrandomSource& rng)
{
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::FILTERCLEAR, DataStream{}), "filterclear");
}

static UniValue GenCFilterQuery(NodeContext& node, UrandomSource& rng)
{
    ChainstateManager& chainman{EnsureChainman(node)};
    uint256 stop_hash;
    {
        LOCK(cs_main);
        if (const CBlockIndex* pindex{RandomBlockIndex(chainman, rng)}) stop_hash = pindex->GetBlockHash();
    }
    const uint8_t filter_type{static_cast<uint8_t>(rng.randrange(4) == 0 ? rng.rand8() : 0)};
    const uint32_t start_height{static_cast<uint32_t>(rng.randrange(200))};
    DataStream ss;
    const char* type{nullptr};
    switch (rng.randrange(3)) {
    case 0:
        ss << filter_type << start_height << stop_hash;
        type = NetMsgType::GETCFILTERS;
        break;
    case 1:
        ss << filter_type << start_height << stop_hash;
        type = NetMsgType::GETCFHEADERS;
        break;
    default:
        ss << filter_type << stop_hash;
        type = NetMsgType::GETCFCHECKPT;
        break;
    }
    return AdvResult(PushRandom(EnsureConnman(node), rng, type, std::move(ss)), type);
}

static UniValue GenSendCompactBlock(NodeContext& node, UrandomSource& rng)
{
    ChainstateManager& chainman{EnsureChainman(node)};
    CBlock block;
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{RandomBlockIndex(chainman, rng)};
        if (!pindex || !chainman.m_blockman.ReadBlock(block, *pindex)) return AdvResult(false, "compactblock:noblock");
    }
    if (block.vtx.empty()) return AdvResult(false, "compactblock:empty");
    AdvCompactBlock cmpct{block, rng.rand64(), rng};
    DataStream ss;
    ss << static_cast<const CBlockHeaderAndShortTxIDs&>(cmpct);
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::CMPCTBLOCK, std::move(ss)), "cmpctblock");
}

static UniValue GenSendBlockTxn(NodeContext& node, UrandomSource& rng)
{
    ChainstateManager& chainman{EnsureChainman(node)};
    CBlock block;
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{RandomBlockIndex(chainman, rng)};
        if (!pindex || !chainman.m_blockman.ReadBlock(block, *pindex)) return AdvResult(false, "blocktxn:noblock");
    }
    BlockTransactions resp;
    resp.blockhash = rng.randrange(16) == 0 ? rng.rand<uint256>() : block.GetHash();
    if (!block.vtx.empty()) {
        const size_t count{static_cast<size_t>(rng.randrange(block.vtx.size() + 1))};
        for (size_t i = 0; i < count; ++i) resp.txn.push_back(block.vtx[rng.randrange(block.vtx.size())]);
    }
    DataStream ss;
    ss << resp;
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::BLOCKTXN, std::move(ss)), "blocktxn");
}

static UniValue GenSendTx(NodeContext& node, UrandomSource& rng)
{
    // Pick a random mempool transaction and relay it (optionally witness-stripped).
    const CTxMemPool* mempool{node.mempool.get()};
    if (!mempool) return AdvResult(false, "tx:nomempool");
    std::vector<CTransactionRef> txs;
    for (const auto& info : mempool->infoAll()) txs.push_back(info.tx);
    if (txs.empty()) return AdvResult(false, "tx:empty");
    const CTransactionRef tx{txs[rng.randrange(txs.size())]};
    DataStream ss;
    if (rng.randbool()) {
        ss << TX_WITH_WITNESS(*tx);
    } else {
        ss << TX_NO_WITNESS(*tx);
    }
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::TX, std::move(ss)), "tx");
}

static UniValue GenSendHeaders(NodeContext& node, UrandomSource& rng)
{
    ChainstateManager& chainman{EnsureChainman(node)};
    std::vector<CBlockHeader> headers;
    {
        LOCK(cs_main);
        const size_t count{static_cast<size_t>(rng.randrange(8) + 1)};
        for (size_t i = 0; i < count; ++i) {
            const CBlockIndex* pindex{RandomBlockIndex(chainman, rng)};
            if (!pindex) break;
            headers.push_back(pindex->GetBlockHeader());
        }
    }
    DataStream ss;
    WriteCompactSize(ss, headers.size());
    for (const CBlockHeader& h : headers) {
        ss << h;
        WriteCompactSize(ss, 0); // txn_count, as in the headers wire format
    }
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::HEADERS, std::move(ss)), "headers");
}

static UniValue GenSendBlock(NodeContext& node, UrandomSource& rng)
{
    // Build a block extending a random chain block with a minimal coinbase and a
    // random subset of mempool transactions, then deliver it (with/without witness).
    ChainstateManager& chainman{EnsureChainman(node)};
    const Consensus::Params& consensus{chainman.GetConsensus()};
    CBlock block;
    int height{0};
    {
        LOCK(cs_main);
        const CBlockIndex* prev{RandomBlockIndex(chainman, rng)};
        if (!prev) return AdvResult(false, "block:notip");
        height = prev->nHeight + 1;
        block.hashPrevBlock = prev->GetBlockHash();
        block.nVersion = rng.randrange(4) ? VERSIONBITS_TOP_BITS : static_cast<int32_t>(rng.rand32());
        block.nTime = static_cast<uint32_t>(prev->nTime + 1 + rng.randrange(16));
        block.nBits = GetNextWorkRequired(prev, &block, consensus);
        block.nNonce = 0;
    }
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << height << OP_0;
    cb.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    cb.vout.resize(1);
    cb.vout[0].nValue = GetBlockSubsidy(height, consensus);
    cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));

    if (const CTxMemPool* mempool{node.mempool.get()}) {
        for (const auto& info : mempool->infoAll()) {
            if (rng.randbool()) block.vtx.push_back(info.tx);
        }
    }
    {
        LOCK(cs_main);
        const CBlockIndex* prev{chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock)};
        if (prev) chainman.GenerateCoinbaseCommitment(block, prev);
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);
    if (rng.randbool()) {
        while (block.nNonce < std::numeric_limits<uint32_t>::max() &&
               !CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
            ++block.nNonce;
        }
    }
    DataStream ss;
    if (rng.randbool()) {
        ss << TX_WITH_WITNESS(block);
    } else {
        ss << TX_NO_WITNESS(block);
    }
    return AdvResult(PushRandom(EnsureConnman(node), rng, NetMsgType::BLOCK, std::move(ss)), "block");
}

static UniValue GenAddConnection(NodeContext& node, UrandomSource& rng)
{
    // AddConnectionGenerator: open a random number of connections of a random
    // type to addresses the node already knows (current peers / addrman).
    CConnman& connman{EnsureConnman(node)};
    std::vector<std::string> targets;
    connman.ForEachNode([&targets](CNode* n) { targets.push_back(n->addr.ToStringAddrPort()); });
    if (targets.empty()) {
        AddrMan& addrman{EnsureAddrman(node)};
        const auto [addr, _t]{addrman.Select()};
        if (addr.IsValid()) targets.push_back(addr.ToStringAddrPort());
    }
    if (targets.empty()) return AdvResult(false, "addconnection:notargets");
    static constexpr std::array<ConnectionType, 4> kTypes{
        ConnectionType::OUTBOUND_FULL_RELAY, ConnectionType::BLOCK_RELAY,
        ConnectionType::ADDR_FETCH, ConnectionType::FEELER};
    const size_t num{static_cast<size_t>(rng.randrange(5) + 1)};
    size_t opened{0};
    for (size_t i = 0; i < num; ++i) {
        const std::string& target{targets[rng.randrange(targets.size())]};
        if (connman.AddConnection(target, kTypes[rng.randrange(kTypes.size())], /*use_v2transport=*/rng.randbool())) ++opened;
    }
    return AdvResult(opened > 0, strprintf("addconnection:%u", opened));
}

//! Build a parameterless generator RPC from a body function.
using AdvGenFn = std::function<UniValue(NodeContext&, UrandomSource&)>;
static RPCMethod MakeGenerator(const char* name, const char* description, AdvGenFn body)
{
    return RPCMethod{
        name, description, {},
        RPCResult{RPCResult::Type::ANY, "", "An object with at least {sent: bool, action: str}."},
        RPCExamples{HelpExampleCli(name, "") + HelpExampleRpc(name, "")},
        [body](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            UrandomSource rng;
            return body(node, rng);
        }};
}

#define ADV_GEN(rpcname, desc, fn) \
    static RPCMethod rpcname() { return MakeGenerator(#rpcname, desc, fn); }

ADV_GEN(adv_gen_sendmessage, "Send a random p2p message (random type + random payload) to a random peer. All choices from /dev/urandom.", GenSendMessage)
ADV_GEN(adv_gen_inv, "Send an inv with a random set of known txs/blocks and random inventory types to a random peer.", GenSendInv)
ADV_GEN(adv_gen_getdata, "Send a getdata with a random set of known txs/blocks and random inventory types to a random peer.", GenSendGetData)
ADV_GEN(adv_gen_getaddr, "Send getaddr to a random peer.", GenGetAddr)
ADV_GEN(adv_gen_addr, "Send an addr message with a random list of random addresses to a random peer.", [](NodeContext& n, UrandomSource& r) { return GenSendAddr(n, r, /*v2=*/false); })
ADV_GEN(adv_gen_addrv2, "Send an addrv2 message with a random list of random addresses to a random peer.", [](NodeContext& n, UrandomSource& r) { return GenSendAddr(n, r, /*v2=*/true); })
ADV_GEN(adv_gen_filterload, "Send a BIP37 filterload with random parameters to a random peer.", GenFilterLoad)
ADV_GEN(adv_gen_filteradd, "Send a BIP37 filteradd with random data to a random peer.", GenFilterAdd)
ADV_GEN(adv_gen_filterclear, "Send a BIP37 filterclear to a random peer.", GenFilterClear)
ADV_GEN(adv_gen_cfilterquery, "Send a random BIP157 getcfilters/getcfheaders/getcfcheckpt to a random peer.", GenCFilterQuery)
ADV_GEN(adv_gen_compactblock, "Send a cmpctblock for a random known block with a random prefill set / nonce to a random peer.", GenSendCompactBlock)
ADV_GEN(adv_gen_blocktxn, "Send a blocktxn with a random (possibly wrong) set of transactions to a random peer.", GenSendBlockTxn)
ADV_GEN(adv_gen_tx, "Relay a random mempool transaction (with or without witness) to a random peer.", GenSendTx)
ADV_GEN(adv_gen_headers, "Send a headers message built from random known headers to a random peer.", GenSendHeaders)
ADV_GEN(adv_gen_block, "Build a block on a random chain block (random coinbase/txs/version) and send it to a random peer.", GenSendBlock)
ADV_GEN(adv_gen_addconnection, "Open a random number of connections of random types to known addresses.", GenAddConnection)

void RegisterAdversarialRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"adversarial", &adv_connect},
        {"adversarial", &adv_disconnect},
        {"adversarial", &adv_sendrawmessage},
        {"adversarial", &adv_buildblock},
        {"adversarial", &adv_sendblock},
        {"adversarial", &adv_gen_sendmessage},
        {"adversarial", &adv_gen_inv},
        {"adversarial", &adv_gen_getdata},
        {"adversarial", &adv_gen_getaddr},
        {"adversarial", &adv_gen_addr},
        {"adversarial", &adv_gen_addrv2},
        {"adversarial", &adv_gen_filterload},
        {"adversarial", &adv_gen_filteradd},
        {"adversarial", &adv_gen_filterclear},
        {"adversarial", &adv_gen_cfilterquery},
        {"adversarial", &adv_gen_compactblock},
        {"adversarial", &adv_gen_blocktxn},
        {"adversarial", &adv_gen_tx},
        {"adversarial", &adv_gen_headers},
        {"adversarial", &adv_gen_block},
        {"adversarial", &adv_gen_addconnection},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
