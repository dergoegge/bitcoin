// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_NET_H
#define BITCOIN_TEST_UTIL_NET_H

#include <compat/compat.h>
#include <net.h>
#include <netaddress.h>
#include <node/connections.h>
#include <node/eviction_impl.h>
#include <util/sock.h>

#include <array>
#include <cassert>
#include <cstring>
#include <memory>
#include <string>

struct ConnmanTestMsg : public CConnman {
    using CConnman::CConnman;

    void SetPeerConnectTimeout(std::chrono::seconds timeout)
    {
        m_peer_connect_timeout = timeout;
    }

    void AddTestNode(CNode& node)
    {
        LOCK(m_nodes_mutex);
        m_nodes.push_back(&node);
    }
    void ClearTestNodes()
    {
        LOCK(m_nodes_mutex);
        for (CNode* node : m_nodes) {
            delete node;
        }
        m_nodes.clear();
    }

    void Handshake(CNode& node,
                   bool successfully_connected,
                   ServiceFlags remote_services,
                   ServiceFlags local_services,
                   int32_t version,
                   bool relay_txs)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);

    void ProcessMessagesOnce(CNode& node) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) { m_msgproc->ProcessMessages(&node, flagInterruptMsgProc); }

    void NodeReceiveMsgBytes(CNode& node, Span<const uint8_t> msg_bytes, bool& complete) const;

    bool ReceiveMsgFrom(CNode& node, CSerializedNetMsg& ser_msg) const;
};

constexpr ServiceFlags ALL_SERVICE_FLAGS[]{
    NODE_NONE,
    NODE_NETWORK,
    NODE_BLOOM,
    NODE_WITNESS,
    NODE_COMPACT_FILTERS,
    NODE_NETWORK_LIMITED,
};

constexpr NetPermissionFlags ALL_NET_PERMISSION_FLAGS[]{
    NetPermissionFlags::None,
    NetPermissionFlags::BloomFilter,
    NetPermissionFlags::Relay,
    NetPermissionFlags::ForceRelay,
    NetPermissionFlags::NoBan,
    NetPermissionFlags::Mempool,
    NetPermissionFlags::Addr,
    NetPermissionFlags::Download,
    NetPermissionFlags::Implicit,
    NetPermissionFlags::All,
};

constexpr ConnectionType ALL_CONNECTION_TYPES[]{
    ConnectionType::INBOUND,
    ConnectionType::OUTBOUND_FULL_RELAY,
    ConnectionType::MANUAL,
    ConnectionType::FEELER,
    ConnectionType::BLOCK_RELAY,
    ConnectionType::ADDR_FETCH,
};

constexpr auto ALL_NETWORKS = std::array{
    Network::NET_UNROUTABLE,
    Network::NET_IPV4,
    Network::NET_IPV6,
    Network::NET_ONION,
    Network::NET_I2P,
    Network::NET_CJDNS,
    Network::NET_INTERNAL,
};

/**
 * A mocked Sock alternative that returns a statically contained data upon read and succeeds
 * and ignores all writes. The data to be returned is given to the constructor and when it is
 * exhausted an EOF is returned by further reads.
 */
class StaticContentsSock : public Sock
{
public:
    explicit StaticContentsSock(const std::string& contents) : m_contents{contents}
    {
        // Just a dummy number that is not INVALID_SOCKET.
        m_socket = INVALID_SOCKET - 1;
    }

    ~StaticContentsSock() override { m_socket = INVALID_SOCKET; }

    StaticContentsSock& operator=(Sock&& other) override
    {
        assert(false && "Move of Sock into MockSock not allowed.");
        return *this;
    }

    ssize_t Send(const void*, size_t len, int) const override { return len; }

    ssize_t Recv(void* buf, size_t len, int flags) const override
    {
        const size_t consume_bytes{std::min(len, m_contents.size() - m_consumed)};
        std::memcpy(buf, m_contents.data() + m_consumed, consume_bytes);
        if ((flags & MSG_PEEK) == 0) {
            m_consumed += consume_bytes;
        }
        return consume_bytes;
    }

    int Connect(const sockaddr*, socklen_t) const override { return 0; }

    int Bind(const sockaddr*, socklen_t) const override { return 0; }

    int Listen(int) const override { return 0; }

    std::unique_ptr<Sock> Accept(sockaddr* addr, socklen_t* addr_len) const override
    {
        if (addr != nullptr) {
            // Pretend all connections come from 5.5.5.5:6789
            memset(addr, 0x00, *addr_len);
            const socklen_t write_len = static_cast<socklen_t>(sizeof(sockaddr_in));
            if (*addr_len >= write_len) {
                *addr_len = write_len;
                sockaddr_in* addr_in = reinterpret_cast<sockaddr_in*>(addr);
                addr_in->sin_family = AF_INET;
                memset(&addr_in->sin_addr, 0x05, sizeof(addr_in->sin_addr));
                addr_in->sin_port = htons(6789);
            }
        }
        return std::make_unique<StaticContentsSock>("");
    };

    int GetSockOpt(int level, int opt_name, void* opt_val, socklen_t* opt_len) const override
    {
        std::memset(opt_val, 0x0, *opt_len);
        return 0;
    }

    int SetSockOpt(int, int, const void*, socklen_t) const override { return 0; }

    int GetSockName(sockaddr* name, socklen_t* name_len) const override
    {
        std::memset(name, 0x0, *name_len);
        return 0;
    }

    bool SetNonBlocking() const override { return true; }

    bool IsSelectable() const override { return true; }

    bool Wait(std::chrono::milliseconds timeout,
              Event requested,
              Event* occurred = nullptr) const override
    {
        if (occurred != nullptr) {
            *occurred = requested;
        }
        return true;
    }

    bool WaitMany(std::chrono::milliseconds timeout, EventsPerSock& events_per_sock) const override
    {
        for (auto& [sock, events] : events_per_sock) {
            (void)sock;
            events.occurred = events.requested;
        }
        return true;
    }

private:
    const std::string m_contents;
    mutable size_t m_consumed{0};
};

std::vector<NodeEvictionCandidate> GetRandomNodeEvictionCandidates(int n_candidates, FastRandomContext& random_context);

// TODO move const data functions to ConnectionContext and inherit from Connection instead
class MockConnection : public CNode
{
public:
    MockConnection(ConnectionContext&& conn_ctx) : CNode(std::move(conn_ctx), nullptr) {}

    bool IsSendingPaused() const override { return false; }

    size_t PushMessage(node::CSerializedNetMsg&& msg, unsigned int max_buf_size) override
    {
        ++m_message_types_received[msg.m_type];
        m_received_messages.emplace_back(std::move(msg));
        return 0;
    }

    std::optional<std::pair<node::CNetMessage, bool>> PollMessage() override
    {
        if (m_send_queue.empty()) return std::nullopt;

        auto& msg = m_send_queue.front();

        CNetMessage net_msg(CDataStream{msg.data, SER_NETWORK, PROTOCOL_VERSION});
        net_msg.m_type = msg.m_type;
        net_msg.m_message_size = msg.data.size();
        net_msg.m_time = GetTime<std::chrono::microseconds>();

        m_send_queue.pop_front();

        return std::make_pair(std::move(net_msg), !m_send_queue.empty());
    }

    CService GetAddrLocal() const override { return CService(); }
    void SetAddrLocal(const CService& addrLocalIn) override {}

    std::deque<node::CSerializedNetMsg> m_send_queue;
    std::deque<node::CSerializedNetMsg> m_received_messages;
    std::map<std::string, uint64_t> m_message_types_received;
};


/** Mock the connections interface. */
class MockConnectionsInterface : public ConnectionsInterface
{
public:
    bool ForNode(NodeId id, std::function<bool(Connection* pnode)> func) override
    {
        auto& conn = m_conns.at(id);
        return !conn.MarkedForDisconnect() && conn.IsSuccessfullyConnected() && func(&conn);
    }
    using NodeFn = std::function<void(Connection*)>;
    void ForEachNode(const NodeFn& func) override
    {
        for (auto& [id, conn] : m_conns) {
            if (!conn.MarkedForDisconnect() && conn.IsSuccessfullyConnected()) func(&conn);
        }
    }
    void ForEachNode(const NodeFn& func) const override
    {
        for (auto& [id, conn] : m_conns) {
            if (!conn.MarkedForDisconnect() && conn.IsSuccessfullyConnected()) func((Connection*)&conn);
        }
    }
    void PushMessage(Connection* conn, CSerializedNetMsg&& msg) override
    {
        m_conns.at(conn->GetId()).PushMessage(std::move(msg), 0);
    }
    CSipHasher GetDeterministicRandomizer(uint64_t id) const override { return {0, 0}; }
    void WakeMessageHandler() override {}
    bool OutboundTargetReached(bool historicalBlockServingLimit) const override { return true; }
    std::vector<CAddress> GetAddresses(size_t max_addresses,
                                       size_t max_pct,
                                       std::optional<Network> network) const override { return {}; }
    std::vector<CAddress> GetAddresses(Connection& requestor, size_t max_addresses, size_t max_pct) override { return {}; }
    bool DisconnectNode(const CNetAddr& addr) override { return true; }
    int GetExtraFullOutboundCount() const override
    {
        int extra{0};
        for (auto& [id, conn] : m_conns)
            extra += conn.IsFullOutboundConn();
        return std::max(0, extra - MAX_OUTBOUND_FULL_RELAY_CONNECTIONS);
    }
    int GetExtraBlockRelayCount() const override { return 0; }
    void SetTryNewOutboundPeer(bool flag) override { m_try_new_outbound = flag; }
    bool GetTryNewOutboundPeer() const override { return m_try_new_outbound; }
    bool GetNetworkActive() const override { return true; }
    bool GetUseAddrmanOutgoing() const override { return true; }
    void StartExtraBlockRelayPeers() override {}
    bool ShouldRunInactivityChecks(const Connection& node, std::chrono::seconds now) const override { return true; }

    virtual ~MockConnectionsInterface() {}

    MockConnection& AddMockConnection(ConnectionContext&& ctx)
    {
        auto it = m_conns.emplace_hint(m_conns.end(), ctx.id, std::move(ctx));
        return it->second;
    }

    std::map<NodeId, MockConnection> m_conns;
    bool m_try_new_outbound{false};
};

#endif // BITCOIN_TEST_UTIL_NET_H
