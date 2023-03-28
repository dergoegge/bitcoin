#ifndef BITCOIN_NODE_CONNECTIONS_H
#define BITCOIN_NODE_CONNECTIONS_H

#include <net_permissions.h>
#include <netaddress.h>
#include <protocol.h>
#include <sync.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

typedef int64_t NodeId;

namespace node {

struct CSerializedNetMsg;
class CNetMessage;

class Connection
{
public:
    virtual NodeId GetId() const = 0;
    virtual std::chrono::seconds GetConnected() const = 0;
    virtual const CAddress& GetAddr() const = 0;
    virtual const CAddress& GetAddrBind() const = 0;
    virtual const std::string& GetAddrName() const = 0;
    virtual bool HasPermission(NetPermissionFlags permission) const = 0;
    virtual bool IsInboundOnionConn() const = 0;

    virtual void MarkAsSuccessfullyConnected() = 0;
    virtual bool IsSuccessfullyConnected() const = 0;

    virtual void Disconnect() = 0;
    virtual bool MarkedForDisconnect() const = 0;

    virtual bool IsSendingPaused() const = 0;

    virtual size_t PushMessage(CSerializedNetMsg&& msg, unsigned int max_buf_size) = 0;
    virtual std::optional<std::pair<CNetMessage, bool>> PollMessage() = 0;

    virtual bool IsOutboundOrBlockRelayConn() const = 0;
    virtual bool IsFullOutboundConn() const = 0;
    virtual bool IsManualConn() const = 0;
    virtual bool IsBlockOnlyConn() const = 0;
    virtual bool IsFeelerConn() const = 0;
    virtual bool IsAddrFetchConn() const = 0;
    virtual bool IsInboundConn() const = 0;
    virtual bool ExpectServicesFromConn() const = 0;

    /**
     * Get the connection's network.
     *
     * Returns Network::NET_ONION for *inbound* onion connections,
     * and CNetAddr::GetNetClass() otherwise. The latter cannot be used directly
     * because it doesn't detect the former, and it's not the responsibility of
     * the CNetAddr class to know the actual network a peer is connected through.
     *
     * @return network the peer connected through.
     */
    virtual Network ConnectedThroughNetwork() const = 0;

    virtual CService GetAddrLocal() const = 0;
    virtual void SetAddrLocal(const CService& addrLocalIn) = 0;

    virtual std::string ConnectionTypeAsString() const = 0;

    /** A ping-pong round trip has completed successfully. Update latest ping time. */
    virtual void PongReceived(std::chrono::microseconds ping_time) = 0;
};

bool IsPeerAddrLocalGood(Connection* conn);
/** Returns a local address that we should advertise to this peer. */
std::optional<CService> GetLocalAddrForPeer(Connection& conn);

class ConnectionsInterface
{
public:
    virtual bool ForNode(NodeId id, std::function<bool(Connection*)> func) = 0;
    using NodeFn = std::function<void(Connection*)>;
    virtual void ForEachNode(const NodeFn& func) = 0;
    virtual void ForEachNode(const NodeFn& func) const = 0;
    virtual void PushMessage(Connection* conn, CSerializedNetMsg&& msg) = 0;
    /** Get a unique deterministic randomizer. */
    virtual CSipHasher GetDeterministicRandomizer(uint64_t id) const = 0;
    virtual void WakeMessageHandler() = 0;
    //! check if the outbound target is reached
    //! if param historicalBlockServingLimit is set true, the function will
    //! response true if the limit for serving historical blocks has been reached
    virtual bool OutboundTargetReached(bool historicalBlockServingLimit) const = 0;
    /**
     * Return all or many randomly selected addresses, optionally by network.
     *
     * @param[in] max_addresses  Maximum number of addresses to return (0 = all).
     * @param[in] max_pct        Maximum percentage of addresses to return (0 = all).
     * @param[in] network        Select only addresses of this network (nullopt = all).
     */
    virtual std::vector<CAddress> GetAddresses(size_t max_addresses, size_t max_pct, std::optional<Network> network) const = 0;
    /**
     * Cache is used to minimize topology leaks, so it should
     * be used for all non-trusted calls, for example, p2p.
     * A non-malicious call (from RPC or a peer with addr permission) should
     * call the function without a parameter to avoid using the cache.
     */
    virtual std::vector<CAddress> GetAddresses(Connection& requestor, size_t max_addresses, size_t max_pct) = 0;
    virtual bool DisconnectNode(const CNetAddr& addr) = 0;
    // Return the number of outbound peers we have in excess of our target (eg,
    // if we previously called SetTryNewOutboundPeer(true), and have since set
    // to false, we may have extra peers that we wish to disconnect). This may
    // return a value less than (num_outbound_connections - num_outbound_slots)
    // in cases where some outbound connections are not yet fully connected, or
    // not yet fully disconnected.
    virtual int GetExtraFullOutboundCount() const = 0;
    // Count the number of block-relay-only peers we have over our limit.
    virtual int GetExtraBlockRelayCount() const = 0;
    // This allows temporarily exceeding m_max_outbound_full_relay, with the goal of finding
    // a peer that is better than all our current peers.
    virtual void SetTryNewOutboundPeer(bool flag) = 0;
    virtual bool GetTryNewOutboundPeer() const = 0;
    virtual bool GetNetworkActive() const = 0;
    virtual bool GetUseAddrmanOutgoing() const = 0;
    virtual void StartExtraBlockRelayPeers() = 0;
    /** Return true if we should disconnect the peer for failing an inactivity check. */
    virtual bool ShouldRunInactivityChecks(const Connection& node, std::chrono::seconds now) const = 0;

protected:
    ~ConnectionsInterface() = default;
};

/**
 * Interface for message handling
 */
class NetEventsInterface
{
public:
    /** Mutex for anything that is only accessed via the msg processing thread */
    static Mutex g_msgproc_mutex;

    /** Initialize a peer (setup state, queue any initial messages) */
    virtual void InitializeNode(Connection& conn, ServiceFlags our_services) = 0;

    /** Handle removal of a peer (clear state) */
    virtual void FinalizeNode(const Connection& conn) = 0;

    /**
    * Process protocol messages received from a given node
    *
    * @param[in]   pnode           The node which we have received messages from.
    * @param[in]   interrupt       Interrupt condition for processing threads
    * @return                      True if there is more work to be done
    */
    virtual bool ProcessMessages(Connection* pnode, std::atomic<bool>& interrupt) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /**
    * Send queued protocol messages to a given node.
    *
    * @param[in]   pnode           The node which we are sending messages to.
    * @return                      True if there is more work to be done
    */
    virtual bool SendMessages(Connection* pnode) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;


protected:
    /**
     * Protected destructor so that instances can only be deleted by derived classes.
     * If that restriction is no longer desired, this should be made public and virtual.
     */
    ~NetEventsInterface() = default;
};

}

#endif // BITCOIN_NODE_CONNECTIONS_H
