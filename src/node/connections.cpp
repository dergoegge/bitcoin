#include <logging.h>
#include <net_permissions.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/connections.h>
#include <node/net.h>
#include <protocol.h>
#include <util/system.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace node {

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(Connection* conn)
{
    CService addrLocal = conn->GetAddrLocal();
    return fDiscover && conn->GetAddr().IsRoutable() && addrLocal.IsRoutable() &&
           IsReachable(addrLocal.GetNetwork());
}

std::optional<CService> GetLocalAddrForPeer(Connection& conn)
{
    CService addrLocal{GetLocalAddress(conn.GetAddr())};
    if (gArgs.GetBoolArg("-addrmantest", false)) {
        // use IPv4 loopback during addrmantest
        addrLocal = CService(LookupNumeric("127.0.0.1", GetListenPort()));
    }
    // If discovery is enabled, sometimes give our peer the address it
    // tells us that it sees us as in case it has a better idea of our
    // address than we do.
    FastRandomContext rng;
    if (IsPeerAddrLocalGood(&conn) && (!addrLocal.IsRoutable() ||
         rng.randbits((GetnScore(addrLocal) > LOCAL_MANUAL) ? 3 : 1) == 0))
    {
        if (conn.IsInboundConn()) {
            // For inbound connections, assume both the address and the port
            // as seen from the peer.
            addrLocal = CService{conn.GetAddrLocal()};
        } else {
            // For outbound connections, assume just the address as seen from
            // the peer and leave the port in `addrLocal` as returned by
            // `GetLocalAddress()` above. The peer has no way to observe our
            // listening port when we have initiated the connection.
            addrLocal.SetIP(conn.GetAddrLocal());
        }
    }
    if (addrLocal.IsRoutable() || gArgs.GetBoolArg("-addrmantest", false))
    {
        LogPrint(BCLog::NET, "Advertising address %s to peer=%d\n", addrLocal.ToStringAddrPort(), conn.GetId());
        return addrLocal;
    }
    // Address is unroutable. Don't advertise.
    return std::nullopt;
}

}
