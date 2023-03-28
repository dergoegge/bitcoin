#ifndef BITCOIN_NODE_NET_H
#define BITCOIN_NODE_NET_H

#include <netaddress.h>
#include <protocol.h>
#include <streams.h>
#include <sync.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace node {

struct CSerializedNetMsg {
    CSerializedNetMsg() = default;
    CSerializedNetMsg(CSerializedNetMsg&&) = default;
    CSerializedNetMsg& operator=(CSerializedNetMsg&&) = default;
    // No implicit copying, only moves.
    CSerializedNetMsg(const CSerializedNetMsg& msg) = delete;
    CSerializedNetMsg& operator=(const CSerializedNetMsg&) = delete;

    CSerializedNetMsg Copy() const
    {
        CSerializedNetMsg copy;
        copy.data = data;
        copy.m_type = m_type;
        return copy;
    }

    std::vector<unsigned char> data;
    std::string m_type;
};

/** Transport protocol agnostic message container.
 * Ideally it should only contain receive time, payload,
 * type and size.
 */
class CNetMessage {
public:
    CDataStream m_recv;                  //!< received message data
    std::chrono::microseconds m_time{0}; //!< time of message receipt
    uint32_t m_message_size{0};          //!< size of the payload
    uint32_t m_raw_message_size{0};      //!< used wire size of the message (including header/checksum)
    std::string m_type;

    CNetMessage(CDataStream&& recv_in) : m_recv(std::move(recv_in)) {}
    // Only one CNetMessage object will exist for the same message on either
    // the receive or processing queue. For performance reasons we therefore
    // delete the copy constructor and assignment operator to avoid the
    // possibility of copying CNetMessage objects.
    CNetMessage(CNetMessage&&) = default;
    CNetMessage(const CNetMessage&) = delete;
    CNetMessage& operator=(CNetMessage&&) = default;
    CNetMessage& operator=(const CNetMessage&) = delete;

    void SetVersion(int nVersionIn)
    {
        m_recv.SetVersion(nVersionIn);
    }
};


/**
 * Look up IP addresses from all interfaces on the machine and add them to the
 * list of local addresses to self-advertise.
 * The loopback interface is skipped and only the first address from each
 * interface is used.
 */
void Discover();

uint16_t GetListenPort();

enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_MAPPED, // address reported by UPnP or NAT-PMP
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};

/**
 * Mark a network as reachable or unreachable (no automatic connects to it)
 * @note Networks are reachable by default
 */
void SetReachable(enum Network net, bool reachable);
/** @returns true if the network is reachable, false otherwise */
bool IsReachable(enum Network net);
/** @returns true if the address is in a reachable network, false otherwise */
bool IsReachable(const CNetAddr& addr);

bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
void RemoveLocal(const CService& addr);
bool SeenLocal(const CService& addr);
bool IsLocal(const CService& addr);
bool GetLocal(CService& addr, const CNetAddr* paddrPeer = nullptr);
int GetnScore(const CService& addr);

CService GetLocalAddress(const CNetAddr& addrPeer);
CService MaybeFlipIPv6toCJDNS(const CService& service);

extern bool fDiscover;
extern bool fListen;

/** Subversion as sent to the P2P network in `version` messages */
extern std::string strSubVersion;

struct LocalServiceInfo {
    int nScore;
    uint16_t nPort;
};

extern GlobalMutex g_maplocalhost_mutex;
extern std::map<CNetAddr, LocalServiceInfo> mapLocalHost GUARDED_BY(g_maplocalhost_mutex);

/** Dump binary message to file, with timestamp */
void CaptureMessageToFile(const CAddress& addr,
                          const std::string& msg_type,
                          Span<const unsigned char> data,
                          bool is_incoming);

/** Defaults to `CaptureMessageToFile()`, but can be overridden by unit tests. */
extern std::function<void(const CAddress& addr,
                          const std::string& msg_type,
                          Span<const unsigned char> data,
                          bool is_incoming)>
    CaptureMessage;

}

#endif // BITCOIN_NODE_NET_H
