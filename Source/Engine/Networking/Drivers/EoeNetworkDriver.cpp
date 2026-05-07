// Copyright (c) Wojciech Figat. All rights reserved.

#include "EoeNetworkDriver.h"
#include "Engine/Networking/NetworkChannelType.h"
#include "Engine/Networking/NetworkEvent.h"
#include "Engine/Networking/NetworkPeer.h"
#include "Engine/Networking/NetworkStats.h"
#include "Engine/Core/Log.h"
#include "Engine/Core/Collections/Array.h"
#include "Engine/Core/Collections/Dictionary.h"
#include "Engine/Core/Math/Math.h"
#include "Engine/Platform/Platform.h"
#include "Engine/Threading/Threading.h"
#include <string.h>  // memcmp

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <enet/enet.h>
#undef _WINSOCK_DEPRECATED_NO_WARNINGS
#undef SendMessage
#undef InterlockedIncrement
#undef InterlockedDecrement
#undef InterlockedCompareExchange
#undef InterlockedExchange
#undef InterlockedAdd

// ---------------------------------------------------------------------------
// STUN protocol constants (RFC 5389 / RFC 3489)
// ---------------------------------------------------------------------------
namespace
{
    constexpr uint32 STUN_MAGIC_COOKIE = 0x2112A442;

    // STUN message types (class | method, 14 bits packed)
    constexpr uint16 STUN_BINDING_REQUEST = 0x0001;
    constexpr uint16 STUN_BINDING_INDICATION = 0x0011;
    constexpr uint16 STUN_BINDING_SUCCESS = 0x0101;
    constexpr uint16 STUN_BINDING_ERROR = 0x0111;

    // STUN attribute types
    constexpr uint16 STUN_ATTR_MAPPED_ADDRESS = 0x0001;
    constexpr uint16 STUN_ATTR_CHANGE_REQUEST = 0x0003;
    constexpr uint16 STUN_ATTR_CHANGED_ADDRESS = 0x0005; // RFC 3489 (deprecated by 5780 OTHER-ADDRESS)
    constexpr uint16 STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    constexpr uint16 STUN_ATTR_RESPONSE_ORIGIN = 0x802B;
    constexpr uint16 STUN_ATTR_OTHER_ADDRESS = 0x802C;

    // CHANGE-REQUEST flag bits
    constexpr uint8 STUN_CHANGE_IP = 0x4;
    constexpr uint8 STUN_CHANGE_PORT = 0x2;

    // Address families used in STUN address attributes
    constexpr uint8 STUN_FAMILY_IPV4 = 0x01;
    constexpr uint8 STUN_FAMILY_IPV6 = 0x02;

    constexpr int32 STUN_HEADER_SIZE = 20;

    // Hole-punch retransmit / STUN retransmit cadence
    constexpr int32 STUN_MAX_RETRANSMITS = 5;
    constexpr double STUN_INITIAL_TIMEOUT_S = 0.1;  // doubled each retransmit, capped
    constexpr double STUN_MAX_TIMEOUT_S = 1.6;

    // Marker placed in the first 4 bytes of a hole-punch indication's transaction-id
    // so we can distinguish locally-emitted punches in inbound traffic if they ever loop back.
    constexpr uint32 STUN_HOLEPUNCH_TXID_TAG = 0x484F4C45; // 'HOLE'
}

// ---------------------------------------------------------------------------
// STUN message helpers (build / parse)
// ---------------------------------------------------------------------------
namespace
{
    FORCE_INLINE void Write16BE(uint8* p, uint16 v)
    {
        p[0] = (uint8)(v >> 8);
        p[1] = (uint8)(v & 0xFF);
    }

    FORCE_INLINE void Write32BE(uint8* p, uint32 v)
    {
        p[0] = (uint8)(v >> 24);
        p[1] = (uint8)(v >> 16);
        p[2] = (uint8)(v >> 8);
        p[3] = (uint8)(v & 0xFF);
    }

    FORCE_INLINE uint16 Read16BE(const uint8* p)
    {
        return (uint16)(((uint16)p[0] << 8) | (uint16)p[1]);
    }

    FORCE_INLINE uint32 Read32BE(const uint8* p)
    {
        return ((uint32)p[0] << 24) | ((uint32)p[1] << 16) | ((uint32)p[2] << 8) | (uint32)p[3];
    }

    void WriteStunHeader(uint8* buf, uint16 messageType, uint16 attributeBytes, const uint8 txid[12])
    {
        Write16BE(buf + 0, messageType);
        Write16BE(buf + 2, attributeBytes);
        Write32BE(buf + 4, STUN_MAGIC_COOKIE);
        Platform::MemoryCopy(buf + 8, txid, 12);
    }

    // Append a CHANGE-REQUEST attribute to a STUN message buffer.
    // Returns the number of bytes written (8: 4 header + 4 value).
    int32 AppendChangeRequest(uint8* p, uint8 flags)
    {
        Write16BE(p + 0, STUN_ATTR_CHANGE_REQUEST);
        Write16BE(p + 2, 4);
        p[4] = 0;
        p[5] = 0;
        p[6] = 0;
        p[7] = flags;
        return 8;
    }

    // Generate a 96-bit transaction id from time, a process counter, and a small random salt.
    // STUN only requires uniqueness across in-flight transactions, not cryptographic strength.
    void GenerateTxid(uint8 out[12], uint32 prefixTag = 0)
    {
        static volatile int64 counter = 0;
        const int64 c = Platform::InterlockedIncrement(&counter);
        const double t = Platform::GetTimeSeconds();
        const uint64 tBits = *reinterpret_cast<const uint64*>(&t);
        const uint32 r = (uint32)(tBits ^ (uint64)c ^ ((uint64)c >> 32));
        if (prefixTag != 0)
        {
            Write32BE(out + 0, prefixTag);
        }
        else
        {
            Write32BE(out + 0, r);
        }
        Write32BE(out + 4, (uint32)(tBits >> 32));
        Write32BE(out + 8, (uint32)c);
    }

    // Decode a STUN MAPPED-ADDRESS / XOR-MAPPED-ADDRESS / OTHER-ADDRESS attribute value into an ENetAddress.
    // For XOR variants pass `xored = true` and the message's transaction id.
    bool DecodeStunAddress(const uint8* attrValue, int32 attrLen, bool xored, const uint8 txid[12], ENetAddress& out)
    {
        if (attrLen < 8)
            return false;
        // attrValue[0] reserved, [1] family, [2..3] port, [4..] address bytes
        const uint8 family = attrValue[1];
        uint16 port = Read16BE(attrValue + 2);
        if (xored)
        {
            port ^= (uint16)(STUN_MAGIC_COOKIE >> 16);
        }
        out.port = port;
        out.sin6_scope_id = 0;
        Platform::MemoryClear(&out.host, sizeof(out.host));

        uint8* hostBytes = (uint8*)&out.host;
        if (family == STUN_FAMILY_IPV4)
        {
            if (attrLen < 8)
                return false;
            // Encode as IPv4-mapped IPv6 (::ffff:a.b.c.d)
            hostBytes[10] = 0xFF;
            hostBytes[11] = 0xFF;
            for (int i = 0; i < 4; i++)
            {
                uint8 b = attrValue[4 + i];
                if (xored)
                {
                    // Cookie bytes are big-endian: 0x21,0x12,0xA4,0x42
                    static const uint8 cookieBytes[4] = { 0x21, 0x12, 0xA4, 0x42 };
                    b ^= cookieBytes[i];
                }
                hostBytes[12 + i] = b;
            }
            return true;
        }
        if (family == STUN_FAMILY_IPV6)
        {
            if (attrLen < 20)
                return false;
            for (int i = 0; i < 16; i++)
            {
                uint8 b = attrValue[4 + i];
                if (xored)
                {
                    if (i < 4)
                    {
                        static const uint8 cookieBytes[4] = { 0x21, 0x12, 0xA4, 0x42 };
                        b ^= cookieBytes[i];
                    }
                    else
                    {
                        b ^= txid[i - 4];
                    }
                }
                hostBytes[i] = b;
            }
            return true;
        }
        return false;
    }

    bool AddressEqual(const ENetAddress& a, const ENetAddress& b)
    {
        if (a.port != b.port)
            return false;
        return memcmp(&a.host, &b.host, sizeof(a.host)) == 0;
    }

    String AddressToString(const ENetAddress& a)
    {
        char buf[64] = { 0 };
        enet_address_get_host_ip(&a, buf, sizeof(buf));
        return String(buf);
    }
}

// ---------------------------------------------------------------------------
// Internal state (PIMPL)
// ---------------------------------------------------------------------------
namespace
{
    enum class StunPhase
    {
        Idle,
        Test1,        // Send to (IP_A, port_A), no CHANGE-REQUEST -> determine mapped address
        Test2,        // Send to (IP_A, port_A), CHANGE-REQUEST(IP+port) -> Open/FullCone vs Restricted
        Test1Alt,     // Send to (IP_B, port_B), no CHANGE-REQUEST -> Symmetric detection (mapped address comparison)
        Test3,        // Send to (IP_A, port_A), CHANGE-REQUEST(port) -> Restricted vs PortRestricted
        Done,
    };

    struct StunTransaction
    {
        bool active = false;
        bool gotResponse = false;
        ENetAddress destination = {};
        uint8 changeFlags = 0;
        uint8 txid[12] = {};
        double sentAt = 0.0;
        double timeoutAt = 0.0;
        int32 retransmitsLeft = 0;
        // Captured from a successful response:
        ENetAddress mappedAddress = {};
        ENetAddress responseFrom = {};
        ENetAddress otherAddress = {};
        bool hasOtherAddress = false;
    };

    struct PunchSchedule
    {
        ENetAddress destination = {};
        int32 remaining = 0;
        double intervalS = 0.05;
        double nextSendAt = 0.0;
    };
}

struct EoeStunImpl
{
    // STUN endpoints derived from SetStunServers() and any OTHER-ADDRESS reflected by the server.
    bool hasPrimary = false;
    bool hasSecondary = false; // Set if a secondary URL was provided by the user.
    bool hasAlternate = false; // Set when we know IP_B (either secondary URL or OTHER-ADDRESS).
    ENetAddress primaryAA = {}; // (IP_A, port_A)
    ENetAddress primaryAB = {}; // (IP_A, port_B)  - port_B always known because user supplies two ports
    ENetAddress secondaryBB = {}; // (IP_B, port_B) - filled from secondary URL or OTHER-ADDRESS
    ENetAddress secondaryBA = {}; // (IP_B, port_A)
    uint16 portA = 0;
    uint16 portB = 0;

    // Discovery state
    StunPhase phase = StunPhase::Idle;
    StunTransaction current = {};
    EoeNatDiscoveryResult result = {};
    ENetAddress firstMapped = {}; // Mapped address observed in Test 1 - kept for Symmetric detection.
    bool resultReady = false;
    bool resultDispatched = false;

    // Hole-punch
    Array<PunchSchedule, HeapAllocation> punches;

    // Inbound hole-punch queue (drained in PopEvent on the calling thread).
    CriticalSection eventLock;
    struct InboundPunch
    {
        ENetAddress from;
    };
    Array<InboundPunch, HeapAllocation> inboundPunches;
};

// ---------------------------------------------------------------------------
// Host -> driver instance reverse map (intercept callback has no user-data slot)
// ---------------------------------------------------------------------------
namespace
{
    CriticalSection& InterceptMapLock()
    {
        static CriticalSection s;
        return s;
    }

    Dictionary<ENetHost*, EoeNetworkDriver*>& InterceptMap()
    {
        static Dictionary<ENetHost*, EoeNetworkDriver*> s;
        return s;
    }
}

// ---------------------------------------------------------------------------
// Construction / driver lifecycle
// ---------------------------------------------------------------------------
EoeNetworkDriver::EoeNetworkDriver(const SpawnParams& params)
    : ScriptingObject(params)
{
}

EoeNetworkDriver::~EoeNetworkDriver()
{
    // Safety net: release the UDP socket and ENet state if the owner forgot to call Dispose().
    // Without this, a leaked driver instance (e.g. surviving editor play-mode hot-reload) keeps
    // the port bound and the next launch fails to bind the same port.
    if (_host || _enetInitialized || _impl)
    {
        LOG(Warning, "[EoeNetworkDriver] Destructor running with live state - Dispose() should have been called explicitly.");
        Dispose();
    }
}

bool EoeNetworkDriver::SetupSocketAndStun(const NetworkConfig& config)
{
    if (enet_initialize() != 0)
    {
        LOG(Error, "[EoeNetworkDriver] Failed to initialize ENet.");
        return true;
    }
    _enetInitialized = true;

    // Eager bind: create the enet host (and its UDP socket) up-front so STUN and hole-punching
    // can run before Connect() / Listen(). For server use the configured port; for clients pass
    // port=0 in the config to let the OS choose an ephemeral port.
    ENetAddress bindAddr = { 0 };
    bindAddr.port = config.Port;
    bindAddr.host = ENET_HOST_ANY;
    if (config.Address.HasChars() && config.Address != TEXT("any") && config.Address != TEXT("0.0.0.0") && config.Address != TEXT("::"))
    {
        // Best-effort: honor a specific bind address if the user supplied one.
        enet_address_set_host(&bindAddr, config.Address.ToStringAnsi().GetText());
    }

    const size_t peerSlots = Math::Max<size_t>(1, config.ConnectionsLimit);
    _host = enet_host_create(&bindAddr, peerSlots, 1, 0, 0);
    if (_host == nullptr)
    {
        LOG(Error, "[EoeNetworkDriver] Failed to create ENet host on port {0}.", config.Port);
        enet_deinitialize();
        _enetInitialized = false;
        return true;
    }

    _impl = New<EoeStunImpl>();

    {
        ScopeLock lock(InterceptMapLock());
        InterceptMap().Add(_host, this);
    }
    enet_host_set_intercept(_host, &EoeNetworkDriver::InterceptThunk);
    return false;
}

bool EoeNetworkDriver::InitializeStun(const NetworkConfig& config)
{
    if (_host)
    {
        LOG(Warning, "[EoeNetworkDriver] InitializeStun: already initialized (bound port {0}); ignoring.", _host->address.port);
        return false;
    }
    _networkHost = nullptr;
    _config = config;
    _peerMap.Clear();
    _isServer = false;
    _peer = nullptr;
    if (SetupSocketAndStun(_config))
        return true;
    LOG(Info, "[EoeNetworkDriver] STUN initialized (bound port {0}); NetworkPeer not yet attached.", _host->address.port);
    return false;
}

bool EoeNetworkDriver::Initialize(NetworkPeer* host, const NetworkConfig& config)
{
    if (_host)
    {
        // Socket already bound by InitializeStun - keep it so the STUN-derived NAT mapping stays valid.
        const uint16 boundPort = _host->address.port;
        if (config.Port != 0 && config.Port != boundPort)
            LOG(Warning, "[EoeNetworkDriver] Initialize: config.Port {0} differs from STUN-bound port {1}; keeping bound port.", config.Port, boundPort);
        _networkHost = host;
        _config = config;
        _config.Port = boundPort;
        LOG(Info, "[EoeNetworkDriver] NetworkPeer attached to existing socket (port {0}).", boundPort);
        return false;
    }

    _networkHost = host;
    _config = config;
    _peerMap.Clear();
    _isServer = false;
    _peer = nullptr;

    if (SetupSocketAndStun(_config))
        return true;

    LOG(Info, "[EoeNetworkDriver] Initialized (bound port {0}).", _host->address.port);
    return false;
}

void EoeNetworkDriver::Dispose()
{
    if (_peer)
    {
        enet_peer_disconnect_now(_peer, 0);
        _peer = nullptr;
    }
    if (_host)
    {
        {
            ScopeLock lock(InterceptMapLock());
            InterceptMap().Remove(_host);
        }
        enet_host_destroy(_host);
        _host = nullptr;
    }
    if (_enetInitialized)
    {
        enet_deinitialize();
        _enetInitialized = false;
    }
    if (_impl)
    {
        Delete(_impl);
        _impl = nullptr;
    }
    _peerMap.Clear();
    _isServer = false;
    LOG(Info, "[EoeNetworkDriver] Stopped.");
}

bool EoeNetworkDriver::Listen()
{
    if (!_host)
    {
        LOG(Error, "[EoeNetworkDriver] Listen() called before Initialize().");
        return false;
    }
    // Host is already bound from Initialize(); enet accepts incoming connections automatically.
    _isServer = true;
    LOG(Info, "[EoeNetworkDriver] Listening on port {0}.", _host->address.port);
    return true;
}

bool EoeNetworkDriver::Connect()
{
    if (!_host)
    {
        LOG(Error, "[EoeNetworkDriver] Connect() called before Initialize().");
        return false;
    }
    LOG(Info, "[EoeNetworkDriver] Connecting...");

    ENetAddress address = { 0 };
    address.port = _config.Port;
    if (enet_address_set_host(&address, _config.Address.ToStringAnsi().GetText()) != 0)
    {
        LOG(Error, "[EoeNetworkDriver] Failed to resolve connect address '{0}'.", _config.Address);
        return false;
    }

    _peer = enet_host_connect(_host, &address, 1, 0);
    if (_peer == nullptr)
    {
        LOG(Error, "[EoeNetworkDriver] enet_host_connect returned null.");
        return false;
    }
    return true;
}

void EoeNetworkDriver::Disconnect()
{
    if (_peer)
    {
        enet_peer_disconnect_now(_peer, 0);
        _peer = nullptr;
        LOG(Info, "[EoeNetworkDriver] Disconnected.");
    }
}

void EoeNetworkDriver::Disconnect(const NetworkConnection& connection)
{
    const int connectionId = connection.ConnectionId;
    ENetPeer* peer;
    if (_peerMap.TryGet(connectionId, peer))
    {
        enet_peer_disconnect_now(peer, 0);
        _peerMap.Remove(connectionId);
    }
    else
    {
        LOG(Error, "[EoeNetworkDriver] Disconnect(connection {0}): peer not found.", connection.ConnectionId);
    }
}

// ---------------------------------------------------------------------------
// Per-tick driver pump - drains enet events and ticks STUN/punch state machines.
// ---------------------------------------------------------------------------
void EoeNetworkDriver::DriveStunAndPunchTick()
{
    if (!_impl)
        return;

    // Tick our own state machines first - this may emit packets via host->socket.
    TickStunStateMachine();
    TickHolePunchScheduler();

    // Surface a NAT-discovery completion to user code via the C# delegate.
    if (_impl->resultReady && !_impl->resultDispatched)
    {
        _impl->resultDispatched = true;
        NatDiscovered(_impl->result);
    }

    // Surface inbound hole-punches to user code via the C# delegate.
    Array<EoeStunImpl::InboundPunch, HeapAllocation> drained;
    {
        ScopeLock lock(_impl->eventLock);
        if (_impl->inboundPunches.HasItems())
            drained = MoveTemp(_impl->inboundPunches);
    }
    for (const auto& p : drained)
    {
        EoeHolePunchEvent ev;
        ev.Address = AddressToString(p.from);
        ev.Port = p.from.port;
        HolePunchReceived(ev);
    }
}

void EoeNetworkDriver::TickStun()
{
    if (!_host || !_impl)
        return;
    // Once a NetworkPeer is attached, the framework's PopEvent is the authoritative pump.
    // Letting both sides call enet_host_service concurrently would race on the host's protocol state.
    if (_networkHost != nullptr)
        return;

    DriveStunAndPunchTick();

    // Drive enet so the intercept callback fires for received STUN packets. Discard any
    // non-STUN ENet events that arrive in this phase - we have no peer to surface them to.
    ENetEvent event;
    while (enet_host_service(_host, &event, 0) > 0)
    {
        if (event.type == ENET_EVENT_TYPE_RECEIVE && event.packet)
            enet_packet_destroy(event.packet);
    }
}

bool EoeNetworkDriver::PopEvent(NetworkEvent& eventPtr)
{
    ASSERT(_host);

    DriveStunAndPunchTick();

    ENetEvent event;
    const int result = enet_host_service(_host, &event, 0);
    if (result < 0)
    {
        LOG(Error, "[EoeNetworkDriver] enet_host_service returned {0}.", result);
        return false;
    }
    if (result == 0)
        return false;

    const uint32 connectionId = event.peer ? enet_peer_get_id(event.peer) : 0;
    eventPtr.Sender.ConnectionId = connectionId;
    switch (event.type)
    {
    case ENET_EVENT_TYPE_CONNECT:
        eventPtr.EventType = NetworkEventType::Connected;
        if (IsServer())
            _peerMap.Add(connectionId, event.peer);
        break;
    case ENET_EVENT_TYPE_DISCONNECT:
        eventPtr.EventType = NetworkEventType::Disconnected;
        if (IsServer())
            _peerMap.Remove(connectionId);
        break;
    case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:
        eventPtr.EventType = NetworkEventType::Timeout;
        if (IsServer())
            _peerMap.Remove(connectionId);
        break;
    case ENET_EVENT_TYPE_RECEIVE:
        eventPtr.EventType = NetworkEventType::Message;
        if (_networkHost)
        {
            eventPtr.Message = _networkHost->CreateMessage();
            eventPtr.Message.Length = event.packet->dataLength;
            Platform::MemoryCopy(eventPtr.Message.Buffer, event.packet->data, event.packet->dataLength);
        }
        else
        {
            // STUN-only phase: peer not attached yet, drop unexpected ENet payload.
            eventPtr.EventType = NetworkEventType::Undefined;
        }
        enet_packet_destroy(event.packet);
        break;
    default:
        eventPtr.EventType = NetworkEventType::Undefined;
        break;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Outgoing message paths (delegate straight to ENet, identical to ENetDriver).
// ---------------------------------------------------------------------------
namespace
{
    ENetPacketFlag ChannelTypeToPacketFlag(NetworkChannelType channel)
    {
        int flag = 0;
        if (channel == NetworkChannelType::Reliable || channel == NetworkChannelType::ReliableOrdered)
            flag |= ENET_PACKET_FLAG_RELIABLE;
        if (channel == NetworkChannelType::Unreliable)
            flag |= ENET_PACKET_FLAG_UNSEQUENCED;
        return (ENetPacketFlag)flag;
    }

    void SendPacketToPeer(ENetPeer* peer, NetworkChannelType channelType, const NetworkMessage& message)
    {
        ENetPacket* packet = enet_packet_create(message.Buffer, message.Length, ChannelTypeToPacketFlag(channelType));
        enet_peer_send(peer, 0, packet);
    }
}

void EoeNetworkDriver::SendMessage(NetworkChannelType channelType, const NetworkMessage& message)
{
    ASSERT(!IsServer() && _peer);
    SendPacketToPeer(_peer, channelType, message);
}

void EoeNetworkDriver::SendMessage(NetworkChannelType channelType, const NetworkMessage& message, NetworkConnection target)
{
    ASSERT(IsServer());
    ENetPeer* peer;
    if (_peerMap.TryGet(target.ConnectionId, peer) && peer && peer->state == ENET_PEER_STATE_CONNECTED)
        SendPacketToPeer(peer, channelType, message);
}

void EoeNetworkDriver::SendMessage(NetworkChannelType channelType, const NetworkMessage& message, const Array<NetworkConnection, HeapAllocation>& targets)
{
    ASSERT(IsServer());
    ENetPeer* peer;
    for (const NetworkConnection& target : targets)
    {
        if (_peerMap.TryGet(target.ConnectionId, peer) && peer && peer->state == ENET_PEER_STATE_CONNECTED)
            SendPacketToPeer(peer, channelType, message);
    }
}

NetworkDriverStats EoeNetworkDriver::GetStats()
{
    return GetStats({ 0 });
}

NetworkDriverStats EoeNetworkDriver::GetStats(NetworkConnection target)
{
    NetworkDriverStats stats;
    ENetPeer* peer = _peer;
    if (!peer)
        _peerMap.TryGet(target.ConnectionId, peer);
    if (!peer && _host && _host->peerCount > 0)
        peer = _host->peers;
    if (peer)
    {
        stats.RTT = (float)peer->roundTripTime;
        stats.TotalDataSent = peer->totalDataSent;
        stats.TotalDataReceived = peer->totalDataReceived;
    }
    return stats;
}

// ---------------------------------------------------------------------------
// STUN configuration / discovery API
// ---------------------------------------------------------------------------
void EoeNetworkDriver::SetStunServers(const String& primaryUrl, const String& secondaryUrl, uint16 primaryPort, uint16 secondaryPort)
{
    if (!_impl)
    {
        LOG(Error, "[EoeNetworkDriver] SetStunServers called before Initialize.");
        return;
    }

    _impl->hasPrimary = false;
    _impl->hasSecondary = false;
    _impl->hasAlternate = false;
    _impl->portA = primaryPort;
    _impl->portB = secondaryPort;

    if (primaryUrl.IsEmpty())
    {
        LOG(Warning, "[EoeNetworkDriver] SetStunServers: primary URL is empty.");
        return;
    }

    StringAnsi primaryAnsi = primaryUrl.ToStringAnsi();
    if (enet_address_set_host(&_impl->primaryAA, primaryAnsi.GetText()) != 0)
    {
        LOG(Warning, "[EoeNetworkDriver] Failed to resolve STUN primary host '{0}'.", primaryUrl);
        return;
    }
    _impl->primaryAA.port = primaryPort;
    // Same IP, alternate port
    _impl->primaryAB = _impl->primaryAA;
    _impl->primaryAB.port = secondaryPort;
    _impl->hasPrimary = true;

    if (secondaryUrl.HasChars())
    {
        StringAnsi secondaryAnsi = secondaryUrl.ToStringAnsi();
        if (enet_address_set_host(&_impl->secondaryBB, secondaryAnsi.GetText()) == 0)
        {
            _impl->secondaryBB.port = secondaryPort;
            _impl->secondaryBA = _impl->secondaryBB;
            _impl->secondaryBA.port = primaryPort;
            _impl->hasSecondary = true;
            _impl->hasAlternate = true;
        }
        else
        {
            LOG(Warning, "[EoeNetworkDriver] Failed to resolve STUN secondary host '{0}' - falling back to RFC 3489 CHANGE-REQUEST.", secondaryUrl);
        }
    }
}

void EoeNetworkDriver::StartNatDiscovery()
{
    if (!_impl || !_host)
    {
        LOG(Error, "[EoeNetworkDriver] StartNatDiscovery: driver not initialized.");
        return;
    }
    if (!_impl->hasPrimary)
    {
        LOG(Error, "[EoeNetworkDriver] StartNatDiscovery: no STUN servers configured.");
        EoeNatDiscoveryResult r;
        r.NatType = EoeNatType::Unknown;
        _impl->result = r;
        _impl->resultReady = true;
        _impl->resultDispatched = false;
        return;
    }

    // Reset
    _impl->result = EoeNatDiscoveryResult();
    _impl->resultReady = false;
    _impl->resultDispatched = false;
    _impl->phase = StunPhase::Test1;
    _impl->current = StunTransaction();
    _impl->current.destination = _impl->primaryAA;
    _impl->current.changeFlags = 0;

    // Capture the locally bound port (we bound to ANY at Initialize, so the IP side is unhelpful for classification).
    ENetAddress local = {};
    if (enet_socket_get_address(_host->socket, &local) == 0)
        _impl->result.LocalPort = local.port;

    StunSendCurrentTest();
}

bool EoeNetworkDriver::IsNatDiscoveryComplete() const
{
    return _impl && _impl->resultReady;
}

EoeNatDiscoveryResult EoeNetworkDriver::GetNatDiscoveryResult() const
{
    if (!_impl)
        return EoeNatDiscoveryResult();
    return _impl->result;
}

// ---------------------------------------------------------------------------
// Hole punching API
// ---------------------------------------------------------------------------
void EoeNetworkDriver::SendHolePunch(const String& address, uint16 port, int32 count, float intervalMs)
{
    if (!_impl || !_host)
    {
        LOG(Error, "[EoeNetworkDriver] SendHolePunch: driver not initialized.");
        return;
    }
    if (count <= 0)
        return;

    PunchSchedule sched;
    sched.destination.port = port;
    if (enet_address_set_host(&sched.destination, address.ToStringAnsi().GetText()) != 0)
    {
        LOG(Warning, "[EoeNetworkDriver] SendHolePunch: failed to resolve '{0}'.", address);
        return;
    }
    sched.destination.port = port; // defensive - enet_address_set_host shouldn't touch the port but we set it again to be sure
    sched.remaining = count;
    sched.intervalS = Math::Max(0.001f, intervalMs * 0.001f);
    sched.nextSendAt = Platform::GetTimeSeconds(); // first packet fires immediately on next tick
    _impl->punches.Add(sched);
}

// ---------------------------------------------------------------------------
// Receive interception (demux STUN / hole-punch / ENet)
// ---------------------------------------------------------------------------
int EoeNetworkDriver::InterceptThunk(ENetHost* host, void* /*event*/)
{
    EoeNetworkDriver* driver;
    {
        ScopeLock lock(InterceptMapLock());
        if (!InterceptMap().TryGet(host, driver))
            return 0;
    }
    if (!driver->_impl)
        return 0;
    return driver->OnIntercept();
}

int EoeNetworkDriver::OnIntercept()
{
    const int32 length = (int32)_host->receivedDataLength;
    const uint8* data = (const uint8*)_host->receivedData;
    if (length < STUN_HEADER_SIZE)
        return 0; // Not STUN; let enet handle.

    // Magic cookie at bytes 4..7 is the disambiguator.
    if (Read32BE(data + 4) != STUN_MAGIC_COOKIE)
        return 0;

    const uint16 msgType = Read16BE(data + 0);
    const uint16 attrLen = Read16BE(data + 2);
    if (length < STUN_HEADER_SIZE + (int32)attrLen)
        return 1; // Malformed STUN, but consume to keep enet from misinterpreting.

    const ENetAddress& from = _host->receivedAddress;
    switch (msgType)
    {
    case STUN_BINDING_SUCCESS:
    case STUN_BINDING_ERROR:
        HandleStunResponse(from, data, length);
        return 1;
    case STUN_BINDING_INDICATION:
        HandleStunIndication(from, data, length);
        return 1;
    case STUN_BINDING_REQUEST:
        // A peer is hole-punching us with a STUN request. Treat as a hole-punch and (optionally) reply with an indication.
        HandleStunRequest(from, data, length);
        return 1;
    default:
        return 1;
    }
}

// ---------------------------------------------------------------------------
// STUN state-machine internals
// ---------------------------------------------------------------------------
void EoeNetworkDriver::StunSend(const ENetAddress& dst, const uint8* data, int32 length)
{
    if (!_host)
        return;
    ENetBuffer buf;
    buf.data = (void*)data;
    buf.dataLength = (size_t)length;
    enet_socket_send(_host->socket, &dst, &buf, 1);
}

void EoeNetworkDriver::StunSendCurrentTest()
{
    if (!_impl)
        return;
    StunTransaction& t = _impl->current;
    GenerateTxid(t.txid);

    uint8 buf[64];
    int32 attrBytes = 0;
    if (t.changeFlags != 0)
        attrBytes += AppendChangeRequest(buf + STUN_HEADER_SIZE + attrBytes, t.changeFlags);
    WriteStunHeader(buf, STUN_BINDING_REQUEST, (uint16)attrBytes, t.txid);

    t.active = true;
    t.gotResponse = false;
    t.sentAt = Platform::GetTimeSeconds();
    t.timeoutAt = t.sentAt + STUN_INITIAL_TIMEOUT_S;
    t.retransmitsLeft = STUN_MAX_RETRANSMITS;

    StunSend(t.destination, buf, STUN_HEADER_SIZE + attrBytes);
}

void EoeNetworkDriver::TickStunStateMachine()
{
    if (!_impl || _impl->phase == StunPhase::Idle || _impl->phase == StunPhase::Done)
        return;

    StunTransaction& t = _impl->current;
    if (!t.active)
        return;

    const double now = Platform::GetTimeSeconds();

    // Process state transitions on response
    if (t.gotResponse)
    {
        t.active = false;
        switch (_impl->phase)
        {
        case StunPhase::Test1:
        {
            // We have a mapped address from the primary STUN server.
            _impl->firstMapped = t.mappedAddress;
            _impl->result.Success = true;
            _impl->result.ExternalAddress = AddressToString(t.mappedAddress);
            _impl->result.ExternalPort = t.mappedAddress.port;
            // If the server gave us its alternate endpoint via OTHER-ADDRESS / CHANGED-ADDRESS and we don't already have one, use it.
            if (t.hasOtherAddress && !_impl->hasAlternate)
            {
                _impl->secondaryBB = t.otherAddress;
                _impl->secondaryBA = t.otherAddress;
                _impl->secondaryBA.port = _impl->portA;
                _impl->hasAlternate = true;
            }
            // Test 2: ask the server to reply from its alternate IP+port.
            _impl->phase = StunPhase::Test2;
            _impl->current = StunTransaction();
            _impl->current.destination = _impl->primaryAA;
            _impl->current.changeFlags = STUN_CHANGE_IP | STUN_CHANGE_PORT;
            StunSendCurrentTest();
            return;
        }
        case StunPhase::Test2:
        {
            // Reply received from the alt IP+port, so any NAT in front of us accepts unsolicited inbound.
            // Distinguish Open (no NAT) from FullCone by a port-preservation heuristic: if the mapped
            // port matches our locally bound port we likely have no NAT.
            const bool portPreserved = _impl->result.ExternalPort != 0
                && _impl->result.LocalPort != 0
                && _impl->result.ExternalPort == _impl->result.LocalPort;
            StunFinish(portPreserved ? EoeNatType::Open : EoeNatType::FullCone, true);
            return;
        }
        case StunPhase::Test1Alt:
        {
            // Compare mapping observed against the alternate STUN endpoint with the original mapping.
            // A symmetric NAT assigns a different external port (and possibly IP) per destination.
            const bool different = !AddressEqual(t.mappedAddress, _impl->firstMapped);
            if (different)
            {
                StunFinish(EoeNatType::Symmetric, true);
                return;
            }
            _impl->phase = StunPhase::Test3;
            _impl->current = StunTransaction();
            _impl->current.destination = _impl->primaryAA;
            _impl->current.changeFlags = STUN_CHANGE_PORT;
            StunSendCurrentTest();
            return;
        }
        case StunPhase::Test3:
        {
            // Server replied from same IP, alt port -> address-restricted (any port from a known IP gets through).
            StunFinish(EoeNatType::RestrictedCone, true);
            return;
        }
        default:
            break;
        }
    }

    // Retransmit / timeout
    if (now >= t.timeoutAt)
    {
        if (t.retransmitsLeft > 0)
        {
            t.retransmitsLeft--;
            const double rto = Math::Min(STUN_MAX_TIMEOUT_S, (now - t.sentAt) * 2.0);
            t.timeoutAt = now + rto;

            uint8 buf[64];
            int32 attrBytes = 0;
            if (t.changeFlags != 0)
                attrBytes += AppendChangeRequest(buf + STUN_HEADER_SIZE + attrBytes, t.changeFlags);
            WriteStunHeader(buf, STUN_BINDING_REQUEST, (uint16)attrBytes, t.txid);
            StunSend(t.destination, buf, STUN_HEADER_SIZE + attrBytes);
            return;
        }

        // Exhausted retries on this phase.
        t.active = false;
        switch (_impl->phase)
        {
        case StunPhase::Test1:
            // No response to the first probe at all.
            StunFinish(EoeNatType::Blocked, false);
            return;
        case StunPhase::Test2:
        {
            // Test 2 timed out -> we have a NAT or a stateful firewall blocking unsolicited inbound.
            // If we have an alternate STUN endpoint, run Test 1-Alt to detect Symmetric NAT.
            // Otherwise fall straight to Test 3 (Symmetric vs Restricted is undecidable without a 2nd server,
            // so we accept that the result will be RestrictedCone or PortRestrictedCone in that case).
            if (_impl->hasAlternate)
            {
                _impl->phase = StunPhase::Test1Alt;
                _impl->current = StunTransaction();
                _impl->current.destination = _impl->secondaryBB;
                _impl->current.changeFlags = 0;
            }
            else
            {
                _impl->phase = StunPhase::Test3;
                _impl->current = StunTransaction();
                _impl->current.destination = _impl->primaryAA;
                _impl->current.changeFlags = STUN_CHANGE_PORT;
            }
            StunSendCurrentTest();
            return;
        }
        case StunPhase::Test1Alt:
            // Couldn't reach the alternate STUN endpoint at all - treat as Symmetric (our mapping
            // is destination-dependent and we couldn't even verify reachability).
            StunFinish(EoeNatType::Symmetric, true);
            return;
        case StunPhase::Test3:
            // Timed out on the alt-port reply -> port-restricted.
            StunFinish(EoeNatType::PortRestrictedCone, true);
            return;
        default:
            break;
        }
    }
}

void EoeNetworkDriver::StunFinish(EoeNatType natType, bool success)
{
    if (!_impl)
        return;
    _impl->result.NatType = natType;
    _impl->result.Success = success || natType != EoeNatType::Unknown;
    _impl->phase = StunPhase::Done;
    _impl->resultReady = true;
    _impl->resultDispatched = false;
}

// ---------------------------------------------------------------------------
// Hole-punch scheduler
// ---------------------------------------------------------------------------
void EoeNetworkDriver::TickHolePunchScheduler()
{
    if (!_impl || _impl->punches.IsEmpty() || !_host)
        return;

    const double now = Platform::GetTimeSeconds();
    for (int32 i = _impl->punches.Count() - 1; i >= 0; i--)
    {
        PunchSchedule& s = _impl->punches[i];
        while (s.remaining > 0 && now >= s.nextSendAt)
        {
            // Build a STUN Binding Indication so the packet looks like benign STUN traffic to NAT devices.
            uint8 buf[STUN_HEADER_SIZE];
            uint8 txid[12];
            GenerateTxid(txid, STUN_HOLEPUNCH_TXID_TAG);
            WriteStunHeader(buf, STUN_BINDING_INDICATION, 0, txid);
            StunSend(s.destination, buf, STUN_HEADER_SIZE);

            s.remaining--;
            s.nextSendAt += s.intervalS;
        }
        if (s.remaining <= 0)
            _impl->punches.RemoveAt(i);
    }
}

// ---------------------------------------------------------------------------
// STUN message handlers (called from intercept thunk)
// ---------------------------------------------------------------------------
void EoeNetworkDriver::HandleStunResponse(const ENetAddress& from, const uint8* data, int32 length)
{
    if (!_impl)
        return;
    StunTransaction& t = _impl->current;
    if (!t.active)
        return;
    // Match transaction id.
    if (memcmp(data + 8, t.txid, 12) != 0)
        return;

    t.gotResponse = true;
    t.responseFrom = from;

    const uint16 msgType = Read16BE(data + 0);
    if (msgType == STUN_BINDING_ERROR)
    {
        // Treat error as "no usable response" - leave mappedAddress zeroed and let the state machine react.
        return;
    }

    // Walk attributes, capture addresses.
    int32 cursor = STUN_HEADER_SIZE;
    while (cursor + 4 <= length)
    {
        const uint16 attrType = Read16BE(data + cursor);
        const uint16 attrLen = Read16BE(data + cursor + 2);
        const int32 valueAt = cursor + 4;
        if (valueAt + attrLen > length)
            break;
        switch (attrType)
        {
        case STUN_ATTR_MAPPED_ADDRESS:
            DecodeStunAddress(data + valueAt, attrLen, false, data + 8, t.mappedAddress);
            break;
        case STUN_ATTR_XOR_MAPPED_ADDRESS:
            DecodeStunAddress(data + valueAt, attrLen, true, data + 8, t.mappedAddress);
            break;
        case STUN_ATTR_OTHER_ADDRESS:
        case STUN_ATTR_CHANGED_ADDRESS:
            if (DecodeStunAddress(data + valueAt, attrLen, false, data + 8, t.otherAddress))
                t.hasOtherAddress = true;
            break;
        default:
            break;
        }
        // Attributes are 4-byte aligned.
        const int32 padded = (attrLen + 3) & ~3;
        cursor = valueAt + padded;
    }
}

void EoeNetworkDriver::HandleStunIndication(const ENetAddress& from, const uint8* /*data*/, int32 /*length*/)
{
    // Any inbound STUN Binding Indication is treated as a hole-punch from a peer.
    if (!_impl)
        return;
    EoeStunImpl::InboundPunch p;
    p.from = from;
    ScopeLock lock(_impl->eventLock);
    _impl->inboundPunches.Add(p);
}

void EoeNetworkDriver::HandleStunRequest(const ENetAddress& from, const uint8* data, int32 /*length*/)
{
    // A peer sent us a STUN Binding Request from a non-STUN-server endpoint - treat as hole-punch.
    // We also send back a Binding Indication so the peer's NAT learns about us symmetrically.
    if (!_impl)
        return;
    EoeStunImpl::InboundPunch p;
    p.from = from;
    {
        ScopeLock lock(_impl->eventLock);
        _impl->inboundPunches.Add(p);
    }

    // Reply with a Binding Indication echoing the txid (drains nothing for the peer, just re-opens our mapping).
    uint8 buf[STUN_HEADER_SIZE];
    WriteStunHeader(buf, STUN_BINDING_INDICATION, 0, data + 8);
    StunSend(from, buf, STUN_HEADER_SIZE);
}
