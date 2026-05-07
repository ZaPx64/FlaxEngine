// Copyright (c) Wojciech Figat. All rights reserved.

#pragma once

#include "Engine/Networking/Types.h"
#include "Engine/Networking/INetworkDriver.h"
#include "Engine/Networking/NetworkConnection.h"
#include "Engine/Networking/NetworkConfig.h"
#include "Engine/Core/Collections/Array.h"
#include "Engine/Core/Collections/Dictionary.h"
#include "Engine/Core/Delegate.h"
#include "Engine/Core/Types/String.h"
#include "Engine/Scripting/ScriptingObject.h"
#include "Engine/Scripting/ScriptingType.h"

/// <summary>
/// NAT classification result produced by STUN discovery on <see cref="EoeNetworkDriver"/>.
/// Mirrors RFC 3489 NAT behavior categories.
/// </summary>
API_ENUM(Namespace="FlaxEngine.Networking") enum class EoeNatType
{
    /// <summary>Discovery has not run or did not produce a result.</summary>
    Unknown = 0,
    /// <summary>No reply received from any STUN endpoint - UDP likely blocked.</summary>
    Blocked,
    /// <summary>Public address with no NAT in front of the host.</summary>
    Open,
    /// <summary>No NAT, but a stateful firewall drops unsolicited inbound packets.</summary>
    SymmetricFirewall,
    /// <summary>Full Cone NAT: any external host can reach the mapped port (best for P2P).</summary>
    FullCone,
    /// <summary>Address-Restricted Cone NAT: external host must have been contacted first (any port).</summary>
    RestrictedCone,
    /// <summary>Port-Restricted Cone NAT: external host must have been contacted first (exact port).</summary>
    PortRestrictedCone,
    /// <summary>Symmetric NAT: mapped port differs per destination - peer-to-peer is unreliable.</summary>
    Symmetric,
};

/// <summary>
/// Result of a STUN-based NAT discovery run on <see cref="EoeNetworkDriver"/>.
/// </summary>
API_STRUCT(Namespace="FlaxEngine.Networking") struct FLAXENGINE_API EoeNatDiscoveryResult
{
    DECLARE_SCRIPTING_TYPE_MINIMAL(EoeNatDiscoveryResult);

    /// <summary>True if at least one STUN reply was received and a mapped address is known.</summary>
    API_FIELD() bool Success = false;
    /// <summary>Classified NAT behavior. See <see cref="EoeNatType"/>.</summary>
    API_FIELD() EoeNatType NatType = EoeNatType::Unknown;
    /// <summary>Public-side IPv4/IPv6 address as observed by the STUN server.</summary>
    API_FIELD() String ExternalAddress;
    /// <summary>Public-side UDP port as observed by the STUN server.</summary>
    API_FIELD() uint16 ExternalPort = 0;
    /// <summary>Public-side address that the local socket was actually bound to (locally observed).</summary>
    API_FIELD() String LocalAddress;
    /// <summary>Local UDP port the socket is bound to.</summary>
    API_FIELD() uint16 LocalPort = 0;
};

/// <summary>
/// Inbound hole-punch event surfaced by <see cref="EoeNetworkDriver.HolePunchReceived"/>.
/// </summary>
API_STRUCT(Namespace="FlaxEngine.Networking") struct FLAXENGINE_API EoeHolePunchEvent
{
    DECLARE_SCRIPTING_TYPE_MINIMAL(EoeHolePunchEvent);

    /// <summary>Source IP address that originated the punch.</summary>
    API_FIELD() String Address;
    /// <summary>Source UDP port that originated the punch.</summary>
    API_FIELD() uint16 Port = 0;
};

/// <summary>
/// Network driver based on the ENet transport with built-in STUN-based NAT classification
/// and UDP hole-punching support, all multiplexed over the same UDP socket so a peer can
/// run STUN, hole-punch a remote endpoint, and then accept or initiate ENet connections
/// from/to the same socket without any tear-down or re-bind.
/// </summary>
/// <remarks>
/// Wire-format demux is performed by an enet receive interceptor. STUN-shaped datagrams
/// (RFC 5389 magic cookie 0x2112A442 at offset 4) are routed into the internal STUN
/// state machine and the inbound hole-punch queue, depending on the STUN message class.
/// All other datagrams fall through to ENet for normal protocol handling.
/// Hole-punch packets are themselves emitted as STUN Binding Indications, so they look
/// like ordinary STUN traffic to NAT devices and middleboxes.
/// </remarks>
API_CLASS(Namespace="FlaxEngine.Networking", Sealed) class FLAXENGINE_API EoeNetworkDriver : public ScriptingObject, public INetworkDriver
{
    DECLARE_SCRIPTING_TYPE(EoeNetworkDriver);
public:
    // [INetworkDriver]
    String DriverName() override
    {
        return String("EoeNetworkDriver");
    }

    bool Initialize(NetworkPeer* host, const NetworkConfig& config) override;
    void Dispose() override;
    bool Listen() override;
    bool Connect() override;
    void Disconnect() override;
    void Disconnect(const NetworkConnection& connection) override;
    bool PopEvent(NetworkEvent& eventPtr) override;
    void SendMessage(NetworkChannelType channelType, const NetworkMessage& message) override;
    void SendMessage(NetworkChannelType channelType, const NetworkMessage& message, NetworkConnection target) override;
    void SendMessage(NetworkChannelType channelType, const NetworkMessage& message, const Array<NetworkConnection, HeapAllocation>& targets) override;
    NetworkDriverStats GetStats() override;
    NetworkDriverStats GetStats(NetworkConnection target) override;

    /// <summary>
    /// Configures the STUN endpoints used by NAT discovery.
    /// Both URLs are resolved via DNS synchronously by this call.
    /// </summary>
    /// <param name="primaryUrl">Primary STUN server hostname or IP. Required.</param>
    /// <param name="secondaryUrl">Optional secondary STUN server hostname or IP. Pass empty string to disable. When omitted, NAT classification falls back to RFC 3489 CHANGE-REQUEST against the primary server.</param>
    /// <param name="primaryPort">Primary STUN port (typically 3478).</param>
    /// <param name="secondaryPort">Alternate STUN port. Used together with the alternate IP to probe additional 4-tuples for NAT classification.</param>
    API_FUNCTION() void SetStunServers(const String& primaryUrl, const String& secondaryUrl, uint16 primaryPort, uint16 secondaryPort);

    /// <summary>
    /// Kicks off a non-blocking NAT discovery run.
    /// Progress is driven from <see cref="PopEvent"/>; the run completes within a few hundred milliseconds in the typical case
    /// and within ~6 seconds in the worst case (UDP blocked / packet loss). Subscribe to <see cref="NatDiscovered"/> or poll
    /// <see cref="IsNatDiscoveryComplete"/> for completion. The C# wrapper exposes a <c>DiscoverNatAsync</c> Task-returning helper.
    /// </summary>
    /// <remarks>Requires <see cref="SetStunServers"/> and <see cref="Initialize"/> to have been called first. Safe to call multiple times - a fresh run replaces the previous result.</remarks>
    API_FUNCTION() void StartNatDiscovery();

    /// <summary>True once the most recent <see cref="StartNatDiscovery"/> has finished.</summary>
    API_FUNCTION() bool IsNatDiscoveryComplete() const;

    /// <summary>Returns the last known NAT discovery result. Valid after <see cref="IsNatDiscoveryComplete"/> returns true.</summary>
    API_FUNCTION() EoeNatDiscoveryResult GetNatDiscoveryResult() const;

    /// <summary>Fires once when a NAT discovery run completes (success or failure).</summary>
    API_EVENT() Delegate<const EoeNatDiscoveryResult&> NatDiscovered;

    /// <summary>
    /// Schedules a UDP hole-punch burst toward the given endpoint without first establishing an ENet connection.
    /// Packets are emitted as STUN Binding Indications and are sent from the same socket the driver uses for ENet traffic.
    /// </summary>
    /// <param name="address">Destination IPv4/IPv6 address (literal or resolvable hostname).</param>
    /// <param name="port">Destination UDP port.</param>
    /// <param name="count">Number of packets to send (e.g. 5).</param>
    /// <param name="intervalMs">Spacing between packets in milliseconds (e.g. 50).</param>
    API_FUNCTION() void SendHolePunch(const String& address, uint16 port, int32 count, float intervalMs);

    /// <summary>Fires when a hole-punch packet is received from any remote peer.</summary>
    API_EVENT() Delegate<const EoeHolePunchEvent&> HolePunchReceived;

private:
    bool IsServer() const
    {
        return _networkHost != nullptr && _peer == nullptr && _isServer;
    }

    // Wire-level intercept entry point invoked by enet for each received UDP datagram.
    // Demuxes STUN/hole-punch from ENet protocol traffic. See EoeNetworkDriver.cpp.
    static int InterceptThunk(struct _ENetHost* host, void* event);
    int OnIntercept();

    // Internal helpers - see implementation file.
    void TickStunStateMachine();
    void TickHolePunchScheduler();
    void HandleStunResponse(const struct _ENetAddress& from, const uint8* data, int32 length);
    void HandleStunIndication(const struct _ENetAddress& from, const uint8* data, int32 length);
    void HandleStunRequest(const struct _ENetAddress& from, const uint8* data, int32 length);
    void StunSend(const struct _ENetAddress& dst, const uint8* data, int32 length);
    void StunFinish(EoeNatType natType, bool success);
    void StunSendCurrentTest();

private:
    NetworkConfig _config;
    NetworkPeer* _networkHost = nullptr;
    struct _ENetHost* _host = nullptr;
    struct _ENetPeer* _peer = nullptr;
    bool _isServer = false;
    bool _enetInitialized = false;
    Dictionary<uint32, struct _ENetPeer*> _peerMap;

    // Opaque internal state owns STUN/hole-punch bookkeeping (PIMPL to keep this header light).
    // ENet's intercept callback receives the host but no user-data slot, so the static thunk routes to
    // the matching instance via a host->driver map kept in the implementation file.
    struct EoeStunImpl* _impl = nullptr;
};
