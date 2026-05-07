// Copyright (c) Wojciech Figat. All rights reserved.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace FlaxEngine.Networking
{
    partial class EoeNetworkDriver
    {
        /// <summary>
        /// Awaitable variant of <see cref="StartNatDiscovery"/>. Kicks off discovery and polls the
        /// state machine to completion. Drives <see cref="TickStun"/> internally so this works
        /// before <see cref="Initialize"/> has attached a <see cref="NetworkPeer"/> (i.e. immediately
        /// after <see cref="InitializeStun"/>); once a peer is attached the framework's pump takes
        /// over and <see cref="TickStun"/> becomes a no-op.
        /// </summary>
        /// <param name="cancellationToken">Optional token. Cancellation aborts the wait; the in-flight state machine is left to finish or time out on its own.</param>
        /// <returns>Task that resolves with the discovery outcome.</returns>
        public async Task<EoeNatDiscoveryResult> DiscoverNatAsync(CancellationToken cancellationToken = default)
        {
            StartNatDiscovery();
            while (!IsNatDiscoveryComplete())
            {
                cancellationToken.ThrowIfCancellationRequested();
                TickStun();
                await Task.Delay(20, cancellationToken);
            }
            return GetNatDiscoveryResult();
        }

        /// <summary>
        /// Awaitable variant of <see cref="SendHolePunch"/>. Schedules the burst on the native scheduler and
        /// resolves once the last packet has been emitted (including a small slack for scheduler granularity).
        /// </summary>
        /// <param name="address">Destination IPv4/IPv6 address (literal or hostname).</param>
        /// <param name="port">Destination UDP port.</param>
        /// <param name="count">Number of packets to send.</param>
        /// <param name="intervalMs">Spacing between packets in milliseconds.</param>
        /// <param name="cancellationToken">Optional token to abort the wait. The native scheduler is not stopped - already-queued packets will still be sent.</param>
        public Task SendHolePunchAsync(string address, ushort port, int count, float intervalMs, CancellationToken cancellationToken = default)
        {
            if (count <= 0)
                return Task.CompletedTask;
            SendHolePunch(address, port, count, intervalMs);
            // Total wall time = (count - 1) * intervalMs for spacing, plus a small slack so the last packet
            // is actually flushed by the network tick that follows the final scheduled send time.
            var totalMs = (int)Math.Ceiling(Math.Max(0f, (count - 1) * intervalMs)) + 16;
            return Task.Delay(totalMs, cancellationToken);
        }
    }
}
