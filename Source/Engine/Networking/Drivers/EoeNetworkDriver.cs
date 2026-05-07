// Copyright (c) Wojciech Figat. All rights reserved.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace FlaxEngine.Networking
{
    partial class EoeNetworkDriver
    {
        /// <summary>
        /// Awaitable variant of <see cref="StartNatDiscovery"/>. Subscribes to <see cref="NatDiscovered"/>,
        /// kicks off discovery, and resolves with the result once the state machine completes.
        /// </summary>
        /// <param name="cancellationToken">Optional token. Cancellation unsubscribes the internal handler but does not stop the in-flight state machine - the result will simply be discarded.</param>
        /// <returns>Task that resolves with the discovery outcome.</returns>
        public Task<EoeNatDiscoveryResult> DiscoverNatAsync(CancellationToken cancellationToken = default)
        {
            var tcs = new TaskCompletionSource<EoeNatDiscoveryResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            Action<EoeNatDiscoveryResult> handler = null;
            handler = result =>
            {
                NatDiscovered -= handler;
                tcs.TrySetResult(result);
            };
            NatDiscovered += handler;

            CancellationTokenRegistration ctr = default;
            if (cancellationToken.CanBeCanceled)
            {
                ctr = cancellationToken.Register(() =>
                {
                    NatDiscovered -= handler;
                    tcs.TrySetCanceled(cancellationToken);
                });
            }

            // Free the registration once the task completes either way.
            tcs.Task.ContinueWith(_ => ctr.Dispose(), TaskContinuationOptions.ExecuteSynchronously);

            try
            {
                StartNatDiscovery();
            }
            catch
            {
                NatDiscovered -= handler;
                throw;
            }
            return tcs.Task;
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
