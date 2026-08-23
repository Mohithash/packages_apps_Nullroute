package com.bestrom.nullroute.deep

import android.app.PendingIntent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import java.net.Inet6Address

/**
 * Builds the Deep-mode tun interface.
 *
 * The whole shape of this file is one decision: **route the DNS server addresses
 * and nothing else.** Two `/32`s and two `/128`s onto the aliases from
 * [AliasPool], never a default route. Every other packet the device sends goes
 * out exactly as it would with Deep mode off, so the tunnel's cost is one
 * userspace hop per DNS query rather than per byte, and a bug in the packet path
 * cannot take the network down — only DNS, which the watchdog then switches off.
 */
object TunnelBuilder {

    private const val TAG = "NullrouteDeep"

    /**
     * Standard Ethernet-ish MTU. Larger would let big EDNS answers through
     * without a TCP round trip, but it would also mean every DNS-adjacent path
     * MTU on the device is a number we invented, and the correct handling of an
     * oversized answer already exists: set TC and let [Tcp53Server] serve the
     * retry.
     */
    const val MTU = 1500

    class Tunnel(
        val fd: ParcelFileDescriptor,
        val mtu: Int,
    )

    /**
     * Configures and establishes the tunnel. [pool] must already have been
     * [AliasPool.reset] and [AliasPool.remap]ped.
     *
     * Throws [IllegalStateException] if the tunnel cannot be established —
     * including the case `establish()` documents as a null return, which happens
     * when the app is no longer the prepared VPN (another app took the slot
     * between `prepare()` and here).
     */
    fun build(vpn: VpnService, pool: AliasPool, configureIntent: PendingIntent?): Tunnel {
        check(pool.isConfigured) { "alias pool not reset" }

        val b = vpn.Builder()
            .setSession("Nullroute Deep")
            .setMtu(MTU)

        pool.tunnelAddress4?.let { b.addAddress(it, AliasPool.V4_PREFIX_LEN) }
        pool.tunnelAddress6?.let { b.addAddress(it, AliasPool.V6_PREFIX_LEN) }

        var routes = 0
        for (alias in pool.aliases()) {
            // addDnsServer() rejects loopback and any-local addresses, which is
            // exactly why the aliases are documentation-block unicast rather
            // than the 127.x a naive implementation would reach for.
            b.addDnsServer(alias.address)
            b.addRoute(alias.address, if (alias.address is Inet6Address) 128 else 32)
            routes++
        }
        check(routes > 0) { "no alias routes" }

        // Belt and braces. Adding an address, route and DNS server of a family
        // already unblocks it; stating it means a future change that drops one
        // of those cannot silently start blackholing that family instead.
        b.allowFamily(OsConstants.AF_INET)
        b.allowFamily(OsConstants.AF_INET6)

        // ---------------------------------------------------------------
        // allowBypass() IS DELIBERATELY NOT CALLED.
        //
        // It exists so an app can opt out of the tunnel with
        // Network.bindSocket() / ConnectivityManager.bindProcessToNetwork().
        // DNS66 calls it, and thereby ships a filter that any app which wants
        // to escape can escape with two lines and no permission. A blocker
        // whose bypass is a public API is not a blocker; it is a preference.
        //
        // Our own upstream sockets do not need it — VpnService.protect() is
        // the per-socket exemption, and TunLoop protects every socket it
        // creates.
        // ---------------------------------------------------------------

        // Nor addDisallowedApplication(our own package): the Deep-mode liveness
        // probe (vpn-probe.nullroute.invalid -> 127.0.0.9) is resolved from this
        // process and MUST traverse the tunnel, or the one signal that proves
        // Deep mode is alive can never go green.

        // Non-blocking: TunLoop multiplexes this descriptor with the wake pipe
        // and every upstream socket in a single poll().
        b.setBlocking(false)

        // Without this the VPN network is unconditionally metered, and every app
        // routed through it — which, with no default route, is still every app
        // for the purpose of NetworkCapabilities — would see "metered" on Wi-Fi
        // and start deferring downloads. Passing false lets the VPN inherit the
        // underlying network's real metered state instead of asserting one.
        b.setMetered(false)

        // Follow whatever the system considers the default network. Deep mode
        // has no opinion about which transport carries DNS; pinning one would
        // break the handover the moment Wi-Fi drops.
        b.setUnderlyingNetworks(null)

        configureIntent?.let { b.setConfigureIntent(it) }

        val fd = b.establish()
            ?: throw IllegalStateException(
                "establish() returned null — this app is not the prepared VPN"
            )

        Log.i(TAG, "tunnel up: mtu=$MTU routes=$routes upstreams=${pool.upstreams().size}")
        return Tunnel(fd, MTU)
    }
}
