package com.bestrom.nullroute.deep

import android.util.Log
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * The in-tunnel DNS server addresses, and their mapping onto the real upstream
 * resolvers.
 *
 * Deep mode advertises DNS servers that do not exist. They are drawn from the
 * documentation blocks — RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`,
 * `203.0.113.0/24` and RFC 3849 `2001:db8::/32` — which are guaranteed never to
 * be routed on a real network, so a `/32` route onto one of them cannot
 * blackhole anything the user actually needs. The cost of the tunnel is then
 * **per DNS query**, not per byte of the device's traffic: nothing else is
 * routed in, so nothing else is copied through userspace.
 *
 * ## Why the alias set is fixed and the upstream set is not
 *
 * `VpnService.Builder.addDnsServer()` takes effect at `establish()` and cannot
 * be changed afterwards; changing the advertised server list means tearing the
 * tunnel down and building a new one, which drops every socket bound to it.
 * Meanwhile the *real* upstream resolvers change every time the device moves
 * between Wi-Fi and cellular — several times an hour on a phone in a pocket.
 *
 * So the alias is a **stable handle** and the mapping behind it is what moves:
 * [reset] fixes two aliases per family for the tunnel's lifetime, and [remap]
 * re-points them at whatever the underlying network now offers. A network change
 * costs one array swap and no packets.
 *
 * Two aliases per family rather than one because stub resolvers retry across the
 * server list: with two, that retry naturally lands on a *different real
 * upstream*, so the client's own failover keeps working instead of hammering one
 * resolver twice.
 *
 * ## Families are handles, not paths
 *
 * A query that arrives on the IPv4 alias may be relayed to an IPv6 upstream and
 * back. The tunnel is a virtual transport we terminate, not something we bridge,
 * so the address family of the in-tunnel packet has nothing to do with the
 * family of the socket we forward on. That is what keeps Deep mode working on an
 * IPv6-only/464XLAT carrier (SPEC §10.6 spike 7) instead of advertising an IPv4
 * resolver it cannot reach.
 */
class AliasPool {

    companion object {
        private const val TAG = "NullrouteDeep"

        /** See the class comment: two per family, fixed for the tunnel's life. */
        const val ALIASES_PER_FAMILY = 2

        const val DNS_PORT = 53

        /** RFC 5737 documentation prefixes, tried in order. */
        private val V4_CANDIDATES = arrayOf(
            byteArrayOf(192.toByte(), 0, 2),
            byteArrayOf(198.toByte(), 51, 100),
            byteArrayOf(203.toByte(), 0, 113),
        )

        /** RFC 3849 `2001:db8::/32`. */
        private val V6_PREFIX = byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte())

        const val V4_PREFIX_LEN = 24
        const val V6_PREFIX_LEN = 120

        /** Host part of the tunnel's own address; aliases start at 2. */
        private const val HOST_TUNNEL = 1
        private const val HOST_ALIAS_BASE = 2
    }

    /** One advertised in-tunnel resolver. [bytes] is the wire form, for matching. */
    class Alias(
        val address: InetAddress,
        val bytes: ByteArray,
        /** 4 or 6. */
        val version: Int,
        /** 0-based position within its family; selects the real upstream. */
        val slot: Int,
    )

    private class State(
        val tunnel4: InetAddress?,
        val tunnel6: InetAddress?,
        val aliases: Array<Alias>,
        val upstreams: Array<InetAddress>,
    ) {
        companion object {
            val EMPTY = State(null, null, emptyArray(), emptyArray())
        }
    }

    /**
     * Read on the tunnel thread, replaced on the connectivity callback. A whole
     * new immutable [State] is published rather than mutating in place, so a
     * remap mid-query can only be seen as entirely before or entirely after.
     */
    @Volatile
    private var state: State = State.EMPTY

    val tunnelAddress4: InetAddress? get() = state.tunnel4
    val tunnelAddress6: InetAddress? get() = state.tunnel6

    /** The addresses to pass to `addDnsServer()` and `addRoute()`, in order. */
    fun aliases(): List<Alias> = state.aliases.asList()

    val isConfigured: Boolean get() = state.aliases.isNotEmpty()

    /**
     * Picks the documentation prefixes and lays out the tunnel address and the
     * aliases. Call once, before `establish()`.
     *
     * Returns false only if every IPv4 candidate prefix is already present on a
     * local interface, which would mean routing a `/32` that some other
     * interface legitimately owns.
     */
    fun reset(): Boolean {
        val v4 = V4_CANDIDATES.firstOrNull { !prefixInUse(it, V4_PREFIX_LEN) }
        if (v4 == null) {
            // All three RFC 5737 blocks present locally is not a configuration
            // we are willing to guess our way through: a /32 onto an address
            // another interface owns is a silent blackhole for real traffic.
            Log.w(TAG, "every RFC 5737 prefix is in use on a local interface")
            return false
        }
        val v6InUse = prefixInUse(V6_PREFIX, 32)
        if (v6InUse) Log.w(TAG, "2001:db8::/32 is in use locally; IPv6 aliases disabled")

        val aliases = ArrayList<Alias>(ALIASES_PER_FAMILY * 2)
        val tunnel4 = v4Address(v4, HOST_TUNNEL)
        for (i in 0 until ALIASES_PER_FAMILY) {
            val a = v4Address(v4, HOST_ALIAS_BASE + i)
            aliases += Alias(a, a.address, 4, i)
        }
        var tunnel6: InetAddress? = null
        if (!v6InUse) {
            tunnel6 = v6Address(HOST_TUNNEL)
            for (i in 0 until ALIASES_PER_FAMILY) {
                val a = v6Address(HOST_ALIAS_BASE + i)
                aliases += Alias(a, a.address, 6, i)
            }
        }

        state = State(tunnel4, tunnel6, aliases.toTypedArray(), state.upstreams)
        Log.i(TAG, "aliases: " + aliases.joinToString { it.address.hostAddress ?: "?" })
        return true
    }

    /**
     * Re-points the aliases at a new set of real resolvers. Safe to call at any
     * time from any thread; queries already in flight keep the upstream they
     * were sent to, because the pending entry holds the address, not the slot.
     *
     * Filters out anything that would make the tunnel eat its own tail: our own
     * aliases (a loop that would spin a core), loopback, and unspecified
     * addresses. A device whose only advertised resolver is one of ours is a
     * device where Deep mode must forward nothing rather than forward to itself.
     */
    fun remap(upstreams: List<InetAddress>) {
        val s = state
        val clean = upstreams.filter { candidate ->
            when {
                candidate.isLoopbackAddress -> false
                candidate.isAnyLocalAddress -> false
                s.aliases.any { it.address == candidate } -> false
                else -> true
            }
        }
        state = State(s.tunnel4, s.tunnel6, s.aliases, clean.toTypedArray())
        Log.i(TAG, "upstreams: " + (clean.joinToString { it.hostAddress ?: "?" }.ifEmpty { "none" }))
    }

    val hasUpstreams: Boolean get() = state.upstreams.isNotEmpty()

    fun upstreams(): List<InetAddress> = state.upstreams.asList()

    /**
     * The alias a packet is addressed to, or null when it is not ours. Compares
     * raw bytes against the packet buffer so the hot path never materialises an
     * `InetAddress`.
     */
    fun aliasFor(buf: ByteArray, off: Int, len: Int): Alias? {
        val aliases = state.aliases
        for (i in aliases.indices) {
            val a = aliases[i]
            if (a.bytes.size == len && PacketCodec.addrEquals(a.bytes, 0, buf, off, len)) return a
        }
        return null
    }

    /**
     * The real resolver behind [alias].
     *
     * The slot indexes the upstream list modulo its size, so alias 0 and alias 1
     * address different resolvers whenever the network offers more than one and
     * the same one when it offers exactly one. Returns null when the network has
     * advertised no resolver at all, which the caller answers with SERVFAIL —
     * inventing an upstream would be worse than saying so.
     */
    fun upstreamFor(alias: Alias): InetAddress? {
        val ups = state.upstreams
        if (ups.isEmpty()) return null
        return ups[alias.slot % ups.size]
    }

    /** The next resolver to try after [previous] failed, or null when exhausted. */
    fun nextUpstreamAfter(previous: InetAddress): InetAddress? {
        val ups = state.upstreams
        if (ups.size < 2) return null
        val i = ups.indexOf(previous)
        if (i < 0) return ups[0]
        return ups[(i + 1) % ups.size]
    }

    // ---- address construction ----------------------------------------------

    private fun v4Address(prefix: ByteArray, host: Int): InetAddress =
        InetAddress.getByAddress(byteArrayOf(prefix[0], prefix[1], prefix[2], host.toByte()))

    private fun v6Address(host: Int): InetAddress {
        val b = ByteArray(16)
        System.arraycopy(V6_PREFIX, 0, b, 0, V6_PREFIX.size)
        b[15] = host.toByte()
        return InetAddress.getByAddress(b)
    }

    /**
     * Whether any address on any local interface falls inside the prefix.
     *
     * `VpnService.Builder.addAddress()` does *not* detect this — it validates the
     * address, not the topology — so the check the SPEC sketch delegated to a
     * caught `IllegalArgumentException` has to be made explicitly. Failure to
     * enumerate is treated as "not in use": the documentation blocks are
     * unroutable by definition, and refusing to start Deep mode because we could
     * not read the interface list would be the wrong way round.
     */
    private fun prefixInUse(prefix: ByteArray, prefixLen: Int): Boolean = try {
        val ifaces = NetworkInterface.getNetworkInterfaces()
        var hit = false
        while (ifaces != null && ifaces.hasMoreElements() && !hit) {
            val iface = ifaces.nextElement()
            for (ia in iface.interfaceAddresses) {
                val addr = ia.address ?: continue
                val wantV4 = prefix.size == 3
                if (wantV4 && addr !is Inet4Address) continue
                if (!wantV4 && addr !is Inet6Address) continue
                if (matchesPrefix(addr.address, prefix, prefixLen)) { hit = true; break }
            }
        }
        hit
    } catch (t: Throwable) {
        Log.w(TAG, "interface scan failed: ${t.message}")
        false
    }

    private fun matchesPrefix(addr: ByteArray, prefix: ByteArray, prefixLen: Int): Boolean {
        val fullBytes = prefixLen / 8
        if (fullBytes > prefix.size || fullBytes > addr.size) return false
        for (i in 0 until fullBytes) if (addr[i] != prefix[i]) return false
        val bits = prefixLen % 8
        if (bits == 0) return true
        val mask = (0xFF shl (8 - bits)) and 0xFF
        if (fullBytes >= prefix.size || fullBytes >= addr.size) return false
        return (addr[fullBytes].toInt() and mask) == (prefix[fullBytes].toInt() and mask)
    }
}
