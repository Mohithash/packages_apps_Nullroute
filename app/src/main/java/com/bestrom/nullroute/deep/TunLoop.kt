package com.bestrom.nullroute.deep

import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Probes
import java.io.FileDescriptor
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress

/** No uid could be attributed to a query. Matches `Process.INVALID_UID`. */
const val UID_UNKNOWN = -1

/**
 * The first uid the framework hands to an installed app. Anything below it is
 * a platform component — for the `getaddrinfo` path that means netd, whose uid
 * says nothing about which app asked.
 */
private const val FIRST_APPLICATION_UID = 10000

/** Writing packets to the tun and opening protected sockets off it. */
interface DeepTransport {
    fun emit(packet: ByteArray, len: Int)

    /** A connected, protected, non-blocking TCP socket, or null. */
    fun openStreamSocket(peer: InetAddress): FileDescriptor?

    fun closeSocket(fd: FileDescriptor)
}

/**
 * The block decision for one parsed query.
 *
 * Tri-state and deliberately not a boolean:
 *  * `> 0` — a response of that many bytes was written to `out`;
 *  * `0` — no opinion, relay the query to the real resolver;
 *  * `< 0` — drop it, answer nothing.
 *
 * "Relay" and "drop" are not interchangeable. Relaying a query we decided to
 * block because the reply would not fit in a buffer would silently un-block it.
 */
interface DeepDnsPolicy {
    fun decide(q: DnsMessage, uid: Int, out: ByteArray, outOff: Int): Int
}

/** What the loop needs from the service that owns the VPN. */
interface DeepHost {
    fun protectSocket(fd: FileDescriptor): Boolean
    fun bindToUnderlying(fd: FileDescriptor)
    fun connectionOwnerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int
    fun onHealthTick(uptimeMs: Long)
    fun onTunnelFailed(reason: String)
}

/**
 * The Deep-mode packet loop: one thread, one `poll()`, no locks.
 *
 * Everything the tunnel does happens here — reading the tun descriptor,
 * deciding each query against the same index the resolver hook uses, relaying
 * what passes, and writing the answer back. The TCP/53 half lives in
 * [Tcp53Server] but shares this thread and this poll set, so no state in either
 * class is ever touched by two threads and none of it needs a lock.
 *
 * ## One socket per outstanding query
 *
 * A forwarder that reuses one upstream socket pins the source port for every
 * query it ever sends, throwing away the entropy the stub resolver would have
 * had against off-path spoofing. So each relayed query gets its own connected
 * socket with a kernel-chosen ephemeral port, closed as soon as the answer
 * arrives. At DNS rates that is three extra syscalls per query for the property
 * that a forwarder is supposed to preserve, and it is why the poll set is
 * "the tun, the wake pipe, and N upstream sockets" rather than a fixed four.
 *
 * The socket being *connected* also means the kernel drops answers from any
 * other address before they reach us; [DnsMessage.matchesResponse] closes the
 * rest of the gap.
 *
 * ## Failing open
 *
 * Every unexpected condition here relays the query rather than answering it.
 * A malformed message, an index that would not map, a verdict the native side
 * refused to give — all of them pass the query through to the real resolver.
 * Deep mode not blocking something is a missed advert; Deep mode swallowing a
 * query is a broken phone.
 */
class TunLoop(
    private val host: DeepHost,
    private val tunFd: FileDescriptor,
    private val pool: AliasPool,
    private val evaluator: DeepEvaluator,
    private val stats: DeepStats,
    private val mtu: Int,
) : Runnable, DeepTransport, DeepDnsPolicy {

    companion object {
        private const val TAG = "NullrouteDeep"

        /** Queries awaiting an upstream answer. Past this, new ones are dropped. */
        private const val MAX_PENDING = 96

        private const val UPSTREAM_TIMEOUT_MS = 5_000L

        /** Packets drained per readable event before the timers get a turn. */
        private const val READ_BURST = 64

        private const val POLL_CEILING_MS = 1_000L

        private const val HEALTH_INTERVAL_MS = 5_000L

        /**
         * Attempts before uid attribution gives up. On the `getaddrinfo` path
         * the packet is emitted by netd, not by the app that asked, so the
         * lookup costs a binder round trip to learn nothing; on Chromium's own
         * resolver it costs one and learns the truth. Measuring which of the two
         * this device is beats guessing.
         */
        private const val UID_PROBE_ATTEMPTS = 32

        private val ANY_LOCAL_V4 = ByteArray(4)
        private val ANY_LOCAL_V6 = ByteArray(16)
    }

    private val tcp = Tcp53Server(this, this, pool, stats, mtu)

    private val readBuf = ByteArray(mtu + 128)
    private val outBuf = ByteArray(mtu + 128)
    private val synthBuf = ByteArray(4096)

    /** Upstream answers. EDNS payloads above this are answered with TC instead. */
    private val upstreamBuf = ByteArray(4096)

    private val redirectAddr = ByteArray(16)
    private val wakeByte = ByteArray(1)
    private val wakeDrain = ByteArray(64)
    private val pkt = PacketCodec.IpPacket()
    private val query = DnsMessage()
    private val echo = DnsMessage()

    private val pending = ArrayList<Pending>(MAX_PENDING)

    private val probeName = Probes.DEEP.toByteArray(Charsets.US_ASCII)
    private val probeAddr = parseLiteral(Probes.DEEP_EXPECT, byteArrayOf(127, 0, 0, 9))

    @Volatile
    private var running = true

    private var wakeRead: FileDescriptor? = null
    private var wakeWrite: FileDescriptor? = null

    @Volatile
    private var networkChanged = false

    private var uidAttempts = 0
    private var uidHits = 0
    private var uidAttribution = true

    private var startedAtMs = 0L
    private var lastHealthMs = 0L

    private class Pending(
        val fd: FileDescriptor,
        val alias: AliasPool.Alias,
        val clientAddr: ByteArray,
        val clientPort: Int,
        val version: Int,
        val query: ByteArray,
        val deadline: Long,
    )

    // ---- lifecycle ----------------------------------------------------------

    /** Interrupts `poll()`. Safe from any thread. */
    fun wake() {
        val fd = wakeWrite ?: return
        runCatching { Os.write(fd, wakeByte, 0, 1) }
    }

    fun stop() {
        running = false
        wake()
    }

    /**
     * The underlying network changed. Every in-flight upstream socket is bound
     * to the network that is going away, so they are abandoned rather than left
     * to time out one by one — the client retries and lands on the new one.
     */
    fun onNetworkChanged() {
        networkChanged = true
        wake()
    }

    override fun run() {
        startedAtMs = SystemClock.elapsedRealtime()
        lastHealthMs = startedAtMs
        try {
            // Os.pipe2() is not on the public android.system.Os surface, so the
            // flags go on afterwards. Both ends must be non-blocking: a full
            // wake pipe must never block the thread calling wake(), and a
            // drained one must never block the loop.
            val pipe = Os.pipe()
            Os.fcntlInt(pipe[0], OsConstants.F_SETFL, OsConstants.O_NONBLOCK)
            Os.fcntlInt(pipe[1], OsConstants.F_SETFL, OsConstants.O_NONBLOCK)
            wakeRead = pipe[0]
            wakeWrite = pipe[1]
            loop()
        } catch (e: ErrnoException) {
            if (running) host.onTunnelFailed("poll loop: ${e.message}")
        } catch (t: Throwable) {
            // A crash here leaves the tunnel established and silent, which is
            // the worst possible state: DNS routed into a process that is no
            // longer reading. Tell the service so it tears the tunnel down.
            Log.e(TAG, "tun loop crashed", t)
            if (running) host.onTunnelFailed("tun loop crashed: ${t.javaClass.simpleName}")
        } finally {
            cleanup()
        }
    }

    private fun cleanup() {
        for (p in pending) closeSocket(p.fd)
        pending.clear()
        tcp.closeAll()
        wakeRead?.let { runCatching { Os.close(it) } }
        wakeWrite?.let { runCatching { Os.close(it) } }
        wakeRead = null
        wakeWrite = null
    }

    // ---- the loop -----------------------------------------------------------

    private fun loop() {
        val fds = ArrayList<StructPollfd>(8)
        val owners = ArrayList<Any?>(8)

        while (running) {
            fds.clear()
            owners.clear()
            fds += pollfd(tunFd, OsConstants.POLLIN); owners += OWNER_TUN
            wakeRead?.let { fds += pollfd(it, OsConstants.POLLIN); owners += OWNER_WAKE }
            for (p in pending) { fds += pollfd(p.fd, OsConstants.POLLIN); owners += p }
            tcp.collectPollFds(fds)
            while (owners.size < fds.size) owners += OWNER_TCP

            val now = SystemClock.elapsedRealtime()
            val timeout = timeoutMs(now)
            val array = fds.toTypedArray()

            val ready = try {
                Os.poll(array, timeout.toInt())
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                throw e
            }

            val after = SystemClock.elapsedRealtime()
            if (ready > 0) {
                for (i in array.indices) {
                    val revents = array[i].revents.toInt()
                    if (revents == 0) continue
                    when (val owner = owners[i]) {
                        OWNER_TUN -> drainTun(after)
                        OWNER_WAKE -> drainWake()
                        OWNER_TCP -> tcp.onPollEvent(array[i].fd, revents, after)
                        is Pending -> onUpstreamReadable(owner)
                        else -> Unit
                    }
                }
            }
            tick(SystemClock.elapsedRealtime())
        }
    }

    private fun timeoutMs(now: Long): Long {
        var t = POLL_CEILING_MS
        for (p in pending) t = minOf(t, (p.deadline - now).coerceAtLeast(0))
        t = tcp.nextTimeout(now, t)
        t = minOf(t, (lastHealthMs + HEALTH_INTERVAL_MS - now).coerceAtLeast(0))
        return t
    }

    private fun tick(now: Long) {
        if (networkChanged) {
            networkChanged = false
            // Sockets bound to the previous network cannot produce an answer;
            // holding them open just delays the client's retry by a timeout.
            for (p in pending) closeSocket(p.fd)
            pending.clear()
            stats.networkChanges++
        }

        var i = 0
        while (i < pending.size) {
            val p = pending[i]
            if (now >= p.deadline) {
                // No SERVFAIL on an upstream timeout: a lost datagram is what
                // the client's own retry exists for, and inventing a hard
                // failure would turn a slow network into a broken one.
                closeSocket(p.fd)
                pending.removeAt(i)
                stats.upstreamTimeouts++
            } else i++
        }

        tcp.onTick(now)

        if (now - lastHealthMs >= HEALTH_INTERVAL_MS) {
            lastHealthMs = now
            host.onHealthTick(now - startedAtMs)
        }
    }

    private fun drainWake() {
        val fd = wakeRead ?: return
        while (true) {
            val n = try {
                Os.read(fd, wakeDrain, 0, wakeDrain.size)
            } catch (e: ErrnoException) {
                return                       // EAGAIN: the pipe is empty again
            }
            if (n < wakeDrain.size) return
        }
    }

    private fun drainTun(now: Long) {
        var burst = 0
        while (burst++ < READ_BURST) {
            val n = try {
                Os.read(tunFd, readBuf, 0, readBuf.size)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EAGAIN -> return
                    OsConstants.EINTR -> continue
                    else -> throw e
                }
            }
            // 0 means the descriptor was closed under us — the tunnel is gone.
            if (n <= 0) { running = false; return }
            handlePacket(n, now)
        }
    }

    private fun handlePacket(len: Int, now: Long) {
        if (!PacketCodec.parse(readBuf, len, pkt)) { stats.malformed++; return }
        val alias = pool.aliasFor(readBuf, pkt.dstOff, pkt.addrLen)
        if (alias == null) {
            // Only /32s onto the aliases are routed in, so this should be
            // unreachable. Counting it makes a routing mistake visible instead
            // of silently expensive.
            stats.stray++
            return
        }
        when {
            pkt.protocol == PacketCodec.PROTO_UDP && pkt.dstPort == AliasPool.DNS_PORT ->
                onDatagram(alias, now)
            pkt.protocol == PacketCodec.PROTO_TCP && pkt.dstPort == AliasPool.DNS_PORT ->
                tcp.onSegment(pkt, alias, now)
            pkt.protocol == PacketCodec.PROTO_TCP -> tcp.reject(pkt)
            else -> stats.stray++
        }
    }

    // ---- the DNS path -------------------------------------------------------

    private fun onDatagram(alias: AliasPool.Alias, now: Long) {
        if (!query.wrap(readBuf, pkt.payloadOff, pkt.payloadLen)) { forward(alias, now); return }
        if (!query.isQuery || query.opcode != 0 || !query.parseQuestion()) {
            // Not a question we can reason about — an update, a notify, a
            // multi-question query. Relay it untouched.
            forward(alias, now)
            return
        }
        query.parseEdns()

        val uid = attributeUid(alias)
        when (val n = decide(query, uid, synthBuf, 0)) {
            0 -> forward(alias, now)
            in 1..Int.MAX_VALUE -> reply(synthBuf, 0, n)
            else -> stats.dropped++
        }
    }

    override fun decide(q: DnsMessage, uid: Int, out: ByteArray, outOff: Int): Int {
        stats.queries++

        // The Deep-mode liveness probe. Answered here and not from the index on
        // purpose: it must prove that THIS tunnel is carrying and answering
        // traffic, which an index redirect (served identically by the resolver
        // hook) could not distinguish.
        if (q.nameEquals(probeName)) {
            stats.probes++
            val n = if (q.qtype == DnsMessage.TYPE_A || q.qtype == DnsMessage.TYPE_ANY) {
                ResponseSynthesizer.sinkhole(q, probeAddr, probeAddr.size, out, outOff)
            } else {
                ResponseSynthesizer.nodata(q, out, outOff)
            }
            return if (n > 0) n else -1
        }

        if (q.nameLen == 0) return 0
        if (q.qclass != DnsMessage.CLASS_IN) return 0

        val packed = evaluator.evaluate(q.name, q.nameLen, uid, redirectAddr)
        if (packed < 0) { stats.evalErrors++; return 0 }

        val n = when (DeepVerdict.kind(packed)) {
            DeepVerdict.REDIRECT -> {
                stats.redirected++
                val len = if (DeepVerdict.family(packed) == OsConstants.AF_INET6) 16 else 4
                ResponseSynthesizer.sinkhole(q, redirectAddr, len, out, outOff)
            }
            DeepVerdict.BLOCK -> {
                stats.blocked++
                when (DeepVerdict.responseMode(packed)) {
                    ControlPage.RESP_NODATA -> ResponseSynthesizer.nodata(q, out, outOff)
                    ControlPage.RESP_SINKHOLE -> {
                        // 0.0.0.0 / :: — the documented trap from SPEC §3.5,
                        // reachable only as a per-app compatibility override.
                        val any = if (q.qtype == DnsMessage.TYPE_AAAA) ANY_LOCAL_V6 else ANY_LOCAL_V4
                        ResponseSynthesizer.sinkhole(q, any, any.size, out, outOff)
                    }
                    else -> ResponseSynthesizer.nxdomain(q, out, outOff)
                }
            }
            else -> return 0
        }
        // A block we could not encode is dropped, never relayed: see DeepDnsPolicy.
        return if (n > 0) n else -1
    }

    /**
     * Best-effort uid for a query, or [UID_UNKNOWN].
     *
     * Returns [UID_UNKNOWN] for every platform uid as well as for a failed
     * lookup. On the `getaddrinfo` path the datagram is emitted by netd on the
     * app's behalf (SPEC §3.3 step 1), so "netd" is a true answer to the wrong
     * question — and feeding it to the matcher would apply the per-app policy of
     * whichever appId happens to collide with netd's uid. Per-app rules are
     * exact at the resolver hook and simply absent here; approximating them
     * would be worse than not having them.
     */
    private fun attributeUid(alias: AliasPool.Alias): Int {
        if (!uidAttribution) return UID_UNKNOWN
        val uid = try {
            val local = InetSocketAddress(
                InetAddress.getByAddress(readBuf.copyOfRange(pkt.srcOff, pkt.srcOff + pkt.addrLen)),
                pkt.srcPort,
            )
            val remote = InetSocketAddress(alias.address, AliasPool.DNS_PORT)
            host.connectionOwnerUid(OsConstants.IPPROTO_UDP, local, remote)
        } catch (t: Throwable) {
            UID_UNKNOWN
        }
        uidAttempts++
        if (uid >= FIRST_APPLICATION_UID) uidHits++
        if (uidAttempts >= UID_PROBE_ATTEMPTS && uidHits == 0) {
            uidAttribution = false
            Log.i(TAG, "uid attribution disabled: $UID_PROBE_ATTEMPTS lookups, none named an app")
        }
        return if (uid >= FIRST_APPLICATION_UID) uid else UID_UNKNOWN
    }

    private fun reply(payload: ByteArray, off: Int, len: Int) {
        val n = PacketCodec.writeUdpReply(pkt, payload, off, len, outBuf, 0)
        if (n > 0) emit(outBuf, n) else stats.dropped++
    }

    // ---- upstream relay -----------------------------------------------------

    private fun forward(alias: AliasPool.Alias, now: Long) {
        if (pending.size >= MAX_PENDING) { stats.dropped++; return }

        val upstream = pool.upstreamFor(alias)
        if (upstream == null) {
            // No resolver to relay to. SERVFAIL is honest here in a way that a
            // timeout is not: the network really has told us it has no DNS.
            servfail()
            return
        }
        val fd = openDatagramSocket(upstream) ?: run { servfail(); return }
        try {
            Os.write(fd, readBuf, pkt.payloadOff, pkt.payloadLen)
        } catch (t: Throwable) {
            closeSocket(fd)
            stats.upstreamErrors++
            servfail()
            return
        }
        pending += Pending(
            fd = fd,
            alias = alias,
            clientAddr = readBuf.copyOfRange(pkt.srcOff, pkt.srcOff + pkt.addrLen),
            clientPort = pkt.srcPort,
            version = pkt.version,
            query = readBuf.copyOfRange(pkt.payloadOff, pkt.payloadOff + pkt.payloadLen),
            deadline = now + UPSTREAM_TIMEOUT_MS,
        )
        stats.forwarded++
    }

    private fun onUpstreamReadable(p: Pending) {
        val raw = try {
            // MSG_TRUNC makes recvfrom report the datagram's REAL length even
            // when it did not fit, which is the only way to tell "small answer"
            // from "answer we silently cut in half".
            Os.recvfrom(p.fd, upstreamBuf, 0, upstreamBuf.size, OsConstants.MSG_TRUNC, null)
        } catch (e: ErrnoException) {
            if (e.errno == OsConstants.EAGAIN) return
            finish(p)
            stats.upstreamErrors++
            return
        }
        if (raw <= 0) { finish(p); stats.upstreamErrors++; return }

        val have = minOf(raw, upstreamBuf.size)
        if (!echo.wrap(p.query, 0, p.query.size) || !echo.parseQuestion()) { finish(p); return }
        if (!echo.matchesResponse(upstreamBuf, 0, have)) {
            // The socket is connected, so this is not an off-path packet; it is
            // an answer to a different question on a reused port. Ignore the
            // datagram and keep waiting for ours.
            stats.upstreamMismatch++
            return
        }
        echo.parseEdns()

        val overhead = PacketCodec.udpOverhead(p.version)
        val sent = if (raw > upstreamBuf.size || overhead + have > mtu) {
            // Too big for the tunnel. TC=1 sends the client to TCP/53, which we
            // serve; forwarding it would mean writing an over-MTU packet, and
            // dropping it would look like a dead resolver.
            stats.truncatedAnswers++
            val tc = ResponseSynthesizer.truncated(echo, synthBuf, 0)
            if (tc > 0) emitReplyTo(p, synthBuf, 0, tc) else 0
        } else {
            emitReplyTo(p, upstreamBuf, 0, have)
        }
        if (sent > 0) stats.answered++
        finish(p)
    }

    private fun emitReplyTo(p: Pending, payload: ByteArray, off: Int, len: Int): Int {
        val n = PacketCodec.writeUdp(
            outBuf, 0, p.version,
            p.alias.bytes, 0,
            p.clientAddr, 0,
            AliasPool.DNS_PORT, p.clientPort,
            payload, off, len,
        )
        if (n > 0) emit(outBuf, n)
        return n
    }

    private fun finish(p: Pending) {
        closeSocket(p.fd)
        pending.remove(p)
    }

    /**
     * SERVFAIL for the query currently in [query]. Silently does nothing for a
     * message we never parsed — echoing a question we could not read would emit
     * a malformed response, and the client's own timeout is the better failure.
     */
    private fun servfail() {
        if (!query.questionOk) { stats.dropped++; return }
        val n = ResponseSynthesizer.servfail(query, synthBuf, 0)
        if (n > 0) reply(synthBuf, 0, n)
        stats.servfails++
    }

    // ---- DeepTransport ------------------------------------------------------

    override fun emit(packet: ByteArray, len: Int) {
        try {
            Os.write(tunFd, packet, 0, len)
        } catch (e: ErrnoException) {
            // EAGAIN here means the kernel's tun queue is full: the device is
            // dropping our answer exactly as a congested link would, and the
            // client will retry.
            if (e.errno != OsConstants.EAGAIN) Log.w(TAG, "tun write: ${e.message}")
            stats.writeDrops++
        }
    }

    override fun openStreamSocket(peer: InetAddress): FileDescriptor? =
        openSocket(peer, OsConstants.SOCK_STREAM, OsConstants.IPPROTO_TCP, tolerateInProgress = true)

    private fun openDatagramSocket(peer: InetAddress): FileDescriptor? =
        openSocket(peer, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP, tolerateInProgress = false)

    private fun openSocket(
        peer: InetAddress, type: Int, protocol: Int, tolerateInProgress: Boolean,
    ): FileDescriptor? {
        var fd: FileDescriptor? = null
        return try {
            val af = if (peer is Inet6Address) OsConstants.AF_INET6 else OsConstants.AF_INET
            fd = Os.socket(af, type, protocol)
            Os.fcntlInt(fd, OsConstants.F_SETFL, OsConstants.O_NONBLOCK)
            // Without protect() this socket is routed back into our own tunnel
            // and the loop eats itself; the failure is a hung phone, so it is
            // fatal to the socket rather than merely logged.
            if (!host.protectSocket(fd)) throw IllegalStateException("protect() refused")
            host.bindToUnderlying(fd)
            try {
                Os.connect(fd, peer, AliasPool.DNS_PORT)
            } catch (e: ErrnoException) {
                if (!(tolerateInProgress && e.errno == OsConstants.EINPROGRESS)) throw e
            }
            fd
        } catch (t: Throwable) {
            fd?.let { runCatching { Os.close(it) } }
            stats.socketErrors++
            Log.w(TAG, "upstream socket to ${peer.hostAddress}: ${t.message}")
            null
        }
    }

    override fun closeSocket(fd: FileDescriptor) {
        runCatching { Os.close(fd) }
    }

    // ---- helpers ------------------------------------------------------------

    private fun pollfd(fd: FileDescriptor, events: Int): StructPollfd {
        val p = StructPollfd()
        p.fd = fd
        p.events = events.toShort()
        return p
    }

    private fun parseLiteral(text: String, fallback: ByteArray): ByteArray = try {
        // A dotted-quad never reaches the resolver, so this cannot block or
        // recurse into the tunnel we are about to build.
        InetAddress.getByName(text).address ?: fallback
    } catch (t: Throwable) {
        fallback
    }
}

/** Identity tokens naming what each poll slot belongs to. */
private val OWNER_TUN = Any()
private val OWNER_WAKE = Any()
private val OWNER_TCP = Any()
