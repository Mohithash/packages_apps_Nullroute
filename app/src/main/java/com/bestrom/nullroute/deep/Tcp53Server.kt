package com.bestrom.nullroute.deep

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import java.io.FileDescriptor
import java.net.InetAddress
import java.security.SecureRandom

/**
 * DNS over TCP/53 inside the Deep-mode tunnel.
 *
 * ## Why this file has to exist, and why it has to be a TCP implementation
 *
 * A `/32` route captures every protocol to that address, not just UDP — so the
 * SYN of a TCP/53 lookup arrives on the tun descriptor too. Without an answer it
 * is a black hole: the client waits out its full connect timeout and the lookup
 * fails, which is *worse* than not running Deep mode at all.
 *
 * The obvious shortcut — bind a `ServerSocket` and let the kernel do TCP — does
 * not work here, twice over. The alias addresses are routed *into* the tunnel
 * rather than assigned to it, so no local socket can receive them; and port 53
 * is privileged, which an app cannot bind on Android in any case. The only place
 * these segments can be answered is userspace, from the packets themselves.
 *
 * ## What it implements, and what it deliberately does not
 *
 * The peer is the local kernel, one virtual hop away, on a link with no
 * congestion, no reordering and loss only if *we* fall behind. So this is a
 * correct-but-minimal endpoint:
 *
 * * three-way handshake with MSS negotiation, ACK of in-order data, dup-ACK on
 *   retransmission, graceful FIN in both directions, RST on anything anomalous;
 * * a single retransmission timer with a fixed interval and a bounded retry
 *   count (go-back-N from `snd.una`), which is all a lossless link can need;
 * * **no** congestion control, no fast retransmit, no SACK, no window scaling,
 *   no out-of-order reassembly — a segment arriving ahead of `rcv.nxt` is
 *   dropped and re-ACKed, and the peer retransmits.
 *
 * Each of those omissions is safe *because of the link*, not because it is
 * convenient, and each one would be a bug on a real network.
 *
 * ## Ports other than 53
 *
 * [reject] answers them with RST rather than silence, and that matters for one
 * case in particular: opportunistic Private DNS probes TCP/853 on whatever
 * resolver the network advertises — which, with the tunnel up, is our alias. A
 * fast RST makes the probe fail immediately and netd falls back to plaintext 53,
 * where we can actually filter. Dropping the SYN instead would stall DNS for the
 * length of a TCP timeout on every network change. (Private DNS in *strict*
 * mode is a different matter entirely — see [DeepVpnService].)
 */
class Tcp53Server(
    private val transport: DeepTransport,
    private val policy: DeepDnsPolicy,
    private val pool: AliasPool,
    private val stats: DeepStats,
    private val mtu: Int,
) {

    companion object {
        private const val TAG = "NullrouteDeep"

        /** Concurrent connections. TCP/53 is a fallback path, not a workload. */
        private const val MAX_CONNECTIONS = 8

        /**
         * Largest query we will assemble. A DNS *query* over TCP is a few
         * hundred bytes; a client announcing 64 KB is either broken or trying to
         * make us hold memory, and 4 KB is past every legitimate case.
         */
        private const val MAX_QUERY = 4096

        /** Largest response stream we will buffer per connection. */
        private const val MAX_STREAM = 128 * 1024

        /** RFC 9293 default MSS when the peer offers none. */
        private const val DEFAULT_MSS_V4 = 536
        private const val DEFAULT_MSS_V6 = 1220

        private const val RETRANSMIT_MS = 300L
        private const val MAX_RETRANSMITS = 5

        /** No progress for this long and the connection is reset and forgotten. */
        private const val IDLE_TIMEOUT_MS = 20_000L

        private const val UPSTREAM_TIMEOUT_MS = 5_000L

        /** Linger after our FIN is acknowledged, to absorb a retransmitted FIN. */
        private const val CLOSE_LINGER_MS = 2_000L
    }

    private enum class State { SYN_RCVD, ESTABLISHED, FIN_SENT, CLOSING }

    private val rng = SecureRandom()
    private val conns = ArrayList<Conn>(MAX_CONNECTIONS)
    private val pktBuf = ByteArray(mtu + 128)
    private val synthBuf = ByteArray(4096)
    private val query = DnsMessage()

    // ---- connection state ---------------------------------------------------

    private inner class Conn(
        val alias: AliasPool.Alias,
        val clientAddr: ByteArray,
        val clientPort: Int,
        val version: Int,
    ) {
        var state = State.SYN_RCVD

        /** Our initial sequence number; `isn + 1` is the first data byte. */
        var isn = 0
        var sndUna = 0
        var sndNxt = 0
        var sndWnd = 0
        var mss = 0

        /** Next sequence number we expect from the peer. */
        var rcvNxt = 0

        /** Unconsumed inbound stream bytes, compacted after each message. */
        val inBuf = ByteArray(2 + MAX_QUERY)
        var inLen = 0

        /** The outbound stream, indexed from `isn + 1`. Never compacted. */
        var outBuf = ByteArray(1024)
        var outLen = 0

        /** True once we have queued a FIN after [outLen]. */
        var finQueued = false
        var peerFin = false

        var retransmitAt = 0L
        var retransmits = 0
        var lastActivityMs = 0L
        var deadAt = 0L

        var relay: Relay? = null

        /** Sequence number of `outBuf[0]`; the SYN consumes `isn` itself. */
        val dataBase get() = isn + 1

        fun appendOut(src: ByteArray, off: Int, len: Int): Boolean {
            if (outLen + len > MAX_STREAM) return false
            if (outLen + len > outBuf.size) {
                var cap = outBuf.size
                while (cap < outLen + len) cap *= 2
                outBuf = outBuf.copyOf(cap)
            }
            System.arraycopy(src, off, outBuf, outLen, len)
            outLen += len
            return true
        }
    }

    /** A protected TCP socket relaying one connection's queries to a resolver. */
    private inner class Relay(
        val fd: FileDescriptor,
        val conn: Conn,
        val upstream: InetAddress,
    ) {
        var connected = false
        var tx: ByteArray = ByteArray(0)
        var txOff = 0
        val rx = ByteArray(2 + 65535)
        var rxLen = 0
        var deadline = 0L
    }

    // ---- inbound ------------------------------------------------------------

    /** Handles one TCP segment addressed to port 53 on one of our aliases. */
    fun onSegment(pkt: PacketCodec.IpPacket, alias: AliasPool.Alias, nowMs: Long) {
        val conn = find(pkt)

        if (pkt.hasFlag(PacketCodec.TCP_RST)) {
            conn?.let { drop(it) }
            return
        }

        if (conn == null) {
            if (pkt.hasFlag(PacketCodec.TCP_SYN) && !pkt.hasFlag(PacketCodec.TCP_ACK)) {
                accept(pkt, alias, nowMs)
            } else {
                // A segment for a connection we have no record of. RFC 9293 says
                // reset it; staying silent makes the peer retransmit until its
                // own timeout, which is the stall this class exists to avoid.
                sendReset(pkt)
            }
            return
        }

        conn.lastActivityMs = nowMs

        if (pkt.hasFlag(PacketCodec.TCP_SYN)) {
            // A retransmitted SYN before our SYN-ACK landed: re-send it.
            if (conn.state == State.SYN_RCVD) sendSynAck(conn)
            return
        }

        if (!pkt.hasFlag(PacketCodec.TCP_ACK)) return

        if (conn.state == State.SYN_RCVD) {
            if (pkt.tcpAck != conn.isn + 1) { sendReset(pkt); drop(conn); return }
            conn.state = State.ESTABLISHED
            conn.sndUna = conn.isn + 1
            conn.sndNxt = conn.isn + 1
            conn.retransmits = 0
        }

        // Acknowledgement processing. Our stream is data then FIN, so an ack
        // covering outLen + 1 acknowledges the FIN as well.
        if (seqGt(pkt.tcpAck, conn.sndUna)) {
            val limit = conn.dataBase + conn.outLen + (if (conn.finQueued) 1 else 0)
            conn.sndUna = if (seqGt(pkt.tcpAck, limit)) limit else pkt.tcpAck
            conn.retransmits = 0
            conn.retransmitAt = 0L
        }
        conn.sndWnd = pkt.tcpWindow

        if (pkt.payloadLen > 0) {
            onData(conn, pkt, nowMs)
            // onData may have reset and forgotten this connection. Carrying on
            // would emit segments for a connection we have already RST.
            if (!conns.contains(conn)) return
        }

        if (pkt.hasFlag(PacketCodec.TCP_FIN) && pkt.tcpSeq == conn.rcvNxt && !conn.peerFin) {
            conn.peerFin = true
            conn.rcvNxt += 1
            sendAck(conn)
            // Half-close: the peer is done asking, but we may still owe an
            // answer, so the connection is not finished until our stream is.
            maybeFinish(conn)
        }

        pumpOutput(conn, nowMs)

        if (conn.state == State.FIN_SENT &&
            conn.sndUna == conn.dataBase + conn.outLen + 1 &&
            conn.deadAt == 0L
        ) {
            conn.deadAt = nowMs + CLOSE_LINGER_MS
            conn.state = State.CLOSING
        }
    }

    /** RST for a TCP segment we will not serve — a port other than 53. */
    fun reject(pkt: PacketCodec.IpPacket) {
        if (!pkt.hasFlag(PacketCodec.TCP_RST)) sendReset(pkt)
    }

    private fun accept(pkt: PacketCodec.IpPacket, alias: AliasPool.Alias, nowMs: Long) {
        if (conns.size >= MAX_CONNECTIONS) {
            stats.tcpRejected++
            sendReset(pkt)
            return
        }
        val conn = Conn(
            alias = alias,
            clientAddr = pkt.buf.copyOfRange(pkt.srcOff, pkt.srcOff + pkt.addrLen),
            clientPort = pkt.srcPort,
            version = pkt.version,
        )
        conn.isn = rng.nextInt()
        conn.sndUna = conn.isn
        conn.sndNxt = conn.isn
        conn.rcvNxt = pkt.tcpSeq + 1
        conn.sndWnd = pkt.tcpWindow
        conn.lastActivityMs = nowMs

        val ourMss = mtu - PacketCodec.tcpOverhead(conn.version)
        val peerMss = PacketCodec.tcpMss(pkt)
        val fallback = if (conn.version == 4) DEFAULT_MSS_V4 else DEFAULT_MSS_V6
        conn.mss = minOf(ourMss, if (peerMss > 0) peerMss else fallback).coerceAtLeast(128)

        conns += conn
        stats.tcpAccepted++
        sendSynAck(conn)
    }

    private fun onData(conn: Conn, pkt: PacketCodec.IpPacket, nowMs: Long) {
        if (pkt.tcpSeq != conn.rcvNxt) {
            // Duplicate (already consumed) or out of order (we do not buffer
            // ahead). Either way a bare ACK of rcv.nxt is the right answer: it
            // is a dup-ACK for the first and a retransmit trigger for the second.
            sendAck(conn)
            return
        }
        val space = conn.inBuf.size - conn.inLen
        if (pkt.payloadLen > space) {
            // We advertised a window; the peer overran it. Reset rather than
            // silently discarding half a DNS message.
            sendReset(pkt)
            drop(conn)
            return
        }
        System.arraycopy(pkt.buf, pkt.payloadOff, conn.inBuf, conn.inLen, pkt.payloadLen)
        conn.inLen += pkt.payloadLen
        conn.rcvNxt += pkt.payloadLen
        sendAck(conn)
        consumeMessages(conn, nowMs)
    }

    /**
     * Pulls whole length-prefixed messages out of the inbound buffer.
     *
     * RFC 7766 allows a client to pipeline several queries on one connection, so
     * this loops rather than assuming one. Each is answered in arrival order,
     * which is the only ordering guarantee a DNS client is entitled to.
     */
    private fun consumeMessages(conn: Conn, nowMs: Long) {
        while (conn.inLen >= 2) {
            val msgLen = ((conn.inBuf[0].toInt() and 0xFF) shl 8) or (conn.inBuf[1].toInt() and 0xFF)
            if (msgLen == 0 || msgLen > MAX_QUERY) {
                resetConn(conn)
                return
            }
            if (conn.inLen < 2 + msgLen) return
            handleQuery(conn, conn.inBuf, 2, msgLen, nowMs)
            val consumed = 2 + msgLen
            System.arraycopy(conn.inBuf, consumed, conn.inBuf, 0, conn.inLen - consumed)
            conn.inLen -= consumed
            // Only one query may be in flight upstream per connection; the rest
            // stay buffered until the relay is free.
            if (conn.relay != null) return
        }
    }

    private fun handleQuery(conn: Conn, buf: ByteArray, off: Int, len: Int, nowMs: Long) {
        stats.tcpQueries++
        if (!query.wrap(buf, off, len) || !query.isQuery || query.opcode != 0 ||
            !query.parseQuestion()
        ) {
            relay(conn, buf, off, len, nowMs)
            return
        }
        query.parseEdns()

        // No uid attribution on the TCP path. getConnectionOwnerUid() wants a
        // live 5-tuple in the kernel's table, and this connection exists only in
        // this process, so there is nothing to look up. Per-app policy therefore
        // does not apply to TCP/53 — stated here rather than approximated.
        when (val synth = policy.decide(query, UID_UNKNOWN, synthBuf, 0)) {
            0 -> relay(conn, buf, off, len, nowMs)
            in 1..Int.MAX_VALUE -> {
                queueResponse(conn, synthBuf, 0, synth)
                pumpOutput(conn, nowMs)
            }
            // A decision we could not encode. Answering nothing on a TCP
            // connection the client is holding open is better than relaying a
            // query we had already decided to block.
            else -> Unit
        }
    }

    private fun queueResponse(conn: Conn, buf: ByteArray, off: Int, len: Int) {
        val prefix = byteArrayOf(((len ushr 8) and 0xFF).toByte(), (len and 0xFF).toByte())
        if (!conn.appendOut(prefix, 0, 2) || !conn.appendOut(buf, off, len)) {
            resetConn(conn)
            return
        }
        maybeFinish(conn)
    }

    /**
     * Queues a FIN once the peer has stopped asking and nothing is outstanding.
     * Holding the connection open after that would only pin a slot.
     */
    private fun maybeFinish(conn: Conn) {
        if (conn.peerFin && conn.relay == null && conn.inLen == 0 && !conn.finQueued) {
            conn.finQueued = true
        }
    }

    // ---- outbound -----------------------------------------------------------

    /** Sends whatever the peer's window allows, and arms the retransmit timer. */
    private fun pumpOutput(conn: Conn, nowMs: Long) {
        if (conn.state != State.ESTABLISHED && conn.state != State.FIN_SENT) return

        val endOfData = conn.dataBase + conn.outLen
        var windowEnd = conn.sndUna + conn.sndWnd
        // Never stall completely on a zero window: one byte keeps the peer's
        // window probe honest. In practice the local stack never advertises zero
        // for a few-kilobyte DNS answer.
        if (conn.sndWnd == 0) windowEnd = conn.sndUna + 1

        while (seqLt(conn.sndNxt, endOfData) && seqLt(conn.sndNxt, windowEnd)) {
            val idx = conn.sndNxt - conn.dataBase
            var chunk = minOf(conn.mss, conn.outLen - idx)
            val room = windowEnd - conn.sndNxt
            if (room < chunk) chunk = room
            if (chunk <= 0) break
            val last = idx + chunk >= conn.outLen
            sendSegment(
                conn, conn.sndNxt, PacketCodec.TCP_ACK or (if (last) PacketCodec.TCP_PSH else 0),
                conn.outBuf, idx, chunk,
            )
            conn.sndNxt += chunk
            if (conn.retransmitAt == 0L) conn.retransmitAt = nowMs + RETRANSMIT_MS
        }

        if (conn.finQueued && conn.sndNxt == endOfData && conn.state == State.ESTABLISHED) {
            sendSegment(conn, conn.sndNxt, PacketCodec.TCP_ACK or PacketCodec.TCP_FIN, null, 0, 0)
            conn.sndNxt += 1
            conn.state = State.FIN_SENT
            if (conn.retransmitAt == 0L) conn.retransmitAt = nowMs + RETRANSMIT_MS
        }

        if (conn.sndUna == conn.sndNxt) conn.retransmitAt = 0L
    }

    private fun sendSynAck(conn: Conn) {
        val opts = byteArrayOf(
            2, 4,
            ((conn.mss ushr 8) and 0xFF).toByte(), (conn.mss and 0xFF).toByte(),
        )
        emit(
            conn, conn.isn, PacketCodec.TCP_SYN or PacketCodec.TCP_ACK,
            opts, opts.size, null, 0, 0,
        )
    }

    private fun sendAck(conn: Conn) =
        emit(conn, conn.sndNxt, PacketCodec.TCP_ACK, null, 0, null, 0, 0)

    private fun sendSegment(
        conn: Conn, seq: Int, flags: Int, payload: ByteArray?, payloadOff: Int, payloadLen: Int,
    ) = emit(conn, seq, flags, null, 0, payload, payloadOff, payloadLen)

    private fun emit(
        conn: Conn, seq: Int, flags: Int,
        options: ByteArray?, optionsLen: Int,
        payload: ByteArray?, payloadOff: Int, payloadLen: Int,
    ) {
        val n = PacketCodec.writeTcp(
            pktBuf, 0, conn.version,
            conn.alias.bytes, 0,
            conn.clientAddr, 0,
            AliasPool.DNS_PORT, conn.clientPort,
            // The advertised window is exactly the free space in the assembly
            // buffer. Advertising more than we can hold is how a well-behaved
            // peer gets its connection reset for "overrunning" a window we
            // never had.
            seq, conn.rcvNxt, flags, conn.inBuf.size - conn.inLen,
            options, optionsLen,
            payload, payloadOff, payloadLen,
        )
        if (n > 0) transport.emit(pktBuf, n)
    }

    /** RST built straight from an inbound segment, with no connection state. */
    private fun sendReset(pkt: PacketCodec.IpPacket) {
        // RFC 9293 §3.10.7.1: if the offending segment carried an ACK, the RST
        // takes its sequence from that ACK; otherwise it acknowledges the
        // segment's own sequence space so the peer accepts it.
        val ack = pkt.hasFlag(PacketCodec.TCP_ACK)
        val seq = if (ack) pkt.tcpAck else 0
        val payloadSpace = pkt.payloadLen + (if (pkt.hasFlag(PacketCodec.TCP_SYN)) 1 else 0) +
            (if (pkt.hasFlag(PacketCodec.TCP_FIN)) 1 else 0)
        val flags = if (ack) PacketCodec.TCP_RST
        else PacketCodec.TCP_RST or PacketCodec.TCP_ACK
        val n = PacketCodec.writeTcp(
            pktBuf, 0, pkt.version,
            pkt.buf, pkt.dstOff,
            pkt.buf, pkt.srcOff,
            pkt.dstPort, pkt.srcPort,
            seq, pkt.tcpSeq + payloadSpace, flags, 0,
            null, 0, null, 0, 0,
        )
        if (n > 0) transport.emit(pktBuf, n)
    }

    private fun resetConn(conn: Conn) {
        val n = PacketCodec.writeTcp(
            pktBuf, 0, conn.version,
            conn.alias.bytes, 0,
            conn.clientAddr, 0,
            AliasPool.DNS_PORT, conn.clientPort,
            conn.sndNxt, conn.rcvNxt, PacketCodec.TCP_RST or PacketCodec.TCP_ACK, 0,
            null, 0, null, 0, 0,
        )
        if (n > 0) transport.emit(pktBuf, n)
        drop(conn)
    }

    private fun drop(conn: Conn) {
        conn.relay?.let { closeRelay(it) }
        conns.remove(conn)
    }

    // ---- upstream relay -----------------------------------------------------

    private fun relay(conn: Conn, buf: ByteArray, off: Int, len: Int, nowMs: Long) {
        if (conn.relay != null) return                       // one in flight per connection
        val upstream = pool.upstreamFor(conn.alias)
        if (upstream == null) { failQuery(conn, buf, off, len, nowMs); return }
        val fd = transport.openStreamSocket(upstream)
        if (fd == null) { failQuery(conn, buf, off, len, nowMs); return }

        val relay = Relay(fd, conn, upstream)
        relay.tx = ByteArray(2 + len)
        relay.tx[0] = ((len ushr 8) and 0xFF).toByte()
        relay.tx[1] = (len and 0xFF).toByte()
        System.arraycopy(buf, off, relay.tx, 2, len)
        relay.deadline = nowMs + UPSTREAM_TIMEOUT_MS
        conn.relay = relay
        stats.tcpRelayed++
    }

    /** SERVFAIL for a query we could not relay. Never a block — see §3.5. */
    private fun failQuery(conn: Conn, buf: ByteArray, off: Int, len: Int, nowMs: Long) {
        if (query.wrap(buf, off, len) && query.parseQuestion()) {
            query.parseEdns()
            val n = ResponseSynthesizer.servfail(query, synthBuf, 0)
            if (n > 0) {
                queueResponse(conn, synthBuf, 0, n)
                pumpOutput(conn, nowMs)
            }
        }
    }

    /** Descriptors the owning [TunLoop] must include in its poll set. */
    fun collectPollFds(into: MutableList<StructPollfd>) {
        for (conn in conns) {
            val relay = conn.relay ?: continue
            val p = StructPollfd()
            p.fd = relay.fd
            // POLLOUT covers both "connect() has completed" and "there is still
            // request left to write"; only once the whole query is out do we
            // start waiting for the answer.
            val pending = !relay.connected || relay.txOff < relay.tx.size
            p.events = (if (pending) OsConstants.POLLOUT else OsConstants.POLLIN).toShort()
            into += p
        }
    }

    /** Returns true when [fd] belonged to this server and was handled. */
    fun onPollEvent(fd: FileDescriptor, revents: Int, nowMs: Long): Boolean {
        val conn = conns.firstOrNull { it.relay?.fd === fd } ?: return false
        val relay = conn.relay ?: return false
        try {
            if (!relay.connected) {
                if ((revents and (OsConstants.POLLERR or OsConstants.POLLHUP)) != 0) {
                    throw ErrnoException("connect", OsConstants.ECONNREFUSED)
                }
                if (!connectCompleted(relay)) return true
                relay.connected = true
            }
            if (relay.txOff < relay.tx.size) {
                relay.txOff += Os.write(relay.fd, relay.tx, relay.txOff, relay.tx.size - relay.txOff)
                return true
            }
            val n = Os.read(relay.fd, relay.rx, relay.rxLen, relay.rx.size - relay.rxLen)
            // 0 is a clean EOF from the resolver before a whole message arrived,
            // which is a failed query, not a closed idle connection.
            if (n <= 0) throw ErrnoException("read", OsConstants.ECONNRESET)
            relay.rxLen += n
            if (relay.rxLen >= 2) {
                val want = 2 + (((relay.rx[0].toInt() and 0xFF) shl 8) or (relay.rx[1].toInt() and 0xFF))
                if (relay.rxLen >= want) {
                    conn.relay = null
                    closeRelay(relay)
                    stats.tcpAnswered++
                    queueResponse(conn, relay.rx, 2, want - 2)
                    pumpOutput(conn, nowMs)
                    consumeMessages(conn, nowMs)
                }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "tcp relay to ${relay.upstream.hostAddress} failed: ${t.message}")
            conn.relay = null
            closeRelay(relay)
            stats.tcpErrors++
            failQuery(conn, relay.tx, 2, relay.tx.size - 2, nowMs)
        }
        return true
    }

    /**
     * Whether a non-blocking connect has finished, and successfully.
     *
     * `SO_ERROR` — the usual way to ask — is not on the public `android.system.Os`
     * surface, so this uses the portable alternative: re-issuing `connect()` on
     * a socket whose connect has completed returns `EISCONN`, one still in
     * flight returns `EALREADY`, and one that failed reports its error. Throws
     * on failure, which the caller already treats as a dead relay.
     */
    private fun connectCompleted(relay: Relay): Boolean = try {
        Os.connect(relay.fd, relay.upstream, AliasPool.DNS_PORT)
        true
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.EISCONN -> true
            OsConstants.EALREADY, OsConstants.EINPROGRESS -> false
            else -> throw e
        }
    }

    private fun closeRelay(relay: Relay) {
        transport.closeSocket(relay.fd)
    }

    // ---- timers -------------------------------------------------------------

    fun onTick(nowMs: Long) {
        var i = 0
        while (i < conns.size) {
            val conn = conns[i]
            var removed = false

            val relay = conn.relay
            if (relay != null && nowMs >= relay.deadline) {
                conn.relay = null
                closeRelay(relay)
                stats.tcpTimeouts++
                failQuery(conn, relay.tx, 2, relay.tx.size - 2, nowMs)
            }

            if (conn.deadAt != 0L && nowMs >= conn.deadAt) {
                drop(conn); removed = true
            } else if (nowMs - conn.lastActivityMs > IDLE_TIMEOUT_MS) {
                resetConn(conn); removed = true
            } else if (conn.retransmitAt != 0L && nowMs >= conn.retransmitAt) {
                if (++conn.retransmits > MAX_RETRANSMITS) {
                    resetConn(conn); removed = true
                } else {
                    // Go-back-N: everything from snd.una is resent. Correct and
                    // trivial on a link where the only loss is our own overrun.
                    conn.sndNxt = conn.sndUna
                    conn.retransmitAt = nowMs + RETRANSMIT_MS
                    if (conn.state == State.FIN_SENT) conn.state = State.ESTABLISHED
                    pumpOutput(conn, nowMs)
                }
            }

            if (!removed) i++
        }
    }

    /** Milliseconds until this server next needs attention, or [ceiling]. */
    fun nextTimeout(nowMs: Long, ceiling: Long): Long {
        var t = ceiling
        for (conn in conns) {
            if (conn.retransmitAt != 0L) t = minOf(t, (conn.retransmitAt - nowMs).coerceAtLeast(0))
            if (conn.deadAt != 0L) t = minOf(t, (conn.deadAt - nowMs).coerceAtLeast(0))
            conn.relay?.let { t = minOf(t, (it.deadline - nowMs).coerceAtLeast(0)) }
        }
        return t
    }

    fun closeAll() {
        for (conn in ArrayList(conns)) {
            conn.relay?.let { closeRelay(it) }
        }
        conns.clear()
    }

    // ---- helpers ------------------------------------------------------------

    private fun find(pkt: PacketCodec.IpPacket): Conn? {
        for (conn in conns) {
            if (conn.clientPort == pkt.srcPort &&
                conn.version == pkt.version &&
                PacketCodec.addrEquals(conn.clientAddr, 0, pkt.buf, pkt.srcOff, pkt.addrLen) &&
                PacketCodec.addrEquals(conn.alias.bytes, 0, pkt.buf, pkt.dstOff, pkt.addrLen)
            ) return conn
        }
        return null
    }

    /** Wrapped 32-bit sequence comparison (RFC 9293 §3.4). */
    private fun seqLt(a: Int, b: Int) = (a - b) < 0
    private fun seqGt(a: Int, b: Int) = (a - b) > 0
}
