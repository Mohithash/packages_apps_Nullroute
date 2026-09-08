package com.bestrom.nullroute.deep

/**
 * IPv4 / IPv6 + UDP + TCP parse and emit for the Deep-mode tunnel.
 *
 * A `VpnService` tun descriptor carries **bare IP packets** — no link layer, no
 * framing, one packet per `read()`. Because Deep mode routes only `/32` and
 * `/128` prefixes onto the DNS aliases (see [TunnelBuilder]), everything that
 * arrives here is addressed to one of those aliases. That is what keeps this
 * file small: there is no general-purpose stack to write, only the two transport
 * headers that can carry a DNS message.
 *
 * ## Conventions
 *
 * Nothing here allocates on the hot path. [IpPacket] is a caller-owned mutable
 * descriptor that is reused for every packet, addresses stay as `(array,
 * offset)` pairs rather than `InetAddress` objects, and every emit function
 * writes into a caller-supplied buffer and returns the byte count.
 *
 * ## What is deliberately not implemented
 *
 * * **Fragment reassembly.** A fragmented IPv4 datagram or an IPv6 fragment
 *   header is dropped. The peer on this link is the local kernel sending a DNS
 *   query to a `/32` on a 1500-byte MTU; if that ever fragments, the query was
 *   already past the point where a UDP answer would fit and the client's TCP
 *   fallback ([Tcp53Server]) is the correct path.
 * * **Inbound checksum verification.** Every packet on this interface was
 *   generated moments ago by the kernel on this device, so a bad checksum means
 *   a bug in *this* file, not corruption in flight — and dropping DNS because of
 *   a bug in our own verifier would be far worse than the corruption it guards
 *   against. Outbound checksums are computed in full: those we are responsible
 *   for, and the receiving stack does verify them.
 */
object PacketCodec {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    const val IPV4_HEADER_MIN = 20
    const val IPV6_HEADER = 40
    const val UDP_HEADER = 8
    const val TCP_HEADER_MIN = 20

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    /** Hop limit / TTL on everything we emit. The peer is one virtual hop away. */
    private const val DEFAULT_TTL = 64

    /**
     * IPv4 `Don't Fragment`, with the ID field left at zero.
     *
     * Legal precisely because we never emit a packet larger than the tunnel MTU
     * — [Tcp53Server] segments to the MSS and the UDP path sets TC rather than
     * overflowing (RFC 6864 §4.1: an atomic datagram may carry ID 0).
     */
    private const val IPV4_FLAGS_DF = 0x4000

    private val EMPTY = ByteArray(0)

    /**
     * One parsed packet. Field validity depends on [protocol]: the `tcp*` fields
     * are only filled for [PROTO_TCP], and [payloadOff] / [payloadLen] describe
     * the UDP payload or the TCP segment data respectively.
     */
    class IpPacket {
        var buf: ByteArray = EMPTY

        /** 4 or 6. */
        var version = 0
        var protocol = 0
        var ipHeaderLen = 0

        /** Offsets into [buf] of the source and destination addresses. */
        var srcOff = 0
        var dstOff = 0

        /** 4 for IPv4, 16 for IPv6. */
        var addrLen = 0

        var srcPort = 0
        var dstPort = 0

        var payloadOff = 0
        var payloadLen = 0

        var tcpSeq = 0
        var tcpAck = 0
        var tcpFlags = 0
        var tcpWindow = 0
        var tcpHeaderOff = 0
        var tcpHeaderLen = 0

        fun hasFlag(flag: Int) = (tcpFlags and flag) != 0
    }

    // ---- parse --------------------------------------------------------------

    /**
     * Parses one IP packet into [out]. Returns false for anything this tunnel
     * has no business handling; the caller drops those silently.
     */
    fun parse(buf: ByteArray, len: Int, out: IpPacket): Boolean {
        if (len < 1) return false
        // Mask before shifting: a Byte widens with sign extension, so
        // `toInt() ushr 4` on anything with the high bit set drags 1s down from
        // the top of the Int.
        return when ((buf[0].toInt() and 0xFF) ushr 4) {
            4 -> parseV4(buf, len, out)
            6 -> parseV6(buf, len, out)
            else -> false
        }
    }

    private fun parseV4(buf: ByteArray, len: Int, out: IpPacket): Boolean {
        if (len < IPV4_HEADER_MIN) return false
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < IPV4_HEADER_MIN || ihl > len) return false

        val totalLen = u16(buf, 2)
        // A tun read gives one whole packet. total_length larger than what we
        // read means a truncated or malformed packet; smaller is legitimate
        // padding and the header, not the read, is authoritative.
        if (totalLen < ihl || totalLen > len) return false

        // MF set or a non-zero fragment offset: see the class comment.
        if ((u16(buf, 6) and 0x3FFF) != 0) return false

        out.buf = buf
        out.version = 4
        out.ipHeaderLen = ihl
        out.protocol = buf[9].toInt() and 0xFF
        out.srcOff = 12
        out.dstOff = 16
        out.addrLen = 4
        return parseTransport(out, ihl, totalLen - ihl)
    }

    private fun parseV6(buf: ByteArray, len: Int, out: IpPacket): Boolean {
        if (len < IPV6_HEADER) return false
        val payloadLen = u16(buf, 4)
        if (IPV6_HEADER + payloadLen > len) return false

        // Walk the extension chain. Bounded by construction — every recognised
        // header advances the cursor by at least 8 bytes and the loop count is
        // capped, so a crafted chain cannot spin.
        var next = buf[6].toInt() and 0xFF
        var off = IPV6_HEADER
        val end = IPV6_HEADER + payloadLen
        var hops = 0
        while (hops++ < 8) {
            when (next) {
                0, 43, 60 -> {                       // hop-by-hop, routing, dest opts
                    if (off + 8 > end) return false
                    val hdrLen = ((buf[off + 1].toInt() and 0xFF) + 1) * 8
                    next = buf[off].toInt() and 0xFF
                    off += hdrLen
                    if (off > end) return false
                }
                else -> break
            }
        }
        if (next != PROTO_UDP && next != PROTO_TCP) return false

        out.buf = buf
        out.version = 6
        out.ipHeaderLen = off
        out.protocol = next
        out.srcOff = 8
        out.dstOff = 24
        out.addrLen = 16
        return parseTransport(out, off, end - off)
    }

    private fun parseTransport(out: IpPacket, transportOff: Int, transportLen: Int): Boolean {
        if (transportLen < 0) return false
        val buf = out.buf
        return when (out.protocol) {
            PROTO_UDP -> {
                if (transportLen < UDP_HEADER) return false
                out.srcPort = u16(buf, transportOff)
                out.dstPort = u16(buf, transportOff + 2)
                val udpLen = u16(buf, transportOff + 4)
                // Trust the shorter of the two lengths: a UDP length field that
                // overruns the IP payload is the classic parser overflow.
                val bodyLen = (if (udpLen in UDP_HEADER..transportLen) udpLen else transportLen) -
                    UDP_HEADER
                out.payloadOff = transportOff + UDP_HEADER
                out.payloadLen = bodyLen
                true
            }
            PROTO_TCP -> {
                if (transportLen < TCP_HEADER_MIN) return false
                out.srcPort = u16(buf, transportOff)
                out.dstPort = u16(buf, transportOff + 2)
                out.tcpSeq = u32(buf, transportOff + 4)
                out.tcpAck = u32(buf, transportOff + 8)
                val dataOff = ((buf[transportOff + 12].toInt() and 0xFF) ushr 4) * 4
                if (dataOff < TCP_HEADER_MIN || dataOff > transportLen) return false
                out.tcpFlags = buf[transportOff + 13].toInt() and 0xFF
                out.tcpWindow = u16(buf, transportOff + 14)
                out.tcpHeaderOff = transportOff
                out.tcpHeaderLen = dataOff
                out.payloadOff = transportOff + dataOff
                out.payloadLen = transportLen - dataOff
                true
            }
            else -> false
        }
    }

    /**
     * The peer's MSS from a SYN's options, or 0 when it offered none.
     *
     * Option parsing is length-driven and bounded by the header; a zero-length
     * option (which would otherwise spin) is treated as the end of the list.
     */
    fun tcpMss(pkt: IpPacket): Int {
        var p = pkt.tcpHeaderOff + TCP_HEADER_MIN
        val end = pkt.tcpHeaderOff + pkt.tcpHeaderLen
        while (p < end) {
            when (val kind = pkt.buf[p].toInt() and 0xFF) {
                0 -> return 0                        // EOL
                1 -> p++                             // NOP
                else -> {
                    if (p + 1 >= end) return 0
                    val optLen = pkt.buf[p + 1].toInt() and 0xFF
                    if (optLen < 2 || p + optLen > end) return 0
                    if (kind == 2 && optLen == 4) return u16(pkt.buf, p + 2)
                    p += optLen
                }
            }
        }
        return 0
    }

    // ---- emit ---------------------------------------------------------------

    /** Bytes of IP + UDP header for [version]. */
    fun udpOverhead(version: Int) = (if (version == 4) IPV4_HEADER_MIN else IPV6_HEADER) + UDP_HEADER

    /** Bytes of IP + minimal TCP header for [version]. */
    fun tcpOverhead(version: Int) = (if (version == 4) IPV4_HEADER_MIN else IPV6_HEADER) + TCP_HEADER_MIN

    /**
     * Writes a UDP datagram. Returns the total packet length, or 0 if it would
     * not fit in [out] — callers must treat 0 as "drop", never as "sent".
     */
    fun writeUdp(
        out: ByteArray,
        outOff: Int,
        version: Int,
        srcAddr: ByteArray, srcAddrOff: Int,
        dstAddr: ByteArray, dstAddrOff: Int,
        srcPort: Int, dstPort: Int,
        payload: ByteArray, payloadOff: Int, payloadLen: Int,
    ): Int {
        val addrLen = if (version == 4) 4 else 16
        val ipLen = if (version == 4) IPV4_HEADER_MIN else IPV6_HEADER
        val total = ipLen + UDP_HEADER + payloadLen
        if (outOff + total > out.size) return 0

        writeIpHeader(out, outOff, version, srcAddr, srcAddrOff, dstAddr, dstAddrOff,
            PROTO_UDP, UDP_HEADER + payloadLen)

        val t = outOff + ipLen
        putU16(out, t, srcPort)
        putU16(out, t + 2, dstPort)
        putU16(out, t + 4, UDP_HEADER + payloadLen)
        putU16(out, t + 6, 0)
        System.arraycopy(payload, payloadOff, out, t + UDP_HEADER, payloadLen)

        putU16(out, t + 6, transportChecksum(
            out, t, UDP_HEADER + payloadLen, PROTO_UDP,
            srcAddr, srcAddrOff, dstAddr, dstAddrOff, addrLen,
        ))
        return total
    }

    /**
     * Writes a UDP datagram back to whoever sent [req], with the endpoints
     * swapped. The reply's source must be the alias the client addressed, or the
     * stub resolver discards it as coming from the wrong server.
     */
    fun writeUdpReply(
        req: IpPacket,
        payload: ByteArray, payloadOff: Int, payloadLen: Int,
        out: ByteArray, outOff: Int,
    ): Int = writeUdp(
        out, outOff, req.version,
        req.buf, req.dstOff,
        req.buf, req.srcOff,
        req.dstPort, req.srcPort,
        payload, payloadOff, payloadLen,
    )

    /**
     * Writes a TCP segment. [options] is appended verbatim after the fixed
     * header and must already be padded to a 4-byte boundary.
     */
    @Suppress("LongParameterList")
    fun writeTcp(
        out: ByteArray,
        outOff: Int,
        version: Int,
        srcAddr: ByteArray, srcAddrOff: Int,
        dstAddr: ByteArray, dstAddrOff: Int,
        srcPort: Int, dstPort: Int,
        seq: Int, ack: Int, flags: Int, window: Int,
        options: ByteArray?, optionsLen: Int,
        payload: ByteArray?, payloadOff: Int, payloadLen: Int,
    ): Int {
        val addrLen = if (version == 4) 4 else 16
        val ipLen = if (version == 4) IPV4_HEADER_MIN else IPV6_HEADER
        val tcpLen = TCP_HEADER_MIN + optionsLen
        val total = ipLen + tcpLen + payloadLen
        if (outOff + total > out.size) return 0
        if ((optionsLen and 0x03) != 0) return 0        // data offset is in 32-bit words

        writeIpHeader(out, outOff, version, srcAddr, srcAddrOff, dstAddr, dstAddrOff,
            PROTO_TCP, tcpLen + payloadLen)

        val t = outOff + ipLen
        putU16(out, t, srcPort)
        putU16(out, t + 2, dstPort)
        putU32(out, t + 4, seq)
        putU32(out, t + 8, ack)
        out[t + 12] = (((tcpLen / 4) shl 4) and 0xF0).toByte()
        out[t + 13] = (flags and 0xFF).toByte()
        putU16(out, t + 14, window)
        putU16(out, t + 16, 0)                          // checksum
        putU16(out, t + 18, 0)                          // urgent pointer
        if (options != null && optionsLen > 0) {
            System.arraycopy(options, 0, out, t + TCP_HEADER_MIN, optionsLen)
        }
        if (payload != null && payloadLen > 0) {
            System.arraycopy(payload, payloadOff, out, t + tcpLen, payloadLen)
        }

        putU16(out, t + 16, transportChecksum(
            out, t, tcpLen + payloadLen, PROTO_TCP,
            srcAddr, srcAddrOff, dstAddr, dstAddrOff, addrLen,
        ))
        return total
    }

    private fun writeIpHeader(
        out: ByteArray, off: Int, version: Int,
        srcAddr: ByteArray, srcAddrOff: Int,
        dstAddr: ByteArray, dstAddrOff: Int,
        protocol: Int, transportLen: Int,
    ) {
        if (version == 4) {
            out[off] = 0x45                              // IPv4, IHL 5
            out[off + 1] = 0                             // DSCP / ECN
            putU16(out, off + 2, IPV4_HEADER_MIN + transportLen)
            putU16(out, off + 4, 0)                      // identification
            putU16(out, off + 6, IPV4_FLAGS_DF)
            out[off + 8] = DEFAULT_TTL.toByte()
            out[off + 9] = protocol.toByte()
            putU16(out, off + 10, 0)                     // checksum placeholder
            System.arraycopy(srcAddr, srcAddrOff, out, off + 12, 4)
            System.arraycopy(dstAddr, dstAddrOff, out, off + 16, 4)
            putU16(out, off + 10, fold(sum16(out, off, IPV4_HEADER_MIN, 0)).inv() and 0xFFFF)
        } else {
            out[off] = 0x60                              // IPv6, traffic class 0
            out[off + 1] = 0
            out[off + 2] = 0
            out[off + 3] = 0
            putU16(out, off + 4, transportLen)
            out[off + 6] = protocol.toByte()
            out[off + 7] = DEFAULT_TTL.toByte()
            System.arraycopy(srcAddr, srcAddrOff, out, off + 8, 16)
            System.arraycopy(dstAddr, dstAddrOff, out, off + 24, 16)
        }
    }

    // ---- checksums ----------------------------------------------------------

    /**
     * The RFC 768 / RFC 793 transport checksum over the pseudo-header and the
     * transport PDU.
     *
     * The pseudo-header is identical in shape for both families once reduced to
     * a 16-bit sum — addresses, then the protocol number, then the upper-layer
     * length — because every other field in it is zero. That is why one function
     * serves IPv4 and IPv6.
     */
    private fun transportChecksum(
        buf: ByteArray, transportOff: Int, transportLen: Int, protocol: Int,
        srcAddr: ByteArray, srcAddrOff: Int,
        dstAddr: ByteArray, dstAddrOff: Int,
        addrLen: Int,
    ): Int {
        var sum = sum16(srcAddr, srcAddrOff, addrLen, 0)
        sum = sum16(dstAddr, dstAddrOff, addrLen, sum)
        sum += protocol
        sum += transportLen
        sum = sum16(buf, transportOff, transportLen, sum)
        val c = fold(sum).inv() and 0xFFFF
        // A computed zero must go on the wire as 0xFFFF: for UDP a literal zero
        // means "no checksum", which is illegal over IPv6 and would make a
        // strict receiver drop the answer.
        return if (c == 0) 0xFFFF else c
    }

    /**
     * One's-complement 16-bit accumulation. The result is deliberately *not*
     * folded so that several regions can be summed in sequence; only [fold]
     * closes it out. An odd trailing byte is the high half of its word, per RFC
     * 1071 — every caller but the last passes an even length, so this can only
     * happen once and cannot mis-align a following region.
     */
    private fun sum16(buf: ByteArray, off: Int, len: Int, initial: Int): Int {
        var sum = initial
        var i = off
        val end = off + (len and 1.inv())
        while (i < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            // Fold opportunistically so a 64 KB TCP segment cannot overflow the
            // signed 32-bit accumulator.
            if (sum and 0xFFFF0000.toInt() != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
        }
        if ((len and 1) != 0) sum += (buf[end].toInt() and 0xFF) shl 8
        return sum
    }

    private fun fold(sum: Int): Int {
        var s = sum
        while ((s ushr 16) != 0) s = (s and 0xFFFF) + (s ushr 16)
        return s and 0xFFFF
    }

    // ---- primitives ---------------------------------------------------------

    fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    fun u32(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 24) or
            ((buf[off + 1].toInt() and 0xFF) shl 16) or
            ((buf[off + 2].toInt() and 0xFF) shl 8) or
            (buf[off + 3].toInt() and 0xFF)

    fun putU16(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value ushr 8) and 0xFF).toByte()
        buf[off + 1] = (value and 0xFF).toByte()
    }

    fun putU32(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value ushr 24) and 0xFF).toByte()
        buf[off + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[off + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[off + 3] = (value and 0xFF).toByte()
    }

    /** True when [len] bytes at [aOff] and [bOff] are equal. */
    fun addrEquals(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): Boolean {
        for (i in 0 until len) if (a[aOff + i] != b[bOff + i]) return false
        return true
    }
}
