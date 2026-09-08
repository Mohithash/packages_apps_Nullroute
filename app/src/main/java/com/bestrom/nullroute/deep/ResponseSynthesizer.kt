package com.bestrom.nullroute.deep

/**
 * Builds the answers Deep mode invents rather than relays.
 *
 * Every function writes into a caller-supplied buffer and returns the message
 * length, or 0 when it would not fit — nothing here allocates, because a blocked
 * domain on a busy page is a burst, not an event.
 *
 * ## Why NXDOMAIN carries an SOA
 *
 * A bare NXDOMAIN with an empty authority section is negatively cacheable only
 * for an implementation-defined interval, and several stub resolvers cache it
 * for minutes or not at all. RFC 2308 makes the SOA's MINIMUM field the negative
 * cache TTL, so shipping one with `MINIMUM = 60` bounds the damage of a wrong
 * block: after the user hits **Allow**, the name starts resolving within a
 * minute even in caches we cannot reach. That is the whole reason the record is
 * there — it is not decoration.
 *
 * ## Why the sinkhole variant exists but is not the default
 *
 * Linux treats `connect()` to `0.0.0.0` as `INADDR_LOOPBACK`, so an app pointed
 * at the sinkhole talks to *itself* rather than failing. It stays available as a
 * per-app escape hatch (`NR_RESP_SINKHOLE`) and is what serves the liveness
 * probes, and it is never a default. See SPEC §3.5.
 *
 * ## Names in the records we emit
 *
 * Owner names are the compression pointer `0xC00C`, which is legal and minimal
 * because we always place the echoed question immediately after the 12-byte
 * header. The SOA's MNAME and RNAME are written out in full: compression inside
 * RDATA is permitted for SOA but not universally handled, and they are 40 bytes.
 */
object ResponseSynthesizer {

    /**
     * TTL on everything we synthesize, and the SOA's MINIMUM. Short on purpose —
     * see the class comment. Long enough that a page full of blocked trackers
     * does not re-ask on every image.
     */
    const val NEG_TTL = 60

    /** Compression pointer to offset 12: the question's QNAME. */
    private const val PTR_QNAME = 0xC00C

    private val SOA_MNAME = encodeName("nullroute.invalid")
    private val SOA_RNAME = encodeName("block.nullroute.invalid")

    /** MNAME + RNAME + serial, refresh, retry, expire, minimum. */
    private val SOA_RDLEN = SOA_MNAME.size + SOA_RNAME.size + 20

    /** Owner pointer (2) + type/class/ttl/rdlength (10) + RDATA. */
    private val SOA_RR_LEN = 12 + SOA_RDLEN

    /** Root owner (1) + type/class/ttl/rdlength (10). */
    private const val OPT_RR_LEN = 11

    /**
     * NXDOMAIN with an SOA in the authority section.
     *
     * The default block response, and byte-for-byte what a real "this name does
     * not exist" looks like — which is exactly the point: an app cannot tell it
     * apart from an unregistered domain and therefore makes zero connection
     * attempts.
     */
    fun nxdomain(q: DnsMessage, out: ByteArray, outOff: Int): Int =
        withSoa(q, out, outOff, DnsMessage.RCODE_NXDOMAIN)

    /**
     * NOERROR with no answer and an SOA — "the name exists, it has no records of
     * this type".
     *
     * The gentler block response (`NR_RESP_NODATA`) for apps that treat
     * NXDOMAIN as a fatal configuration error rather than a missing host, and
     * also the correct reply when a sinkhole address exists but does not match
     * the question's type.
     */
    fun nodata(q: DnsMessage, out: ByteArray, outOff: Int): Int =
        withSoa(q, out, outOff, DnsMessage.RCODE_NOERROR)

    /**
     * An A or AAAA answer pointing at [addr].
     *
     * Falls back to [nodata] when the question's type cannot carry this address
     * — answering an AAAA query with an A record is not a compatibility
     * shortcut, it is a malformed message.
     */
    fun sinkhole(q: DnsMessage, addr: ByteArray, addrLen: Int, out: ByteArray, outOff: Int): Int {
        val type = when (addrLen) {
            4 -> DnsMessage.TYPE_A
            16 -> DnsMessage.TYPE_AAAA
            else -> return nodata(q, out, outOff)
        }
        if (q.qtype != type && q.qtype != DnsMessage.TYPE_ANY) return nodata(q, out, outOff)
        if (q.qclass != DnsMessage.CLASS_IN) return nodata(q, out, outOff)

        val need = DnsMessage.HEADER_LEN + q.questionLen + 12 + addrLen + optLen(q)
        if (outOff + need > out.size) return 0

        var p = preamble(q, out, outOff, DnsMessage.RCODE_NOERROR, an = 1, ns = 0)
        PacketCodec.putU16(out, p, PTR_QNAME); p += 2
        PacketCodec.putU16(out, p, type); p += 2
        PacketCodec.putU16(out, p, DnsMessage.CLASS_IN); p += 2
        PacketCodec.putU32(out, p, NEG_TTL); p += 4
        PacketCodec.putU16(out, p, addrLen); p += 2
        System.arraycopy(addr, 0, out, p, addrLen); p += addrLen
        p = appendOpt(q, out, p)
        return p - outOff
    }

    /**
     * A truncated (TC=1) empty response, telling the client to retry over
     * TCP/53.
     *
     * Emitted when an upstream answer will not fit in the tunnel MTU. Dropping
     * it instead would leave the client to time out, and forwarding it would
     * mean writing an over-MTU packet to the tun — [Tcp53Server] exists so this
     * has somewhere to go.
     */
    fun truncated(q: DnsMessage, out: ByteArray, outOff: Int): Int {
        val need = DnsMessage.HEADER_LEN + q.questionLen + optLen(q)
        if (outOff + need > out.size) return 0
        var p = preamble(q, out, outOff, DnsMessage.RCODE_NOERROR, an = 0, ns = 0)
        p = appendOpt(q, out, p)
        // Set TC after the preamble rather than threading another parameter
        // through it; the flags word is at a fixed offset.
        PacketCodec.putU16(
            out, outOff + 2,
            PacketCodec.u16(out, outOff + 2) or DnsMessage.FLAG_TC,
        )
        return p - outOff
    }

    /**
     * SERVFAIL, used only when *we* failed — no upstream is reachable, or the
     * relay socket died. It is never a block response: telling an app that a
     * name is blocked by claiming the server broke would send it into a retry
     * loop and put the failure on the wrong component.
     */
    fun servfail(q: DnsMessage, out: ByteArray, outOff: Int): Int {
        val need = DnsMessage.HEADER_LEN + q.questionLen + optLen(q)
        if (outOff + need > out.size) return 0
        var p = preamble(q, out, outOff, DnsMessage.RCODE_SERVFAIL, an = 0, ns = 0)
        p = appendOpt(q, out, p)
        return p - outOff
    }

    // ---- internals ----------------------------------------------------------

    private fun withSoa(q: DnsMessage, out: ByteArray, outOff: Int, rcode: Int): Int {
        val need = DnsMessage.HEADER_LEN + q.questionLen + SOA_RR_LEN + optLen(q)
        if (outOff + need > out.size) return 0

        var p = preamble(q, out, outOff, rcode, an = 0, ns = 1)
        PacketCodec.putU16(out, p, PTR_QNAME); p += 2
        PacketCodec.putU16(out, p, DnsMessage.TYPE_SOA); p += 2
        PacketCodec.putU16(out, p, DnsMessage.CLASS_IN); p += 2
        PacketCodec.putU32(out, p, NEG_TTL); p += 4
        PacketCodec.putU16(out, p, SOA_RDLEN); p += 2
        System.arraycopy(SOA_MNAME, 0, out, p, SOA_MNAME.size); p += SOA_MNAME.size
        System.arraycopy(SOA_RNAME, 0, out, p, SOA_RNAME.size); p += SOA_RNAME.size
        PacketCodec.putU32(out, p, 1); p += 4            // SERIAL
        PacketCodec.putU32(out, p, 3600); p += 4         // REFRESH
        PacketCodec.putU32(out, p, 600); p += 4          // RETRY
        PacketCodec.putU32(out, p, 86400); p += 4        // EXPIRE
        PacketCodec.putU32(out, p, NEG_TTL); p += 4      // MINIMUM — the negative TTL
        p = appendOpt(q, out, p)
        return p - outOff
    }

    /** Header plus the question echoed verbatim. Returns the cursor after it. */
    private fun preamble(
        q: DnsMessage, out: ByteArray, outOff: Int, rcode: Int, an: Int, ns: Int,
    ): Int {
        var p = outOff
        PacketCodec.putU16(out, p, q.id); p += 2

        // QR + RA, RD mirrored from the query, no AA: we are not authoritative
        // for the zone, we are intercepting it, and claiming otherwise would be
        // a lie a resolver is entitled to act on.
        var flags = DnsMessage.FLAG_QR or DnsMessage.FLAG_RA or (rcode and 0x0F)
        if (q.recursionDesired) flags = flags or DnsMessage.FLAG_RD
        PacketCodec.putU16(out, p, flags); p += 2

        PacketCodec.putU16(out, p, 1); p += 2                       // QDCOUNT
        PacketCodec.putU16(out, p, an); p += 2
        PacketCodec.putU16(out, p, ns); p += 2
        PacketCodec.putU16(out, p, if (q.optOff >= 0) 1 else 0); p += 2

        val qLen = q.questionLen
        System.arraycopy(q.buf, q.off + DnsMessage.HEADER_LEN, out, p, qLen)
        return p + qLen
    }

    private fun optLen(q: DnsMessage) = if (q.optOff >= 0) OPT_RR_LEN else 0

    /**
     * Echoes an EDNS0 OPT when the query carried one (RFC 6891 §6.1.1).
     *
     * The DO bit is deliberately **not** mirrored. We sign nothing, so claiming
     * DNSSEC-awareness in a response we invented would invite a validator to
     * treat the absence of signatures as an attack rather than as an unsigned
     * answer. A validating client that set DO gets an unsigned NXDOMAIN and may
     * refuse it — which, for a name we are blocking, is the outcome we wanted.
     */
    private fun appendOpt(q: DnsMessage, out: ByteArray, at: Int): Int {
        if (q.optOff < 0) return at
        var p = at
        out[p] = 0; p += 1                                          // root owner name
        PacketCodec.putU16(out, p, DnsMessage.TYPE_OPT); p += 2
        PacketCodec.putU16(out, p, DnsMessage.EDNS_UDP_SIZE); p += 2
        PacketCodec.putU32(out, p, 0); p += 4                       // ext-rcode 0, version 0, flags 0
        PacketCodec.putU16(out, p, 0); p += 2                       // RDLENGTH
        return p
    }

    /** "a.b" -> 01 'a' 01 'b' 00. Called once per constant at class-init. */
    private fun encodeName(name: String): ByteArray {
        val parts = name.split('.').filter { it.isNotEmpty() }
        var size = 1
        for (part in parts) size += 1 + part.length
        val out = ByteArray(size)
        var p = 0
        for (part in parts) {
            out[p++] = part.length.toByte()
            for (c in part) out[p++] = c.code.toByte()
        }
        out[p] = 0
        return out
    }
}
