package com.bestrom.nullroute.deep

/**
 * A bounded, allocation-free DNS wire reader for the Deep-mode tunnel.
 *
 * This is a *reader for queries we are about to answer or relay*, not a general
 * DNS library. It reads the header, the single question, and — because RFC 6891
 * says a response to a query carrying OPT must itself carry OPT — enough of the
 * additional section to find the requestor's EDNS0 record.
 *
 * ## Hostile-input rules, all of them load-bearing
 *
 * * **A compression pointer in the question is rejected outright.** RFC 1035
 *   §4.1.4 only permits pointers to a *prior* occurrence of a name, and the
 *   question is the first name in the message, so a pointer there can only be
 *   malformed or an attempt to make the parser loop. Rejecting is both correct
 *   and the cheapest possible loop defence.
 * * **Names being skipped are never followed.** Skipping past an RR's owner name
 *   only has to know where the name *ends*, and a pointer always ends it in two
 *   bytes. So the skip walk is O(bytes) with no pointer chasing at all, and the
 *   classic compression-loop DoS has nowhere to live.
 * * Every read is bounds-checked against the message extent, label length is
 *   capped at 63, label count at [MAX_LABELS] and the assembled name at 253.
 *
 * ## Instances are reused
 *
 * One [DnsMessage] is allocated per loop and re-[wrap]ped for every packet. The
 * canonical question name lands in [name] / [nameLen] as raw lowercase bytes —
 * deliberately bytes and not a `String`, because the matcher hashes the same
 * octets the resolver would and a UTF-8 round trip through `String` would change
 * them for any non-ASCII label.
 */
class DnsMessage {

    companion object {
        const val HEADER_LEN = 12

        const val TYPE_A = 1
        const val TYPE_NS = 2
        const val TYPE_CNAME = 5
        const val TYPE_SOA = 6
        const val TYPE_AAAA = 28
        const val TYPE_OPT = 41
        const val TYPE_ANY = 255

        const val CLASS_IN = 1

        const val RCODE_NOERROR = 0
        const val RCODE_FORMERR = 1
        const val RCODE_SERVFAIL = 2
        const val RCODE_NXDOMAIN = 3
        const val RCODE_NOTIMP = 4
        const val RCODE_REFUSED = 5

        const val FLAG_QR = 0x8000
        const val FLAG_AA = 0x0400
        const val FLAG_TC = 0x0200
        const val FLAG_RD = 0x0100
        const val FLAG_RA = 0x0080

        /** RFC 1035 caps a name at 255 wire bytes; 253 as text, 127 labels. */
        const val MAX_NAME = 253
        const val MAX_LABELS = 127

        /**
         * What we advertise in a synthesized OPT. 1232 is the DNS Flag Day 2020
         * value — the largest payload that survives the common 1280-byte IPv6
         * MTU without fragmentation, which is also comfortably inside our own
         * 1500-byte tunnel.
         */
        const val EDNS_UDP_SIZE = 1232
    }

    var buf: ByteArray = ByteArray(0)
        private set
    var off = 0
        private set
    var len = 0
        private set

    /** Offset of the question's QNAME — always [off] + 12 when [questionOk]. */
    var qnameOff = 0
        private set

    /** Offset just past QNAME, i.e. where QTYPE begins. */
    var qnameEnd = 0
        private set

    var qtype = 0
        private set
    var qclass = 0
        private set

    /** True once [parseQuestion] has succeeded for the wrapped message. */
    var questionOk = false
        private set

    /** Canonical question name: lowercase, dot-separated, no trailing root dot. */
    val name = ByteArray(MAX_NAME + 1)
    var nameLen = 0
        private set

    /** Offset of the OPT RR's owner-name byte, or -1 when the query has no OPT. */
    var optOff = -1
        private set

    /** Requestor's advertised UDP payload size, or 0 when there is no OPT. */
    var ednsUdpSize = 0
        private set

    /** The OPT record's version and flags (bit 15 of [ednsFlags] is DO). */
    var ednsVersion = 0
        private set
    var ednsFlags = 0
        private set

    // ---- header -------------------------------------------------------------

    val id get() = u16(0)
    val flags get() = u16(2)
    val qdCount get() = u16(4)
    val anCount get() = u16(6)
    val nsCount get() = u16(8)
    val arCount get() = u16(10)

    val isQuery get() = (flags and FLAG_QR) == 0
    val opcode get() = (flags ushr 11) and 0x0F
    val recursionDesired get() = (flags and FLAG_RD) != 0

    /** Bytes from the start of the question through QCLASS. */
    val questionLen get() = qnameEnd + 4 - (off + HEADER_LEN)

    /**
     * Points this instance at a message. Returns false if it is too short to
     * carry a header, in which case nothing else on this object is meaningful.
     */
    fun wrap(buf: ByteArray, off: Int, len: Int): Boolean {
        this.buf = buf
        this.off = off
        this.len = len
        questionOk = false
        nameLen = 0
        qnameOff = 0
        qnameEnd = 0
        qtype = 0
        qclass = 0
        optOff = -1
        ednsUdpSize = 0
        ednsVersion = 0
        ednsFlags = 0
        return len >= HEADER_LEN && off >= 0 && off + len <= buf.size
    }

    /**
     * Reads the single question into [name] / [qtype] / [qclass].
     *
     * Returns false for a malformed question, for QDCOUNT != 1, and for a name
     * that cannot be a hostname. The caller's response to false is to **relay
     * the query untouched**, never to answer it: a message we could not parse is
     * one we have no standing to have an opinion about.
     */
    fun parseQuestion(): Boolean {
        questionOk = false
        if (len < HEADER_LEN) return false
        if (qdCount != 1) return false

        var p = off + HEADER_LEN
        val end = off + len
        qnameOff = p

        var out = 0
        var labels = 0
        while (true) {
            if (p >= end) return false
            val l = buf[p].toInt() and 0xFF
            if (l == 0) { p++; break }
            if ((l and 0xC0) != 0) return false            // pointer or reserved: see class doc
            if (l > 63) return false
            if (++labels > MAX_LABELS) return false
            if (p + 1 + l > end) return false
            if (out > 0) {
                if (out + 1 > MAX_NAME) return false
                name[out++] = '.'.code.toByte()
            }
            if (out + l > MAX_NAME) return false
            for (i in 0 until l) {
                val c = buf[p + 1 + i].toInt() and 0xFF
                // ASCII-only case folding, matching the matcher's canonicalizer
                // (native/NrCanon.cpp). DNS comparison is case-insensitive for
                // ASCII and byte-exact for everything else.
                name[out++] = (if (c in 0x41..0x5A) c + 0x20 else c).toByte()
            }
            p += 1 + l
        }
        if (p + 4 > end) return false

        qnameEnd = p
        nameLen = out
        qtype = u16At(p)
        qclass = u16At(p + 2)
        questionOk = true
        return true
    }

    /**
     * Locates the EDNS0 OPT record, if any. Cheap and best-effort: a query whose
     * additional section does not parse simply reports "no OPT", because the
     * only consequence is that our synthesized answer omits one.
     */
    fun parseEdns(): Boolean {
        if (!questionOk) return false
        val total = anCount + nsCount + arCount
        if (total == 0) return false

        var p = qnameEnd + 4
        val end = off + len
        var seen = 0
        while (seen++ < total) {
            p = skipName(p, end)
            if (p < 0 || p + 10 > end) return false
            val type = u16At(p)
            val klass = u16At(p + 2)
            val ttl = u32At(p + 4)
            val rdLen = u16At(p + 8)
            val rrEnd = p + 10 + rdLen
            if (rdLen < 0 || rrEnd > end) return false
            if (type == TYPE_OPT) {
                optOff = p
                // In an OPT RR the CLASS field carries the requestor's payload
                // size and the TTL carries {extended-rcode, version, flags}.
                ednsUdpSize = klass
                ednsVersion = (ttl ushr 16) and 0xFF
                ednsFlags = ttl and 0xFFFF
                return true
            }
            p = rrEnd
        }
        return false
    }

    /**
     * Advances past a wire-format name. Returns the offset after it, or -1.
     *
     * Deliberately does not follow pointers — a pointer terminates the name in
     * two bytes, which is all a *skip* needs to know, and not following is what
     * makes this immune to compression loops.
     */
    private fun skipName(start: Int, end: Int): Int {
        var p = start
        var guard = 0
        while (p < end) {
            if (guard++ > MAX_LABELS) return -1
            val l = buf[p].toInt() and 0xFF
            if ((l and 0xC0) == 0xC0) return if (p + 2 <= end) p + 2 else -1
            if ((l and 0xC0) != 0) return -1
            if (l == 0) return p + 1
            p += 1 + l
        }
        return -1
    }

    /** The question name as text. Diagnostics and logging only — it allocates. */
    fun nameAsString(): String {
        if (nameLen == 0) return "."
        val sb = StringBuilder(nameLen)
        for (i in 0 until nameLen) sb.append((name[i].toInt() and 0xFF).toChar())
        return sb.toString()
    }

    /** True when the parsed question names exactly [other] (ASCII, lowercase). */
    fun nameEquals(other: ByteArray): Boolean {
        if (nameLen != other.size) return false
        for (i in 0 until nameLen) if (name[i] != other[i]) return false
        return true
    }

    /**
     * True when [response] answers this query: same id, same question. The
     * upstream socket is connected so the kernel already filtered the source
     * address; this closes the remaining gap of an off-path answer arriving on a
     * reused ephemeral port.
     */
    fun matchesResponse(response: ByteArray, rOff: Int, rLen: Int): Boolean {
        if (rLen < HEADER_LEN + questionLen) return false
        if (((response[rOff].toInt() and 0xFF) shl 8 or (response[rOff + 1].toInt() and 0xFF)) != id) {
            return false
        }
        // QDCOUNT must still be 1 and the question echoed verbatim; anything
        // else is not an answer to what we asked.
        val rQd = ((response[rOff + 4].toInt() and 0xFF) shl 8) or (response[rOff + 5].toInt() and 0xFF)
        if (rQd != 1) return false
        val qLen = questionLen
        for (i in 0 until qLen) {
            val a = response[rOff + HEADER_LEN + i]
            val b = buf[off + HEADER_LEN + i]
            // Case-insensitively, because 0x20-encoding upstreams legitimately
            // flip the case of the echoed QNAME.
            if (a != b && lower(a) != lower(b)) return false
        }
        return true
    }

    private fun lower(b: Byte): Int {
        val c = b.toInt() and 0xFF
        return if (c in 0x41..0x5A) c + 0x20 else c
    }

    // ---- primitives ---------------------------------------------------------

    private fun u16(i: Int) = u16At(off + i)

    private fun u16At(p: Int) =
        ((buf[p].toInt() and 0xFF) shl 8) or (buf[p + 1].toInt() and 0xFF)

    private fun u32At(p: Int) =
        ((buf[p].toInt() and 0xFF) shl 24) or
            ((buf[p + 1].toInt() and 0xFF) shl 16) or
            ((buf[p + 2].toInt() and 0xFF) shl 8) or
            (buf[p + 3].toInt() and 0xFF)
}
