/*
 * Nullroute — libFuzzer target: arbitrary bytes as a DNS WIRE MESSAGE. [MERGE GATE]
 *
 *   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address \
 *           -I resolver-patch/nullroute native/fuzz/nr_wire_fuzzer.cpp -o nr_wire_fuzzer
 *   ./nr_wire_fuzzer -max_len=600 corpus/
 *
 * WHY THIS ONE MATTERS MOST. The other two gates fuzz inputs we merely receive:
 * a hostname handed over by an app through a length-prefixed IPC, and an index
 * file this project wrote itself. This one fuzzes the only place in Nullroute
 * that parses NETWORK-SHAPED bytes — length-prefixed labels, offsets, and
 * compression pointers that address back into the same buffer — and it does it
 * inside netd, whose init stanza carries `onrestart restart zygote`. A crash
 * here is a boot loop on a user's phone (§10.1), and the bytes come from
 * `DnsResolver.rawQuery()`, so any app on the device picks every one of them.
 *
 * The message is always copied into a heap allocation of EXACTLY its length, so
 * ASAN's redzones turn a single byte read past the end into a crash. libFuzzer's
 * own buffer is already redzoned, but the copy also lets mode B rewrite the
 * header without mutating the harness's input.
 *
 * Three things are fuzzed, not one:
 *
 *   A. The raw input as a whole message. Finds header-gate bugs.
 *   B. The same bytes with a VALID query header forced on. Without it a byte
 *      oriented fuzzer spends nearly its whole budget being rejected at the QR /
 *      opcode / QDCOUNT check and never reaches the label walk, which is where
 *      the interesting bounds live.
 *   C. nr_wire_read_name() started at an input-chosen offset. The question
 *      parser only ever starts at offset 12; the codec is general, and the
 *      pointer-chasing guard has to hold from anywhere.
 *
 * Every successful parse is then round-tripped through all three emitters at a
 * range of output capacities — including one byte short of exact, which is the
 * only way to prove the sticky-overflow writer never returns a truncated record.
 * Output buffers are heap allocations sized to the capacity under test, for the
 * same redzone reason.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "nr_wire.h"

using namespace nr;

namespace {

/* A failed invariant is a bug in the codec, not a rejected input, so it aborts
 * rather than returning — libFuzzer only reports what crashes. */
void must(bool cond, const char* what) {
    if (!cond) {
        fprintf(stderr, "nr_wire invariant violated: %s\n", what);
        abort();
    }
}

void check_question(size_t len, const NrWireQuestion& q) {
    must(q.q_off == NR_WIRE_HEADER, "q_off is not the header size");
    must(q.q_end > q.q_off, "question section is empty");
    must(q.q_end <= len, "question section runs past the message");
    must(q.q_end - q.q_off <= NR_WIRE_MAX_NAME + 6u, "question section is impossibly long");
    must(q.name.len <= NR_WIRE_MAX_NAME, "name exceeds the presentation bound");
    must(strlen(q.name.text) == q.name.len, "name text and length disagree");

    for (uint16_t i = 0; i < q.name.len; ++i) {
        const unsigned char c = (unsigned char)q.name.text[i];
        must(c >= 0x21u && c <= 0x7Eu, "name carries an unprintable byte");
        must(!(c >= 'A' && c <= 'Z'), "name was not lowercased");
    }
    /* Neither a leading, trailing nor doubled dot can appear: every label the
     * walk accepted had length >= 1 and contained no '.' of its own. A caller
     * that split this on '.' must see exactly the wire's labels. */
    must(q.name.len == 0 || q.name.text[0] != '.', "name starts with a separator");
    must(q.name.len == 0 || q.name.text[q.name.len - 1] != '.', "name ends with a separator");
    for (uint16_t i = 1; i < q.name.len; ++i)
        must(!(q.name.text[i] == '.' && q.name.text[i - 1] == '.'), "empty label in name");
}

/* Verifies a reply the codec claims to have produced: it fits, it is a response
 * to THIS query, and the question it echoes is byte-identical to the one asked. */
void check_reply(const uint8_t* msg, const NrWireQuestion& q, const uint8_t* out, size_t n,
                 size_t cap, unsigned rcode, uint16_t ancount, uint16_t nscount) {
    if (n == 0) return; /* did not fit; the writer's sticky-overflow path */

    must(n <= cap, "reply exceeded the capacity it was given");
    must(n >= NR_WIRE_HEADER, "reply is shorter than a header");

    const size_t qlen = (size_t)(q.q_end - q.q_off);
    must(n >= NR_WIRE_HEADER + qlen, "reply does not contain the echoed question");
    must(memcmp(out + NR_WIRE_HEADER, msg + q.q_off, qlen) == 0,
         "echoed question differs from the question asked");

    must(nr_wire_u16(out + 0) == q.id, "reply id does not match the query");
    const uint16_t flags = nr_wire_u16(out + 2);
    must((flags & 0x8000u) != 0u, "QR is not set on a reply");
    must((flags & 0x000Fu) == (rcode & 0x0Fu), "reply carries the wrong rcode");
    must((flags & 0x0100u) == (q.flags & 0x0100u), "RD was not mirrored");
    must(nr_wire_u16(out + 4) == 1u, "QDCOUNT is not 1");
    must(nr_wire_u16(out + 6) == ancount, "ANCOUNT is wrong");
    must(nr_wire_u16(out + 8) == nscount, "NSCOUNT is wrong");
    must(nr_wire_u16(out + 10) == 0u, "ARCOUNT is not 0");

    /* A reply must never parse as a query, or a caller that fed one back in
     * would evaluate its own answer. */
    NrWireQuestion again;
    must(nr_wire_parse_query(out, n, &again) == NR_WIRE_NOT_A_QUERY,
         "a synthesized reply parses as a query");
}

/* Builds one emitter's output into a heap buffer of exactly `cap` bytes. */
void build_at(const uint8_t* msg, const NrWireQuestion& q, size_t cap) {
    /* A zero-length allocation is legal but gives ASAN nothing to guard, and the
     * writer must handle cap == 0 as "nothing fits". */
    std::vector<uint8_t> out(cap ? cap : 1u);
    uint8_t* p = out.data();

    size_t n = nr_wire_build_denial(msg, &q, NR_WIRE_RCODE_NXDOMAIN, 60u, p, cap);
    check_reply(msg, q, p, n, cap, NR_WIRE_RCODE_NXDOMAIN, 0, 1);

    n = nr_wire_build_denial(msg, &q, NR_WIRE_RCODE_NOERROR, 60u, p, cap);
    check_reply(msg, q, p, n, cap, NR_WIRE_RCODE_NOERROR, 0, 1);

    static const uint8_t kV4[4]  = {127, 0, 0, 7};
    static const uint8_t kV6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    n = nr_wire_build_address(msg, &q, kV4, sizeof(kV4), 60u, p, cap);
    check_reply(msg, q, p, n, cap, NR_WIRE_RCODE_NOERROR, 1, 0);

    n = nr_wire_build_address(msg, &q, kV6, sizeof(kV6), 60u, p, cap);
    check_reply(msg, q, p, n, cap, NR_WIRE_RCODE_NOERROR, 1, 0);

    /* An address length the emitter must refuse outright rather than write. */
    must(nr_wire_build_address(msg, &q, kV6, 5u, 60u, p, cap) == 0u,
         "an impossible address length produced a record");

    n = nr_wire_build_bare(msg, &q, NR_WIRE_RCODE_NXDOMAIN, p, cap);
    check_reply(msg, q, p, n, cap, NR_WIRE_RCODE_NXDOMAIN, 0, 0);
}

void exercise(const uint8_t* data, size_t size) {
    /* Exact-size copy: ASAN redzones both ends of it. */
    std::vector<uint8_t> msg(data, data + size);
    const uint8_t* p = msg.empty() ? (const uint8_t*)"" : msg.data();

    NrWireQuestion q;
    if (nr_wire_parse_query(p, msg.size(), &q) != NR_WIRE_OK) return;
    check_question(msg.size(), q);

    /* The exact size the SOA form needs, so `exact - 1` below lands precisely on
     * the boundary the sticky writer has to get right. */
    std::vector<uint8_t> probe(NR_WIRE_MAX_REPLY);
    const size_t exact =
            nr_wire_build_denial(p, &q, NR_WIRE_RCODE_NXDOMAIN, 60u, probe.data(), probe.size());
    must(exact > 0u, "the SOA denial did not fit NR_WIRE_MAX_REPLY");
    must(exact <= NR_WIRE_MAX_REPLY, "NR_WIRE_MAX_REPLY is too small for a legal question");

    build_at(p, q, 0u);
    build_at(p, q, NR_WIRE_HEADER - 1u);
    build_at(p, q, exact - 1u);
    build_at(p, q, exact);
    build_at(p, q, NR_WIRE_MAX_REPLY);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* ---- A: the input is the whole message ------------------------------- */
    exercise(data, size);

    /* ---- B: the same bytes behind a header that passes the gate ----------- */
    if (size >= NR_WIRE_HEADER) {
        std::vector<uint8_t> shaped(data, data + size);
        /* QR clear, opcode QUERY, RD taken from the input so both arms of the
         * mirror are covered; QDCOUNT forced to 1. */
        shaped[2] = (uint8_t)(shaped[2] & 0x01u);
        shaped[3] = (uint8_t)(shaped[3] & 0x7Fu);
        shaped[4] = 0;
        shaped[5] = 1;
        exercise(shaped.data(), shaped.size());
    }

    /* ---- C: the name reader from an input-chosen offset -------------------
     * The question parser always starts at 12. The reader is general, and the
     * pointer walk's "strictly backwards" rule has to terminate from any start
     * — including one INSIDE a name, where the first byte read is a label body
     * rather than a length. */
    if (size >= 2u) {
        std::vector<uint8_t> raw(data, data + size);
        const size_t start = (size_t)raw[0] % raw.size();

        NrWireName name;
        size_t     wire_end = 0;
        bool       saw_ptr  = false;
        if (nr_wire_read_name(raw.data(), raw.size(), start, &name, &wire_end, &saw_ptr) ==
            NR_WIRE_OK) {
            must(name.len <= NR_WIRE_MAX_NAME, "read_name exceeded the presentation bound");
            must(strlen(name.text) == name.len, "read_name text and length disagree");
            must(wire_end > start, "read_name did not advance");
            must(wire_end <= raw.size(), "read_name ran past the buffer");
        }
    }
    return 0;
}
