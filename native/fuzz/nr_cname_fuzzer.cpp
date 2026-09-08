/*
 * Nullroute — libFuzzer target: arbitrary bytes as a DNS ANSWER SECTION. [MERGE GATE]
 *
 *   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address \
 *           -I resolver-patch/nullroute native/fuzz/nr_cname_fuzzer.cpp -o nr_cname_fuzzer
 *   ./nr_cname_fuzzer -max_len=900 corpus/
 *
 * WHY THIS IS A GATE AND NOT A NICE-TO-HAVE. nr_wire_fuzzer covers the QUESTION
 * side, whose bytes an app on the device chooses. This one covers the ANSWER
 * side, whose bytes the NETWORK chooses — a DNS server, or anyone able to answer
 * for one. It is parsed inside netd, whose init stanza carries
 * `onrestart restart zygote`, so a fault is a boot loop rather than a failed
 * lookup, triggered by a packet the user never sees.
 *
 * The answer section is also strictly harder than the question: it is a walk over
 * a variable number of records, each of which begins with a compressible name of
 * unknown length and continues with an RDLENGTH the message itself supplies.
 * Every one of those is an attacker-chosen offset.
 *
 * Like nr_wire_fuzzer this target links NOTHING else — no index, no control
 * page, no filter — because NrCname.h is header-only by design. A crash here is
 * therefore unambiguously a parser bug.
 *
 * Three shapes are fuzzed:
 *
 *   A. The raw input as a whole reply. Finds header-gate bugs.
 *   B. The same bytes behind a header that PASSES the gate (QR set, opcode
 *      QUERY, rcode NOERROR, QDCOUNT 0 or 1, ANCOUNT non-zero). Without this a
 *      byte-oriented fuzzer spends nearly its whole budget being rejected before
 *      it ever reaches the record walk, which is where the interesting bounds
 *      are. QDCOUNT 0 matters on its own: it is the only way to reach the walk
 *      without first surviving the question skip.
 *   C. A structurally VALID reply built from the input — a real question, then
 *      real CNAME records whose targets and compression pointers come from the
 *      fuzzer. This is what reaches the deep branches: chain overflow,
 *      truncation, RDATA that ends before its name does, and pointers from
 *      inside RDATA back into the question.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "NrCname.h"

using namespace nr;

namespace {

/* A failed invariant is a bug in the parser, not a rejected input, so it aborts
 * rather than returning — libFuzzer only reports what crashes. */
void must(bool cond, const char* what) {
    if (!cond) {
        fprintf(stderr, "nr_cname invariant violated: %s\n", what);
        abort();
    }
}

/* Every collected link has to be something the matcher can actually be handed:
 * NUL-terminated, within the presentation bound, lowercase, printable, and with
 * label boundaries that survive a split on '.'. nr_evaluate() is entitled to all
 * of that, and a link that broke it would be a name the index judges wrongly
 * rather than a crash — the quietest possible failure. */
void check_link(const NrWireName& n) {
    must(n.len > 0u, "a collected link is empty");
    must(n.len <= NR_WIRE_MAX_NAME, "link exceeds the presentation bound");
    must(strlen(n.text) == n.len, "link text and length disagree");
    for (uint16_t i = 0; i < n.len; ++i) {
        const unsigned char c = (unsigned char)n.text[i];
        must(c >= 0x21u && c <= 0x7Eu, "link carries an unprintable byte");
        must(!(c >= 'A' && c <= 'Z'), "link was not lowercased");
    }
    must(n.text[0] != '.', "link starts with a separator");
    must(n.text[n.len - 1] != '.', "link ends with a separator");
    for (uint16_t i = 1; i < n.len; ++i)
        must(!(n.text[i] == '.' && n.text[i - 1] == '.'), "empty label in link");
}

void exercise(const uint8_t* data, size_t size) {
    /* Exact-size copy: ASAN redzones both ends of it, so a single byte read past
     * the end of the message is a crash rather than a silent success. */
    std::vector<uint8_t> msg(data, data + size);
    const uint8_t* p = msg.empty() ? (const uint8_t*)"" : msg.data();

    /* Poison the output so "count is 0 on a non-OK return" is a real assertion
     * and not one the previous iteration happened to satisfy. */
    NrCnameChain chain;
    memset(&chain, 0xA5, sizeof(chain));

    const NrCnameStatus st = nr_cname_collect(p, msg.size(), &chain);

    must(chain.count <= NR_CNAME_MAX_LINKS, "count exceeds the chain bound");
    if (st != NR_CNAME_OK) {
        must(chain.count == 0u, "a declined answer still produced links");
        return;
    }
    must(chain.count > 0u, "NR_CNAME_OK with no links");
    for (uint8_t i = 0; i < chain.count; ++i) check_link(chain.link[i]);

    /* Deterministic: the same bytes must produce the same chain. A parser whose
     * result depended on uninitialised stack would pass every bound above and
     * still make the filter block different things on different runs. */
    NrCnameChain again;
    memset(&again, 0x5A, sizeof(again));
    must(nr_cname_collect(p, msg.size(), &again) == st, "status is not deterministic");
    must(again.count == chain.count, "chain length is not deterministic");
    must(again.truncated == chain.truncated, "truncation flag is not deterministic");
    for (uint8_t i = 0; i < chain.count; ++i)
        must(strcmp(again.link[i].text, chain.link[i].text) == 0,
             "chain contents are not deterministic");
}

void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)(x >> 8));
    v.push_back((uint8_t)(x & 0xFFu));
}

/*
 * Mode C: a reply the gate cannot reject on sight, assembled around
 * fuzzer-chosen bytes.
 *
 * The point is not that the records are legal — several deliberately are not —
 * but that the walk gets far enough in to be tested. RDLENGTH is taken from the
 * input rather than computed, so "RDATA shorter than the name inside it" and
 * "RDLENGTH that runs off the end" are both reachable, and those are exactly the
 * two ways a record walk overruns.
 */
void exercise_shaped(const uint8_t* data, size_t size) {
    if (size < 4u) return;

    size_t                cur = 0;
    auto                  take = [&](uint8_t def) -> uint8_t {
        return cur < size ? data[cur++] : def;
    };

    const uint8_t nrec = (uint8_t)((take(1) % 6u) + 1u); /* 1..6 records */

    std::vector<uint8_t> m;
    put16(m, 0x1234);           /* ID                        */
    put16(m, 0x8180);           /* QR + RD + RA, rcode 0     */
    put16(m, 1);                /* QDCOUNT                   */
    put16(m, nrec);             /* ANCOUNT                   */
    put16(m, 0);                /* NSCOUNT                   */
    put16(m, 0);                /* ARCOUNT                   */

    /* A real question, so the skip has something well-formed to step over. */
    const uint8_t kQ[] = {7, 'm', 'e', 't', 'r', 'i', 'c', 's', 7, 'e', 'x', 'a',
                          'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    m.insert(m.end(), kQ, kQ + sizeof(kQ));
    put16(m, 1); /* QTYPE A   */
    put16(m, 1); /* QCLASS IN */

    for (uint8_t r = 0; r < nrec; ++r) {
        /* Owner: half the time a compression pointer at the question (offset 12,
         * which is the shape every real resolver emits), half the time raw
         * fuzzer bytes. */
        if ((take(0) & 1u) != 0u) {
            m.push_back(0xC0);
            m.push_back(0x0C);
        } else {
            const uint8_t n = (uint8_t)(take(0) % 8u);
            for (uint8_t i = 0; i < n; ++i) m.push_back(take(0));
            m.push_back(0); /* terminate, or not: a zero byte inside is fine too */
        }

        put16(m, (take(5) & 1u) ? NR_CNAME_TYPE : 1u); /* mostly CNAME, sometimes A */
        put16(m, (take(1) & 3u) ? 1u : 3u);            /* mostly IN, sometimes CHAOS */
        put16(m, 0);                                   /* TTL high */
        put16(m, 60);                                  /* TTL low  */

        const uint8_t rdlen = (uint8_t)(take(0) % 40u);
        put16(m, rdlen);
        for (uint8_t i = 0; i < rdlen; ++i) m.push_back(take(0));
    }

    exercise(m.data(), m.size());
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* ---- A: the input is the whole reply ---------------------------------- */
    exercise(data, size);

    /* ---- B: the same bytes behind a header that passes the gate ------------ */
    if (size >= NR_WIRE_HEADER) {
        std::vector<uint8_t> shaped(data, data + size);
        shaped[2] = 0x81;                                  /* QR set, opcode QUERY, RD */
        shaped[3] = (uint8_t)(shaped[3] & 0xF0u);          /* rcode NOERROR            */
        shaped[4] = 0;
        shaped[5] = (uint8_t)(shaped[5] & 1u);             /* QDCOUNT 0 or 1           */
        shaped[6] = 0;
        if (shaped[7] == 0u) shaped[7] = 1u;               /* ANCOUNT >= 1             */
        exercise(shaped.data(), shaped.size());
    }

    /* ---- C: a structurally valid reply built around the input -------------- */
    exercise_shaped(data, size);
    return 0;
}
