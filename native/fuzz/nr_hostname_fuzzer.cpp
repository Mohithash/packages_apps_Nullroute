/*
 * Nullroute — libFuzzer target: arbitrary bytes as a HOSTNAME. [MERGE GATE]
 *
 *   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address -I native/include \
 *           native/NrCanon.cpp native/NrQuery.cpp \
 *           native/fuzz/nr_hostname_fuzzer.cpp -o nr_hostname_fuzzer
 *   ./nr_hostname_fuzzer -max_len=300 corpus/
 *
 * WHY THIS IS A GATE. nr_evaluate() runs inside netd on every DNS lookup, and
 * netd's init stanza carries `onrestart restart zygote`: a crash or a hang here
 * is a UI/boot loop on the user's phone, not "no internet" (§10.1). The hostname
 * is the most attacker-influenced input in the system — any app can call
 * getaddrinfo() with any bytes at all, including no NUL, 253 dots in a row, or a
 * label longer than the buffer.
 *
 * The input is passed to the matcher AS-IS: not copied, not NUL-terminated, not
 * length-clamped. Under ASAN, libFuzzer's buffer is redzoned, so a single byte
 * read past `size` is a crash rather than a silent success — which is the entire
 * point of testing the (pointer, length) contract rather than a C string.
 *
 * The index is built here by hand rather than with NrBuilder, because the
 * resolver links only libnrfilter and this target must exercise exactly what the
 * resolver links. It covers every RuleKind and a redirect, so the fuzzer reaches
 * the allow walk, the block walk, kind_applies() and nr_redir_get().
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "NrControl.h"
#include "NrHash.h"
#include "NrIndex.h"
#include "NrQuery.h"

using namespace nr;

namespace {

struct Rule {
    const char* domain;
    RuleKind    kind;
    uint16_t    group;
};

const Rule kBlock[] = {
    {"fuzz-apex.example",           K_SUFFIX,        11},
    {"fuzz-wild.example",           K_WILDCARD_ONLY, 12},
    {"a.fuzz-exact.example",        K_EXACT,         13},
    {"fuzz-carve.example",          K_SUFFIX,        14},
    {"deep.nested.long.fuzz.example", K_SUFFIX,      15},
};
const Rule kAllow[] = {
    {"cdn.fuzz-carve.example", K_SUFFIX, 21},
    {"fuzz-force.example",     K_FORCE,  22},
};

size_t align_up(size_t v) { return (v + NR_PAGE - 1) & ~(size_t)(NR_PAGE - 1); }

void fill(std::vector<uint64_t>& tbl, uint32_t cap, std::vector<uint8_t>& bloom,
          const Rule* rules, size_t n, uint64_t seed) {
    for (size_t r = 0; r < n; ++r) {
        uint64_t h;
        uint8_t  labels;
        if (!nr_rule_hash(rules[r].domain, strlen(rules[r].domain), seed, &h, &labels))
            abort();   /* a fixture rule the matcher cannot represent is a test bug */
        size_t i = nr_bucket(h, cap);
        for (uint32_t probe = 0; probe < cap; ++probe) {
            if (tbl[i] == 0) {
                tbl[i] = nr_slot_pack(h, (uint8_t)rules[r].kind, rules[r].group);
                break;
            }
            i = (i + 1) & (size_t)(cap - 1);
        }
        nr_bloom_set(bloom.data(), bloom.size(), h);
    }
}

struct Fixture {
    std::vector<uint8_t> blob;
    NrIndex              ix{};
    NrControl*           ctl = nullptr;
};

Fixture* build_fixture() {
    Fixture* f = new Fixture();
    const uint64_t seed = NR_FNV_OFFSET;
    const uint32_t bt_cap = 1024, at_cap = 1024, rt_cap = 64;

    std::vector<uint8_t>  bf(512, 0), af(512, 0);
    std::vector<uint64_t> bt(bt_cap, 0), at(at_cap, 0);
    std::vector<NrRedir>  rt(rt_cap);
    memset(rt.data(), 0, rt.size() * sizeof(NrRedir));

    const size_t nblock = sizeof(kBlock) / sizeof(kBlock[0]);
    const size_t nallow = sizeof(kAllow) / sizeof(kAllow[0]);
    fill(bt, bt_cap, bf, kBlock, nblock, seed);
    fill(at, at_cap, af, kAllow, nallow, seed);

    {
        uint64_t h;
        uint8_t  labels;
        const char* probe = "idx-probe.nullroute.invalid";
        if (!nr_rule_hash(probe, strlen(probe), seed, &h, &labels)) abort();
        size_t i = nr_bucket(h, rt_cap);
        rt[i].fp     = nr_fp46(h);
        rt[i].family = 2 /* AF_INET */;
        rt[i].addr[0] = 127;
        rt[i].addr[3] = 7;
    }

    size_t off = NR_PAGE;
    struct { uint64_t off, len; } sec[NR_SEC_COUNT] = {};
    auto place = [&](unsigned idx, size_t len) {
        sec[idx].off = off;
        sec[idx].len = len;
        off = align_up(off + len);
    };
    place(NR_SEC_BF, bf.size());
    place(NR_SEC_BT, bt.size() * sizeof(uint64_t));
    place(NR_SEC_AF, af.size());
    place(NR_SEC_AT, at.size() * sizeof(uint64_t));
    place(NR_SEC_RT, rt.size() * sizeof(NrRedir));

    f->blob.assign(off, 0);
    memcpy(f->blob.data() + sec[NR_SEC_BF].off, bf.data(), bf.size());
    memcpy(f->blob.data() + sec[NR_SEC_BT].off, bt.data(), bt.size() * sizeof(uint64_t));
    memcpy(f->blob.data() + sec[NR_SEC_AF].off, af.data(), af.size());
    memcpy(f->blob.data() + sec[NR_SEC_AT].off, at.data(), at.size() * sizeof(uint64_t));
    memcpy(f->blob.data() + sec[NR_SEC_RT].off, rt.data(), rt.size() * sizeof(NrRedir));

    NrHeader h{};
    h.magic       = NR_MAGIC;
    h.fmt_version = (uint16_t)NR_FMT_VERSION;
    h.generation  = 1;
    h.built_at_ms = 1700000000000ULL;
    h.n_block     = (uint32_t)nblock;
    h.n_allow     = (uint32_t)nallow;
    h.n_redirect  = 1;
    h.bt_cap      = bt_cap;
    h.at_cap      = at_cap;
    h.rt_cap      = rt_cap;
    h.hash_seed   = seed;
    /* Label statistics must describe the fixture, or depth_plausible() skips the
     * very probes this target exists to exercise. */
    for (const Rule* set : {kBlock, kAllow}) {
        const size_t n = (set == kBlock) ? nblock : nallow;
        for (size_t r = 0; r < n; ++r) {
            unsigned d = 1;
            for (const char* p = set[r].domain; *p; ++p) if (*p == '.') ++d;
            if (d > NR_MAX_LABELS) d = NR_MAX_LABELS;
            h.label_mask |= (uint16_t)(1u << (d < 15 ? d : 15));
            if (h.min_labels == 0 || d < h.min_labels) h.min_labels = (uint8_t)d;
            if (d > h.max_labels) h.max_labels = (uint8_t)d;
        }
    }
    for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
        h.sec[i].off = sec[i].off;
        h.sec[i].len = sec[i].len;
    }
    memcpy(f->blob.data(), &h, sizeof(h));

    if (!nr_index_validate(f->blob.data(), f->blob.size(), &f->ix)) abort();

    f->ctl = (NrControl*)calloc(1, sizeof(NrControl));
    if (!f->ctl) abort();
    f->ctl->mode          = NR_MODE_ENFORCE;   /* 0, but say so explicitly */
    f->ctl->response_mode = NR_RESP_NONAME;
    /* One exempt appId, and it must be one the uid below can actually produce —
     * data[0] == 0 gives uid 10000 — or the EXEMPT arm of the gate is never taken
     * and the fixture only looks like it covers it. */
    f->ctl->uid_policy[10000] = NR_POLICY_EXEMPT;
    return f;
}

Fixture* fixture() {
    static Fixture* f = build_fixture();
    return f;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Fixture* f = fixture();

    /* Vary the uid without consuming a byte of the name: the whole input stays
     * the hostname, so every mutation libFuzzer makes lands where it matters. */
    const uid_t uid = size ? (uid_t)(10000u + data[0] * 37u) : 0u;

    const char* name = (const char*)data;
    nr_evaluate(f->ix, *f->ctl, name, size, uid);
    nr_evaluate_index(f->ix, name, size);

    /* The builder hashes rule text with the same canonicalizer, so rule text is
     * an equally untrusted input path — a downloaded blocklist line reaches it. */
    uint64_t h;
    uint8_t  labels;
    nr_rule_hash(name, size, f->ix.hdr->hash_seed, &h, &labels);

    /* And the canonicalizer alone, where the label/length bounds live. */
    NrCanon c;
    nr_canonicalize(name, size, f->ix.hdr->hash_seed, &c);
    if (c.usable && c.depth > NR_MAX_LABELS) abort();   /* the hard bound must hold */
    return 0;
}
