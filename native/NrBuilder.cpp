/*
 * Nullroute — NRDX serialization.
 *
 * App-side only. netd never links this; it only ever maps the finished artifact
 * read-only.
 *
 * The line parser lives in NrParse.cpp and the suffix collapse in
 * NrCollapse.cpp; this file is now only the part that turns normalized records
 * into the exact bytes the resolver mmaps.
 */
#include "NrBuilder.h"
#include "NrQuery.h"

#include <string.h>
#include <algorithm>

namespace nr {

// ---------------------------------------------------------------------------
// Table construction
// ---------------------------------------------------------------------------

static uint32_t next_pow2_cap(size_t n) {
    /* Load factor <= 0.5 so linear probe chains stay inside a cache line or two. */
    uint32_t cap = 1024;
    while ((size_t)cap < n * 2 && cap < (1u << 30)) cap <<= 1;
    return cap;
}

static size_t align_up(size_t v) { return (v + NR_PAGE - 1) & ~(size_t)(NR_PAGE - 1); }

/*
 * Precedence when two rules for the same name land in one slot. Lower wins.
 *
 * This is §6.5 step 5's "dedupe with kind precedence", and it is not
 * hypothetical: `promotion.xmeye.net` arrives from 1Hosts as `*.promotion.xmeye.net`
 * (K_WILDCARD_ONLY) and from AdGuard Mobile Ads as `0.0.0.0 promotion.xmeye.net`
 * (K_SUFFIX). First-writer-wins keeps the wildcard, and the apex — which two
 * separate lists agreed should be blocked — quietly resolves. The corpus
 * round-trip in nrtest catches exactly this, which is why it is a suite check
 * and not a comment.
 *
 * K_FORCE is strongest because it is the never-block floor: an ordinary allow
 * for the same name must never be able to demote it.
 */
static inline unsigned kind_rank(uint8_t k) {
    switch (k) {
        case K_FORCE:         return 0;
        case K_SUFFIX:        return 1;
        case K_WILDCARD_ONLY: return 2;
        case K_EXACT:         return 3;
        default:              return 4;
    }
}

/* Fill an open-addressed table. Returns false if a slot cannot be placed, which
 * can only happen if the capacity was mis-sized — a build-time bug, not a
 * runtime condition. */
static bool fill_table(std::vector<uint64_t>& tbl, uint32_t cap,
                       const std::vector<BuildEntry>& entries, uint64_t seed,
                       std::vector<uint8_t>& bloom, size_t* conflicts) {
    for (const auto& e : entries) {
        uint64_t h; uint8_t nlab;
        if (!nr_rule_hash(e.domain.data(), e.domain.size(), seed, &h, &nlab)) continue;
        const uint64_t want = nr_fp46(h);
        size_t i = nr_bucket(h, cap);
        bool placed = false;
        for (uint32_t probe = 0; probe < cap; ++probe) {
            if (tbl[i] == 0) {
                tbl[i] = nr_slot_pack(h, (uint8_t)e.kind, e.group);
                placed = true;
                break;
            }
            if (nr_slot_fp(tbl[i]) == want) {
                /* Same name (or a 1-in-2^46 fingerprint collision). Keep the
                 * rule that governs the most names; the group follows the kind,
                 * because the group is what the log and the Query screen name as
                 * the reason, and naming a source whose rule did not fire is
                 * worse than naming none. */
                const uint8_t had = nr_slot_kind(tbl[i]);
                if (kind_rank((uint8_t)e.kind) < kind_rank(had)) {
                    tbl[i] = nr_slot_pack(h, (uint8_t)e.kind, e.group);
                }
                if (had != (uint8_t)e.kind && conflicts) ++*conflicts;
                placed = true;
                break;
            }
            i = (i + 1) & (size_t)(cap - 1);
        }
        if (!placed) return false;
        nr_bloom_set(bloom.data(), bloom.size(), h);
    }
    return true;
}

static void label_stats(const std::vector<BuildEntry>& v,
                        uint16_t* mask, uint8_t* mn, uint8_t* mx) {
    for (const auto& e : v) {
        unsigned d = 1;
        for (char c : e.domain) if (c == '.') ++d;
        if (d > NR_MAX_LABELS) d = NR_MAX_LABELS;
        *mask |= (uint16_t)(1u << (d < 15 ? d : 15));
        if (*mn == 0 || d < *mn) *mn = (uint8_t)d;
        if (d > *mx) *mx = (uint8_t)d;
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

bool nr_wrap_strings_blob(const std::vector<uint8_t>& payload,
                          uint64_t generation, uint64_t built_at_ms, uint64_t hash_seed,
                          std::vector<uint8_t>* out) {
    if (!out || payload.empty()) return false;

    out->assign(align_up(NR_PAGE + payload.size()), 0);
    memcpy(out->data() + NR_PAGE, payload.data(), payload.size());

    /* An ordinary NrHeader with a single populated section. That is what lets
     * `nrctl verify`, nr_index_open_ro() and the sha256 seal work on the sidecar
     * unchanged — and it is why the resolver, which reads sec[NR_SEC_STR] never,
     * pays nothing for it. */
    NrHeader h{};
    h.magic       = NR_MAGIC;
    h.fmt_version = (uint16_t)NR_FMT_VERSION;
    h.flags       = 0;
    h.generation  = generation;
    h.built_at_ms = built_at_ms;
    h.hash_seed   = hash_seed ? hash_seed : NR_FNV_OFFSET;
    h.sec[NR_SEC_STR].off = NR_PAGE;
    h.sec[NR_SEC_STR].len = payload.size();
    memcpy(out->data(), &h, sizeof(h));
    return true;
}

bool nr_build_index(std::vector<BuildEntry> block,
                    std::vector<BuildEntry> allow,
                    std::vector<BuildRedirect> redirects,
                    uint64_t generation, uint64_t built_at_ms, uint64_t hash_seed,
                    std::vector<uint8_t>* out, BuildStats* stats,
                    std::vector<uint8_t>* strings_out) {
    if (!hash_seed) hash_seed = NR_FNV_OFFSET;

    stats->block_in = block.size();
    stats->allow_in = allow.size();
    stats->block_collapsed = nr_collapse(&block);
    nr_collapse(&allow);
    stats->redirects = redirects.size();

    const uint32_t bt_cap = block.empty() ? 0 : next_pow2_cap(block.size());
    const uint32_t at_cap = allow.empty() ? 0 : next_pow2_cap(allow.size());
    const uint32_t rt_cap = redirects.empty() ? 0 : next_pow2_cap(redirects.size());

    /* Bloom sized at ~12 bits/entry -> ~0.3% false positive at k=8. A false
     * positive costs one extra table probe, never a wrong verdict, because the
     * table is then consulted for the real fingerprint. */
    auto bloom_bytes = [](size_t n) -> size_t {
        if (n == 0) return 0;
        size_t bytes = (n * 12 + 7) / 8;
        bytes = (bytes + NR_BLOOM_BLOCK_BYTES - 1) / NR_BLOOM_BLOCK_BYTES * NR_BLOOM_BLOCK_BYTES;
        return std::max(bytes, (size_t)NR_BLOOM_BLOCK_BYTES);
    };

    std::vector<uint8_t> bf(bloom_bytes(block.size()), 0);
    std::vector<uint8_t> af(bloom_bytes(allow.size()), 0);
    std::vector<uint64_t> bt(bt_cap, 0), at(at_cap, 0);
    std::vector<NrRedir> rt(rt_cap);
    memset(rt.data(), 0, rt.size() * sizeof(NrRedir));

    size_t conflicts = 0;
    if (bt_cap && !fill_table(bt, bt_cap, block, hash_seed, bf, &conflicts)) return false;
    if (at_cap && !fill_table(at, at_cap, allow, hash_seed, af, &conflicts)) return false;
    stats->kind_conflicts = conflicts;

    for (const auto& r : redirects) {
        uint64_t h; uint8_t nlab;
        if (!nr_rule_hash(r.domain.data(), r.domain.size(), hash_seed, &h, &nlab)) continue;
        const uint64_t want = nr_fp46(h);
        size_t i = nr_bucket(h, rt_cap);
        for (uint32_t probe = 0; probe < rt_cap; ++probe) {
            if (rt[i].fp == 0 || rt[i].fp == want) {
                rt[i].fp = want;
                rt[i].family = r.family;
                memcpy(rt[i].addr, r.addr, 16);
                break;
            }
            i = (i + 1) & (size_t)(rt_cap - 1);
        }
    }

    /* ---- lay the file out, every section page-aligned -------------------- */
    size_t off = NR_PAGE;
    struct { uint64_t off, len; } sec[NR_SEC_COUNT] = {};
    auto place = [&](unsigned idx, size_t len) {
        if (!len) return;
        sec[idx].off = off;
        sec[idx].len = len;
        off = align_up(off + len);
    };
    place(NR_SEC_BF, bf.size());
    place(NR_SEC_BT, bt.size() * sizeof(uint64_t));
    place(NR_SEC_AF, af.size());
    place(NR_SEC_AT, at.size() * sizeof(uint64_t));
    place(NR_SEC_RT, rt.size() * sizeof(NrRedir));

    out->assign(off, 0);

    auto blit = [&](unsigned idx, const void* p) {
        if (sec[idx].len) memcpy(out->data() + sec[idx].off, p, (size_t)sec[idx].len);
    };
    blit(NR_SEC_BF, bf.data());
    blit(NR_SEC_BT, bt.data());
    blit(NR_SEC_AF, af.data());
    blit(NR_SEC_AT, at.data());
    blit(NR_SEC_RT, rt.data());

    uint16_t mask = 0; uint8_t mn = 0, mx = 0;
    label_stats(block, &mask, &mn, &mx);
    label_stats(allow, &mask, &mn, &mx);

    /* ---- header: populate the struct and blit it -------------------------
     * Written through NrHeader rather than field-by-field at hand-counted
     * offsets, so the writer and the resolver's reader agree by construction.  */
    NrHeader h{};
    h.magic       = NR_MAGIC;
    h.fmt_version = (uint16_t)NR_FMT_VERSION;
    h.flags       = 0;
    h.generation  = generation;
    h.built_at_ms = built_at_ms;
    h.n_block     = (uint32_t)block.size();
    h.n_allow     = (uint32_t)allow.size();
    h.n_redirect  = (uint32_t)redirects.size();
    h.bt_cap      = bt_cap;
    h.at_cap      = at_cap;
    h.rt_cap      = rt_cap;
    h.label_mask  = mask;
    h.min_labels  = mn;
    h.max_labels  = mx;
    h.hash_seed   = hash_seed;
    for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
        h.sec[i].off = sec[i].off;
        h.sec[i].len = sec[i].len;
    }
    /* sha256 and the manifest pointers are filled by the caller, which owns the
     * hashing library; leaving them zero here keeps this file dependency-free. */
    memcpy(out->data(), &h, sizeof(h));

    stats->bt_cap = bt_cap;
    stats->at_cap = at_cap;
    stats->rt_cap = rt_cap;
    stats->bytes  = off;

    /* ---- NR_SEC_STR, last, because it consumes the entry vectors ---------
     * Built from the COLLAPSED sets so the count the Rules screen shows is the
     * count that is actually in the index. Failing to build it is not fatal to
     * the index — the resolver never reads it — but it is reported as zero
     * rather than silently pretending an empty blob is a valid one. */
    if (strings_out) {
        strings_out->clear();
        std::vector<uint8_t> payload;
        NrStringsStats sstats;
        if (nr_strings_build(std::move(block), std::move(allow),
                             (uint16_t)NR_STR_RESTART_DEFAULT, &payload, &sstats) &&
            nr_wrap_strings_blob(payload, generation, built_at_ms, hash_seed, strings_out)) {
            stats->strings_bytes = strings_out->size();
            stats->strings_count = sstats.count;
        } else {
            strings_out->clear();
        }
    }
    return true;
}

}  // namespace nr
