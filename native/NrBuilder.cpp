/*
 * Nullroute — blocklist parsing, suffix collapse and NRDX serialization.
 *
 * App-side only. netd never links this; it only ever maps the finished artifact
 * read-only.
 */
#include "NrBuilder.h"
#include "NrQuery.h"

#include <string.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace nr {

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

static inline bool valid_label(const char* p, size_t n) {
    if (n == 0 || n > NR_MAX_LABEL) return false;
    if (p[0] == '-' || p[n - 1] == '-') return false;
    for (size_t i = 0; i < n; ++i) {
        const char c = p[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

/* A domain we are willing to put in the index. Rejects IP literals, single-label
 * names and anything with an invalid label — a blocklist that smuggles in
 * "0.0.0.0" as a *domain* would otherwise become an entry that matches nothing
 * and costs a table slot forever. */
static bool valid_domain(const std::string& s) {
    if (s.empty() || s.size() > NR_MAX_NAME) return false;
    if (nr_is_ip_literal(s.c_str())) return false;
    size_t start = 0, labels = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '.') {
            if (!valid_label(s.data() + start, i - start)) return false;
            start = i + 1;
            ++labels;
        }
    }
    return labels >= 2;
}

static void lower_trim(std::string* s) {
    size_t b = 0, e = s->size();
    while (b < e && (unsigned char)(*s)[b] <= ' ') ++b;
    while (e > b && (unsigned char)(*s)[e - 1] <= ' ') --e;
    *s = s->substr(b, e - b);
    for (auto& c : *s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    while (!s->empty() && s->back() == '.') s->pop_back();
}

bool nr_parse_line(const char* line, size_t len,
                   std::string* domain, RuleKind* kind, bool* is_allow) {
    *is_allow = false;
    *kind = K_SUFFIX;

    std::string s(line, len);
    /* strip inline comments */
    const size_t hash = s.find('#');
    if (hash != std::string::npos) s.resize(hash);
    const size_t excl = s.find("//");
    if (excl != std::string::npos) s.resize(excl);
    lower_trim(&s);
    if (s.empty()) return false;

    /* dnsmasq: address=/example.com/0.0.0.0 */
    if (s.rfind("address=/", 0) == 0) {
        const size_t e = s.find('/', 9);
        if (e == std::string::npos) return false;
        s = s.substr(9, e - 9);
    }

    /* ABP exception must be tested before the plain ABP form. */
    if (s.rfind("@@", 0) == 0) { *is_allow = true; s = s.substr(2); }

    if (s.rfind("||", 0) == 0) {
        s = s.substr(2);
        const size_t caret = s.find_first_of("^$");
        if (caret != std::string::npos) s.resize(caret);
        *kind = K_SUFFIX;
    } else if (s.rfind("@", 0) == 0) {
        *is_allow = true;
        s = s.substr(1);
    }

    if (s.rfind("!", 0) == 0) { *is_allow = true; *kind = K_FORCE; s = s.substr(1); }

    /* hosts format: "<ip> <domain> [more...]" — take the second field only.
     * Multiple names on one hosts line are legal but essentially never used by
     * the lists we consume; taking the first is the conservative reading. */
    const size_t sp = s.find_first_of(" \t");
    if (sp != std::string::npos) {
        std::string first = s.substr(0, sp);
        if (nr_is_ip_literal(first.c_str())) {
            std::string rest = s.substr(sp + 1);
            lower_trim(&rest);
            const size_t sp2 = rest.find_first_of(" \t");
            if (sp2 != std::string::npos) rest.resize(sp2);
            s = rest;
        } else {
            return false;   /* not a form we recognise */
        }
    }

    if (s.rfind("*.", 0) == 0) {
        if (*kind != K_FORCE) *kind = K_WILDCARD_ONLY;
        s = s.substr(2);
    } else if (s.rfind("=", 0) == 0) {
        if (*kind != K_FORCE) *kind = K_EXACT;
        s = s.substr(1);
    }

    lower_trim(&s);
    /* A leading "www." is not stripped: it is a real label and the suffix walk
     * already covers it via the apex entry. */
    if (!valid_domain(s)) return false;

    /* Localhost aliases appear at the top of every hosts file. Indexing them
     * would blackhole loopback. */
    if (s == "localhost" || s == "localhost.localdomain" ||
        s == "local" || s == "ip6-localhost" || s == "ip6-loopback" ||
        s == "broadcasthost" || s == "ip6-localnet" || s == "ip6-mcastprefix" ||
        s == "ip6-allnodes" || s == "ip6-allrouters" || s == "ip6-allhosts") {
        return false;
    }

    *domain = s;
    return true;
}

// ---------------------------------------------------------------------------
// Suffix collapse
// ---------------------------------------------------------------------------

size_t nr_collapse(std::vector<BuildEntry>* entries) {
    /* Only a K_SUFFIX entry can subsume a descendant: a K_WILDCARD_ONLY does not
     * cover the apex and a K_EXACT covers only itself. */
    std::unordered_set<std::string> suffixes;
    suffixes.reserve(entries->size() * 2);
    for (const auto& e : *entries)
        if (e.kind == K_SUFFIX) suffixes.insert(e.domain);

    const size_t before = entries->size();
    std::unordered_set<std::string> seen;
    seen.reserve(entries->size() * 2);

    std::vector<BuildEntry> kept;
    kept.reserve(entries->size());

    for (auto& e : *entries) {
        /* exact duplicate (same domain, same kind) */
        std::string key = e.domain;
        key.push_back('\x01');
        key.push_back((char)('0' + (int)e.kind));
        if (!seen.insert(key).second) continue;

        /* covered by a broader K_SUFFIX ancestor? */
        bool covered = false;
        size_t pos = e.domain.find('.');
        while (pos != std::string::npos) {
            const std::string parent = e.domain.substr(pos + 1);
            if (parent.find('.') == std::string::npos) break;   /* stop at the TLD */
            if (suffixes.count(parent)) { covered = true; break; }
            pos = e.domain.find('.', pos + 1);
        }
        if (covered) continue;

        kept.push_back(std::move(e));
    }
    *entries = std::move(kept);
    return before - entries->size();
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

static uint32_t next_pow2_cap(size_t n) {
    /* Load factor <= 0.5 so linear probe chains stay inside a cache line or two. */
    uint32_t cap = 1024;
    while ((size_t)cap < n * 2 && cap < (1u << 30)) cap <<= 1;
    return cap;
}

static size_t align_up(size_t v) { return (v + NR_PAGE - 1) & ~(size_t)(NR_PAGE - 1); }

/* Fill an open-addressed table. Returns false if a slot cannot be placed, which
 * can only happen if the capacity was mis-sized — a build-time bug, not a
 * runtime condition. */
static bool fill_table(std::vector<uint64_t>& tbl, uint32_t cap,
                       const std::vector<BuildEntry>& entries, uint64_t seed,
                       std::vector<uint8_t>& bloom) {
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
            if (nr_slot_fp(tbl[i]) == want) { placed = true; break; }  /* dup hash */
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

bool nr_build_index(std::vector<BuildEntry> block,
                    std::vector<BuildEntry> allow,
                    std::vector<BuildRedirect> redirects,
                    uint64_t generation, uint64_t built_at_ms, uint64_t hash_seed,
                    std::vector<uint8_t>* out, BuildStats* stats) {
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

    if (bt_cap && !fill_table(bt, bt_cap, block, hash_seed, bf)) return false;
    if (at_cap && !fill_table(at, at_cap, allow, hash_seed, af)) return false;

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
    return true;
}

}  // namespace nr
