/*
 * Nullroute — implementation of the front-coded rule-text blob declared in
 * include/NrStrings.h.
 *
 * App-side only, and UI-side at that: netd never links this and never maps what
 * it produces. Every read is bounds-checked anyway. The blob is written by the
 * update job and read by the Rules screen minutes to days later, across an app
 * upgrade and possibly across a partially-failed write, and a decoder that
 * trusts its own header is a decoder that segfaults the settings app.
 */
#include "NrStrings.h"

#include <string.h>

#include <algorithm>

namespace nr {

// ---------------------------------------------------------------------------
// Reversed-label form
// ---------------------------------------------------------------------------

void nr_reverse_labels(const char* s, size_t n, std::string* out) {
    out->clear();
    if (!s || n == 0) return;
    out->reserve(n);
    size_t end = n;
    for (size_t i = n; i-- > 0;) {
        if (s[i] == '.') {
            out->append(s + i + 1, end - i - 1);
            out->push_back('.');
            end = i;
        }
    }
    out->append(s, end);
}

// ---------------------------------------------------------------------------
// varint (LEB128)
// ---------------------------------------------------------------------------

static void put_varint(std::vector<uint8_t>* v, uint32_t x) {
    while (x >= 0x80u) {
        v->push_back((uint8_t)(x | 0x80u));
        x >>= 7;
    }
    v->push_back((uint8_t)x);
}

/* Returns false on a truncated or over-long encoding rather than reading past
 * `end`. Five groups is the most a uint32 can need. */
static bool get_varint(const uint8_t* p, const uint8_t* end, uint32_t* out, size_t* used) {
    uint32_t x = 0;
    unsigned shift = 0;
    size_t   i = 0;
    while (p + i < end && i < 5) {
        const uint8_t b = p[i++];
        x |= (uint32_t)(b & 0x7fu) << shift;
        if (!(b & 0x80u)) {
            *out  = x;
            *used = i;
            return true;
        }
        shift += 7;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

static inline uint32_t load_u32(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

bool nr_strings_open(const uint8_t* section, size_t len, NrStrings* out) {
    *out = NrStrings{};
    if (!section || len < sizeof(NrStrHeader)) return false;

    NrStrHeader h;
    memcpy(&h, section, sizeof(h));
    if (h.magic != NR_STR_MAGIC) return false;
    if (h.version > NR_STR_VERSION) return false;   /* forward-compat: decline */
    if (h.restart == 0) return false;

    /* Overflow-safe bounds. Written the same shape as nr_index_validate()'s,
     * because the arithmetic is where this class of check usually goes wrong. */
    auto in_bounds = [&](uint32_t off, uint32_t n) -> bool {
        if (n == 0) return true;
        if (off > len) return false;
        return n <= len - off;
    };
    if (!in_bounds(h.index_off, h.index_len)) return false;
    if (!in_bounds(h.meta_off, h.meta_len)) return false;
    if (!in_bounds(h.data_off, h.data_len)) return false;

    if (h.count == 0) {
        if (h.blocks != 0) return false;
    } else {
        const uint32_t want_blocks = (h.count + h.restart - 1u) / h.restart;
        if (h.blocks != want_blocks) return false;
        if (h.index_len < (uint64_t)h.blocks * sizeof(uint32_t)) return false;
        if (h.data_len == 0) return false;
    }
    if (h.meta_len && h.meta_len < (uint64_t)h.count * sizeof(NrStrMeta)) return false;

    out->base     = section;
    out->size     = len;
    out->hdr      = (const NrStrHeader*)section;
    out->data     = section + h.data_off;
    out->data_len = h.data_len;
    out->index    = h.index_len ? section + h.index_off : nullptr;
    out->meta     = h.meta_len ? section + h.meta_off : nullptr;
    return true;
}

bool nr_strings_open_index(const NrIndex& ix, NrStrings* out) {
    *out = NrStrings{};
    if (!ix.hdr || !ix.base) return false;
    const NrSection& sec = ix.hdr->sec[NR_SEC_STR];
    if (sec.len == 0) return false;
    /* nr_index_validate() already bounded every section against the mapping. */
    return nr_strings_open(ix.base + sec.off, (size_t)sec.len, out);
}

/* Decodes the entry beginning at `pos`, given the previous key. On a restart
 * entry `prev` is ignored. */
static bool decode_entry(const NrStrings& s, size_t pos, bool restart,
                         std::string* key, size_t* next) {
    const uint8_t* p   = s.data + pos;
    const uint8_t* end = s.data + s.data_len;
    if (pos > s.data_len) return false;

    uint32_t shared = 0;
    size_t   used = 0;
    if (!restart) {
        if (!get_varint(p, end, &shared, &used)) return false;
        p += used;
    }
    uint32_t suffix = 0;
    if (!get_varint(p, end, &suffix, &used)) return false;
    p += used;

    if (shared > key->size()) return false;
    if ((size_t)(end - p) < suffix) return false;
    if ((size_t)shared + suffix > NR_MAX_NAME) return false;

    key->resize(shared);
    key->append((const char*)p, suffix);
    *next = (size_t)((p + suffix) - s.data);
    return true;
}

bool nr_strings_seek(const NrStrings& s, uint32_t i, NrStrCursor* out) {
    *out = NrStrCursor{};
    if (!s.hdr || i >= s.hdr->count) return false;

    const uint32_t restart = s.hdr->restart;
    const uint32_t block   = i / restart;
    if (!s.index || block >= s.hdr->blocks) return false;

    size_t pos = load_u32(s.index + (size_t)block * sizeof(uint32_t));
    std::string key;
    for (uint32_t j = block * restart; j <= i; ++j) {
        size_t next = 0;
        if (!decode_entry(s, pos, j % restart == 0, &key, &next)) return false;
        pos = next;
    }

    out->owner = &s;
    out->index = i;
    out->next  = pos;
    out->key   = std::move(key);
    out->valid = true;
    return true;
}

bool nr_strings_next(NrStrCursor* c) {
    if (!c || !c->valid || !c->owner || !c->owner->hdr) return false;
    const NrStrings& s = *c->owner;
    const uint32_t i = c->index + 1;
    if (i >= s.hdr->count) { c->valid = false; return false; }

    size_t next = 0;
    if (!decode_entry(s, c->next, i % s.hdr->restart == 0, &c->key, &next)) {
        c->valid = false;
        return false;
    }
    c->index = i;
    c->next  = next;
    return true;
}

bool nr_strings_key(const NrStrings& s, uint32_t i, std::string* out_reversed) {
    NrStrCursor c;
    if (!nr_strings_seek(s, i, &c)) return false;
    *out_reversed = c.key;
    return true;
}

bool nr_strings_rule(const NrStrings& s, uint32_t i, std::string* out_forward) {
    std::string rev;
    if (!nr_strings_key(s, i, &rev)) return false;
    nr_reverse_labels(rev.data(), rev.size(), out_forward);
    return true;
}

bool nr_strings_meta(const NrStrings& s, uint32_t i, NrStrMeta* out) {
    *out = NrStrMeta{};
    if (!s.hdr || !s.meta || i >= s.hdr->count) return false;
    memcpy(out, s.meta + (size_t)i * sizeof(NrStrMeta), sizeof(NrStrMeta));
    return true;
}

/* First key of a restart block, decoded whole. */
static bool block_first_key(const NrStrings& s, uint32_t block, std::string* out) {
    if (!s.index || !s.hdr || block >= s.hdr->blocks) return false;
    const size_t pos = load_u32(s.index + (size_t)block * sizeof(uint32_t));
    out->clear();
    size_t next = 0;
    return decode_entry(s, pos, true, out, &next);
}

/* First entry whose key is >= `key`, or count. */
static uint32_t lower_bound_key(const NrStrings& s, const std::string& key) {
    if (!s.hdr || s.hdr->count == 0) return 0;
    const uint32_t restart = s.hdr->restart;

    /* Locate the last block whose first key is <= `key`. */
    uint32_t lo = 0, hi = s.hdr->blocks;
    std::string probe;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        if (!block_first_key(s, mid, &probe)) return s.hdr->count;   /* corrupt: no match */
        if (probe.compare(key) <= 0) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return 0;                       /* every key sorts above it */
    const uint32_t block = lo - 1;

    NrStrCursor c;
    if (!nr_strings_seek(s, block * restart, &c)) return s.hdr->count;
    do {
        if (c.key.compare(key) >= 0) return c.index;
        if (c.index + 1 >= (block + 1) * restart) break;
    } while (nr_strings_next(&c));

    const uint32_t after = (block + 1) * restart;
    return after < s.hdr->count ? after : s.hdr->count;
}

NrStrRange nr_strings_range_for_suffix(const NrStrings& s, const char* base, size_t len) {
    NrStrRange r;
    if (!s.hdr || s.hdr->count == 0 || !base || len == 0) return r;

    std::string norm(base, len);
    nr_parse_normalize(&norm);
    if (norm.empty()) return r;

    std::string rev;
    nr_reverse_labels(norm.data(), norm.size(), &rev);

    /* Apex rows: keys exactly equal to `rev`. There can be several — one per
     * (kind, role) — and they are adjacent because the builder sorted on the key
     * first. 0x01 is below every byte a label may contain, so it terminates the
     * run of equal keys without reaching the next real name. */
    std::string apex_hi = rev;
    apex_hi.push_back('\x01');

    /* Subdomain rows: keys with the `rev + '.'` prefix. Bounded above by the
     * same prefix with '/' (0x2F) in place of '.' (0x2E), which is the smallest
     * byte that cannot begin a label. Starting at `rev + '.'` rather than at the
     * apex is what excludes `net.doubleclick-cn`. */
    std::string sub_lo = rev;
    sub_lo.push_back('.');
    std::string sub_hi = rev;
    sub_hi.push_back((char)('.' + 1));

    r.apex_begin = lower_bound_key(s, rev);
    r.apex_end   = lower_bound_key(s, apex_hi);
    r.sub_begin  = lower_bound_key(s, sub_lo);
    r.sub_end    = lower_bound_key(s, sub_hi);
    if (r.apex_end < r.apex_begin) r.apex_end = r.apex_begin;
    if (r.sub_end < r.sub_begin) r.sub_end = r.sub_begin;
    return r;
}

/* Walks one span, classifying each row. Returns how many it visited. */
static uint32_t tally_span(const NrStrings& s, uint32_t begin, uint32_t end,
                           uint32_t budget, uint32_t* into, NrStrPreview* p) {
    if (end <= begin || budget == 0) return 0;
    NrStrCursor c;
    if (!nr_strings_seek(s, begin, &c)) return 0;

    uint32_t seen = 0;
    do {
        if (c.index >= end || seen >= budget) break;
        ++seen;
        ++*into;
        NrStrMeta m;
        if (nr_strings_meta(s, c.index, &m)) {
            if (m.flags & NR_STR_FLAG_ALLOW) ++p->allows; else ++p->blocks;
        }
    } while (nr_strings_next(&c));
    return seen;
}

NrStrPreview nr_strings_preview(const NrStrings& s, const char* base, size_t len,
                                uint32_t limit) {
    NrStrPreview p;
    const NrStrRange r = nr_strings_range_for_suffix(s, base, len);
    if (r.empty()) return p;

    /* A zero limit means unbounded; anything else is a shared budget across both
     * spans so that "com" cannot walk 200,000 rows on the UI thread. */
    uint32_t budget = limit ? limit : 0xFFFFFFFFu;
    budget -= tally_span(s, r.apex_begin, r.apex_end, budget, &p.apex, &p);
    tally_span(s, r.sub_begin, r.sub_end, budget, &p.subdomains, &p);
    return p;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

namespace {

struct Rule {
    std::string key;      /* reversed-label */
    uint16_t    group;
    uint8_t     kind;
    uint8_t     flags;
};

size_t shared_prefix(const std::string& a, const std::string& b) {
    const size_t n = std::min(a.size(), b.size());
    size_t i = 0;
    while (i < n && a[i] == b[i]) ++i;
    return i;
}

void collect(std::vector<BuildEntry>& in, uint8_t flags, std::vector<Rule>* out) {
    for (auto& e : in) {
        if (e.domain.empty() || e.domain.size() > NR_MAX_NAME) continue;
        Rule r;
        nr_reverse_labels(e.domain.data(), e.domain.size(), &r.key);
        if (r.key.empty()) continue;
        r.group = e.group;
        r.kind  = (uint8_t)e.kind;
        r.flags = flags;
        out->push_back(std::move(r));
    }
    in.clear();
    in.shrink_to_fit();
}

}  // namespace

bool nr_strings_build(std::vector<BuildEntry> block, std::vector<BuildEntry> allow,
                      uint16_t restart, std::vector<uint8_t>* out,
                      NrStringsStats* stats) {
    if (!out) return false;
    if (restart == 0) restart = (uint16_t)NR_STR_RESTART_DEFAULT;
    if (stats) *stats = NrStringsStats{};

    std::vector<Rule> rules;
    rules.reserve(block.size() + allow.size());
    collect(block, 0, &rules);
    collect(allow, (uint8_t)NR_STR_FLAG_ALLOW, &rules);

    /* Sort on the key, then on flags so a block rule precedes an allow rule for
     * the same name — the Rules screen reads the first hit as "what this domain
     * is", and "blocked, with an allow exception" is the more useful reading of
     * that pair than the reverse. */
    std::sort(rules.begin(), rules.end(), [](const Rule& a, const Rule& b) {
        const int c = a.key.compare(b.key);
        if (c != 0) return c < 0;
        if (a.flags != b.flags) return a.flags < b.flags;
        return a.kind < b.kind;
    });
    /* One row per (name, kind, role): two lists blocking the same domain with
     * the same kind is the common case and there is nothing to say twice. */
    rules.erase(std::unique(rules.begin(), rules.end(),
                            [](const Rule& a, const Rule& b) {
                                return a.key == b.key && a.kind == b.kind &&
                                       a.flags == b.flags;
                            }),
                rules.end());

    const uint32_t count  = (uint32_t)rules.size();
    const uint32_t blocks = count ? (count + restart - 1u) / restart : 0u;

    std::vector<uint8_t>  data;
    std::vector<uint32_t> index;
    data.reserve(count * 12u + 64u);
    index.reserve(blocks);

    std::string prev;
    uint32_t longest = 0;
    uint64_t raw = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const std::string& key = rules[i].key;
        raw += key.size() + 1;
        if (key.size() > longest) longest = (uint32_t)key.size();

        if (i % restart == 0) {
            index.push_back((uint32_t)data.size());
            put_varint(&data, (uint32_t)key.size());
            data.insert(data.end(), key.begin(), key.end());
        } else {
            const size_t sh = shared_prefix(prev, key);
            put_varint(&data, (uint32_t)sh);
            put_varint(&data, (uint32_t)(key.size() - sh));
            data.insert(data.end(), key.begin() + (std::ptrdiff_t)sh, key.end());
        }
        prev = key;
    }

    std::vector<NrStrMeta> meta;
    meta.reserve(count);
    uint32_t n_block_out = 0, n_allow_out = 0;
    for (const Rule& r : rules) {
        NrStrMeta m{r.group, r.kind, r.flags};
        meta.push_back(m);
        if (r.flags & NR_STR_FLAG_ALLOW) ++n_allow_out; else ++n_block_out;
    }

    /* Layout: header, block index, meta, data. Everything downstream of the
     * 64-byte header is 4-byte aligned by construction, which is what lets the
     * reader index straight into it. */
    const uint32_t index_off = (uint32_t)sizeof(NrStrHeader);
    const uint32_t index_len = (uint32_t)(index.size() * sizeof(uint32_t));
    const uint32_t meta_off  = index_off + index_len;
    const uint32_t meta_len  = (uint32_t)(meta.size() * sizeof(NrStrMeta));
    const uint32_t data_off  = meta_off + meta_len;
    const uint32_t data_len  = (uint32_t)data.size();

    out->assign((size_t)data_off + data_len, 0);

    NrStrHeader h{};
    h.magic     = NR_STR_MAGIC;
    h.version   = (uint16_t)NR_STR_VERSION;
    h.restart   = restart;
    h.count     = count;
    h.blocks    = blocks;
    h.index_off = index_off;
    h.index_len = index_len;
    h.meta_off  = meta_off;
    h.meta_len  = meta_len;
    h.data_off  = data_off;
    h.data_len  = data_len;
    h.longest   = longest;
    h.n_block   = n_block_out;
    h.n_allow   = n_allow_out;
    memcpy(out->data(), &h, sizeof(h));
    if (index_len) memcpy(out->data() + index_off, index.data(), index_len);
    if (meta_len)  memcpy(out->data() + meta_off, meta.data(), meta_len);
    if (data_len)  memcpy(out->data() + data_off, data.data(), data_len);

    if (stats) {
        stats->count   = count;
        stats->blocks  = blocks;
        stats->longest = longest;
        stats->bytes   = out->size();
        stats->raw     = raw;
    }

    /* A blob the reader would decline is worse than none: it would make the
     * Rules screen say "unavailable" with no way to tell that from a missing
     * file. Prove it round-trips before handing it back. */
    NrStrings check;
    return nr_strings_open(out->data(), out->size(), &check);
}

}  // namespace nr
