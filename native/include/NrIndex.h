/*
 * Nullroute — the NRDX on-disk index format. THE single source of truth.
 *
 * This header is the module `libnrformat_headers` and is consumed by BOTH
 * packages/apps/Nullroute (builder, CLI, JNI) and packages/modules/DnsResolver
 * (the live filter) via `header_libs:`. It is deliberately not copied into the
 * resolver tree: two "byte-identical" copies drift the first time someone
 * rebases one repo and not the other, and the failure mode is a silently
 * mis-parsed index inside netd.
 *
 * The file is immutable once written. Updates are published by writing a new
 * generation to a staging path, fsync, rename() and a release-store of
 * NrControl::want_generation — never by mutating a live mapping.
 */
#ifndef NULLROUTE_NR_INDEX_H
#define NULLROUTE_NR_INDEX_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "NrHash.h"
#include "NrVerdict.h"

#define NR_MAGIC        0x5844524Eu  /* "NRDX" little-endian */
#define NR_FMT_VERSION  1u
#define NR_MAX_LABELS   16u          /* hard bound; fuzz-critical */
#define NR_PAGE         4096u
#define NR_MAX_NAME     253u         /* RFC 1035 */
#define NR_MAX_LABEL    63u

/* Section indices into NrHeader::sec[]. */
#define NR_SEC_BF    0u  /* block  Bloom filter          */
#define NR_SEC_BT    1u  /* block  table  (NrSlot[])     */
#define NR_SEC_AF    2u  /* allow  Bloom filter          */
#define NR_SEC_AT    3u  /* allow  table  (NrSlot[])     */
#define NR_SEC_RT    4u  /* redirect table (NrRedir[])   */
#define NR_SEC_STR   5u  /* front-coded rule text — UI only, NEVER mapped by netd */
#define NR_SEC_RSV6  6u
#define NR_SEC_RSV7  7u
#define NR_SEC_COUNT 8u

#ifdef __cplusplus
namespace nr {

typedef uint64_t NrSlot;

struct NrSection { uint64_t off, len; };

/*
 * Page 0 of the file. Fixed layout, little-endian, never reordered within a
 * major format version; new fields go in the reserved tail.
 *
 * Every pad is EXPLICIT and every offset is asserted. This struct is written by
 * the app and read by netd — two separately-compiled binaries — so relying on
 * the compiler's natural alignment to agree is not good enough. (`hash_seed`
 * needs 8-byte alignment and therefore does not sit where a naive
 * field-by-field writer would put it; that mismatch would produce an index that
 * validates and then silently mis-hashes every lookup.)
 */
struct NrHeader {
    /*   0 */ uint32_t magic;            /* NR_MAGIC                                    */
    /*   4 */ uint16_t fmt_version;      /* NR_FMT_VERSION                              */
    /*   6 */ uint16_t flags;
    /*   8 */ uint64_t generation;       /* monotonic, assigned by the builder          */
    /*  16 */ uint64_t built_at_ms;
    /*  24 */ uint32_t n_block;
    /*  28 */ uint32_t n_allow;
    /*  32 */ uint32_t n_redirect;
    /*  36 */ uint32_t bt_cap;           /* power-of-two table capacities               */
    /*  40 */ uint32_t at_cap;
    /*  44 */ uint32_t rt_cap;
    /*  48 */ uint16_t label_mask;       /* bit d set == some rule has exactly d labels */
    /*  50 */ uint8_t  min_labels;
    /*  51 */ uint8_t  max_labels;
    /*  52 */ uint32_t _pad0;
    /*  56 */ uint64_t hash_seed;
    /*  64 */ struct NrSection sec[NR_SEC_COUNT];
    /* 192 */ uint8_t  sha256[32];       /* over bytes [NR_PAGE, EOF)                   */
    /* 224 */ uint64_t manifest_off;
    /* 232 */ uint64_t manifest_len;
    /* 240 */ uint8_t  reserved[NR_PAGE - 240];
};

static_assert(sizeof(NrHeader) == NR_PAGE, "NrHeader must be exactly one page");
static_assert(offsetof(NrHeader, hash_seed) == 56, "hash_seed offset is ABI");
static_assert(offsetof(NrHeader, sec) == 64, "section table offset is ABI");
static_assert(offsetof(NrHeader, sha256) == 192, "sha256 offset is ABI");

struct NrRedir {
    uint64_t fp;        /* nr_fp46() of the full-FQDN hash */
    uint8_t  family;    /* AF_INET / AF_INET6              */
    uint8_t  addr[16];
    uint8_t  _pad[7];
};

/* A validated, mapped index. Pointers are into the shared file mapping and are
 * valid for the lifetime of the mapping only. */
struct NrIndex {
    const NrHeader* hdr;
    const uint8_t*  base;
    size_t          size;
    const uint8_t*  block_filter;
    const NrSlot*   block_table;
    const uint8_t*  allow_filter;
    const NrSlot*   allow_table;
    const NrRedir*  redir_table;
};

static inline bool nr_is_pow2(uint32_t v) { return v && !(v & (v - 1)); }

/*
 * Structural validation of a mapping before a single lookup is served.
 *
 * This runs against a file that a compromised or merely buggy app could have
 * written, inside netd, whose death restarts zygote. Every offset/length pair is
 * bounds-checked against the real mapping size and every capacity is checked to
 * be a power of two, because nr_table_get() masks with (cap - 1) and a non-power
 * of two would read out of bounds.
 *
 * Returns false rather than aborting: the caller falls OPEN (filtering
 * disabled), never closed. A corrupt index must not take DNS down.
 */
static inline bool nr_index_validate(const uint8_t* base, size_t size, NrIndex* out) {
    if (!base || size < NR_PAGE) return false;
    const NrHeader* h = (const NrHeader*)base;
    if (h->magic != NR_MAGIC) return false;
    if (h->fmt_version > NR_FMT_VERSION) return false;   /* forward-compat: fall open */
    if (h->max_labels > NR_MAX_LABELS) return false;
    if (h->min_labels > h->max_labels && h->max_labels != 0) return false;

    for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
        const struct NrSection* s = &h->sec[i];
        if (s->len == 0) continue;
        if (s->off < NR_PAGE) return false;
        if (s->off > size) return false;
        if (s->len > size - s->off) return false;        /* overflow-safe form */
    }
    if (h->n_block && !nr_is_pow2(h->bt_cap)) return false;
    if (h->n_allow && !nr_is_pow2(h->at_cap)) return false;
    if (h->sec[NR_SEC_BT].len < (uint64_t)h->bt_cap * sizeof(NrSlot)) return false;
    if (h->sec[NR_SEC_AT].len < (uint64_t)h->at_cap * sizeof(NrSlot)) return false;
    if (h->sec[NR_SEC_RT].len < (uint64_t)h->rt_cap * sizeof(NrRedir)) return false;
    /* Load factor sanity: a table fuller than 7/8 makes linear probing degenerate
     * into a full scan, which is the one thing the hot path must never do. */
    if (h->bt_cap && h->n_block > (h->bt_cap / 8) * 7) return false;
    if (h->at_cap && h->n_allow > (h->at_cap / 8) * 7) return false;

    out->hdr  = h;
    out->base = base;
    out->size = size;
    out->block_filter = h->sec[NR_SEC_BF].len ? base + h->sec[NR_SEC_BF].off : nullptr;
    out->block_table  = h->sec[NR_SEC_BT].len ? (const NrSlot*)(base + h->sec[NR_SEC_BT].off) : nullptr;
    out->allow_filter = h->sec[NR_SEC_AF].len ? base + h->sec[NR_SEC_AF].off : nullptr;
    out->allow_table  = h->sec[NR_SEC_AT].len ? (const NrSlot*)(base + h->sec[NR_SEC_AT].off) : nullptr;
    out->redir_table  = h->sec[NR_SEC_RT].len ? (const NrRedir*)(base + h->sec[NR_SEC_RT].off) : nullptr;
    return true;
}

static inline bool nr_redir_get(const NrIndex& ix, uint64_t h, NrRedir* out) {
    if (!ix.redir_table || ix.hdr->rt_cap == 0) return false;
    const uint64_t want = nr_fp46(h);
    size_t i = nr_bucket(h, ix.hdr->rt_cap);
    for (uint32_t probe = 0; probe < ix.hdr->rt_cap; ++probe) {
        const NrRedir* r = &ix.redir_table[i];
        if (r->fp == 0) return false;
        if (r->fp == want) { *out = *r; return true; }
        i = (i + 1) & (size_t)(ix.hdr->rt_cap - 1);
    }
    return false;
}

}  /* namespace nr */
#endif /* __cplusplus */
#endif /* NULLROUTE_NR_INDEX_H */
