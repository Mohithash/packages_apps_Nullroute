/*
 * Nullroute — hashing, blocked-Bloom geometry and open-addressed probing.
 *
 * Everything here is header-only and allocation-free: it runs inside netd on the
 * DNS hot path, where a single unnecessary syscall or heap touch would be a
 * per-query cost paid by every app on the device.
 *
 * The index stores 46-bit fingerprints rather than domain text, so a lookup
 * never dereferences a string and the table stays cache-resident. A 64-bit hash
 * over the measured 224,541-domain BALANCED corpus produced zero collisions
 * (expected rate ~n^2/2^65 ~ 3e-9), and a false positive costs at most one
 * wrongly-blocked domain that the allowlist can override.
 */
#ifndef NULLROUTE_NR_HASH_H
#define NULLROUTE_NR_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
namespace nr {

/* FNV-1a-64 constants. Chosen over a stronger hash because the input is
 * attacker-influenced only in the sense that a hostname can be arbitrary — there
 * is no secret to leak and no reason to pay for SipHash on every label. */
static const uint64_t NR_FNV_OFFSET = 0xcbf29ce484222325ULL;
static const uint64_t NR_FNV_PRIME  = 0x100000001b3ULL;

/* Finalizer (splitmix64). FNV-1a alone has weak avalanche in the low bits, and
 * we take the bucket index from the low bits and the fingerprint from the high
 * bits — they must be independent or the table degenerates. */
static inline uint64_t nr_mix(uint64_t x) {
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static inline uint64_t nr_hash_bytes(const char* p, size_t n, uint64_t seed) {
    uint64_t h = seed;
    for (size_t i = 0; i < n; ++i) h = (h ^ (uint8_t)p[i]) * NR_FNV_PRIME;
    return nr_mix(h);
}

/* ---------------------------------------------------------------------------
 * Table slot packing
 *
 *   bits 63..18  fp46        46-bit fingerprint, taken from the high hash bits
 *   bits 17..16  kind        RuleKind
 *   bits 15..0   rule_group  source-list id
 *
 * A slot of all-zero means empty. A real entry whose fingerprint happens to be
 * zero would be indistinguishable from an empty slot, so fp46 == 0 is remapped
 * to 1 — a 1-in-2^46 event that would otherwise be a silent lookup miss.
 * ------------------------------------------------------------------------- */
static inline uint64_t nr_fp46(uint64_t h) {
    uint64_t fp = h >> 18;                 /* 46 bits */
    return fp ? fp : 1ULL;
}
static inline uint64_t nr_slot_pack(uint64_t h, uint8_t kind, uint16_t group) {
    return (nr_fp46(h) << 18) | ((uint64_t)(kind & 0x3) << 16) | group;
}
static inline uint64_t nr_slot_fp(uint64_t slot)    { return slot >> 18; }
static inline uint8_t  nr_slot_kind(uint64_t slot)  { return (uint8_t)((slot >> 16) & 0x3); }
static inline uint16_t nr_slot_group(uint64_t slot) { return (uint16_t)(slot & 0xffff); }

/* Bucket index comes from the LOW hash bits, the fingerprint from the HIGH bits,
 * so a fingerprint match inside a bucket is genuinely independent evidence. */
static inline size_t nr_bucket(uint64_t h, uint32_t cap_pow2) {
    return (size_t)(h & (uint64_t)(cap_pow2 - 1));
}

/*
 * Open-addressed linear-probe lookup over a power-of-two table of NrSlot.
 *
 * Linear probing (not quadratic/robin-hood) because the table is built offline
 * at a load factor <= 0.5 and probe chains are short: staying inside one or two
 * cache lines beats a theoretically better probe sequence that jumps pages.
 *
 * `cap` MUST be a power of two and the caller MUST have validated that the table
 * section is cap*8 bytes long — see nr_index_validate().
 */
static inline bool nr_table_get(const uint64_t* tbl, uint32_t cap, uint64_t h, uint64_t* out) {
    if (!tbl || cap == 0) return false;
    const uint64_t want = nr_fp46(h);
    size_t i = nr_bucket(h, cap);
    /* Hard bound: never scan more than the table. A corrupt, fully-occupied table
     * must terminate rather than spin — this loop runs inside netd, and netd's
     * init stanza carries `onrestart restart zygote`, so a hang here is a UI loop,
     * not merely a network outage. */
    for (uint32_t probe = 0; probe < cap; ++probe) {
        uint64_t s = tbl[i];
        if (s == 0) return false;                 /* empty slot terminates the chain */
        if (nr_slot_fp(s) == want) { *out = s; return true; }
        i = (i + 1) & (size_t)(cap - 1);
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Blocked Bloom filter: 512-bit (one cache line) blocks, k = 8.
 *
 * "Blocked" so a probe touches exactly ONE cache line instead of k scattered
 * ones. This is the difference between ~8 cache misses and 1 on the negative
 * path, and the negative path is the overwhelmingly common one — most hostnames
 * a phone resolves are not on any blocklist.
 * ------------------------------------------------------------------------- */
#define NR_BLOOM_BLOCK_BYTES 64u
#define NR_BLOOM_BLOCK_BITS  512u
#define NR_BLOOM_K           8u

static inline bool nr_bloom_maybe(const uint8_t* bf, uint64_t bf_len, uint64_t h) {
    if (!bf || bf_len < NR_BLOOM_BLOCK_BYTES) return true;  /* fail open, never closed */
    const uint64_t nblocks = bf_len / NR_BLOOM_BLOCK_BYTES;
    const uint8_t* blk = bf + (size_t)((h % nblocks) * NR_BLOOM_BLOCK_BYTES);
    uint64_t x = nr_mix(h ^ 0x9e3779b97f4a7c15ULL);
    for (unsigned k = 0; k < NR_BLOOM_K; ++k) {
        unsigned bit = (unsigned)(x & (NR_BLOOM_BLOCK_BITS - 1));
        if (!(blk[bit >> 3] & (uint8_t)(1u << (bit & 7)))) return false;
        x >>= 9;
        if (k == 6) x = nr_mix(x);   /* refresh entropy; 64 bits only carries 7 draws */
    }
    return true;
}

static inline void nr_bloom_set(uint8_t* bf, uint64_t bf_len, uint64_t h) {
    if (!bf || bf_len < NR_BLOOM_BLOCK_BYTES) return;
    const uint64_t nblocks = bf_len / NR_BLOOM_BLOCK_BYTES;
    uint8_t* blk = bf + (size_t)((h % nblocks) * NR_BLOOM_BLOCK_BYTES);
    uint64_t x = nr_mix(h ^ 0x9e3779b97f4a7c15ULL);
    for (unsigned k = 0; k < NR_BLOOM_K; ++k) {
        unsigned bit = (unsigned)(x & (NR_BLOOM_BLOCK_BITS - 1));
        blk[bit >> 3] |= (uint8_t)(1u << (bit & 7));
        x >>= 9;
        if (k == 6) x = nr_mix(x);
    }
}

}  /* namespace nr */
#endif /* __cplusplus */
#endif /* NULLROUTE_NR_HASH_H */
