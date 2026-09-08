/*
 * Nullroute — the front-coded rule-text blob (`NR_SEC_STR`).
 *
 * ============================================================================
 *  netd NEVER MAPS THIS. It is section 5 of the NRDX layout and it is emitted
 *  into a SEPARATE artefact, `strings.<gen>.nrdx`, precisely so that the file
 *  the resolver maps stays 4.6 MB at BALANCED rather than 7.2 MB. The sidecar
 *  carries an ordinary NrHeader with only sec[NR_SEC_STR] populated, so it
 *  validates, seals and versions through exactly the same code as the index.
 * ============================================================================
 *
 * WHAT IT IS FOR. The index stores 46-bit fingerprints, not text, which is what
 * makes a lookup 206 ns and the tables cache-resident — but it also means the
 * index cannot answer "how many rules does `*.doubleclick.net` cover?". That
 * question is the whole of the Rules screen: §6.2's correction to Re-Malwack is
 * that a wildcard allow is STORED as a pattern instead of being expanded, and
 * the honest way to present a pattern the user cannot see the effect of is to
 * show the count at the moment they type it.
 *
 * WHY REVERSED-LABEL ORDER. Written as `com.example.ads` and sorted, the rules
 * under a suffix become CONTIGUOUS. `stringsRangeForSuffix("d.net")` is
 * therefore a handful of binary searches and the counts are subtractions —
 * O(log n + k), never a scan of 226,000 strings on the UI thread.
 *
 * THE RANGE IS TWO SPANS, NOT ONE, and the reason is a real domain that a
 * one-span version got wrong. Sorted reversed-label keys around
 * `doubleclick.net` read:
 *
 *     net.doubleclick          <- the apex
 *     net.doubleclick-cn       <- doubleclick-cn.net: A DIFFERENT DOMAIN
 *     net.doubleclick.ads      <- a real subdomain
 *     net.doubleclickfoo       <- doubleclickfoo.net: also unrelated
 *
 * `'-'` is 0x2D and `'.'` is 0x2E, so the hyphenated neighbour sorts *between*
 * the apex and its own subdomains. A single `[lower(rev), lower(rev + '/'))`
 * span therefore silently counts `doubleclick-cn.net` as a subdomain of
 * `doubleclick.net`, and the Rules screen tells the user their pattern covers a
 * domain it does not. So the apex span and the subdomain span are found
 * separately: `[lower(rev), lower(rev+0x01))` and
 * `[lower(rev + '.'), lower(rev + '/'))`.
 *
 * WHY FRONT CODING RATHER THAN A DAFSA. Measured, not assumed: a DAFSA over the
 * BALANCED corpus was actually built — 940,676 nodes / 1,184,412 edges ≈ 2.61 MB,
 * no better than plain front coding, and with an ~18-step dependent-pointer walk
 * per lookup. Domain labels are too high-entropy for the Chromium-PSL intuition
 * to hold (§7.2).
 */
#ifndef NULLROUTE_NR_STRINGS_H
#define NULLROUTE_NR_STRINGS_H

#include <stdint.h>
#include <stddef.h>

#include <string>
#include <vector>

#include "NrIndex.h"
#include "NrParse.h"
#include "NrVerdict.h"

#define NR_STR_MAGIC   0x5453524Eu   /* "NRST" little-endian */
#define NR_STR_VERSION 1u

/* Entries between restart points. 16 keeps the block index at ~1/16 of an entry
 * per rule (56 KB for BALANCED) while bounding the linear walk after a binary
 * search to fifteen varint decodes — under a microsecond, and the walk is over
 * bytes that are already in the same page. */
#define NR_STR_RESTART_DEFAULT 16u

namespace nr {

/*
 * Header of the NR_SEC_STR payload. Every offset is relative to the start of
 * the section, so the blob is position-independent and can be copied out of the
 * sidecar and into a future combined file without rewriting it.
 */
struct NrStrHeader {
    /*  0 */ uint32_t magic;
    /*  4 */ uint16_t version;
    /*  6 */ uint16_t restart;      /* entries per restart block                 */
    /*  8 */ uint32_t count;        /* total rules                               */
    /* 12 */ uint32_t blocks;       /* ceil(count / restart)                     */
    /* 16 */ uint32_t index_off;    /* uint32_t[blocks], byte offset into data   */
    /* 20 */ uint32_t index_len;
    /* 24 */ uint32_t meta_off;     /* NrStrMeta[count]; len 0 == absent         */
    /* 28 */ uint32_t meta_len;
    /* 32 */ uint32_t data_off;     /* the front-coded stream                    */
    /* 36 */ uint32_t data_len;
    /* 40 */ uint32_t longest;      /* longest key, so a reader can size a buffer*/
    /* 44 */ uint32_t n_block;      /* how many of `count` came from block rules */
    /* 48 */ uint32_t n_allow;
    /* 52 */ uint32_t _rsv[3];
};
static_assert(sizeof(NrStrHeader) == 64, "NrStrHeader is ABI");

/* Per-rule side data. Four bytes: enough to name the source list and the kind,
 * which is what turns "12 rules match" into "12 rules match, 9 of them from
 * HaGeZi Multi Pro". */
struct NrStrMeta {
    uint16_t group;
    uint8_t  kind;     /* RuleKind                                     */
    uint8_t  flags;    /* bit 0: this is an ALLOW rule, not a block    */
};
static_assert(sizeof(NrStrMeta) == 4, "NrStrMeta is ABI");

#define NR_STR_FLAG_ALLOW 0x01u

/* A validated, mapped strings blob. Pointers are into the caller's mapping and
 * are valid for its lifetime only. */
struct NrStrings {
    const uint8_t*     base = nullptr;
    size_t             size = 0;
    const NrStrHeader* hdr  = nullptr;
    const uint8_t*     data = nullptr;
    size_t             data_len = 0;
    const uint8_t*     index = nullptr;   /* uint32_t[], read via memcpy */
    const uint8_t*     meta  = nullptr;   /* NrStrMeta[], or nullptr     */
};

/*
 * Two half-open spans: the rows whose name IS the base, and the rows strictly
 * below it. See the file comment for why one span cannot express this.
 */
struct NrStrRange {
    uint32_t apex_begin = 0, apex_end = 0;
    uint32_t sub_begin  = 0, sub_end  = 0;

    uint32_t apex()       const { return apex_end > apex_begin ? apex_end - apex_begin : 0u; }
    uint32_t subdomains() const { return sub_end  > sub_begin  ? sub_end  - sub_begin  : 0u; }
    uint32_t count()      const { return apex() + subdomains(); }
    bool     empty()      const { return count() == 0; }
};

/*
 * What a pattern would match, in the shape §6.2's Rules screen needs.
 *
 * Reported separately because the three rule kinds answer three different
 * questions about the same range: a suffix rule covers apex + subdomains, a
 * `*.` rule covers subdomains only, and `=` covers the apex only. Collapsing
 * them to one number would make `@*.example.com` claim credit for the apex it
 * deliberately does not cover.
 */
struct NrStrPreview {
    uint32_t apex       = 0;   /* rules that are exactly the base name      */
    uint32_t subdomains = 0;   /* rules strictly below it                   */
    uint32_t blocks     = 0;   /* of the above, how many are block rules    */
    uint32_t allows     = 0;
    uint32_t total() const { return apex + subdomains; }

    /* The number to show for a rule of `kind` written against this base. */
    uint32_t matched(RuleKind kind) const {
        switch (kind) {
            case K_SUFFIX:
            case K_FORCE:         return total();
            case K_WILDCARD_ONLY: return subdomains;
            case K_EXACT:         return apex;
        }
        return 0;
    }
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/* Validates and binds a section payload. Returns false — never a partial
 * binding — if anything is out of bounds; the caller then shows "unavailable"
 * rather than a count it cannot stand behind. */
bool nr_strings_open(const uint8_t* section, size_t len, NrStrings* out);

/* Convenience for a mapped NRDX (the sidecar, or an index that embedded it). */
bool nr_strings_open_index(const NrIndex& ix, NrStrings* out);

inline uint32_t nr_strings_count(const NrStrings& s) { return s.hdr ? s.hdr->count : 0u; }

/* Sequential decoder. Front coding means entry i is only reachable through the
 * restart point above it, so random access seeks to a block and walks; keep a
 * cursor when you want more than one neighbour. */
struct NrStrCursor {
    const NrStrings* owner = nullptr;
    uint32_t         index = 0;      /* entry the cursor is ON            */
    size_t           next  = 0;      /* byte offset of the NEXT entry     */
    std::string      key;            /* reversed-label form               */
    bool             valid = false;
};

bool nr_strings_seek(const NrStrings& s, uint32_t i, NrStrCursor* out);
bool nr_strings_next(NrStrCursor* c);

/* Single-entry accessors. Each is a seek, so a loop should use a cursor. */
bool nr_strings_key(const NrStrings& s, uint32_t i, std::string* out_reversed);
bool nr_strings_rule(const NrStrings& s, uint32_t i, std::string* out_forward);
bool nr_strings_meta(const NrStrings& s, uint32_t i, NrStrMeta* out);

/*
 * THE query this file exists for: the contiguous range of rules at or below
 * `base`, in O(log n + k). `base` is written the normal way round
 * ("doubleclick.net"); the reversal is ours to do.
 */
NrStrRange nr_strings_range_for_suffix(const NrStrings& s, const char* base, size_t len);

/* Walks the range once and classifies. Bounded by `limit` entries scanned (0 =
 * unbounded) so a pattern like "com" cannot stall the UI thread; when the limit
 * truncates, `apex + subdomains` is less than the range and the caller should
 * present it as "at least N". */
NrStrPreview nr_strings_preview(const NrStrings& s, const char* base, size_t len,
                                uint32_t limit = 0);

/* Reversed-label transform. "ads.example.com" -> "com.example.ads", and its own
 * inverse. */
void nr_reverse_labels(const char* s, size_t n, std::string* out);

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

struct NrStringsStats {
    uint32_t count   = 0;
    uint32_t blocks  = 0;
    uint32_t longest = 0;
    uint64_t bytes   = 0;
    uint64_t raw     = 0;   /* the same text uncompressed, for the ratio */
};

/*
 * Builds the NR_SEC_STR payload from the rules that went into an index.
 *
 * Takes its inputs BY VALUE: it sorts them, and the caller's vectors are dead
 * by this point in the build anyway. Allow rules are merged into the same
 * ordering with NR_STR_FLAG_ALLOW set, because the Rules screen has to be able
 * to say "this domain is already allowed by a seed" as readily as "12 lists
 * block it".
 */
bool nr_strings_build(std::vector<BuildEntry> block, std::vector<BuildEntry> allow,
                      uint16_t restart, std::vector<uint8_t>* out,
                      NrStringsStats* stats);

}  // namespace nr
#endif /* NULLROUTE_NR_STRINGS_H */
