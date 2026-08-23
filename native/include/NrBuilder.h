/*
 * Nullroute — index builder.
 *
 * Runs in the APP process (never in netd), driven by build/IndexBuilder.kt via
 * JNI, and by `nrctl build` for development. Produces a staging.<gen>.nrdx that
 * is fsync'd, renamed and only then published by a release-store of
 * NrControl::want_generation.
 */
#ifndef NULLROUTE_NR_BUILDER_H
#define NULLROUTE_NR_BUILDER_H

#include <stdint.h>
#include <string>
#include <vector>

#include "NrIndex.h"
#include "NrVerdict.h"

namespace nr {

struct BuildEntry {
    std::string domain;   /* already lowercased, no leading dot, no trailing dot */
    RuleKind    kind;
    uint16_t    group;
};

struct BuildRedirect {
    std::string domain;
    uint8_t     family;
    uint8_t     addr[16];
};

struct BuildStats {
    size_t   parsed_lines   = 0;
    size_t   block_in       = 0;
    size_t   block_collapsed= 0;
    size_t   allow_in       = 0;
    size_t   redirects      = 0;
    uint32_t bt_cap = 0, at_cap = 0, rt_cap = 0;
    uint64_t bytes  = 0;
};

/*
 * Parse one line of a blocklist into `out`.
 *
 * Handles every format we actually fetch, and is deliberately conservative:
 * anything it does not positively recognise is skipped rather than guessed at,
 * because a mis-parsed line becomes a wrongly-blocked domain the user has to
 * discover for themselves.
 *
 *   0.0.0.0 ads.example.com          hosts
 *   127.0.0.1 ads.example.com        hosts
 *   ads.example.com                  bare domain      -> K_SUFFIX
 *   *.example.com                    wildcard         -> K_WILDCARD_ONLY
 *   =ads.example.com                 exact            -> K_EXACT
 *   ||example.com^                   ABP              -> K_SUFFIX
 *   @@||example.com^                 ABP exception    -> allow (returns is_allow)
 *   @example.com / @*.x / @=x        our allow syntax
 *   !example.com                     never-block floor-> K_FORCE
 *   address=/example.com/0.0.0.0     dnsmasq
 *   # comment                        skipped
 */
bool nr_parse_line(const char* line, size_t len,
                   std::string* domain, RuleKind* kind, bool* is_allow);

/* Drop any entry whose blocking is already implied by a broader K_SUFFIX entry
 * in the same set. On the measured BALANCED corpus this is a real reduction
 * (274,412 -> 226,398) and it directly shrinks the table the resolver maps. */
size_t nr_collapse(std::vector<BuildEntry>* entries);

/* Serialize a complete NRDX blob. Returns false on overflow or bad input. */
bool nr_build_index(std::vector<BuildEntry> block,
                    std::vector<BuildEntry> allow,
                    std::vector<BuildRedirect> redirects,
                    uint64_t generation, uint64_t built_at_ms, uint64_t hash_seed,
                    std::vector<uint8_t>* out, BuildStats* stats);

}  // namespace nr
#endif /* NULLROUTE_NR_BUILDER_H */
