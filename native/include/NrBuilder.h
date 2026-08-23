/*
 * Nullroute — index builder.
 *
 * Runs in the APP process (never in netd), driven by build/IndexBuilder.kt via
 * JNI, and by `nrctl build` for development. Produces a staging.<gen>.nrdx that
 * is fsync'd, renamed and only then published by a release-store of
 * NrControl::want_generation.
 *
 * The pipeline is four translation units, not one, and each is independently
 * testable:
 *
 *   NrParse.cpp     line -> normalized record          (§6.5 step 3)
 *   NrCollapse.cpp  suffix collapse + dedupe           (§6.5 step 6)
 *   NrBuilder.cpp   filter + tables + header + seal    (§6.5 step 8)
 *   NrStrings.cpp   the UI-only front-coded rule text  (NR_SEC_STR)
 *
 * NrParse.h and NrCollapse.h are included here rather than left to the caller so
 * that everything which reached nr_parse_line() / nr_collapse() / BuildEntry
 * through this header before the split still compiles unchanged.
 */
#ifndef NULLROUTE_NR_BUILDER_H
#define NULLROUTE_NR_BUILDER_H

#include <stdint.h>
#include <string>
#include <vector>

#include "NrCollapse.h"
#include "NrIndex.h"
#include "NrParse.h"
#include "NrStrings.h"
#include "NrVerdict.h"

namespace nr {

struct BuildStats {
    size_t   parsed_lines   = 0;
    size_t   block_in       = 0;
    size_t   block_collapsed= 0;
    size_t   allow_in       = 0;
    size_t   redirects      = 0;
    uint32_t bt_cap = 0, at_cap = 0, rt_cap = 0;
    uint64_t bytes  = 0;

    /* Two names that hashed the same and disagreed about kind, resolved by the
     * SUFFIX > WILDCARD_ONLY > EXACT precedence in fill_table(). Non-zero is
     * normal — the same domain arrives as `*.d` from a wildcard list and as
     * `0.0.0.0 d` from a hosts list all the time — and it is counted because a
     * sudden change in it means a source changed shape. */
    size_t   kind_conflicts = 0;

    /* NR_SEC_STR sidecar, zero when the caller did not ask for one. */
    uint64_t strings_bytes  = 0;
    uint32_t strings_count  = 0;
};

/*
 * Serialize a complete NRDX blob. Returns false on overflow or bad input.
 *
 * `strings_out` is optional. When present it receives a SECOND, self-contained
 * NRDX whose only populated section is NR_SEC_STR — the front-coded rule text
 * that the Rules and Query screens read. It is a separate artefact on purpose:
 * netd maps `current.nrdx` in full, and embedding 2.6 MB of text the resolver
 * will never look at would grow that mapping for the benefit of a screen the
 * resolver cannot see. Write it as `strings.<gen>.nrdx` (§7.1).
 *
 * Neither blob's `sha256` is filled here: this file deliberately links no
 * hashing library, and nr_compile() in NrCtlCore.cpp seals whatever it writes.
 */
bool nr_build_index(std::vector<BuildEntry> block,
                    std::vector<BuildEntry> allow,
                    std::vector<BuildRedirect> redirects,
                    uint64_t generation, uint64_t built_at_ms, uint64_t hash_seed,
                    std::vector<uint8_t>* out, BuildStats* stats,
                    std::vector<uint8_t>* strings_out = nullptr);

/*
 * Wraps an NR_SEC_STR payload in an NRDX container, for callers that build the
 * strings blob on their own schedule (a rebuild of the UI sidecar alone, after
 * an allow-rule edit that did not change the block set).
 */
bool nr_wrap_strings_blob(const std::vector<uint8_t>& payload,
                          uint64_t generation, uint64_t built_at_ms, uint64_t hash_seed,
                          std::vector<uint8_t>* out);

}  // namespace nr
#endif /* NULLROUTE_NR_BUILDER_H */
