/*
 * Nullroute — suffix collapse.
 *
 * Step 6 of the compile pipeline (§6.5): drop `x.d.com` when `d.com` is already
 * present as a K_SUFFIX rule, because the matcher's suffix walk would have
 * blocked it anyway. This is not a cosmetic tidy-up — every entry removed is
 * eight bytes the resolver does not map and one fewer probe chain to collide
 * with. Measured on the BALANCED corpus: 274,412 -> 226,398 (-17.5%), and on the
 * AGGRESSIVE union 592,006 -> 443,145 (-25.1%).
 *
 * Its own translation unit so it can be reasoned about, and timed, without the
 * serializer around it.
 */
#ifndef NULLROUTE_NR_COLLAPSE_H
#define NULLROUTE_NR_COLLAPSE_H

#include <stddef.h>

#include <vector>

#include "NrParse.h"

namespace nr {

/*
 * Collapses `entries` in place and returns how many were removed.
 *
 * FROZEN SEMANTICS. The 31-check semantic suite asserts the resulting index
 * against a real corpus, and the entry counts it prints are the numbers every
 * size estimate in the spec is derived from. Two rules, and only two:
 *
 *   1. an exact duplicate (same domain AND same kind) is dropped;
 *   2. an entry is dropped when some ancestor — a strict suffix with at least
 *      two labels of its own — is present as K_SUFFIX.
 *
 * Only K_SUFFIX can subsume a descendant: K_WILDCARD_ONLY does not cover the
 * apex and K_EXACT covers only itself, so neither can stand in for a child rule.
 *
 * Note what it deliberately does NOT do: it does not merge two entries for the
 * same domain that carry different kinds. That is the table writer's job
 * (`fill_table` in NrBuilder.cpp applies the SUFFIX > WILDCARD_ONLY > EXACT
 * precedence when two kinds land in one slot), and doing it here as well would
 * change the collapse counts the suite pins.
 */
size_t nr_collapse(std::vector<BuildEntry>* entries);

}  // namespace nr
#endif /* NULLROUTE_NR_COLLAPSE_H */
