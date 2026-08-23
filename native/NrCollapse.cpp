/*
 * Nullroute — implementation of the suffix collapse declared in
 * include/NrCollapse.h.
 *
 * App-side only. Runs once per update over a few hundred thousand entries, so it
 * may allocate; what it may not do is hold a second full copy of the corpus at
 * peak, which is why the kept vector is reserved once and entries are moved
 * rather than copied out of the input.
 */
#include "NrCollapse.h"

#include <string>
#include <unordered_set>

namespace nr {

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

        /* Covered by a broader K_SUFFIX ancestor?
         *
         * The walk stops at the last two labels: a "parent" with no dot of its
         * own is a TLD, and a rule that blocked an entire TLD would be a
         * catastrophe we must never infer from someone else's list. */
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

}  // namespace nr
