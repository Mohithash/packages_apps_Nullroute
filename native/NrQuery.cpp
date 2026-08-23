/*
 * Nullroute — nr_evaluate(): THE block decision.
 *
 * Linked into libnetd_resolv AND into the app's libnrjni, so the live filter,
 * `nrctl query`, the Rules-screen preview and the build canary are the same code
 * path. Nothing here allocates, locks, blocks, recurses or makes a syscall.
 *
 * Precedence, normative:
 *   1. K_FORCE (`!domain`) beats everything at any depth — the never-block floor
 *      and the captive-portal set.
 *   2. A REDIRECT on the exact FQDN beats block and allow.
 *   3. Otherwise more specific wins: block example.com + allow cdn.example.com
 *      => cdn.example.com passes, ads.example.com blocks.
 *   4. Ties go to allow.
 */
#include "NrQuery.h"

#include <string.h>

namespace nr {

/* Whether a rule at label-depth `dep` is even worth probing, given what the
 * builder recorded about the corpus. On a deep hostname this skips 60-70% of
 * probes: 96% of blocklist entries are <= 3 labels and BALANCED has none deeper
 * than 10, so most of the walk is provably fruitless. */
static inline bool depth_plausible(const NrHeader* h, unsigned dep) {
    if (h->max_labels && dep > h->max_labels) return false;
    if (h->min_labels && dep < h->min_labels) return false;
    const unsigned bit = dep < 15u ? dep : 15u;
    if (h->label_mask && !(h->label_mask & (1u << bit))) return false;
    return true;
}

/* The index-only core: gates and canonicalization already done. */
static Verdict evaluate_canon(const NrIndex& ix, const NrCanon& c) {
    Verdict v{};
    v.kind = V_PASS;

    const NrHeader* h = ix.hdr;
    const unsigned  D = c.depth;

    /* ---- redirect: exact FQDN only, one small L2-resident page ------------ */
    if (h->n_redirect) {
        NrRedir r;
        if (nr_redir_get(ix, c.h[D - 1], &r)) {
            v.kind   = V_REDIRECT;
            v.depth  = (uint8_t)D;
            v.family = r.family;
            memcpy(v.addr, r.addr, 16);
            return v;
        }
    }

    /* ---- PASS A: allow walk, most specific first --------------------------
     * Run in full BEFORE any block probe. An interleaved single walk would
     * short-circuit on the first block and could never see a shallower K_FORCE.
     * The allow structures total ~72 KB and stay L2-resident, so a complete
     * allow pass costs ~20 ns — correct semantics for very nearly free. */
    unsigned depth_allow = 0;
    if (h->n_allow) {
        for (int d = (int)D - 1; d >= 0; --d) {
            const unsigned dep = (unsigned)d + 1;
            if (!depth_plausible(h, dep)) continue;
            if (!nr_bloom_maybe(ix.allow_filter, h->sec[NR_SEC_AF].len, c.h[d])) continue;
            NrSlot s;
            if (!nr_table_get(ix.allow_table, h->at_cap, c.h[d], &s)) continue;
            const RuleKind k = (RuleKind)nr_slot_kind(s);
            if (!kind_applies(k, dep, D)) continue;
            if (k == K_FORCE) return v;          /* absolute: beats any block */
            depth_allow = dep;
            break;                                /* deepest allow wins */
        }
    }
    if (depth_allow == D) return v;               /* nothing can out-specify it */

    /* ---- PASS B: block walk, most specific first, short-circuits ---------- */
    if (h->n_block) {
        for (int d = (int)D - 1; d >= 0; --d) {
            const unsigned dep = (unsigned)d + 1;
            if (dep <= depth_allow) break;        /* nothing shallower can win */
            if (!depth_plausible(h, dep)) continue;
            if (!nr_bloom_maybe(ix.block_filter, h->sec[NR_SEC_BF].len, c.h[d])) continue;
            NrSlot s;
            if (!nr_table_get(ix.block_table, h->bt_cap, c.h[d], &s)) continue;
            const RuleKind k = (RuleKind)nr_slot_kind(s);
            if (!kind_applies(k, dep, D)) continue;
            v.kind  = V_BLOCK;
            v.depth = (uint8_t)dep;
            v.group = nr_slot_group(s);
            return v;
        }
    }
    return v;
}

Verdict nr_evaluate_index(const NrIndex& ix, const char* name_in, size_t len) {
    Verdict v{};
    v.kind = V_PASS;
    if (!ix.hdr) return v;

    NrCanon c;
    nr_canonicalize(name_in, len, ix.hdr->hash_seed, &c);
    if (!c.usable) return v;
    return evaluate_canon(ix, c);
}

Verdict nr_evaluate(const NrIndex& ix, const NrControl& ctl,
                    const char* name_in, size_t len, uid_t uid) {
    Verdict v{};
    v.kind = V_PASS;

    /* ---- gates: each is one predictable, well-tended branch --------------- */
    if (ctl.mode != NR_MODE_ENFORCE) return v;
    if (!ix.hdr) return v;

    /* Per-app policy. The uid is real here — netd reads it from SO_PEERCRED on
     * the dnsproxyd socket — which is what makes per-app rules correct at this
     * layer and merely approximate in any VpnService design. */
    const uint32_t app_id = (uint32_t)(uid % NR_AID_USER_OFFSET);
    if (app_id < NR_UID_POLICY_LEN && ctl.uid_policy[app_id] == NR_POLICY_EXEMPT) return v;

    NrCanon c;
    nr_canonicalize(name_in, len, ix.hdr->hash_seed, &c);
    if (!c.usable) return v;

    return evaluate_canon(ix, c);
}

}  // namespace nr
