/*
 * Nullroute — the matcher's public surface.
 *
 * nr_evaluate() is THE block decision. The resolver and the app link this exact
 * object, so `nrctl query`, the Rules-screen preview, the build canary and the
 * live filter inside netd can never give different answers.
 */
#ifndef NULLROUTE_NR_QUERY_H
#define NULLROUTE_NR_QUERY_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "NrIndex.h"
#include "NrControl.h"
#include "NrVerdict.h"

#ifdef __cplusplus
namespace nr {

/* Canonicalized name plus the right-to-left suffix hashes, one per label
 * boundary. h[k] covers the last (k+1) labels, so h[D-1] is the whole name. */
struct NrCanon {
    char     name[NR_MAX_NAME + 3];
    size_t   len;
    uint64_t h[NR_MAX_LABELS];
    uint8_t  depth;      /* D — number of usable suffix hashes */
    bool     usable;     /* false => caller must PASS without consulting the index */
};

/* Lowercase, strip the trailing root dot, reject anything a blocklist can never
 * meaningfully describe (IP literals, single-label names, .local/.onion/.arpa/
 * .localhost), and compute the suffix hashes in ONE pass.
 *
 * Never writes to caller memory; `out` is a caller-owned stack struct. */
void nr_canonicalize(const char* name_in, size_t len, uint64_t seed, NrCanon* out);

/* True if the name is a bare IPv4/IPv6 literal. */
bool nr_is_ip_literal(const char* s);

/* True for suffixes a name-layer filter must never touch. NOTE: `.invalid` is
 * deliberately absent — the liveness probes live there. */
bool nr_has_skip_suffix(const char* s, size_t len);

/*
 * The hash the INDEX must store for a rule domain, computed through the exact
 * same canonicalizer the matcher runs at query time.
 *
 * The builder calls this rather than hashing the string itself: the matcher
 * hashes right-to-left and records boundaries before the separator, and any
 * independently-written "equivalent" hash in the builder is one refactor away
 * from silently disagreeing — which produces an index that builds, validates,
 * and matches nothing at all.
 *
 * Returns false if the domain is one the matcher could never match anyway (IP
 * literal, single label, reserved suffix); such an entry must not occupy a slot.
 */
bool nr_rule_hash(const char* domain, size_t len, uint64_t seed,
                  uint64_t* out_hash, uint8_t* out_labels);

/* THE matcher. No allocation, no lock, no I/O, no recursion; every bound hard. */
Verdict nr_evaluate(const NrIndex& ix, const NrControl& ctl,
                    const char* name_in, size_t len, uid_t uid);

/* Index-only evaluation with policy gates already applied — used by the builder's
 * canary and by unit tests, where there is no control page. */
Verdict nr_evaluate_index(const NrIndex& ix, const char* name_in, size_t len);

}  /* namespace nr */
#endif /* __cplusplus */
#endif /* NULLROUTE_NR_QUERY_H */
