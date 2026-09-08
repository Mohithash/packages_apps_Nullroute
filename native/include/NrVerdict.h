/*
 * Nullroute — verdict and rule-kind vocabulary.
 *
 * Shared byte-for-byte between libnetd_resolv (the live filter) and the app
 * (nrctl query, the Rules preview, the canary). If these two ever disagree the
 * product is lying to the user about what it blocks, so there is exactly one
 * definition and both link it.
 */
#ifndef NULLROUTE_NR_VERDICT_H
#define NULLROUTE_NR_VERDICT_H

#include <stdint.h>

#ifdef __cplusplus
namespace nr {

/*
 * How a rule's stored domain relates to the name being queried.
 *
 * `dep` is the label-depth at which the rule matched (1 = TLD, 2 = apex, ...)
 * and `D` is the total label count of the queried name. So for a rule stored as
 * "example.com" (dep 2) against a query "ads.example.com" (D 3): K_SUFFIX
 * applies, K_EXACT does not.
 */
enum RuleKind : uint8_t {
    K_SUFFIX        = 0,  /* example.com     -> apex and every subdomain      */
    K_WILDCARD_ONLY = 1,  /* *.example.com   -> subdomains only, NOT the apex */
    K_EXACT         = 2,  /* =a.example.com  -> that FQDN and nothing else    */
    K_FORCE         = 3,  /* !example.com    -> absolute allow, any depth     */
};

enum VerdictKind : uint8_t {
    V_PASS     = 0,
    V_BLOCK    = 1,
    V_REDIRECT = 2,
};

struct Verdict {
    VerdictKind kind;
    uint8_t     depth;    /* label depth the winning rule matched at, 0 if none */
    uint16_t    group;    /* source-list id, for the log and the UI             */
    uint8_t     family;   /* V_REDIRECT only: AF_INET / AF_INET6                */
    uint8_t     addr[16]; /* V_REDIRECT only                                    */
};

/*
 * Whether a rule of kind `k`, matched at depth `dep`, governs a name with `D`
 * labels. This is the whole of the wildcard semantics — there is no expansion
 * step anywhere in the system, which is the single most important correction to
 * Re-Malwack (its `-w add "*.doubleclick.net"` expands against the list as it
 * exists at that instant and silently stops covering anything added later).
 */
static inline bool kind_applies(RuleKind k, unsigned dep, unsigned D) {
    switch (k) {
        case K_SUFFIX:        return true;
        case K_WILDCARD_ONLY: return dep < D;
        case K_EXACT:         return dep == D;
        case K_FORCE:         return true;
    }
    return false;
}

}  /* namespace nr */
#endif /* __cplusplus */

/* Policy values stored one byte per appId in NrControl::uid_policy. */
#define NR_POLICY_ENFORCE 0
#define NR_POLICY_EXEMPT  1
#define NR_POLICY_STRICT  2

/* NrControl::mode */
#define NR_MODE_ENFORCE 0
#define NR_MODE_PAUSED  1
#define NR_MODE_OFF     2

/* NrControl::response_mode — what a blocked lookup returns.
 *
 * EAI_NONAME is the default: byte-identical to a real NXDOMAIN, so the app makes
 * zero connection attempts. It is NOT a "network unavailable" signal — plenty of
 * apps surface UnknownHostException as a hard error or a retry loop, which is why
 * this is overridable per-app.
 *
 * SINKHOLE is a documented trap, offered as an escape hatch and never a default:
 * Linux connect() to 0.0.0.0 is treated as INADDR_LOOPBACK, so the app connects
 * to itself rather than failing.
 */
#define NR_RESP_NONAME   0
#define NR_RESP_NODATA   1
#define NR_RESP_SINKHOLE 2

#endif /* NULLROUTE_NR_VERDICT_H */
