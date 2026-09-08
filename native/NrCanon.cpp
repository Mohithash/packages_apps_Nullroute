/*
 * Nullroute — hostname canonicalization and the single right-to-left hash pass.
 *
 * Runs inside netd on every DNS lookup. No allocation, no syscall, no recursion.
 * Every loop has a hard bound, because netd's init stanza carries
 * `onrestart restart zygote`: a hang or crash here is a UI loop, not merely a
 * network outage.
 */
#include "NrQuery.h"

#include <arpa/inet.h>
#include <string.h>

namespace nr {

bool nr_is_ip_literal(const char* s) {
    unsigned char buf[16];
    if (inet_pton(AF_INET, s, buf) == 1) return true;
    if (inet_pton(AF_INET6, s, buf) == 1) return true;
    return false;
}

/* Suffixes a name-layer filter must never touch.
 *
 * .local   — mDNS; blocking it breaks Chromecast, printers, local discovery.
 * .onion   — Tor; never resolved through the system resolver anyway.
 * .arpa    — reverse DNS; a blocklist entry can never sensibly describe one.
 * .localhost — reserved to loopback by RFC 6761.
 *
 * `.invalid` is deliberately NOT here: the dual liveness probes
 * (idx-probe.nullroute.invalid / hosts-probe.nullroute.invalid) must reach the
 * index, and they are the only signal that can prove the hook is live.
 */
bool nr_has_skip_suffix(const char* s, size_t len) {
    static const char* kSkip[] = { ".local", ".onion", ".arpa", ".localhost" };
    for (size_t i = 0; i < sizeof(kSkip) / sizeof(kSkip[0]); ++i) {
        const size_t n = strlen(kSkip[i]);
        if (len >= n && memcmp(s + len - n, kSkip[i], n) == 0) return true;
    }
    return false;
}

void nr_canonicalize(const char* name_in, size_t len, uint64_t seed, NrCanon* out) {
    out->usable = false;
    out->depth  = 0;
    out->len    = 0;

    if (!name_in || len == 0 || len > NR_MAX_NAME) return;

    /* Copy onto our own stack buffer. Never lowercase in place: `name_in` is the
     * caller's memory, and in the resolver that is the live request buffer. */
    char*  n = out->name;
    size_t L = 0;
    size_t first_dot = (size_t)-1;                  /* index in `n`, not in name_in */
    size_t label_len = 0;

    for (size_t i = 0; i < len; ++i) {
        char c = name_in[i];
        if (c == '\0') break;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c == '.') {
            if (label_len > NR_MAX_LABEL) return;   /* malformed; PASS */
            label_len = 0;
            if (first_dot == (size_t)-1) first_dot = L;
        } else {
            ++label_len;
        }
        n[L++] = c;
    }
    if (label_len > NR_MAX_LABEL) return;

    while (L > 0 && n[L - 1] == '.') --L;           /* strip trailing root dot(s) */
    /*
     * Single label => PASS, and the test has to be made AFTER the strip. A
     * trailing root dot is not a label separator: "localhost." and "com." are
     * one label, and a plain "did we see any dot" flag says otherwise — which
     * would make L1 authoritative for exactly the names NrFilter's H4 loopback
     * guard documents it as never speaking for, and would let a depth-1 (TLD)
     * rule swallow "localhost.". A surviving dot is a real separator precisely
     * because n[L-1] is now known not to be one.
     */
    if (L == 0 || first_dot >= L) return;           /* "localhost", "com.", NetBIOS */
    n[L] = '\0';
    out->len = L;

    if (nr_is_ip_literal(n)) return;
    if (nr_has_skip_suffix(n, L)) return;

    /* One right-to-left FNV-1a pass, recording a mixed hash at every label
     * boundary. For "ads.doubleclick.net" this yields
     *   h[0] = "net", h[1] = "doubleclick.net", h[2] = "ads.doubleclick.net".
     *
     * The boundary hash is taken BEFORE the separator is absorbed, so h[k] is
     * the hash of the suffix itself with no leading dot — which is exactly the
     * string the builder stored. Recording it after would hash ".net" instead of
     * "net" and nothing would ever match. */
    uint64_t acc = seed ? seed : NR_FNV_OFFSET;
    uint8_t  D   = 0;
    for (size_t i = L; i-- > 0;) {
        /* HARD BOUND — fuzz-critical. Past it we stop RECORDING but keep
         * ABSORBING, so the final entry below is still the hash of the whole
         * name. Breaking out instead left h[D-1] holding a 16-label SUFFIX while
         * every caller reads it as the exact FQDN — nr_redir_get() most of all,
         * which is exact-FQDN-only and would then answer a 20-label query with
         * some other name's redirect address. The loop stays bounded by L, which
         * is already capped at NR_MAX_NAME. */
        if (n[i] == '.' && D < NR_MAX_LABELS - 1) out->h[D++] = nr_mix(acc);
        acc = (acc ^ (uint8_t)n[i]) * NR_FNV_PRIME;
    }
    out->h[D++] = nr_mix(acc);                      /* the whole name */

    out->depth  = D;
    out->usable = true;
}

bool nr_rule_hash(const char* domain, size_t len, uint64_t seed,
                  uint64_t* out_hash, uint8_t* out_labels) {
    NrCanon c;
    nr_canonicalize(domain, len, seed, &c);
    if (!c.usable || c.depth == 0) return false;
    *out_hash   = c.h[c.depth - 1];   /* the whole name */
    *out_labels = c.depth;
    return true;
}

}  // namespace nr
