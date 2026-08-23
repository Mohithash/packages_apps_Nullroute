/*
 * Nullroute — blocklist line parsing, and the normalized record every later
 * build stage consumes.
 *
 * App-side only; netd never links this. It was carved out of NrBuilder.cpp
 * because three separate consumers need it — the builder, `nr_compile()` in
 * NrCtlCore.cpp, and the importers — and a parser that lives inside a serializer
 * is a parser nobody can test on its own.
 *
 * THE HARD RULE HERE IS CONSERVATISM. A line this file does not positively
 * recognise is rejected, never guessed at. A mis-parsed line becomes a wrongly
 * blocked domain that the user has to discover for themselves, from a symptom
 * ("the app just spins") that points nowhere near DNS.
 */
#ifndef NULLROUTE_NR_PARSE_H
#define NULLROUTE_NR_PARSE_H

#include <stdint.h>
#include <stddef.h>

#include <string>
#include <vector>

#include "NrIndex.h"
#include "NrVerdict.h"

namespace nr {

/*
 * One rule, normalized. `domain` is already lowercased, punycode-as-written, no
 * leading dot, no trailing dot, and has passed the label regex.
 *
 * These two structs live here rather than in NrBuilder.h because they are the
 * PARSER's output, not the serializer's input — the sort, the collapse, the
 * strings blob and the builder all take them, and only one of those is the
 * builder. NrBuilder.h includes this header, so every existing caller that
 * reaches them through NrBuilder.h keeps compiling unchanged.
 */
struct BuildEntry {
    std::string domain;
    RuleKind    kind;
    uint16_t    group;
};

struct BuildRedirect {
    std::string domain;
    uint8_t     family;
    uint8_t     addr[16];
};

/* A hosts line legally carries many names after the address. Eight is well past
 * anything the lists we consume actually use, and the bound is what stops a
 * malformed 4 KB line from turning into 400 rules. */
#define NR_PARSE_MAX_NAMES 8u

/*
 * What the extended parser is allowed to do beyond the historical behaviour.
 *
 * NR_PARSE_COMPAT reproduces nr_parse_line() exactly, byte for byte, because
 * the semantic suite and every already-built index depend on it. The other bits
 * are the corrections §6.5 step 3 asks for, and they are opt-in so that turning
 * one on is a decision somebody made rather than a side effect of a refactor.
 */
enum NrParseFlag : uint32_t {
    NR_PARSE_COMPAT = 0u,

    /* Take EVERY field after the address on a hosts line, not just the first.
     * Re-Malwack drops everything after $2; so did our own first cut. */
    NR_PARSE_ALL_NAMES = 1u << 0,

    /* Recognise ABP cosmetic rules (`##`, `#@#`, `#?#`, `#$#`) and reject them.
     * Without this, `example.com##.ad` has its `#`-comment stripped and becomes
     * a block rule for example.com — a manufactured false positive that does not
     * exist upstream, from a syntax whose entire purpose is to NOT block. */
    NR_PARSE_COSMETIC = 1u << 1,

    /* Carry the address a line named: dnsmasq `address=/d/1.2.3.4` and a hosts
     * line whose IP is not a sinkhole. The caller decides whether that becomes a
     * REDIRECT; the parser only stops throwing the fact away. */
    NR_PARSE_ADDRESS = 1u << 2,

    NR_PARSE_FULL = NR_PARSE_ALL_NAMES | NR_PARSE_COSMETIC | NR_PARSE_ADDRESS,
};

/* Why a line produced no rule. Counted per source and surfaced in the UI: a
 * source whose reject reason suddenly becomes UNRECOGNISED en masse has changed
 * format upstream, and that is worth telling the user before their protection
 * quietly halves. */
enum NrParseReject : uint8_t {
    NR_REJ_NONE = 0,
    NR_REJ_BLANK,          /* empty, or nothing left after comment stripping   */
    NR_REJ_COMMENT,        /* a pure comment line                              */
    NR_REJ_COSMETIC,       /* ABP element hiding — deliberately not a DNS rule */
    NR_REJ_UNRECOGNISED,   /* a shape we refuse to guess at                    */
    NR_REJ_BAD_DOMAIN,     /* failed the label rules, or is an IP literal      */
    NR_REJ_LOOPBACK,       /* localhost & friends: indexing them blackholes lo */
    NR_REJ_COUNT,
};

struct NrParsed {
    uint8_t       n_names = 0;
    std::string   names[NR_PARSE_MAX_NAMES];
    RuleKind      kind     = K_SUFFIX;
    bool          is_allow = false;

    /* NR_PARSE_ADDRESS only. `family` is AF_INET / AF_INET6. */
    bool          has_address = false;
    bool          sinkhole    = false;   /* 0.0.0.0 / 127.0.0.1 / :: / ::1     */
    uint8_t       family      = 0;
    uint8_t       addr[16]    = {};

    NrParseReject reject       = NR_REJ_NONE;
    uint8_t       dropped_names = 0;     /* names past NR_PARSE_MAX_NAMES      */

    bool ok() const { return n_names > 0; }
};

/*
 * Parse one line of a blocklist into `out`.
 *
 * FROZEN. NrBuilder.cpp, NrCtlCore.cpp's nr_compile() and native/nrtest.cpp's
 * 31-check semantic suite all call this, and every index ever built on a device
 * was built through it. It is a thin wrapper over nr_parse_record() in
 * NR_PARSE_COMPAT mode and takes the first name only.
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

/* The full surface. Returns false when nothing was parsed; `out->reject` says
 * why, and is meaningful on both outcomes (a line can yield names AND report
 * dropped ones). */
bool nr_parse_record(const char* line, size_t len, uint32_t flags, NrParsed* out);

/* One word for a rejection, for per-source statistics and the Diagnostics
 * bundle. Never null. */
const char* nr_parse_reject_name(NrParseReject reject);

/*
 * A domain we are willing to put in the index. Rejects IP literals, single-label
 * names and anything with an invalid label — a list that smuggles in "0.0.0.0"
 * as a *domain* would otherwise become an entry that matches nothing and costs a
 * table slot forever.
 */
bool nr_parse_valid_domain(const std::string& s);

/* Localhost aliases sit at the top of every hosts file. Indexing them would
 * blackhole loopback, which breaks far more than it fixes. */
bool nr_parse_is_loopback_alias(const std::string& s);

/* Lowercase, trim ASCII whitespace and control bytes from both ends, drop
 * trailing root dots. Exposed because the importers need exactly this
 * normalisation and a second copy of it is a second set of edge cases. */
void nr_parse_normalize(std::string* s);

}  // namespace nr
#endif /* NULLROUTE_NR_PARSE_H */
