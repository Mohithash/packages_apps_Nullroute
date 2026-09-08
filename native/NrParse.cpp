/*
 * Nullroute — implementation of the line parser declared in include/NrParse.h.
 *
 * App-side only. netd never links this; it only ever maps the finished artifact
 * read-only.
 *
 * ONE ENGINE, TWO CONTRACTS. nr_parse_line() is frozen — the semantic suite and
 * every index already on a device were produced by it — while nr_parse_record()
 * is where the §6.5 step 3 corrections live. Rather than keep two parsers in
 * step by review, there is one, and NR_PARSE_COMPAT is the flag set that makes
 * it reproduce the historical behaviour exactly. Every deviation is guarded by a
 * named flag, so the diff between "what we always did" and "what we now do" is
 * visible in the source instead of remembered.
 */
#include "NrParse.h"
#include "NrQuery.h"

#include <arpa/inet.h>
#include <string.h>

namespace nr {

// ---------------------------------------------------------------------------
// Normalisation and validation
// ---------------------------------------------------------------------------

static inline bool valid_label(const char* p, size_t n) {
    if (n == 0 || n > NR_MAX_LABEL) return false;
    if (p[0] == '-' || p[n - 1] == '-') return false;
    for (size_t i = 0; i < n; ++i) {
        const char c = p[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

bool nr_parse_valid_domain(const std::string& s) {
    if (s.empty() || s.size() > NR_MAX_NAME) return false;
    if (nr_is_ip_literal(s.c_str())) return false;
    size_t start = 0, labels = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '.') {
            if (!valid_label(s.data() + start, i - start)) return false;
            start = i + 1;
            ++labels;
        }
    }
    return labels >= 2;
}

void nr_parse_normalize(std::string* s) {
    size_t b = 0, e = s->size();
    while (b < e && (unsigned char)(*s)[b] <= ' ') ++b;
    while (e > b && (unsigned char)(*s)[e - 1] <= ' ') --e;
    *s = s->substr(b, e - b);
    for (auto& c : *s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    while (!s->empty() && s->back() == '.') s->pop_back();
}

bool nr_parse_is_loopback_alias(const std::string& s) {
    return s == "localhost" || s == "localhost.localdomain" ||
           s == "local" || s == "ip6-localhost" || s == "ip6-loopback" ||
           s == "broadcasthost" || s == "ip6-localnet" || s == "ip6-mcastprefix" ||
           s == "ip6-allnodes" || s == "ip6-allrouters" || s == "ip6-allhosts";
}

const char* nr_parse_reject_name(NrParseReject reject) {
    switch (reject) {
        case NR_REJ_NONE:         return "ok";
        case NR_REJ_BLANK:        return "blank";
        case NR_REJ_COMMENT:      return "comment";
        case NR_REJ_COSMETIC:     return "cosmetic";
        case NR_REJ_UNRECOGNISED: return "unrecognised";
        case NR_REJ_BAD_DOMAIN:   return "bad-domain";
        case NR_REJ_LOOPBACK:     return "loopback-alias";
        case NR_REJ_COUNT:        break;
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/* Parses a literal into `out`, returning AF_INET / AF_INET6, or 0. Deliberately
 * not nr_is_ip_literal(): that answers a yes/no question, and the redirect table
 * needs the bytes. */
static uint8_t parse_addr(const std::string& text, uint8_t out[16]) {
    memset(out, 0, 16);
    if (text.empty()) return 0;
    if (inet_pton(AF_INET, text.c_str(), out) == 1) return AF_INET;
    memset(out, 0, 16);
    if (inet_pton(AF_INET6, text.c_str(), out) == 1) return AF_INET6;
    memset(out, 0, 16);
    return 0;
}

/* A "block, with an address that happens to be written down" rather than a real
 * redirect. Every hosts blocklist on earth writes 0.0.0.0 or 127.0.0.1 and means
 * "make this fail", so promoting those to REDIRECT entries would turn 226,000
 * blocks into 226,000 loopback connections — the exact trap NrVerdict.h warns
 * about for NR_RESP_SINKHOLE. */
static bool addr_is_sinkhole(uint8_t family, const uint8_t addr[16]) {
    if (family == AF_INET) {
        const bool zero = addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0;
        const bool loop = addr[0] == 127;
        return zero || loop;
    }
    if (family == AF_INET6) {
        for (unsigned i = 0; i < 15; ++i) if (addr[i]) return false;
        return addr[15] == 0 || addr[15] == 1;      /* :: or ::1 */
    }
    return true;
}

// ---------------------------------------------------------------------------
// Cosmetic (element-hiding) detection
// ---------------------------------------------------------------------------

/*
 * `example.com##.ad-banner`, `example.com#@#.x`, `example.com#?#…`,
 * `example.com#$#…` — ABP cosmetic filters. They hide page elements and say
 * NOTHING about DNS.
 *
 * Getting this wrong is expensive in one specific direction: strip the
 * `#`-comment first and `example.com##.ad` becomes a bare domain, i.e. a block
 * rule for the whole site, invented by us, absent upstream. §10.3.9 is explicit
 * that flattening AdGuard/OISD syntax manufactures false positives.
 *
 * The guard is that a cosmetic marker never has whitespace before it on the
 * line — that is what separates it from a trailing `# comment ## like this`.
 */
static bool is_cosmetic(const std::string& s) {
    for (size_t i = 0; i + 1 < s.size(); ++i) {
        if (s[i] != '#') continue;
        const char n = s[i + 1];
        const bool marker = (n == '#') ||
                            ((n == '@' || n == '?' || n == '$') &&
                             i + 2 < s.size() && s[i + 2] == '#');
        if (!marker) return false;          /* an ordinary comment: stop looking */
        for (size_t j = 0; j < i; ++j) {
            const char c = s[j];
            if (c == ' ' || c == '\t') return false;
        }
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

namespace {

/* Appends one candidate name, applying the `*.` / `=` prefix forms.
 *
 * `may_set_kind` is true only for the first name, which is the only position
 * those prefixes can legally appear in: the second and later fields of a hosts
 * line are bare hostnames, and inventing a per-field kind for them would be
 * semantics nobody wrote down. */
bool push_name(std::string s, bool may_set_kind, NrParsed* out) {
    if (may_set_kind) {
        if (s.rfind("*.", 0) == 0) {
            if (out->kind != K_FORCE) out->kind = K_WILDCARD_ONLY;
            s = s.substr(2);
        } else if (s.rfind("=", 0) == 0) {
            if (out->kind != K_FORCE) out->kind = K_EXACT;
            s = s.substr(1);
        }
    }
    nr_parse_normalize(&s);

    /* A leading "www." is NOT stripped: it is a real label, and the suffix walk
     * already covers it through the apex entry. Stripping it would silently
     * widen every rule that names one host. */
    if (!nr_parse_valid_domain(s)) {
        if (out->reject == NR_REJ_NONE) out->reject = NR_REJ_BAD_DOMAIN;
        return false;
    }
    if (nr_parse_is_loopback_alias(s)) {
        if (out->reject == NR_REJ_NONE) out->reject = NR_REJ_LOOPBACK;
        return false;
    }
    for (unsigned i = 0; i < out->n_names; ++i)
        if (out->names[i] == s) return true;        /* "0.0.0.0 a.com a.com" */
    if (out->n_names >= NR_PARSE_MAX_NAMES) {
        ++out->dropped_names;
        return false;
    }
    out->names[out->n_names++] = std::move(s);
    return true;
}

/* Splits on ASCII whitespace, normalising each field. */
void push_fields(const std::string& text, NrParsed* out) {
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
        size_t j = i;
        while (j < text.size() && text[j] != ' ' && text[j] != '\t') ++j;
        if (j > i) push_name(text.substr(i, j - i), out->n_names == 0, out);
        i = j;
    }
}

}  // namespace

bool nr_parse_record(const char* line, size_t len, uint32_t flags, NrParsed* out) {
    *out = NrParsed{};
    if (!line) { out->reject = NR_REJ_BLANK; return false; }

    std::string s(line, len);

    if (flags & NR_PARSE_COSMETIC) {
        if (is_cosmetic(s)) { out->reject = NR_REJ_COSMETIC; return false; }
    }

    /* Inline comments. `//` as well as `#` because AdAway's hosts.txt and a few
     * dnsmasq conf fragments use it. */
    const size_t hash = s.find('#');
    if (hash != std::string::npos) s.resize(hash);
    const size_t slashes = s.find("//");
    if (slashes != std::string::npos) s.resize(slashes);
    nr_parse_normalize(&s);
    if (s.empty()) {
        out->reject = (hash == 0) ? NR_REJ_COMMENT : NR_REJ_BLANK;
        return false;
    }

    /* ---- dnsmasq ---------------------------------------------------------
     * address=/example.com/0.0.0.0        block (sinkholed)
     * address=/a.com/b.com/1.2.3.4        several names, one address
     * address=/example.com/               NXDOMAIN — a block with no address
     * local=/example.com/                 same meaning, different keyword
     * server=/example.com/9.9.9.9         an UPSTREAM override, NOT a block. */
    bool dnsmasq = false;
    size_t dns_body = 0;
    if (s.rfind("address=/", 0) == 0) {
        dnsmasq = true;
        dns_body = 9;
    } else if ((flags & (NR_PARSE_ALL_NAMES | NR_PARSE_ADDRESS)) &&
               s.rfind("local=/", 0) == 0) {
        dnsmasq = true;
        dns_body = 7;
    }

    if (dnsmasq) {
        const size_t e = s.find('/', dns_body);
        if (e == std::string::npos) { out->reject = NR_REJ_UNRECOGNISED; return false; }

        if (!(flags & (NR_PARSE_ALL_NAMES | NR_PARSE_ADDRESS))) {
            s = s.substr(dns_body, e - dns_body);   /* COMPAT: the first name only */
        } else {
            /* Split the whole body; a trailing field that parses as a literal is
             * the answer, everything else is a name. */
            std::vector<std::string> parts;
            size_t i = dns_body;
            while (i <= s.size()) {
                const size_t slash = s.find('/', i);
                const size_t stop = (slash == std::string::npos) ? s.size() : slash;
                if (stop > i) parts.push_back(s.substr(i, stop - i));
                if (slash == std::string::npos) break;
                i = slash + 1;
            }
            if (parts.empty()) { out->reject = NR_REJ_UNRECOGNISED; return false; }

            if (flags & NR_PARSE_ADDRESS) {
                uint8_t addr[16];
                const uint8_t fam = parse_addr(parts.back(), addr);
                if (fam) {
                    parts.pop_back();
                    out->has_address = true;
                    out->family      = fam;
                    out->sinkhole    = addr_is_sinkhole(fam, addr);
                    memcpy(out->addr, addr, 16);
                }
            }
            if (parts.empty()) { out->reject = NR_REJ_UNRECOGNISED; return false; }
            for (size_t p = 0; p < parts.size(); ++p) {
                push_name(parts[p], p == 0, out);
                if (!(flags & NR_PARSE_ALL_NAMES)) break;
            }
            if (!out->ok() && out->reject == NR_REJ_NONE) out->reject = NR_REJ_BAD_DOMAIN;
            return out->ok();
        }
    }

    /* ---- ABP -------------------------------------------------------------
     * The exception form must be tested before the plain one, or `@@||d^` reads
     * as a block for `@@d`. */
    if (s.rfind("@@", 0) == 0) { out->is_allow = true; s = s.substr(2); }

    if (s.rfind("||", 0) == 0) {
        s = s.substr(2);
        /* `^` ends the hostname; `$` starts the option list (`$third-party`,
         * `$important`, …). Both are the end of the part we can evaluate. */
        const size_t stop = s.find_first_of("^$");
        if (stop != std::string::npos) s.resize(stop);
        out->kind = K_SUFFIX;
    } else if (s.rfind("@", 0) == 0) {
        out->is_allow = true;
        s = s.substr(1);
    }

    if (s.rfind("!", 0) == 0) {
        out->is_allow = true;
        out->kind     = K_FORCE;
        s = s.substr(1);
    }

    /* ---- hosts -----------------------------------------------------------
     * "<ip> <name> [more names...]". A line with whitespace whose first field is
     * NOT an address is a shape we refuse to guess at. */
    const size_t sp = s.find_first_of(" \t");
    if (sp != std::string::npos) {
        const std::string first = s.substr(0, sp);
        if (!nr_is_ip_literal(first.c_str())) { out->reject = NR_REJ_UNRECOGNISED; return false; }

        if (flags & NR_PARSE_ADDRESS) {
            uint8_t addr[16];
            const uint8_t fam = parse_addr(first, addr);
            if (fam) {
                out->has_address = true;
                out->family      = fam;
                out->sinkhole    = addr_is_sinkhole(fam, addr);
                memcpy(out->addr, addr, 16);
            }
        }

        std::string rest = s.substr(sp + 1);
        nr_parse_normalize(&rest);
        if (flags & NR_PARSE_ALL_NAMES) {
            push_fields(rest, out);
            if (!out->ok() && out->reject == NR_REJ_NONE) out->reject = NR_REJ_BAD_DOMAIN;
            return out->ok();
        }
        const size_t sp2 = rest.find_first_of(" \t");
        if (sp2 != std::string::npos) rest.resize(sp2);
        s = rest;
    }

    push_name(s, true, out);
    if (!out->ok() && out->reject == NR_REJ_NONE) out->reject = NR_REJ_BAD_DOMAIN;
    return out->ok();
}

bool nr_parse_line(const char* line, size_t len,
                   std::string* domain, RuleKind* kind, bool* is_allow) {
    NrParsed p;
    if (!nr_parse_record(line, len, NR_PARSE_COMPAT, &p)) {
        *is_allow = false;
        *kind     = K_SUFFIX;
        return false;
    }
    *domain   = p.names[0];
    *kind     = p.kind;
    *is_allow = p.is_allow;
    return true;
}

}  // namespace nr
