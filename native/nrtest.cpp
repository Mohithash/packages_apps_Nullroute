/*
 * Nullroute — host/device test harness for the format, builder and matcher.
 *
 * Build:  clang++ -std=c++17 -O2 -I include native/NrCanon.cpp native/NrQuery.cpp \
 *                 native/NrBuilder.cpp native/nrtest.cpp -o nrtest
 * Run:    ./nrtest <blocklist-file> [more-files...]
 *
 * Exists because the matcher is the one component whose bugs are invisible: a
 * wrong verdict does not crash, it just quietly blocks someone's bank or quietly
 * lets ads through. Every semantic in the spec's precedence table is asserted
 * here against the real corpus.
 */
#include "NrBuilder.h"
#include "NrQuery.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace nr;

static int g_fail = 0, g_pass = 0;

static const char* vname(VerdictKind k) {
    switch (k) {
        case V_PASS: return "PASS";
        case V_BLOCK: return "BLOCK";
        case V_REDIRECT: return "REDIRECT";
    }
    return "?";
}

static void check(const NrIndex& ix, const char* host, VerdictKind want, const char* why) {
    Verdict v = nr_evaluate_index(ix, host, strlen(host));
    if (v.kind == want) {
        ++g_pass;
    } else {
        ++g_fail;
        printf("  FAIL  %-44s got %-8s want %-8s   (%s)\n",
               host, vname(v.kind), vname(want), why);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: nrtest <list> [list...]\n"); return 2; }

    std::vector<BuildEntry> block, allow;
    std::vector<BuildRedirect> redir;
    size_t lines = 0, parsed = 0;

    for (int a = 1; a < argc; ++a) {
        std::ifstream f(argv[a]);
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[a]); return 2; }
        std::string ln;
        while (std::getline(f, ln)) {
            ++lines;
            std::string d; RuleKind k; bool is_allow;
            if (!nr_parse_line(ln.data(), ln.size(), &d, &k, &is_allow)) continue;
            ++parsed;
            (is_allow ? allow : block).push_back(BuildEntry{d, k, (uint16_t)a});
        }
    }
    printf("read %zu lines, parsed %zu entries (%zu block, %zu allow)\n",
           lines, parsed, block.size(), allow.size());

    /* The corpus-only prefix of `block`. The synthetic rules appended below
     * deliberately include entries that are allowed or force-allowed, so the
     * round-trip sampler must not draw from them or it reports its own fixtures
     * as misses. */
    const size_t corpus_n = block.size();

    /* ---- synthetic rules exercising every precedence branch --------------- */
    const std::string kApex = "nrtest-apex.example";       /* K_SUFFIX  */
    const std::string kWild = "nrtest-wild.example";       /* K_WILDCARD_ONLY */
    const std::string kExact= "a.nrtest-exact.example";    /* K_EXACT   */
    const std::string kCarve= "nrtest-carve.example";      /* blocked, one child allowed */
    const std::string kForce= "nrtest-force.example";      /* blocked, but FORCE-allowed */
    const std::string kTie  = "nrtest-tie.example";        /* blocked and allowed at same depth */

    block.push_back({kApex,  K_SUFFIX,        900});
    block.push_back({kWild,  K_WILDCARD_ONLY, 901});
    block.push_back({kExact, K_EXACT,         902});
    block.push_back({kCarve, K_SUFFIX,        903});
    block.push_back({kForce, K_SUFFIX,        904});
    block.push_back({kTie,   K_SUFFIX,        905});

    allow.push_back({"cdn." + kCarve, K_SUFFIX, 1});
    allow.push_back({kForce,          K_FORCE,  1});
    allow.push_back({kTie,            K_SUFFIX, 1});

    redir.push_back(BuildRedirect{"idx-probe.nullroute.invalid", 2 /*AF_INET*/, {127,0,0,7}});

    BuildStats st{};
    std::vector<uint8_t> blob;
    auto t0 = std::chrono::steady_clock::now();
    if (!nr_build_index(block, allow, redir, 1, 1700000000000ULL, 0, &blob, &st)) {
        fprintf(stderr, "BUILD FAILED\n"); return 1;
    }
    auto t1 = std::chrono::steady_clock::now();

    printf("built: %zu block (collapsed %zu), %zu allow, %u bt_cap, %.2f MB, %lld ms\n",
           (size_t)st.block_in - st.block_collapsed, st.block_collapsed,
           (size_t)st.allow_in, st.bt_cap, st.bytes / 1048576.0,
           (long long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    NrIndex ix{};
    if (!nr_index_validate(blob.data(), blob.size(), &ix)) {
        fprintf(stderr, "VALIDATE FAILED\n"); return 1;
    }
    printf("validated: n_block=%u n_allow=%u n_redirect=%u labels=[%u..%u] mask=0x%04x\n\n",
           ix.hdr->n_block, ix.hdr->n_allow, ix.hdr->n_redirect,
           ix.hdr->min_labels, ix.hdr->max_labels, ix.hdr->label_mask);

    /* ---- semantics ------------------------------------------------------- */
    printf("semantics:\n");
    check(ix, kApex.c_str(),                V_BLOCK, "K_SUFFIX blocks the apex");
    check(ix, ("x." + kApex).c_str(),       V_BLOCK, "K_SUFFIX blocks subdomains");
    check(ix, ("a.b.c." + kApex).c_str(),   V_BLOCK, "K_SUFFIX blocks deep subdomains");

    check(ix, kWild.c_str(),                V_PASS,  "K_WILDCARD_ONLY must NOT block the apex");
    check(ix, ("x." + kWild).c_str(),       V_BLOCK, "K_WILDCARD_ONLY blocks subdomains");

    check(ix, kExact.c_str(),               V_BLOCK, "K_EXACT blocks that FQDN");
    check(ix, ("x." + kExact).c_str(),      V_PASS,  "K_EXACT must NOT block subdomains");
    check(ix, "nrtest-exact.example",       V_PASS,  "K_EXACT must NOT block the parent");

    check(ix, kCarve.c_str(),               V_BLOCK, "carve-out: apex still blocked");
    check(ix, ("cdn." + kCarve).c_str(),    V_PASS,  "more specific allow wins");
    check(ix, ("deep.cdn." + kCarve).c_str(), V_PASS, "allow covers its own subtree");
    check(ix, ("ads." + kCarve).c_str(),    V_BLOCK, "sibling of an allow stays blocked");

    check(ix, kForce.c_str(),               V_PASS,  "K_FORCE beats a block at equal depth");
    check(ix, ("x." + kForce).c_str(),      V_PASS,  "K_FORCE beats a block at any depth");

    check(ix, kTie.c_str(),                 V_PASS,  "ties go to allow");

    check(ix, "idx-probe.nullroute.invalid", V_REDIRECT, "liveness probe resolves via redirect");

    printf("\nnon-domains and reserved suffixes (must all PASS):\n");
    const char* skips[] = {
        "localhost", "8.8.8.8", "2001:4860:4860::8888", "printer.local",
        "facebookcorewwwi.onion", "1.0.0.127.in-addr.arpa", "foo.localhost",
        "", ".", "..", "a..b", "-bad.example.com",
    };
    for (const char* s : skips) check(ix, s, V_PASS, "must never be blocked");

    /* A hostname with more labels than NR_MAX_LABELS must terminate, not spin. */
    {
        std::string deep;
        for (int i = 0; i < 40; ++i) deep += "a.";
        deep += kApex;
        check(ix, deep.c_str(), V_BLOCK, "over-deep name still resolves its suffix");
        std::string huge(300, 'a');
        huge += ".example.com";
        check(ix, huge.c_str(), V_PASS, "over-long name is rejected, not read past");
    }

    /* ---- real corpus round-trip ------------------------------------------ */
    printf("\nreal corpus round-trip:\n");
    std::mt19937_64 rng(12345);
    size_t miss = 0, sampled = 0;
    if (corpus_n) {
        for (int i = 0; i < 20000; ++i) {
            const BuildEntry& e = block[rng() % corpus_n];
            if (e.kind != K_SUFFIX) continue;
            ++sampled;
            Verdict v = nr_evaluate_index(ix, e.domain.c_str(), e.domain.size());
            if (v.kind != V_BLOCK) {
                if (++miss <= 5) printf("  MISS  %s\n", e.domain.c_str());
            }
            const std::string sub = "a.b." + e.domain;
            Verdict v2 = nr_evaluate_index(ix, sub.c_str(), sub.size());
            if (v2.kind != V_BLOCK) {
                if (++miss <= 5) printf("  MISS(sub)  %s\n", sub.c_str());
            }
        }
    }
    printf("  sampled %zu suffix entries, %zu misses\n", sampled, miss);
    if (miss) ++g_fail; else ++g_pass;

    const char* clean[] = {
        "google.com", "www.google.com", "github.com", "www.bbc.co.uk",
        "wikipedia.org", "api.whatsapp.com", "signal.org", "mail.proton.me",
    };
    size_t fp = 0;
    for (const char* c : clean) {
        Verdict v = nr_evaluate_index(ix, c, strlen(c));
        if (v.kind != V_PASS) { printf("  FALSE POSITIVE  %s (group %u)\n", c, v.group); ++fp; }
    }
    printf("  %zu false positives on %zu known-good hosts\n", fp, sizeof(clean)/sizeof(*clean));

    /* ---- throughput ------------------------------------------------------ */
    std::vector<std::string> probe;
    probe.reserve(200000);
    for (int i = 0; i < 100000; ++i) {
        const BuildEntry& e = block[rng() % (corpus_n ? corpus_n : block.size())];
        probe.push_back("www." + e.domain);
        probe.push_back("cdn" + std::to_string(i) + ".notblocked-" + std::to_string(i) + ".example");
    }
    auto b0 = std::chrono::steady_clock::now();
    size_t blocked = 0;
    for (const auto& s : probe)
        if (nr_evaluate_index(ix, s.c_str(), s.size()).kind == V_BLOCK) ++blocked;
    auto b1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration_cast<std::chrono::nanoseconds>(b1 - b0).count()
                      / (double)probe.size();
    printf("\nthroughput: %.0f ns/lookup over %zu lookups (%zu blocked)\n",
           ns, probe.size(), blocked);

    printf("\n%s  (%d passed, %d failed)\n", g_fail ? "FAILED" : "ALL OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
