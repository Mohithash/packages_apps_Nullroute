/*
 * Nullroute — libFuzzer target: arbitrary bytes as the INDEX FILE. [MERGE GATE]
 *
 *   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address -I native/include \
 *           native/NrCanon.cpp native/NrQuery.cpp \
 *           native/fuzz/nr_index_fuzzer.cpp -o nr_index_fuzzer
 *   ./nr_index_fuzzer -max_len=65536 corpus/
 *
 * THIS IS THE ONE THAT MATTERS. The index is written by the app from lists
 * downloaded off the internet, and it is read INSIDE netd, whose death restarts
 * zygote (§10.1). Between those two facts sits nr_index_validate(), which is the
 * only thing standing between a corrupt or hostile 4 MB file and a device that
 * boot-loops. Every offset, every length and every capacity in that header is
 * attacker-influenced, and the tables behind them are pure attacker bytes: the
 * validator bounds them, and then the matcher trusts them completely.
 *
 * Two modes per input, because they find different bugs:
 *
 *   A. The raw input as the whole file. Finds header-parsing bugs. The magic is
 *      forced, because a byte-oriented fuzzer will never guess four specific
 *      bytes and would otherwise spend its entire budget proving that garbage is
 *      rejected — the cheap half of the problem.
 *
 *   B. A known-good index with the input applied as a sparse patch. This is the
 *      bit-flip case §10.1 names explicitly, and it is what reaches the probe
 *      loops, the Bloom geometry and nr_redir_get() with a table that validates
 *      but is full of nonsense.
 *
 * The buffer handed to the validator is always a heap allocation of EXACTLY the
 * claimed size, so ASAN's redzones turn any read past the end of the "mapping"
 * into a crash — which is precisely the class of bug that would otherwise be an
 * unreproducible netd SIGSEGV in the field.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include "NrControl.h"
#include "NrHash.h"
#include "NrIndex.h"
#include "NrQuery.h"

using namespace nr;

namespace {

/* Hostnames covering the shapes the walk treats differently: an exact fixture
 * hit, a deep subdomain, a two-label apex, the redirect probe, and a name with
 * more labels than NR_MAX_LABELS so the truncation path is always exercised. */
const char* const kProbes[] = {
    "fuzz-apex.example",
    "a.b.c.d.e.fuzz-apex.example",
    "example.com",
    "idx-probe.nullroute.invalid",
    "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.deep.example",
};

size_t align_up(size_t v) { return (v + NR_PAGE - 1) & ~(size_t)(NR_PAGE - 1); }

/* A structurally valid index for mode B. Deliberately small and hand-built: this
 * target links only libnrfilter, the same set the resolver links, so nothing here
 * depends on the builder being correct. */
const std::vector<uint8_t>& good_index() {
    static std::vector<uint8_t>* blob = [] {
        const uint64_t seed = NR_FNV_OFFSET;
        const uint32_t bt_cap = 256, at_cap = 256, rt_cap = 32;

        std::vector<uint8_t>  bf(512, 0), af(512, 0);
        std::vector<uint64_t> bt(bt_cap, 0), at(at_cap, 0);
        std::vector<NrRedir>  rt(rt_cap);
        memset(rt.data(), 0, rt.size() * sizeof(NrRedir));

        struct R { const char* d; RuleKind k; };
        static const R kB[] = {{"fuzz-apex.example", K_SUFFIX},
                               {"deep.example", K_SUFFIX}};
        static const R kA[] = {{"ok.fuzz-apex.example", K_SUFFIX}};

        uint16_t mask = 0;
        uint8_t  mn = 0, mx = 0;
        auto add = [&](const R* set, size_t n, std::vector<uint64_t>& tbl, uint32_t cap,
                       std::vector<uint8_t>& bloom, uint16_t group) {
            for (size_t i = 0; i < n; ++i) {
                uint64_t h;
                uint8_t  labels;
                if (!nr_rule_hash(set[i].d, strlen(set[i].d), seed, &h, &labels)) abort();
                size_t s = nr_bucket(h, cap);
                while (tbl[s] != 0) s = (s + 1) & (size_t)(cap - 1);
                tbl[s] = nr_slot_pack(h, (uint8_t)set[i].k, group);
                nr_bloom_set(bloom.data(), bloom.size(), h);
                mask |= (uint16_t)(1u << (labels < 15 ? labels : 15));
                if (mn == 0 || labels < mn) mn = labels;
                if (labels > mx) mx = labels;
            }
        };
        add(kB, sizeof(kB) / sizeof(kB[0]), bt, bt_cap, bf, 31);
        add(kA, sizeof(kA) / sizeof(kA[0]), at, at_cap, af, 32);

        {
            uint64_t h;
            uint8_t  labels;
            const char* p = "idx-probe.nullroute.invalid";
            if (!nr_rule_hash(p, strlen(p), seed, &h, &labels)) abort();
            const size_t s = nr_bucket(h, rt_cap);
            rt[s].fp      = nr_fp46(h);
            rt[s].family  = 2 /* AF_INET */;
            rt[s].addr[0] = 127;
            rt[s].addr[3] = 7;
            mask |= (uint16_t)(1u << labels);
            if (labels > mx) mx = labels;
        }

        size_t off = NR_PAGE;
        struct { uint64_t off, len; } sec[NR_SEC_COUNT] = {};
        auto place = [&](unsigned idx, size_t len) {
            sec[idx].off = off;
            sec[idx].len = len;
            off = align_up(off + len);
        };
        place(NR_SEC_BF, bf.size());
        place(NR_SEC_BT, bt.size() * sizeof(uint64_t));
        place(NR_SEC_AF, af.size());
        place(NR_SEC_AT, at.size() * sizeof(uint64_t));
        place(NR_SEC_RT, rt.size() * sizeof(NrRedir));

        auto* out = new std::vector<uint8_t>(off, 0);
        memcpy(out->data() + sec[NR_SEC_BF].off, bf.data(), bf.size());
        memcpy(out->data() + sec[NR_SEC_BT].off, bt.data(), bt.size() * sizeof(uint64_t));
        memcpy(out->data() + sec[NR_SEC_AF].off, af.data(), af.size());
        memcpy(out->data() + sec[NR_SEC_AT].off, at.data(), at.size() * sizeof(uint64_t));
        memcpy(out->data() + sec[NR_SEC_RT].off, rt.data(), rt.size() * sizeof(NrRedir));

        NrHeader h{};
        h.magic       = NR_MAGIC;
        h.fmt_version = (uint16_t)NR_FMT_VERSION;
        h.generation  = 1;
        h.n_block     = (uint32_t)(sizeof(kB) / sizeof(kB[0]));
        h.n_allow     = (uint32_t)(sizeof(kA) / sizeof(kA[0]));
        h.n_redirect  = 1;
        h.bt_cap      = bt_cap;
        h.at_cap      = at_cap;
        h.rt_cap      = rt_cap;
        h.label_mask  = mask;
        h.min_labels  = mn;
        h.max_labels  = mx;
        h.hash_seed   = seed;
        for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
            h.sec[i].off = sec[i].off;
            h.sec[i].len = sec[i].len;
        }
        memcpy(out->data(), &h, sizeof(h));

        NrIndex check{};
        if (!nr_index_validate(out->data(), out->size(), &check)) abort();
        return out;
    }();
    return *blob;
}

const NrControl& control() {
    static NrControl* c = [] {
        auto* p = (NrControl*)calloc(1, sizeof(NrControl));
        if (!p) abort();
        p->mode = NR_MODE_ENFORCE;
        return p;
    }();
    return *c;
}

/*
 * Validate, then use. A false from the validator means the matcher must never be
 * handed this mapping — which is exactly the contract the resolver follows, so
 * calling nr_evaluate() anyway here would be testing a path that cannot happen
 * and hiding the one that can.
 */
void exercise(const uint8_t* base, size_t size) {
    NrIndex ix{};
    if (!nr_index_validate(base, size, &ix)) return;

    for (const char* host : kProbes) {
        nr_evaluate(ix, control(), host, strlen(host), 10123);
        nr_evaluate_index(ix, host, strlen(host));
    }
    /* Reached directly as well: with n_redirect zero but a populated rt_cap, the
     * matcher never calls it, yet a future caller might. */
    NrRedir r;
    nr_redir_get(ix, 0x0123456789abcdefULL, &r);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* ---- mode A: the input IS the file ---------------------------------- */
    if (size >= sizeof(uint32_t)) {
        std::vector<uint8_t> raw(data, data + size);
        const uint32_t magic = NR_MAGIC;
        memcpy(raw.data(), &magic, sizeof(magic));
        exercise(raw.data(), raw.size());
    }

    /* ---- mode B: a valid index, patched by the input --------------------- */
    const std::vector<uint8_t>& good = good_index();
    std::vector<uint8_t> patched(good);
    for (size_t i = 0; i + 2 < size; i += 3) {
        /* (u16 offset, u8 value), offset taken modulo the file so every byte of
         * input is a usable mutation rather than a mostly-ignored one. */
        const size_t off = (((size_t)data[i] << 8) | data[i + 1]) % patched.size();
        patched[off] = data[i + 2];
    }
    exercise(patched.data(), patched.size());

    /* Truncation is its own failure mode: a half-written index left by a killed
     * update job is a real file the resolver can be asked to map. */
    if (size) {
        const size_t cut = 1 + (size_t)data[size - 1] * (patched.size() / 256 + 1);
        if (cut < patched.size()) {
            std::vector<uint8_t> shortened(patched.begin(), patched.begin() + (long)cut);
            exercise(shortened.data(), shortened.size());
        }
    }
    return 0;
}
