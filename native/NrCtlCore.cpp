/*
 * Nullroute — implementation of the shared app-side helpers declared in
 * include/NrCtl.h.
 *
 * FILENAME: this is NrCtlCore.cpp, not NrCtl.cpp, because `native/NrCtl.cpp` and
 * `native/nrctl.cpp` differ only in case and therefore cannot coexist in a
 * checkout on a case-insensitive filesystem (macOS, Windows). Soong does not
 * care; a developer whose checkout silently loses one of the two very much does.
 * The header keeps the name NrCtl.h — nothing collides with it.
 *
 * Never linked into netd. Every function here either reads a file the app owns or
 * writes one; the matcher, the hash and the builder are called, never
 * reimplemented.
 */
#include "NrCtl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#include <algorithm>

namespace nr {

/* AID_MISC — the gid /data/misc uses, and the supplementary group the app gets
 * via rom/nullroute-gid.xml (§8.7). Hardcoded rather than pulled from
 * <private/android_filesystem_config.h> so this file compiles on a host. */
static const gid_t kAidMisc = 9998;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

static void set_err(std::string* err, const char* what, int e) {
    if (!err) return;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s: %s (errno=%d)", what, strerror(e), e);
    err->assign(buf);
}

void nr_format_ms(uint64_t epoch_ms, char* out, size_t n) {
    if (!out || n == 0) return;
    if (epoch_ms == 0) { snprintf(out, n, "never"); return; }
    const time_t s = (time_t)(epoch_ms / 1000);
    struct tm tmv;
    if (!gmtime_r(&s, &tmv)) { snprintf(out, n, "?"); return; }
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

const char* nr_group_builtin_name(uint16_t group) {
    switch (group) {
        case NR_GROUP_UNKNOWN:    return "unattributed";
        case NR_GROUP_BASELINE:   return "built-in baseline";
        case NR_GROUP_USER_DENY:  return "your deny list";
        case NR_GROUP_USER_ALLOW: return "your allow list";
        case NR_GROUP_REDIRECT:   return "your redirects";
        case NR_GROUP_FLOOR:      return "never-block floor";
        case NR_GROUP_CARVEOUT:   return "compatibility carve-out";
        case NR_GROUP_HOTFIX:     return "hotfix allow feed";
        case NR_GROUP_PROBE:      return "liveness probe";
        default:                  return nullptr;   /* a fetched source */
    }
}

const char* nr_mode_name(uint8_t mode) {
    switch (mode) {
        case NR_MODE_ENFORCE: return "ENFORCE";
        case NR_MODE_PAUSED:  return "PAUSED";
        case NR_MODE_OFF:     return "OFF";
        default:              return "UNKNOWN";
    }
}

const char* nr_resp_name(uint8_t resp) {
    switch (resp) {
        case NR_RESP_NONAME:   return "EAI_NONAME";
        case NR_RESP_NODATA:   return "EAI_NODATA";
        case NR_RESP_SINKHOLE: return "SINKHOLE";
        default:               return "UNKNOWN";
    }
}

const char* nr_kind_name(uint8_t kind) {
    switch (kind) {
        case K_SUFFIX:        return "suffix";
        case K_WILDCARD_ONLY: return "wildcard-only";
        case K_EXACT:         return "exact";
        case K_FORCE:         return "force-allow";
        default:              return "?";
    }
}

const char* nr_verdict_name(uint8_t verdict) {
    switch (verdict) {
        case V_PASS:     return "PASS";
        case V_BLOCK:    return "BLOCK";
        case V_REDIRECT: return "REDIRECT";
        default:         return "?";
    }
}

bool nr_mode_parse(const char* s, uint8_t* out_mode) {
    if (!s || !*s) return false;
    if (!strcmp(s, "0") || !strcasecmp(s, "enforce") || !strcasecmp(s, "on") ||
        !strcasecmp(s, "enforcing")) { *out_mode = NR_MODE_ENFORCE; return true; }
    if (!strcmp(s, "1") || !strcasecmp(s, "paused") || !strcasecmp(s, "pause")) {
        *out_mode = NR_MODE_PAUSED; return true;
    }
    if (!strcmp(s, "2") || !strcasecmp(s, "off") || !strcasecmp(s, "disabled")) {
        *out_mode = NR_MODE_OFF; return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

std::string nr_prop_get(const char* name, const char* dflt) {
#if defined(__ANDROID__)
    char v[PROP_VALUE_MAX];
    v[0] = '\0';
    if (__system_property_get(name, v) > 0) return std::string(v);
#else
    (void)name;
#endif
    return std::string(dflt ? dflt : "");
}

int64_t nr_prop_get_i64(const char* name, int64_t dflt) {
    const std::string v = nr_prop_get(name, "");
    if (v.empty()) return dflt;
    errno = 0;
    char* end = nullptr;
    const long long r = strtoll(v.c_str(), &end, 10);
    if (errno != 0 || end == v.c_str()) return dflt;
    return (int64_t)r;
}

bool nr_prop_set(const char* name, const char* value) {
#if defined(__ANDROID__)
    return __system_property_set(name, value) == 0;
#else
    (void)name; (void)value;
    return false;
#endif
}

bool nr_prop_set_i64(const char* name, int64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", (long long)value);
    return nr_prop_set(name, buf);
}

// ---------------------------------------------------------------------------
// Mappings
// ---------------------------------------------------------------------------

bool nr_map_file_ro(const char* path, NrMapRO* out, std::string* err) {
    *out = NrMapRO{};
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { set_err(err, "open", errno); return false; }

    struct stat st;
    if (fstat(fd, &st) != 0) { set_err(err, "fstat", errno); close(fd); return false; }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
        if (err) *err = "not a regular non-empty file";
        close(fd);
        return false;
    }
    /* Same ceiling the resolver applies (NrMap.h): past this it is a corrupt or
     * hostile artefact, not an index, and mapping it only wastes address space. */
    if ((uint64_t)st.st_size > NR_MAP_MAX_BYTES) {
        if (err) *err = "file is larger than the 64 MiB index ceiling";
        close(fd);
        return false;
    }

    const size_t size = (size_t)st.st_size;
    void* p = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        /* The classic silent failure: open() succeeds and mmap() is refused by
         * SELinux for want of the separate `map` permission (§10.7). Naming the
         * errno here is what makes that visible instead of "filtering is off". */
        set_err(err, "mmap", errno);
        close(fd);
        return false;
    }
    out->base = (const uint8_t*)p;
    out->size = size;
    out->fd   = fd;
    return true;
}

void nr_unmap_file(NrMapRO* m) {
    if (!m) return;
    if (m->base) munmap((void*)m->base, m->size);
    if (m->fd >= 0) close(m->fd);
    *m = NrMapRO{};
}

bool nr_index_open_ro(const char* path, NrIndexRO* out, std::string* err) {
    if (!nr_map_file_ro(path, &out->map, err)) return false;
    if (!nr_index_validate(out->map.base, out->map.size, &out->ix)) {
        if (err) {
            /* nr_index_fault_field() is advisory and strictly downstream of the
             * validator that already said no — it only names the first field that
             * looks wrong, so the failure is diagnosable instead of opaque. */
            const char* field = nr_index_fault_field(out->map.base, out->map.size);
            *err = std::string("index failed structural validation: ") +
                   (field ? field : "unknown field");
        }
        nr_unmap_file(&out->map);
        out->ix = NrIndex{};
        return false;
    }
    return true;
}

void nr_index_close_ro(NrIndexRO* out) {
    if (!out) return;
    nr_unmap_file(&out->map);
    out->ix = NrIndex{};
}

// ---------------------------------------------------------------------------
// control.bin
// ---------------------------------------------------------------------------

bool nr_ctl_open(const char* path, bool writable, NrCtlMap* out, std::string* err) {
    *out = NrCtlMap{};
    const int fd = open(path, (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC);
    if (fd < 0) { set_err(err, "open", errno); return false; }

    struct stat st;
    if (fstat(fd, &st) != 0) { set_err(err, "fstat", errno); close(fd); return false; }
    if ((uint64_t)st.st_size < (uint64_t)NR_CONTROL_BYTES) {
        /* Short file: the seeder either has not run or was interrupted. Refuse
         * rather than mapping a partial page — a MAP_SHARED region past EOF
         * faults with SIGBUS on touch, and this code runs inside the app. */
        if (err) *err = "control.bin is short; nullroute_seed has not run";
        close(fd);
        return false;
    }
    void* p = mmap(nullptr, NR_CONTROL_BYTES, PROT_READ | (writable ? PROT_WRITE : 0),
                   MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { set_err(err, "mmap", errno); close(fd); return false; }

    out->p        = (NrControl*)p;
    out->fd       = fd;
    out->size     = NR_CONTROL_BYTES;
    out->writable = writable;
    return true;
}

void nr_ctl_close(NrCtlMap* m) {
    if (!m) return;
    if (m->p) munmap(m->p, m->size);
    if (m->fd >= 0) close(m->fd);
    *m = NrCtlMap{};
}

void nr_ctl_read(const NrCtlMap& m, NrCtlSnapshot* out) {
    memset(out, 0, sizeof(*out));
    if (!m.p) return;
    const NrControl* c = m.p;
    /* Field-by-field acquire loads: netd writes cache lines 1-2 while we read,
     * and a struct copy could tear across a counter update. Nothing here is
     * worth a lock on the resolver's side. */
#define NR_LOAD(f) __atomic_load_n(&c->f, __ATOMIC_ACQUIRE)
    out->want_generation   = NR_LOAD(want_generation);
    out->mode              = NR_LOAD(mode);
    out->response_mode     = NR_LOAD(response_mode);
    out->log_level         = NR_LOAD(log_level);
    out->cname_uncloak     = NR_LOAD(cname_uncloak);
    out->config_epoch      = NR_LOAD(config_epoch);
    out->mapped_generation = NR_LOAD(mapped_generation);
    out->q_total           = NR_LOAD(q_total);
    out->q_blocked         = NR_LOAD(q_blocked);
    out->q_passed          = NR_LOAD(q_passed);
    out->last_map_ms       = NR_LOAD(last_map_ms);
    out->filter_abi        = NR_LOAD(filter_abi);
    out->map_errors        = NR_LOAD(map_errors);
    out->ring_drops        = NR_LOAD(ring_drops);
    out->fault_count       = NR_LOAD(fault_count);
#undef NR_LOAD
}

bool nr_ctl_set_mode(NrCtlMap* m, uint8_t mode) {
    if (!m || !m->p || !m->writable) return false;
    __atomic_store_n(&m->p->mode, mode, __ATOMIC_RELEASE);
    return true;
}

bool nr_ctl_set_want_generation(NrCtlMap* m, uint64_t gen) {
    if (!m || !m->p || !m->writable) return false;
    __atomic_store_n(&m->p->want_generation, gen, __ATOMIC_RELEASE);
    return true;
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

namespace {

struct Sha256 {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   n;
};

const uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

void sha256_block(Sha256* s, const uint8_t* p) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (unsigned i = 16; i < 64; ++i) {
        const uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], hh = s->h[7];
    for (unsigned i = 0; i < 64; ++i) {
        const uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + kK[i] + w[i];
        const uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += hh;
}

void sha256_init(Sha256* s) {
    s->h[0] = 0x6a09e667u; s->h[1] = 0xbb67ae85u; s->h[2] = 0x3c6ef372u;
    s->h[3] = 0xa54ff53au; s->h[4] = 0x510e527fu; s->h[5] = 0x9b05688cu;
    s->h[6] = 0x1f83d9abu; s->h[7] = 0x5be0cd19u;
    s->bits = 0;
    s->n    = 0;
}

void sha256_update(Sha256* s, const uint8_t* p, size_t n) {
    s->bits += (uint64_t)n * 8;
    while (n) {
        const size_t take = std::min(n, sizeof(s->buf) - s->n);
        memcpy(s->buf + s->n, p, take);
        s->n += take;
        p    += take;
        n    -= take;
        if (s->n == sizeof(s->buf)) { sha256_block(s, s->buf); s->n = 0; }
    }
}

void sha256_final(Sha256* s, uint8_t out[32]) {
    /* The padding is not part of the message, so the length counter is restored
     * after every padding byte rather than being allowed to drift. */
    const uint64_t bits = s->bits;
    const uint8_t pad = 0x80;
    sha256_update(s, &pad, 1);
    s->bits = bits;
    const uint8_t zero = 0;
    while (s->n != 56) { sha256_update(s, &zero, 1); s->bits = bits; }
    uint8_t len[8];
    for (unsigned i = 0; i < 8; ++i) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(s, len, 8);
    for (unsigned i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (uint8_t)(s->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(s->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(s->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(s->h[i]);
    }
}

}  // namespace

void nr_sha256(const void* data, size_t len, uint8_t out[32]) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, (const uint8_t*)data, len);
    sha256_final(&s, out);
}

void nr_sha256_hex(const uint8_t digest[32], char out[65]) {
    static const char* hex = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) {
        out[i * 2]     = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0xf];
    }
    out[64] = '\0';
}

bool nr_sha256_selftest(void) {
    uint8_t d[32];
    char hex[65];
    nr_sha256("", 0, d);
    nr_sha256_hex(d, hex);
    if (strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0)
        return false;
    nr_sha256("abc", 3, d);
    nr_sha256_hex(d, hex);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0)
        return false;
    /* One million 'a': exercises the buffered path and the 64-bit length field,
     * which is where hand-written SHA-256 implementations usually go wrong. */
    std::string big(1000000, 'a');
    nr_sha256(big.data(), big.size(), d);
    nr_sha256_hex(d, hex);
    return strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0;
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

bool nr_read_file(const char* path, std::string* out, std::string* err) {
    out->clear();
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { set_err(err, "open", errno); return false; }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0)
        out->reserve((size_t)st.st_size);
    char buf[65536];
    for (;;) {
        const ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            set_err(err, "read", errno);
            close(fd);
            out->clear();
            return false;
        }
        out->append(buf, (size_t)n);
    }
    close(fd);
    return true;
}

static bool fsync_dir_of(const char* path) {
    std::string dir(path);
    const size_t slash = dir.rfind('/');
    dir = (slash == std::string::npos) ? std::string(".") : dir.substr(0, slash ? slash : 1);
    const int dfd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return false;
    const bool ok = fsync(dfd) == 0;
    close(dfd);
    return ok;
}

bool nr_write_file_atomic(const char* path, const void* data, size_t len, std::string* err) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

    const int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0) { set_err(err, "open staging", errno); return false; }

    /* Group `misc` so the other side of the pair can read it: the seeder writes
     * as system and the app reads as its own uid plus supplementary gid misc, and
     * vice versa. Best effort — the DAC is a backstop, SELinux is the gate. */
    (void)fchown(fd, (uid_t)-1, kAidMisc);
    (void)fchmod(fd, 0640);

    const uint8_t* p = (const uint8_t*)data;
    size_t left = len;
    while (left) {
        const ssize_t n = write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            set_err(err, "write", errno);
            close(fd);
            unlink(tmp);
            return false;
        }
        p    += n;
        left -= (size_t)n;
    }
    if (fsync(fd) != 0) {
        set_err(err, "fsync", errno);
        close(fd);
        unlink(tmp);
        return false;
    }
    close(fd);

    if (rename(tmp, path) != 0) {
        set_err(err, "rename", errno);
        unlink(tmp);
        return false;
    }
    /* Without the directory fsync the rename can be lost across a power cut,
     * leaving a name that points at nothing — which the resolver would see as a
     * map failure on the next boot. */
    fsync_dir_of(path);
    return true;
}

// ---------------------------------------------------------------------------
// Explanation
// ---------------------------------------------------------------------------

/* Mirrors depth_plausible() in NrQuery.cpp. It is duplicated deliberately and
 * only ever used to ANNOTATE the trace: a step that shows a table hit while
 * marked implausible is a label_mask bug, and this is how it becomes visible.
 * The verdict itself always comes from nr_evaluate_index(). */
static bool trace_plausible(const NrHeader* h, unsigned dep) {
    if (h->max_labels && dep > h->max_labels) return false;
    if (h->min_labels && dep < h->min_labels) return false;
    const unsigned bit = dep < 15u ? dep : 15u;
    if (h->label_mask && !(h->label_mask & (1u << bit))) return false;
    return true;
}

void nr_explain(const NrIndex& ix, const char* host, size_t len, NrExplain* out) {
    memset(out, 0, sizeof(*out));
    if (!ix.hdr || !host) return;

    NrCanon c;
    nr_canonicalize(host, len, ix.hdr->hash_seed, &c);

    /* nr_canonicalize fills `name`/`len` before its later rejections (IP literal,
     * reserved suffix), so the canonical form is worth reporting even when the
     * name is unusable — "we did not look at this, and here is what we think you
     * typed" is a much better answer than an empty one. */
    if (c.len > 0 && c.len <= NR_MAX_NAME) {
        memcpy(out->canon, c.name, c.len);
        out->canon[c.len] = '\0';
    }
    out->verdict = nr_evaluate_index(ix, host, len);
    if (!c.usable || c.depth == 0) return;

    out->usable = true;
    out->depth  = c.depth;

    /* Offset of the suffix carrying the last `d` labels, for d = 1..D. Computed
     * right-to-left from the canonical text so it lines up with the hash order:
     * off[k] is the string whose hash is c.h[k]. */
    uint16_t off[NR_MAX_LABELS];
    {
        unsigned d = 0;
        for (size_t i = c.len; i-- > 0 && d < c.depth;) {
            if (c.name[i] == '.') off[d++] = (uint16_t)(i + 1);
        }
        while (d < c.depth) off[d++] = 0;   /* the whole name */
    }

    const NrHeader* h = ix.hdr;
    unsigned n = 0;
    for (int di = (int)c.depth - 1; di >= 0 && n < NR_MAX_LABELS; --di, ++n) {
        NrExplainStep* s = &out->steps[n];
        s->depth      = (uint8_t)(di + 1);
        s->suffix_off = off[di];
        s->plausible  = trace_plausible(h, (unsigned)di + 1);

        NrSlot slot;
        if (h->n_block && nr_table_get(ix.block_table, h->bt_cap, c.h[di], &slot)) {
            s->block_hit     = true;
            s->block_kind    = nr_slot_kind(slot);
            s->block_group   = nr_slot_group(slot);
            s->block_applies = kind_applies((RuleKind)s->block_kind,
                                            (unsigned)di + 1, c.depth);
        }
        if (h->n_allow && nr_table_get(ix.allow_table, h->at_cap, c.h[di], &slot)) {
            s->allow_hit     = true;
            s->allow_kind    = nr_slot_kind(slot);
            s->allow_group   = nr_slot_group(slot);
            s->allow_applies = kind_applies((RuleKind)s->allow_kind,
                                            (unsigned)di + 1, c.depth);
        }
    }
    out->n_steps = (uint8_t)n;

    /* The winning allow, read back out of the trace with the matcher's rule:
     * deepest applying allow wins, and a K_FORCE is absolute. */
    for (unsigned i = 0; i < out->n_steps; ++i) {
        const NrExplainStep& s = out->steps[i];
        if (s.allow_hit && s.allow_applies) {
            out->allow_hit   = true;
            out->allow_depth = s.depth;
            out->allow_kind  = s.allow_kind;
            out->allow_group = s.allow_group;
            snprintf(out->allow_rule, sizeof(out->allow_rule), "%s",
                     out->canon + s.suffix_off);
            break;
        }
    }

    if (out->verdict.kind == V_REDIRECT) {
        out->redirect_hit = true;
        const int af = out->verdict.family == AF_INET6 ? AF_INET6 : AF_INET;
        if (!inet_ntop(af, out->verdict.addr, out->redirect_addr,
                       sizeof(out->redirect_addr)))
            snprintf(out->redirect_addr, sizeof(out->redirect_addr), "?");
    }

    /* The matched rule is, by construction, the last `verdict.depth` labels of
     * the canonical name — the exact string the builder hashed. */
    if (out->verdict.depth > 0 && out->verdict.depth <= c.depth) {
        snprintf(out->matched_rule, sizeof(out->matched_rule), "%s",
                 out->canon + off[out->verdict.depth - 1]);
    }
}

const char* nr_expected_absence_note(const char* canon_name) {
    if (!canon_name || !*canon_name) return nullptr;
    struct Known { const char* domain; const char* note; };
    /* Every one of these is a support ticket waiting to happen: the apex is
     * absent from the curated lists ON PURPOSE, so a user testing with it sees
     * "not blocked" and concludes the whole product is broken. */
    static const Known kKnown[] = {
        {"doubleclick.net",
         "Hagezi does not list the doubleclick.net apex — it blocks the specific ad "
         "subdomains (e.g. ad.ae.doubleclick.net) to avoid collateral breakage. "
         "Test with google-analytics.com instead, which IS listed."},
        {"googleadservices.com",
         "Hagezi does not list the googleadservices.com apex; it lists specific "
         "subdomains such as afs.googleadservices.com."},
        {"graph.facebook.com",
         "graph.facebook.com is deliberately absent: blocking it breaks Facebook "
         "login in unrelated apps."},
        {"adservice.google.com",
         "adservice.google.com is deliberately absent from the curated lists."},
    };
    for (const Known& k : kKnown)
        if (strcmp(canon_name, k.domain) == 0) return k.note;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

bool nr_verify_index(const char* path, NrVerifyReport* out) {
    *out = NrVerifyReport{};
    out->path = path ? path : "";

    /* Deliberately NOT nr_index_open_ro(): it collapses "could not read the file"
     * and "read it, and it is not an index" into one false, and those two need
     * different answers from every caller. Mapping and validating separately is
     * the only way to report which one happened. */
    NrIndexRO idx;
    std::string err;
    if (!nr_map_file_ro(path, &idx.map, &err)) {
        out->ok    = false;
        out->error = err;
        return false;
    }
    out->readable = true;
    out->size     = idx.map.size;

    if (!nr_index_validate(idx.map.base, idx.map.size, &idx.ix)) {
        const char* field = nr_index_fault_field(idx.map.base, idx.map.size);
        out->ok    = false;
        out->error = std::string("index failed structural validation: ") +
                     (field ? field : "unknown field");
        nr_index_close_ro(&idx);
        return false;
    }

    const NrHeader* h = idx.ix.hdr;
    out->fmt_version = h->fmt_version;
    out->flags       = h->flags;
    out->generation  = h->generation;
    out->built_at_ms = h->built_at_ms;
    out->hash_seed   = h->hash_seed;
    out->n_block     = h->n_block;
    out->n_allow     = h->n_allow;
    out->n_redirect  = h->n_redirect;
    out->bt_cap      = h->bt_cap;
    out->at_cap      = h->at_cap;
    out->rt_cap      = h->rt_cap;
    out->label_mask  = h->label_mask;
    out->min_labels  = h->min_labels;
    out->max_labels  = h->max_labels;
    for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
        out->sec_off[i] = h->sec[i].off;
        out->sec_len[i] = h->sec[i].len;
    }

    bool sha_zero = true;
    for (unsigned i = 0; i < 32; ++i) if (h->sha256[i]) { sha_zero = false; break; }
    if (sha_zero) {
        out->sha_state = -1;
    } else {
        uint8_t d[32];
        nr_sha256(idx.map.base + NR_PAGE, idx.map.size - NR_PAGE, d);
        nr_sha256_hex(d, out->sha_actual);
        nr_sha256_hex(h->sha256, out->sha_header);
        out->sha_state = (memcmp(d, h->sha256, 32) == 0) ? 1 : 0;
    }

    /* The index-side liveness probe. Its absence does not make the index invalid,
     * but it does mean the app's health card can never turn green — worth saying
     * at the moment someone is asking about the file. */
    const Verdict pv = nr_evaluate_index(idx.ix, NR_PROBE_IDX_NAME,
                                         strlen(NR_PROBE_IDX_NAME));
    if (pv.kind == V_REDIRECT) {
        out->probe_present = true;
        const int af = pv.family == AF_INET6 ? AF_INET6 : AF_INET;
        if (!inet_ntop(af, pv.addr, out->probe_addr, sizeof(out->probe_addr)))
            snprintf(out->probe_addr, sizeof(out->probe_addr), "?");
    }

    if (h->generation == NR_GEN_NONE) {
        /* A generation of 0 is indistinguishable from "nothing mapped", so the
         * resolver would either never pick this up or remap on every query. */
        out->ok    = false;
        out->error = "header generation is 0, which is reserved for 'no index'";
    } else if (out->sha_state == 0) {
        out->ok    = false;
        out->error = "sha256 mismatch: the payload does not match the header";
    } else {
        out->ok = true;
    }

    nr_index_close_ro(&idx);
    return out->ok;
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

static void reverse_labels(std::string* s) {
    std::string outs;
    outs.reserve(s->size());
    size_t end = s->size();
    for (size_t i = s->size(); i-- > 0;) {
        if ((*s)[i] == '.') {
            outs.append(*s, i + 1, end - i - 1);
            outs.push_back('.');
            end = i;
        }
    }
    outs.append(*s, 0, end);
    *s = outs;
}

/* "<ip> <domain>" — the redirect form (§7.5). Deliberately does NOT go through
 * nr_parse_line for the address: that treats a leading IP as a hosts-file
 * sinkhole marker and throws it away, which is the opposite of what a redirect
 * rule means. */
static bool parse_redirect_line(const std::string& raw, BuildRedirect* out) {
    size_t b = 0;
    while (b < raw.size() && (unsigned char)raw[b] <= ' ') ++b;
    if (b >= raw.size() || raw[b] == '#') return false;
    size_t e = b;
    while (e < raw.size() && (unsigned char)raw[e] > ' ') ++e;
    const std::string ip = raw.substr(b, e - b);

    size_t db = e;
    while (db < raw.size() && (unsigned char)raw[db] <= ' ') ++db;
    size_t de = db;
    while (de < raw.size() && (unsigned char)raw[de] > ' ') ++de;
    if (de == db) return false;
    const std::string domain = raw.substr(db, de - db);

    uint8_t addr[16] = {};
    uint8_t family;
    if (inet_pton(AF_INET, ip.c_str(), addr) == 1) {
        family = AF_INET;
    } else if (inet_pton(AF_INET6, ip.c_str(), addr) == 1) {
        family = AF_INET6;
    } else {
        return false;
    }

    /* Normalize the name through the same parser every other rule uses, so that a
     * redirect and a block for the same host agree on what the host is. */
    std::string d;
    RuleKind k;
    bool is_allow;
    if (!nr_parse_line(domain.data(), domain.size(), &d, &k, &is_allow)) return false;

    out->domain = d;
    out->family = family;
    memcpy(out->addr, addr, 16);
    return true;
}

static void split_lines(const std::string& text, NrSourceStat* st, uint8_t role,
                        bool reversed, uint16_t group,
                        std::vector<BuildEntry>* block,
                        std::vector<BuildEntry>* allow,
                        std::vector<BuildRedirect>* redirects) {
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        const size_t len = nl - pos;
        if (len || pos < text.size()) ++st->lines;

        if (len) {
            if (role == NR_ROLE_REDIRECT) {
                BuildRedirect r;
                if (parse_redirect_line(text.substr(pos, len), &r)) {
                    redirects->push_back(std::move(r));
                    ++st->parsed;
                } else {
                    ++st->rejected;
                }
            } else {
                std::string d;
                RuleKind k;
                bool is_allow = false;
                if (nr_parse_line(text.data() + pos, len, &d, &k, &is_allow)) {
                    if (reversed) reverse_labels(&d);
                    if (role == NR_ROLE_FORCE) {
                        allow->push_back(BuildEntry{d, K_FORCE, group});
                    } else if (role == NR_ROLE_ALLOW || is_allow) {
                        allow->push_back(BuildEntry{d, k, group});
                    } else {
                        block->push_back(BuildEntry{d, k, group});
                    }
                    ++st->parsed;
                } else {
                    ++st->rejected;
                }
            }
        }
        if (nl == text.size()) break;
        pos = nl + 1;
    }
}

bool nr_compile(const NrCompileSpec& spec, std::vector<uint8_t>* blob,
                NrCompileResult* result, std::string* err) {
    const uint64_t t0 = nr_now_ms();
    *result = NrCompileResult{};

    if (spec.generation == NR_GEN_NONE) {
        if (err) *err = "generation 0 is reserved for 'no index'";
        return false;
    }

    std::vector<BuildEntry>    block, allow;
    std::vector<BuildRedirect> redirects = spec.redirects;

    for (const NrCompileInput& in : spec.inputs) {
        NrSourceStat st;
        st.path  = in.path;
        st.group = in.group;
        st.role  = in.role;

        /* Referenced, never copied: the seeder hands us ~2 MB of decompressed
         * baseline at post-fs-data and a gratuitous copy of it is real RSS at the
         * worst moment of the boot. */
        std::string loaded;
        const std::string* text = nullptr;
        if (!in.text.empty()) {
            text       = &in.text;
            st.present = true;
        } else if (in.path.empty()) {
            continue;
        } else {
            std::string rerr;
            if (nr_read_file(in.path.c_str(), &loaded, &rerr)) {
                st.present = true;
                text       = &loaded;
            } else {
                st.present = false;
                st.error   = rerr;
                if (!in.optional) {
                    if (err) *err = "required input " + in.path + ": " + rerr;
                    return false;
                }
            }
        }
        if (st.present && text)
            split_lines(*text, &st, in.role, in.reversed_labels, in.group,
                        &block, &allow, &redirects);
        result->sources.push_back(std::move(st));
    }

    if (block.empty() && allow.empty() && redirects.empty()) {
        /* An empty index would validate, map, and block nothing — the exact
         * failure mode that looks identical to success. Refuse instead. */
        if (err) *err = "no rules parsed from any input";
        return false;
    }

    BuildStats stats{};
    if (!nr_build_index(block, allow, redirects, spec.generation,
                        spec.built_at_ms ? spec.built_at_ms : nr_now_ms(),
                        spec.hash_seed, blob, &stats)) {
        if (err) *err = "nr_build_index failed (table sizing or bad input)";
        return false;
    }
    if (blob->size() <= NR_PAGE) {
        if (err) *err = "builder produced a header with no payload";
        return false;
    }

    /* The builder deliberately leaves sha256 zero — it links no hashing library.
     * Filling it here means every artefact that reaches disk carries one, and
     * `nrctl verify` can tell "corrupt" from "not sealed yet". */
    uint8_t digest[32];
    nr_sha256(blob->data() + NR_PAGE, blob->size() - NR_PAGE, digest);
    memcpy(blob->data() + offsetof(NrHeader, sha256), digest, 32);
    nr_sha256_hex(digest, result->sha256_hex);

    const NrHeader* h  = (const NrHeader*)blob->data();
    result->stats      = stats;
    result->generation = spec.generation;
    result->bytes      = blob->size();
    result->block_kept = h->n_block;
    result->allow_kept = h->n_allow;
    result->redirects  = h->n_redirect;
    result->elapsed_ms = nr_now_ms() - t0;
    return true;
}

// ---------------------------------------------------------------------------
// manifest.<gen>.json
// ---------------------------------------------------------------------------

static bool json_string_field(const std::string& obj, const char* key, std::string* out) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t p = obj.find(needle);
    if (p == std::string::npos) return false;
    p = obj.find(':', p + needle.size());
    if (p == std::string::npos) return false;
    ++p;
    while (p < obj.size() && (unsigned char)obj[p] <= ' ') ++p;
    if (p >= obj.size() || obj[p] != '"') return false;
    ++p;
    out->clear();
    while (p < obj.size() && obj[p] != '"') {
        if (obj[p] == '\\' && p + 1 < obj.size()) ++p;
        out->push_back(obj[p++]);
    }
    return !out->empty();
}

static bool json_int_field(const std::string& obj, const char* key, long long* out) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t p = obj.find(needle);
    if (p == std::string::npos) return false;
    p = obj.find(':', p + needle.size());
    if (p == std::string::npos) return false;
    ++p;
    while (p < obj.size() && (unsigned char)obj[p] <= ' ') ++p;
    errno = 0;
    char* end = nullptr;
    const long long v = strtoll(obj.c_str() + p, &end, 10);
    if (errno != 0 || end == obj.c_str() + p) return false;
    *out = v;
    return true;
}

bool nr_manifest_group_name(const char* index_dir, uint64_t generation,
                            uint16_t group, std::string* out) {
    out->clear();
    if (!index_dir || generation == NR_GEN_NONE) return false;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/manifest.%llu.json", index_dir,
             (unsigned long long)generation);

    std::string text;
    if (!nr_read_file(path, &text, nullptr)) return false;

    /* Flat objects only: the manifest is ours and its "sources" entries have no
     * nested objects. Anything cleverer would be a JSON parser in a boot binary,
     * run to recover a display string. */
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t ob = text.find('{', pos);
        if (ob == std::string::npos) break;
        const size_t oe = text.find('}', ob + 1);
        if (oe == std::string::npos) break;
        const std::string obj = text.substr(ob + 1, oe - ob - 1);
        long long g = -1;
        if (json_int_field(obj, "group", &g) && g == (long long)group) {
            if (json_string_field(obj, "name", out)) return true;
        }
        pos = oe + 1;
    }
    return false;
}

// ---------------------------------------------------------------------------
// JSON emission
// ---------------------------------------------------------------------------

void nr_json_escape(const char* s, size_t n, std::string* out) {
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  out->append("\\\""); break;
            case '\\': out->append("\\\\"); break;
            case '\n': out->append("\\n");  break;
            case '\r': out->append("\\r");  break;
            case '\t': out->append("\\t");  break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    /* Hostnames reaching us from the ring, or from a fuzzed CLI
                     * argument, can be arbitrary bytes; anything non-printable is
                     * escaped rather than embedded raw in the app's JSON. */
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out->append(buf);
                } else {
                    out->push_back((char)c);
                }
        }
    }
}

static void jstr(std::string* o, const char* key, const std::string& v) {
    o->push_back('"');
    o->append(key);
    o->append("\":\"");
    nr_json_escape(v.data(), v.size(), o);
    o->append("\"");
}

static void jnum(std::string* o, const char* key, unsigned long long v) {
    char buf[64];
    snprintf(buf, sizeof(buf), "\"%s\":%llu", key, v);
    o->append(buf);
}

static void jbool(std::string* o, const char* key, bool v) {
    o->push_back('"');
    o->append(key);
    o->append(v ? "\":true" : "\":false");
}

/* JSON `null`, not "". core/Native.kt distinguishes them with JSONObject.isNull()
 * and treats a present-but-empty string as a real error message, so emitting ""
 * for "nothing went wrong" makes every source look like it failed. */
static void jstr_or_null(std::string* o, const char* key, const std::string& v) {
    if (v.empty()) {
        o->push_back('"');
        o->append(key);
        o->append("\":null");
        return;
    }
    jstr(o, key, v);
}

/* The wire spelling of a verdict.
 *
 * Lowercase, and deliberately NOT nr_verdict_name(): that one is the human
 * spelling the CLI prints ("BLOCKED" in a terminal), while this is a machine
 * token that core/Native.kt matches with `when (json.optString("verdict"))`
 * against "pass"/"block"/"redirect". A mismatch here does not fail — it falls
 * through to VerdictKind.UNKNOWN, which the app then reports as "cannot tell",
 * for every domain, forever. */
static const char* verdict_wire(uint8_t kind) {
    switch (kind) {
        case V_PASS:     return "pass";
        case V_BLOCK:    return "block";
        case V_REDIRECT: return "redirect";
        default:         return "unknown";
    }
}

std::string nr_json_query(const NrIndexRO& index, const char* index_path, const char* host) {
    NrExplain e;
    nr_explain(index.ix, host, host ? strlen(host) : 0, &e);

    std::string dir(index_path ? index_path : "");
    const size_t slash = dir.rfind('/');
    dir = (slash == std::string::npos) ? std::string(".") : dir.substr(0, slash);

    std::string group_name;
    const uint16_t vg = e.verdict.group;
    if (e.verdict.kind == V_BLOCK) {
        const char* builtin = nr_group_builtin_name(vg);
        if (builtin) {
            group_name = builtin;
        } else {
            nr_manifest_group_name(dir.c_str(), index.ix.hdr->generation, vg, &group_name);
        }
    }

    std::string o = "{";
    jbool(&o, "ok", true);                                     o.push_back(',');
    jstr(&o, "host", host ? host : "");                        o.push_back(',');
    jstr(&o, "canonical", e.canon);                            o.push_back(',');
    jbool(&o, "evaluated", e.usable);                          o.push_back(',');
    jstr(&o, "verdict", verdict_wire(e.verdict.kind));         o.push_back(',');
    jbool(&o, "blocked", e.verdict.kind == V_BLOCK);           o.push_back(',');
    jnum(&o, "labels", e.depth);                               o.push_back(',');
    jnum(&o, "depth", e.verdict.depth);                        o.push_back(',');
    jnum(&o, "group", vg);                                     o.push_back(',');
    jstr(&o, "group_name", group_name);                        o.push_back(',');
    /* `rule` and `address` are the flat names core/Native.kt reads; the nested
     * "allow"/"redirect" objects below carry the same facts with more context for
     * `nrctl --json`. One producer, two shapes of the same answer — never two
     * producers, which is what would let them disagree. */
    jstr(&o, "matched_rule", e.matched_rule);                  o.push_back(',');
    jstr_or_null(&o, "rule", e.matched_rule);                  o.push_back(',');
    jstr_or_null(&o, "address", e.redirect_hit ? e.redirect_addr : "");
    o.push_back(',');

    o.append("\"allow\":{");
    jbool(&o, "hit", e.allow_hit);                             o.push_back(',');
    jnum(&o, "depth", e.allow_depth);                          o.push_back(',');
    jstr(&o, "kind", e.allow_hit ? nr_kind_name(e.allow_kind) : ""); o.push_back(',');
    jnum(&o, "group", e.allow_group);                          o.push_back(',');
    jstr(&o, "rule", e.allow_rule);
    o.append("},");

    o.append("\"redirect\":{");
    jbool(&o, "hit", e.redirect_hit);                          o.push_back(',');
    jstr(&o, "address", e.redirect_hit ? e.redirect_addr : "");
    o.append("},");

    o.append("\"trace\":[");
    for (unsigned i = 0; i < e.n_steps; ++i) {
        const NrExplainStep& s = e.steps[i];
        if (i) o.push_back(',');
        o.push_back('{');
        jnum(&o, "depth", s.depth);                            o.push_back(',');
        jstr(&o, "suffix", nr_explain_suffix(e, i));           o.push_back(',');
        jbool(&o, "probed", s.plausible);                      o.push_back(',');
        jbool(&o, "block_hit", s.block_hit);                   o.push_back(',');
        jbool(&o, "block_applies", s.block_applies);           o.push_back(',');
        jstr(&o, "block_kind", s.block_hit ? nr_kind_name(s.block_kind) : ""); o.push_back(',');
        jnum(&o, "block_group", s.block_group);                o.push_back(',');
        jbool(&o, "allow_hit", s.allow_hit);                   o.push_back(',');
        jbool(&o, "allow_applies", s.allow_applies);           o.push_back(',');
        jstr(&o, "allow_kind", s.allow_hit ? nr_kind_name(s.allow_kind) : ""); o.push_back(',');
        jnum(&o, "allow_group", s.allow_group);
        o.push_back('}');
    }
    o.append("],");

    const char* note = nr_expected_absence_note(e.canon);
    jstr(&o, "note", (e.verdict.kind != V_BLOCK && note) ? note : "");
    o.push_back(',');

    o.append("\"index\":{");
    jstr(&o, "path", index_path ? index_path : "");            o.push_back(',');
    jnum(&o, "generation", index.ix.hdr->generation);          o.push_back(',');
    jnum(&o, "built_at_ms", index.ix.hdr->built_at_ms);        o.push_back(',');
    jnum(&o, "n_block", index.ix.hdr->n_block);                o.push_back(',');
    jnum(&o, "n_allow", index.ix.hdr->n_allow);                o.push_back(',');
    jnum(&o, "n_redirect", index.ix.hdr->n_redirect);
    o.append("}}");
    return o;
}

std::string nr_json_verify(const NrVerifyReport& r) {
    std::string o = "{";
    jbool(&o, "ok", r.ok);                                     o.push_back(',');
    jbool(&o, "readable", r.readable);                         o.push_back(',');
    jstr(&o, "path", r.path);                                  o.push_back(',');
    jstr_or_null(&o, "error", r.error);                        o.push_back(',');
    jnum(&o, "size", r.size);                                  o.push_back(',');
    /* `bytes` and `sha256_ok` are what core/Native.kt reads. sha256_ok is
     * strictly weaker than sha256_state — it cannot distinguish "unset" from
     * "mismatch" — so both are emitted and the tri-state stays the one a human
     * is shown. An index whose seal was never written is a build bug; one whose
     * seal does not match is a corruption, and conflating them costs a diagnosis. */
    jnum(&o, "bytes", r.size);                                 o.push_back(',');
    jbool(&o, "sha256_ok", r.sha_state == 1);                  o.push_back(',');
    jnum(&o, "fmt_version", r.fmt_version);                    o.push_back(',');
    jnum(&o, "generation", r.generation);                      o.push_back(',');
    jnum(&o, "built_at_ms", r.built_at_ms);                    o.push_back(',');
    jnum(&o, "hash_seed", r.hash_seed);                        o.push_back(',');
    jnum(&o, "n_block", r.n_block);                            o.push_back(',');
    jnum(&o, "n_allow", r.n_allow);                            o.push_back(',');
    jnum(&o, "n_redirect", r.n_redirect);                      o.push_back(',');
    jnum(&o, "bt_cap", r.bt_cap);                              o.push_back(',');
    jnum(&o, "at_cap", r.at_cap);                              o.push_back(',');
    jnum(&o, "rt_cap", r.rt_cap);                              o.push_back(',');
    jnum(&o, "min_labels", r.min_labels);                      o.push_back(',');
    jnum(&o, "max_labels", r.max_labels);                      o.push_back(',');
    jnum(&o, "label_mask", r.label_mask);                      o.push_back(',');
    jstr(&o, "sha256_state",
         r.sha_state == 1 ? "match" : (r.sha_state == 0 ? "MISMATCH" : "unset"));
    o.push_back(',');
    jstr(&o, "sha256_header", r.sha_header);                   o.push_back(',');
    jstr(&o, "sha256_actual", r.sha_actual);                   o.push_back(',');
    jbool(&o, "probe_present", r.probe_present);               o.push_back(',');
    jstr(&o, "probe_address", r.probe_addr);                   o.push_back(',');
    o.append("\"sections\":[");
    for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
        if (i) o.push_back(',');
        o.push_back('{');
        jnum(&o, "index", i);          o.push_back(',');
        jnum(&o, "off", r.sec_off[i]); o.push_back(',');
        jnum(&o, "len", r.sec_len[i]);
        o.push_back('}');
    }
    o.append("]}");
    return o;
}

std::string nr_json_compile(const NrCompileResult& r, const char* out_path) {
    /* Rolled up here so the app does not have to sum the per-source array to
     * answer "how many lines did we throw away", which is the number that
     * distinguishes a healthy fetch from a source whose format changed. */
    uint64_t rejected = 0, lines = 0;
    for (const NrSourceStat& s : r.sources) { rejected += s.rejected; lines += s.lines; }

    std::string o = "{";
    jbool(&o, "ok", true);                                     o.push_back(',');
    jstr(&o, "path", out_path ? out_path : "");                o.push_back(',');
    /* core/Native.kt reads out_path; `nrctl --json` and this repo's scripts read
     * path. Same value, emitted once each — the alternative is a second producer. */
    jstr(&o, "out_path", out_path ? out_path : "");            o.push_back(',');
    jnum(&o, "generation", r.generation);                      o.push_back(',');
    jnum(&o, "bytes", r.bytes);                                o.push_back(',');
    jnum(&o, "parsed_lines", lines);                           o.push_back(',');
    jnum(&o, "rejected", rejected);                            o.push_back(',');
    jnum(&o, "block_in", r.stats.block_in);                    o.push_back(',');
    jnum(&o, "block_collapsed", r.stats.block_collapsed);      o.push_back(',');
    jnum(&o, "block_kept", r.block_kept);                      o.push_back(',');
    jnum(&o, "allow_in", r.stats.allow_in);                    o.push_back(',');
    jnum(&o, "allow_kept", r.allow_kept);                      o.push_back(',');
    jnum(&o, "redirects", r.redirects);                        o.push_back(',');
    jnum(&o, "bt_cap", r.stats.bt_cap);                        o.push_back(',');
    jnum(&o, "at_cap", r.stats.at_cap);                        o.push_back(',');
    jnum(&o, "rt_cap", r.stats.rt_cap);                        o.push_back(',');
    jnum(&o, "elapsed_ms", r.elapsed_ms);                      o.push_back(',');
    jstr(&o, "sha256", r.sha256_hex);                          o.push_back(',');
    o.append("\"sources\":[");
    for (size_t i = 0; i < r.sources.size(); ++i) {
        const NrSourceStat& s = r.sources[i];
        if (i) o.push_back(',');
        o.push_back('{');
        jstr(&o, "path", s.path);         o.push_back(',');
        jnum(&o, "group", s.group);       o.push_back(',');
        jnum(&o, "role", s.role);         o.push_back(',');
        jbool(&o, "present", s.present);  o.push_back(',');
        jnum(&o, "lines", s.lines);       o.push_back(',');
        jnum(&o, "parsed", s.parsed);     o.push_back(',');
        jnum(&o, "rejected", s.rejected); o.push_back(',');
        jstr_or_null(&o, "error", s.error);
        o.push_back('}');
    }
    o.append("]}");
    return o;
}

}  // namespace nr
