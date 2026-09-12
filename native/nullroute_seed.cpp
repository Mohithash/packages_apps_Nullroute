/*
 * Nullroute — `nullroute_seed`, the post-fs-data oneshot. /system_ext/bin/nullroute_seed
 *
 * Runs as user system, group system+misc, in the `nullroute_seed` domain, started
 * asynchronously from `on post-fs-data` (§8.4). Boot is never gated on it: the
 * resolver tolerates a missing index with a lazy-open backoff, and `class core`
 * runs before `class main` (netd), so in practice the index is live before the
 * first query anyway.
 *
 * It does four things, in this order:
 *
 *   1. THE BOOT-LOOP BREAKER (§6.1). The one job that must work even when
 *      everything else is broken. netd's init stanza carries
 *      `onrestart restart zygote`, so a bad index is a UI loop, not a network
 *      outage, and the user has no UI with which to turn anything off. Three
 *      boots without the app reporting 120 s of healthy uptime and the index is
 *      quarantined and the kill switch is set — the third boot is clean.
 *
 *   2. PRE-CREATE control.bin AND ring.bin at the right size, owner and mode.
 *      netd never creates these: it runs as root and would leave root-owned files
 *      the app could not write (§7.1).
 *
 *   3. FIRST-BOOT COMPILE of the baked baseline, with zero network, so a freshly
 *      flashed device that has never seen Wi-Fi still filters.
 *
 *   4. RECONCILE control.bin::want_generation with what is actually on disk.
 *
 * Every failure path here leaves the device FILTERING LESS, never more, and every
 * one of them names itself in `sys.nullroute.seed` so the app's Diagnostics
 * screen can say what happened instead of guessing.
 *
 * ---------------------------------------------------------------------------
 * BASELINE FILE CONTRACT — tools/gen_baseline.py must match this
 *
 *   /system_ext/etc/nullroute/baseline.domains.xz
 *
 *   Optionally xz-compressed (detected by the 6-byte magic, so an uncompressed
 *   file with the same name also works). The decompressed payload is
 *   line-oriented ASCII. If the FIRST line is a header of the form
 *
 *       #NRBASE1 plain     one rule per line, normal label order  (the default)
 *       #NRBASE1 rev       one rule per line, REVERSED labels: "com.example.ads"
 *       #NRBASE1 frontrev  front-coded reversed labels, see below
 *
 *   that mode is used; with no header the payload is treated as `plain`, which
 *   means a bare newline-separated domain list — or even a hosts file — works
 *   unmodified. Every line goes through nr_parse_line(), so comments, hosts
 *   syntax, ABP syntax and wildcards are all understood.
 *
 *   `frontrev` records are: one byte (0x20 + shared_prefix_len), the literal
 *   remainder, then '\n'. shared_prefix_len is relative to the previous record
 *   and is capped at 94 by the encoder so the length byte stays printable and a
 *   plain `\n` split is never ambiguous.
 *
 *   If baseline.domains.xz.sha256 exists beside it, its first field must be the
 *   hex sha256 of the file as it sits on disk. A mismatch means we compile
 *   NOTHING rather than compile something unknown.
 * ------------------------------------------------------------------------- */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <string>
#include <vector>

/*
 * ⚠ WHICH liblzma.
 *
 * `shared_libs: ["liblzma"]` resolves to two completely different libraries
 * depending on the tree, and they do NOT share an API:
 *
 *   xz-utils liblzma   <lzma.h>  lzma_stream / lzma_stream_decoder()   — used below
 *   LZMA SDK           <Xz.h>    CXzUnpacker / XzUnpacker_Code()
 *
 * AOSP's external/lzma is the SDK (it is what libunwindstack's MemoryXz.cpp
 * includes as <7zTypes.h>/<Xz.h>), so on a stock tree this header is absent and
 * the module does not build. __has_include picks whichever the tree really has
 * and says so plainly when it is neither, because the alternative is a bare
 * "lzma.h: No such file or directory" that reads as a broken checkout rather
 * than a missing dependency with three known remedies.
 */
#if __has_include(<lzma.h>)
#define NR_XZ_XZUTILS 1
#include <lzma.h>
#elif __has_include(<Xz.h>)
/* Remedy (b). BestROM's tree has external/lzma, the LZMA SDK, and `liblzma`
 * resolves to it; there is no external/xz-utils to import. xz_decode() below
 * therefore has two bodies, picked by the same __has_include that chose the
 * header. Both take and return the same things and enforce the same 64 MiB
 * output ceiling, so nothing outside this file changes. */
#define NR_XZ_SDK 1
#include <stdlib.h>

#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>
#else
#error "nullroute_seed needs an xz decoder: xz-utils liblzma (<lzma.h>) or the \
LZMA SDK (<Xz.h>). This tree has neither. Either (a) import external/xz-utils \
and point shared_libs:[\"liblzma\"] at it, (b) extend xz_decode() below to \
whatever this tree does provide, or (c) regenerate prebuilt/baseline.domains.xz \
uncompressed — load_baseline() already sniffs the xz magic and accepts a plain \
payload, so only tools/gen_baseline.py and the file name would change."
#endif

#include "NrCtl.h"
#include "NrRingReader.h"

#define LOG_TAG "NullrouteSeed"
#include <log/log.h>

using namespace nr;

namespace {

const gid_t kAidMisc = 9998;

/* Bounded wait for init to have loaded /data's persistent properties.
 *
 * This matters more than it looks. `on post-fs-data` ends with
 * `trigger load_persist_props_action`, which is queued BEHIND the post-fs-data
 * blocks contributed by other .rc files — ours included — and we are started
 * with `start`, i.e. asynchronously. So without this wait the boot-loop breaker
 * would race the loader: it would read an empty fail_streak on every boot, and
 * the values it wrote would then be overwritten by the persisted ones a moment
 * later. Three boots of that and a perfectly good index gets quarantined on
 * every device in the field.
 *
 * `ro.persistent_properties.ready` is set by property_service immediately after
 * load_persist_props() and is the only reliable edge to wait on. */
bool wait_for_persist_props(int timeout_ms) {
    const int step_ms = 50;
    for (int waited = 0; waited <= timeout_ms; waited += step_ms) {
        if (nr_prop_get("ro.persistent_properties.ready", "") == "true") return true;
        struct timespec ts = {step_ms / 1000, (long)(step_ms % 1000) * 1000000L};
        nanosleep(&ts, nullptr);
    }
    return false;
}

/* sys.nullroute.seed is the seeder's whole observability surface, so the last
 * value set is remembered: the final "we also could not read persistent
 * properties" note has to qualify the outcome rather than erase it. */
char g_state[92] = "unset";

void set_state(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_state, sizeof(g_state), fmt, ap);
    va_end(ap);
    nr_prop_set(NR_PROP_SEED, g_state);
    ALOGI("state=%s", g_state);
}

/*
 * Create the file if it is absent, extend it if it is short, and never, ever
 * shorten or truncate one that already exists: control.bin carries the user's
 * per-app policy for 100,000 appIds and ring.bin carries log records, and both
 * outlive the process that made them.
 */
bool ensure_file(const char* path, off_t bytes, mode_t mode, bool ring_header, bool* created) {
    *created = false;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode);
        if (fd >= 0) *created = true;
    }
    if (fd < 0) {
        ALOGE("cannot open %s: %s (errno=%d)", path, strerror(errno), errno);
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        ALOGE("fstat %s: %s", path, strerror(errno));
        close(fd);
        return false;
    }
    if (st.st_size < bytes && ftruncate(fd, bytes) != 0) {
        ALOGE("ftruncate %s to %lld: %s", path, (long long)bytes, strerror(errno));
        close(fd);
        return false;
    }

    /* Group `misc` is how the app reaches these files without sharedUserId: it
     * gets gid 9998 from rom/nullroute-gid.xml (§8.7). Changing only the group of
     * a file we own needs no capability, which is why the uid argument is -1. */
    (void)fchmod(fd, mode);
    (void)fchown(fd, (uid_t)-1, kAidMisc);

    if (ring_header) {
        /* A ring whose header we do not recognise is not "corrupt data to
         * preserve", it is telemetry with a stale format; reformatting page 0 is
         * both safe and necessary. Records are left alone — the reader validates
         * every one of them by sequence number anyway. */
        if (*created || nr_ring_check_header(fd) != 1) {
            if (!nr_ring_write_header(fd)) ALOGE("cannot write the ring header");
        }
    }
    close(fd);
    return true;
}

/*
 * Create a state directory only if init did not.
 *
 * The chmod/chown deliberately run ONLY on a directory we created ourselves.
 * init.nullroute.rc already makes all five with the right mode, owner and
 * SELinux label, and the top one — /data/misc/nullroute — keeps the inherited
 * `system_data_file` label on purpose (netd has to traverse it). nullroute_seed
 * holds `search` on that type and nothing else, so an unconditional
 * chmod()/chown() there is a guaranteed setattr denial in every boot's dmesg,
 * on a device where nothing is actually wrong. Denial noise that is always
 * present is denial noise nobody reads when it finally matters.
 */
bool ensure_dir(const char* path, mode_t mode) {
    if (mkdir(path, mode) == 0) {
        (void)chmod(path, mode);
        (void)chown(path, (uid_t)-1, kAidMisc);
        return true;
    }
    if (errno == EEXIST) return true;
    ALOGE("mkdir %s: %s", path, strerror(errno));
    return false;
}

// ---------------------------------------------------------------------------
// The boot-loop breaker (§6.1)
// ---------------------------------------------------------------------------

enum class Breaker { Continue, Quarantined, PropsUnavailable };

Breaker boot_loop_breaker() {
    if (!wait_for_persist_props(10000)) {
        /* Without persistent properties the streak cannot be remembered, so
         * incrementing it would be theatre — and quarantining on the strength of
         * a value we know we cannot trust would disable filtering on healthy
         * devices. Say so and carry on. */
        ALOGE("persistent properties never became ready; skipping the boot-loop breaker");
        return Breaker::PropsUnavailable;
    }

    const std::string prev_ok = nr_prop_get(NR_PROP_BOOT_OK, "");
    int64_t streak = nr_prop_get_i64(NR_PROP_FAIL_STREAK, 0);
    if (streak < 0) streak = 0;

    /* The app sets boot_ok=1 at T+120 s of healthy uptime. A zygote restart loop
     * never gets that far, so the streak advances on exactly the boots that
     * failed. A user who reboots three times in quick succession before the app
     * settles will also trip it — that costs them an unfiltered device and a
     * kill=1 they can clear, which is the right way round to be wrong. */
    if (prev_ok == "1") streak = 0;
    else                ++streak;

    nr_prop_set_i64(NR_PROP_FAIL_STREAK, streak);
    nr_prop_set(NR_PROP_BOOT_OK, "0");        /* re-arm for THIS boot */

    if (streak < NR_FAIL_STREAK_LIMIT) {
        ALOGI("boot streak %lld of %d", (long long)streak, NR_FAIL_STREAK_LIMIT);
        return Breaker::Continue;
    }

    /* Third strike. Move the index aside rather than deleting it — it is the
     * only evidence of what went wrong, and Diagnostics offers to attach it. */
    if (rename(NR_PATH_INDEX_CURRENT, NR_PATH_QUARANTINE) != 0 && errno != ENOENT)
        ALOGE("cannot quarantine %s: %s", NR_PATH_INDEX_CURRENT, strerror(errno));

    /* Belt and braces: with no index the filter already falls open, but the kill
     * switch also covers a control page or a resolver-side fault being the cause.
     * It is never cleared here — only the user or the app clears it, because
     * auto-clearing would re-arm the very loop we just broke. */
    nr_prop_set(NR_PROP_KILL, "1");
    ALOGE("quarantined the index after %lld failed boots; filtering is OFF",
          (long long)streak);
    return Breaker::Quarantined;
}

// ---------------------------------------------------------------------------
// Baseline decode
// ---------------------------------------------------------------------------

bool looks_like_xz(const std::string& s) {
    static const unsigned char kMagic[6] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
    return s.size() >= 6 && memcmp(s.data(), kMagic, 6) == 0;
}

/* Streaming xz decode with hard ceilings on both the decoder's memory and the
 * output. This runs at post-fs-data as a system-uid process; a decompression
 * bomb in a file we shipped ourselves is unlikely, but "unlikely" is not a
 * memory limit. */
#if defined(NR_XZ_SDK)

/* The SDK takes an allocator rather than a memory limit, so the decoder-side
 * ceiling xz-utils gives us for free is not available here. The output ceiling
 * below is unchanged and is the one that actually bounds a decompression bomb. */
void* sdk_alloc(ISzAllocPtr, size_t size) { return size ? malloc(size) : nullptr; }
void sdk_free(ISzAllocPtr, void* addr) { free(addr); }
const ISzAlloc kSdkAlloc = {sdk_alloc, sdk_free};

bool xz_decode(const std::string& in, std::string* out, std::string* err) {
    static const size_t kMaxOut = 64u << 20;

    /* XzUnpacker_Code returns SZ_ERROR_DATA on a valid stream until these
     * tables exist. libunwindstack and simpleperf both initialise them; without
     * that, every baked baseline looks corrupt and the seeder publishes
     * nobaseline, so netd stays at nomap:ENOENT. */
    static bool crc_ready = false;
    if (!crc_ready) {
        CrcGenerateTable();
        Crc64GenerateTable();
        crc_ready = true;
    }

    CXzUnpacker st;
    XzUnpacker_Construct(&st, &kSdkAlloc);
    XzUnpacker_Init(&st);

    out->clear();
    std::vector<uint8_t> buf(256 * 1024);
    size_t in_pos = 0;

    for (;;) {
        SizeT dest_len = buf.size();
        SizeT src_len = in.size() - in_pos;
        ECoderStatus status = CODER_STATUS_NOT_SPECIFIED;
        /* srcFinished is 1 because the whole file is already in `in`; it is what
         * lets the decoder report a truncated stream instead of waiting for
         * bytes that are never coming. */
        const SRes rc = XzUnpacker_Code(&st, buf.data(), &dest_len,
                                        (const Byte*)in.data() + in_pos, &src_len,
                                        1, CODER_FINISH_END, &status);
        if (rc != SZ_OK) {
            *err = "corrupt xz stream";
            XzUnpacker_Free(&st);
            out->clear();
            return false;
        }
        if (out->size() + dest_len > kMaxOut) {
            *err = "baseline expands past the 64 MiB ceiling";
            XzUnpacker_Free(&st);
            out->clear();
            return false;
        }
        out->append((const char*)buf.data(), dest_len);
        in_pos += src_len;
        if (status == CODER_STATUS_FINISHED_WITH_MARK) break;
        if (dest_len == 0 && src_len == 0) {
            *err = "truncated xz stream";
            XzUnpacker_Free(&st);
            out->clear();
            return false;
        }
    }

    const bool finished = XzUnpacker_IsStreamWasFinished(&st) != 0;
    XzUnpacker_Free(&st);
    if (!finished) {
        *err = "truncated xz stream";
        out->clear();
        return false;
    }
    return true;
}

#else

bool xz_decode(const std::string& in, std::string* out, std::string* err) {
    static const uint64_t kMemLimit = 64ull << 20;
    static const size_t   kMaxOut   = 64u << 20;

    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret rc = lzma_stream_decoder(&strm, kMemLimit, LZMA_CONCATENATED);
    if (rc != LZMA_OK) {
        *err = "lzma_stream_decoder failed";
        return false;
    }

    out->clear();
    strm.next_in  = (const uint8_t*)in.data();
    strm.avail_in = in.size();

    std::vector<uint8_t> buf(256 * 1024);
    for (;;) {
        strm.next_out  = buf.data();
        strm.avail_out = buf.size();
        rc = lzma_code(&strm, LZMA_FINISH);
        const size_t produced = buf.size() - strm.avail_out;
        if (out->size() + produced > kMaxOut) {
            *err = "baseline expands past the 64 MiB ceiling";
            lzma_end(&strm);
            return false;
        }
        out->append((const char*)buf.data(), produced);
        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK) {
            *err = "corrupt xz stream";
            lzma_end(&strm);
            out->clear();
            return false;
        }
        if (produced == 0 && strm.avail_in == 0) {
            *err = "truncated xz stream";
            lzma_end(&strm);
            out->clear();
            return false;
        }
    }
    lzma_end(&strm);
    return true;
}

#endif  // NR_XZ_SDK

enum class LineMode { Plain, Rev, FrontRev };

LineMode read_header(std::string* text) {
    if (text->compare(0, 9, "#NRBASE1 ") != 0) return LineMode::Plain;
    const size_t nl = text->find('\n');
    const std::string hdr = text->substr(9, (nl == std::string::npos ? text->size() : nl) - 9);
    LineMode mode = LineMode::Plain;
    if (hdr.compare(0, 8, "frontrev") == 0) mode = LineMode::FrontRev;
    else if (hdr.compare(0, 3, "rev") == 0) mode = LineMode::Rev;
    text->erase(0, nl == std::string::npos ? text->size() : nl + 1);
    return mode;
}

/* Expand front-coded records into ordinary lines, so that everything downstream
 * sees one shape of input. */
std::string expand_frontrev(const std::string& in) {
    std::string out, prev;
    out.reserve(in.size() * 2);
    size_t pos = 0;
    while (pos < in.size()) {
        size_t nl = in.find('\n', pos);
        if (nl == std::string::npos) nl = in.size();
        if (nl > pos) {
            size_t shared = (unsigned char)in[pos] - 0x20;
            if (shared > prev.size()) shared = prev.size();   /* corrupt: clamp */
            std::string rec = prev.substr(0, shared);
            rec.append(in, pos + 1, nl - pos - 1);
            out.append(rec);
            out.push_back('\n');
            prev.swap(rec);
        }
        pos = nl + 1;
    }
    return out;
}

/* Reads the baked baseline and returns its text, already un-front-coded.
 * `reversed` reports whether the caller must un-reverse the labels. */
bool load_baseline(std::string* text, bool* reversed, std::string* why) {
    std::string raw;
    if (!nr_read_file(NR_PATH_BASELINE, &raw, why)) return false;

    /* Optional integrity file. It is inside a verity-protected signed image, so
     * this is a build-mistake detector rather than a security control — but a
     * baseline that was truncated by a bad prebuilt rule would otherwise become
     * a silently smaller blocklist. */
    std::string sums;
    if (nr_read_file((std::string(NR_PATH_BASELINE) + ".sha256").c_str(), &sums, nullptr)) {
        uint8_t d[32];
        char hex[65];
        nr_sha256(raw.data(), raw.size(), d);
        nr_sha256_hex(d, hex);
        size_t b = 0;
        while (b < sums.size() && (unsigned char)sums[b] <= ' ') ++b;
        size_t e = b;
        while (e < sums.size() && (unsigned char)sums[e] > ' ') ++e;
        const std::string want = sums.substr(b, e - b);
        if (!want.empty() && strcasecmp(want.c_str(), hex) != 0) {
            *why = "baseline sha256 mismatch";
            return false;
        }
    }

    if (looks_like_xz(raw)) {
        std::string plain;
        if (!xz_decode(raw, &plain, why)) return false;
        raw.swap(plain);
    }

    const LineMode mode = read_header(&raw);
    *reversed = (mode != LineMode::Plain);
    *text = (mode == LineMode::FrontRev) ? expand_frontrev(raw) : raw;
    return true;
}

// ---------------------------------------------------------------------------
// Compile + publish
// ---------------------------------------------------------------------------

BuildRedirect probe_redirect() {
    BuildRedirect r;
    r.domain = NR_PROBE_IDX_NAME;
    r.family = AF_INET;
    memset(r.addr, 0, sizeof(r.addr));
    r.addr[0] = 127; r.addr[1] = 0; r.addr[2] = 0; r.addr[3] = 7;
    return r;
}

bool compile_baseline(uint64_t generation, uint64_t* out_generation) {
    std::string text, why;
    bool reversed = false;
    if (!load_baseline(&text, &reversed, &why)) {
        ALOGE("baseline unusable: %s", why.c_str());
        set_state("nobaseline");
        return false;
    }

    NrCompileSpec spec;
    spec.generation  = generation;
    spec.built_at_ms = nr_now_ms();

    NrCompileInput base;
    base.text            = std::move(text);
    base.path            = NR_PATH_BASELINE;
    base.group           = NR_GROUP_BASELINE;
    base.role            = NR_ROLE_LIST;
    base.reversed_labels = reversed;
    base.optional        = false;
    spec.inputs.push_back(std::move(base));

    /* The never-block floor, as K_FORCE. It beats any block at any depth, which
     * is what stops a bad list from taking FCM push or the captive-portal check
     * down on a device with no UI to fix it from. */
    NrCompileInput floor;
    floor.path  = NR_PATH_NEVERBLOCK;
    floor.group = NR_GROUP_FLOOR;
    floor.role  = NR_ROLE_FORCE;
    spec.inputs.push_back(floor);

    /* Anti-fraud fingerprinting and attribution/deep-link domains are allow
     * overlays unless the user opts the category in (§7.6). On first boot nobody
     * has opted in to anything, so they go in as allows — this is the difference
     * between a banking app that works out of the box and a support ticket. */
    for (const char* p : {NR_PATH_ANTIFRAUD, NR_PATH_ATTRIB}) {
        NrCompileInput carve;
        carve.path  = p;
        carve.group = NR_GROUP_CARVEOUT;
        carve.role  = NR_ROLE_ALLOW;
        spec.inputs.push_back(carve);
    }

    spec.redirects.push_back(probe_redirect());

    std::vector<uint8_t> blob;
    NrCompileResult res;
    std::string err;
    if (!nr_compile(spec, &blob, &res, &err)) {
        ALOGE("compile failed: %s", err.c_str());
        set_state("error:compile");
        return false;
    }
    if (!nr_write_file_atomic(NR_PATH_INDEX_CURRENT, blob.data(), blob.size(), &err)) {
        ALOGE("cannot publish the index: %s", err.c_str());
        set_state("error:write");
        return false;
    }
    ALOGI("compiled generation %llu: %u block, %u allow, %u redirect, %llu bytes, %llu ms",
          (unsigned long long)res.generation, res.block_kept, res.allow_kept,
          res.redirects, (unsigned long long)res.bytes,
          (unsigned long long)res.elapsed_ms);
    *out_generation = res.generation;
    return true;
}

/* Returns the generation of a valid index at `path`, or 0. */
uint64_t index_generation(const char* path) {
    NrIndexRO idx;
    if (!nr_index_open_ro(path, &idx, nullptr)) return 0;
    const uint64_t gen = idx.ix.hdr->generation;
    nr_index_close_ro(&idx);
    return gen;
}

}  // namespace

int main(int, char**) {
    /* Modes are set explicitly with fchmod; init's umask must not have a say in
     * whether the app can write its own control page. */
    umask(0);

    const Breaker breaker = boot_loop_breaker();

    /* The state directories are created by init (§8.4), but creating them here
     * too costs nothing and means a device whose init.nullroute.rc was dropped by
     * a bad merge produces a diagnosable failure instead of a silent one. */
    ensure_dir(NR_DIR_ROOT, 0771);
    ensure_dir(NR_DIR_INDEX, 0770);
    ensure_dir(NR_DIR_CTL, 0770);
    ensure_dir(NR_DIR_LOG, 0770);
    ensure_dir(NR_DIR_PRIV, 0770);

    bool created_ctl = false, created_ring = false;
    /* 0660: the app (group misc) writes mode and uid_policy here, and netd writes
     * the telemetry lines. 0640 for the ring: netd writes it as root and the app
     * only ever reads. */
    const bool have_ctl  = ensure_file(NR_PATH_CONTROL, NR_CONTROL_BYTES, 0660, false, &created_ctl);
    const bool have_ring = ensure_file(NR_PATH_RING, NR_RING_BYTES, 0640, true, &created_ring);
    if (!have_ring) ALOGE("no ring; logging will be disabled but filtering is unaffected");

    if (breaker == Breaker::Quarantined) {
        set_state("quarantined");
        return 0;                       /* the third bad boot ends clean */
    }
    if (nr_prop_get_i64(NR_PROP_KILL, 0) == 1) {
        /* Files are still created above — the kill switch turns filtering off, it
         * does not take the app's configuration storage away. */
        set_state("killed");
        return 0;
    }
    if (!have_ctl) {
        set_state("error:control");
        return 0;                       /* never non-zero: init would log a fault */
    }

    uint64_t gen = index_generation(NR_PATH_INDEX_CURRENT);

    if (gen == NR_GEN_NONE) {
        /* Degradation ladder (§6.3): current -> previous -> recompiled baseline.
         * previous.nrdx is the last blob that passed a canary, so preferring it
         * over a fresh baseline keeps the user's own rules and profile. */
        const uint64_t prev = index_generation(NR_PATH_PREVIOUS);
        if (prev != NR_GEN_NONE && rename(NR_PATH_PREVIOUS, NR_PATH_INDEX_CURRENT) == 0) {
            gen = prev;
            ALOGI("restored generation %llu from previous.nrdx", (unsigned long long)prev);
            set_state("restored:%llu", (unsigned long long)gen);
        } else {
            /* Generation must move forward across the boundary: control.bin may
             * remember a higher want_generation from before whatever destroyed
             * the index. Reusing a number the resolver has already seen would
             * leave it convinced it is up to date. */
            NrCtlMap probe;
            uint64_t next = 1;
            if (nr_ctl_open(NR_PATH_CONTROL, false, &probe, nullptr)) {
                NrCtlSnapshot s;
                nr_ctl_read(probe, &s);
                if (s.want_generation >= next) next = s.want_generation + 1;
                nr_ctl_close(&probe);
            }
            uint64_t built = 0;
            if (compile_baseline(next, &built)) {
                gen = built;
                set_state("compiled:%llu", (unsigned long long)gen);
            }
        }
    } else {
        set_state("ok:%llu", (unsigned long long)gen);
    }

    /*
     * Reconcile the control page with what is actually on disk.
     *
     * The resolver remaps whenever ctl.want_generation differs from the
     * generation it has mapped. Two states are therefore fatal and both are
     * reachable after a crash or a wipe of one file but not the other:
     *
     *   want == 0 with a real index  -> the resolver never maps anything
     *   want != the index's own gen  -> the resolver remaps on EVERY query
     *
     * Nothing else is running at post-fs-data, so this is the one safe moment to
     * assert the invariant.
     */
    NrCtlMap ctl;
    std::string err;
    if (nr_ctl_open(NR_PATH_CONTROL, true, &ctl, &err)) {
        NrCtlSnapshot s;
        nr_ctl_read(ctl, &s);
        if (s.want_generation != gen) {
            nr_ctl_set_want_generation(&ctl, gen);
            ALOGI("want_generation %llu -> %llu", (unsigned long long)s.want_generation,
                  (unsigned long long)gen);
        }
        /* Mode is persisted in a property and derived into control.bin, so the two
         * authorities can never disagree (§6.3). Only mirror a value that exists:
         * an unset property means "never configured", not "enforce". Init's
         * `on property:` trigger re-runs this through `nrctl syncprop` if the
         * persisted value lands after us. */
        const std::string mode_prop = nr_prop_get(NR_PROP_MODE, "");
        uint8_t mode;
        if (!mode_prop.empty() && nr_mode_parse(mode_prop.c_str(), &mode))
            nr_ctl_set_mode(&ctl, mode);
        nr_ctl_close(&ctl);
    } else {
        ALOGE("cannot open the control page for writing: %s", err.c_str());
    }

    /* Qualify the outcome rather than replace it: "we compiled generation 3, and
     * by the way the boot-loop breaker was blind this boot" is two facts, and
     * Diagnostics needs both. */
    if (breaker == Breaker::PropsUnavailable) {
        /* Via a copy: set_state formats INTO g_state, and passing it as its own
         * argument would be an overlapping vsnprintf. */
        const std::string so_far(g_state);
        set_state("%s+noprops", so_far.c_str());
    }
    return 0;
}
