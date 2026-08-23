/*
 * Nullroute — control-page accessors plus the read-side helpers that the CLI,
 * the boot seeder and the JNI bridge all need.
 *
 * SCOPE, deliberately: none of this is ever linked into netd. `libnrfilter`
 * (NrCanon/NrQuery/NrMap) is the only thing the resolver gets, and it stays
 * allocation-free and dependency-free for that reason. Everything here may
 * allocate, may do I/O and may use the STL, because every caller is either an
 * app process or a oneshot boot binary.
 *
 * It exists as ONE unit rather than five because `nrctl`, `nullroute_seed` and
 * `libnrjni` must answer questions identically — a query explained one way by
 * the CLI and another way by the app is exactly the bug class this project
 * exists to avoid. The verdict itself always comes from nr_evaluate(); nothing
 * here re-implements matching, hashing or building.
 */
#ifndef NULLROUTE_NR_CTL_H
#define NULLROUTE_NR_CTL_H

#include <stdint.h>
#include <stddef.h>

#include <string>
#include <vector>

#include "NrBuilder.h"
#include "NrControl.h"
#include "NrIndex.h"
#include "NrQuery.h"
#include "NrVerdict.h"

/* ---------------------------------------------------------------------------
 * Paths (§7.1). Native-side constants live here rather than being duplicated
 * from core/Paths.kt: three separately-built binaries open these files and a
 * typo in one of them is a silent no-filter device.
 * ------------------------------------------------------------------------- */
#define NR_DIR_ROOT        "/data/misc/nullroute"
#define NR_DIR_INDEX       NR_DIR_ROOT "/index"
#define NR_DIR_CTL         NR_DIR_ROOT "/ctl"
#define NR_DIR_LOG         NR_DIR_ROOT "/log"
#define NR_DIR_PRIV        NR_DIR_ROOT "/priv"

#define NR_PATH_CURRENT    NR_DIR_INDEX "/current.nrdx"
#define NR_PATH_PREVIOUS   NR_DIR_INDEX "/previous.nrdx"
#define NR_PATH_QUARANTINE NR_DIR_INDEX "/quarantine.nrdx"
#define NR_PATH_CONTROL    NR_DIR_CTL   "/control.bin"
#define NR_PATH_RING       NR_DIR_LOG   "/ring.bin"

#define NR_DIR_ETC         "/system_ext/etc/nullroute"
#define NR_PATH_BASELINE   NR_DIR_ETC "/baseline.domains.xz"
#define NR_PATH_NEVERBLOCK NR_DIR_ETC "/neverblock.txt"
#define NR_PATH_ANTIFRAUD  NR_DIR_ETC "/antifraud.txt"
#define NR_PATH_ATTRIB     NR_DIR_ETC "/attribution.txt"

/* ---------------------------------------------------------------------------
 * Properties. `persist.sys.nullroute.*` survive reboot and are the on-disk
 * source of truth for mode and for the boot-loop breaker; `sys.nullroute.*` are
 * volatile observability signals that deliberately do NOT transit control.bin,
 * so a failed mapping of the control page cannot hide its own failure (§3.4).
 * ------------------------------------------------------------------------- */
#define NR_PROP_KILL        "persist.sys.nullroute.kill"
#define NR_PROP_MODE        "persist.sys.nullroute.mode"
#define NR_PROP_BOOT_OK     "persist.sys.nullroute.boot_ok"
#define NR_PROP_FAIL_STREAK "persist.sys.nullroute.fail_streak"
#define NR_PROP_FILTER      "sys.nullroute.filter"   /* written by netd  */
#define NR_PROP_SEED        "sys.nullroute.seed"     /* written by the seeder */

/* The boot-loop breaker quarantines at this streak (§6.1). */
#define NR_FAIL_STREAK_LIMIT 3

/* Liveness probes (§6.7). `.invalid` is deliberately absent from the matcher's
 * skip-suffix list so these can reach the index. */
#define NR_PROBE_IDX_NAME  "idx-probe.nullroute.invalid"
#define NR_PROBE_IDX_ADDR  "127.0.0.7"
#define NR_PROBE_HOSTS_NAME "hosts-probe.nullroute.invalid"

/* generation 0 means "no index". The resolver remaps whenever
 * ctl.want_generation != the generation it currently has mapped, so an index
 * whose header says 0 would either never be mapped or be remapped on every
 * single query. Both are unacceptable; the builder refuses to emit one. */
#define NR_GEN_NONE 0u

/* ---------------------------------------------------------------------------
 * Rule groups. A slot carries 16 bits of `rule_group` (NrHash.h); it is what
 * the log and `nrctl query` use to say WHERE a rule came from. Fetched sources
 * get 1..NR_GROUP_SOURCE_MAX in the order the compile step listed them; the
 * high ids are reserved for inputs that are not a fetched list.
 * ------------------------------------------------------------------------- */
#define NR_GROUP_UNKNOWN     0u
#define NR_GROUP_SOURCE_MIN  1u
#define NR_GROUP_SOURCE_MAX  0xFFEFu
#define NR_GROUP_BASELINE    0xFFF0u   /* baked baseline compiled by the seeder */
#define NR_GROUP_USER_DENY   0xFFF1u   /* priv/deny.txt                          */
#define NR_GROUP_USER_ALLOW  0xFFF2u   /* priv/allow.txt                         */
#define NR_GROUP_REDIRECT    0xFFF3u   /* priv/redirect.txt                      */
#define NR_GROUP_FLOOR       0xFFF4u   /* neverblock.txt, compiled-in K_FORCE    */
#define NR_GROUP_CARVEOUT    0xFFF5u   /* antifraud.txt / attribution.txt        */
#define NR_GROUP_HOTFIX      0xFFF6u   /* BestROM hotfix allow feed              */
#define NR_GROUP_PROBE       0xFFF7u   /* the .invalid liveness redirects        */

namespace nr {

/* Human name for a reserved group, or nullptr for a fetched-source id (whose
 * name lives in manifest.<gen>.json — see nr_manifest_group_name). */
const char* nr_group_builtin_name(uint16_t group);

const char* nr_mode_name(uint8_t mode);
const char* nr_resp_name(uint8_t resp);
const char* nr_kind_name(uint8_t kind);
const char* nr_verdict_name(uint8_t verdict);

/* Accepts "enforce"/"on", "paused"/"pause", "off"/"disabled", or a bare 0/1/2.
 * The persisted property is the source of truth for mode (§6.3) and is written
 * by humans as often as by the app, so parsing is forgiving. */
bool nr_mode_parse(const char* s, uint8_t* out_mode);

uint64_t nr_now_ms(void);

/* ---------------------------------------------------------------------------
 * Properties. Thin wrappers over bionic so the callers stay readable; on a
 * non-Android host build they degrade to "unset" rather than failing to
 * compile, which keeps the CLI and the seeder host-compilable for tests.
 * ------------------------------------------------------------------------- */
std::string nr_prop_get(const char* name, const char* dflt = "");
int64_t     nr_prop_get_i64(const char* name, int64_t dflt);
bool        nr_prop_set(const char* name, const char* value);
bool        nr_prop_set_i64(const char* name, int64_t value);

/* ---------------------------------------------------------------------------
 * Read-only mappings
 * ------------------------------------------------------------------------- */
struct NrMapRO {
    const uint8_t* base = nullptr;
    size_t         size = 0;
    int            fd   = -1;
};

/* MAP_PRIVATE|PROT_READ. `err` (optional) receives a human string including the
 * errno text — every failure path in this file names its errno, because the
 * classic silent failure is EACCES on mmap after a successful open (§10.7). */
bool nr_map_file_ro(const char* path, NrMapRO* out, std::string* err = nullptr);
void nr_unmap_file(NrMapRO* m);

struct NrIndexRO {
    NrMapRO map;
    NrIndex ix{};
};

/* Maps and runs nr_index_validate(). Never partially succeeds: on false the
 * mapping is already released. */
bool nr_index_open_ro(const char* path, NrIndexRO* out, std::string* err = nullptr);
void nr_index_close_ro(NrIndexRO* out);

/* ---------------------------------------------------------------------------
 * control.bin
 * ------------------------------------------------------------------------- */
struct NrCtlMap {
    NrControl* p        = nullptr;
    int        fd       = -1;
    size_t     size     = 0;
    bool       writable = false;
};

/* `writable` needs O_RDWR, which the `shell` domain deliberately does not have
 * (rom/sepolicy/nrctl.te grants r_file_perms only). That is why every mutating
 * CLI verb goes through the app's broadcast receiver instead. */
bool nr_ctl_open(const char* path, bool writable, NrCtlMap* out, std::string* err = nullptr);
void nr_ctl_close(NrCtlMap* m);

struct NrCtlSnapshot {
    uint64_t want_generation, mapped_generation;
    uint64_t q_total, q_blocked, q_passed, last_map_ms;
    uint32_t config_epoch, filter_abi, map_errors, ring_drops, fault_count;
    uint8_t  mode, response_mode, log_level, cname_uncloak;
};

/* Field-by-field acquire loads. The page is written concurrently by netd, so a
 * struct copy could tear; nothing here is worth a lock on the resolver's side. */
void nr_ctl_read(const NrCtlMap& m, NrCtlSnapshot* out);

/* Release-store of ctl.mode. Returns false if the mapping is read-only. */
bool nr_ctl_set_mode(NrCtlMap* m, uint8_t mode);

/* Release-store of ctl.want_generation. Publishing an index is rename() THEN
 * this store, never the other way round. */
bool nr_ctl_set_want_generation(NrCtlMap* m, uint64_t gen);

/* ---------------------------------------------------------------------------
 * Query explanation
 *
 * nr_evaluate() answers "blocked or not" in ~200 ns and returns depth + group,
 * which is all the resolver needs. The UI and the CLI have to answer WHY, so
 * nr_explain() additionally probes each label boundary directly and reports what
 * is stored there.
 *
 * The verdict reported to the user is ALWAYS NrExplain::verdict, which comes
 * from nr_evaluate() — the per-depth trace is diagnostic colour beside it, never
 * a second opinion. If the two ever disagree, the trace is wrong and the tool
 * must still be reporting what the resolver will really do.
 * ------------------------------------------------------------------------- */
struct NrExplainStep {
    uint8_t  depth;          /* 1 = TLD, 2 = apex, ...                       */
    uint16_t suffix_off;     /* byte offset into NrExplain::canon            */
    bool     plausible;      /* survived the matcher's label_mask/min/max gate */
    bool     block_hit, block_applies;
    bool     allow_hit, allow_applies;
    uint8_t  block_kind, allow_kind;
    uint16_t block_group, allow_group;
};

struct NrExplain {
    bool     usable = false;   /* false => the matcher PASSes without looking */
    char     canon[NR_MAX_NAME + 3];
    uint8_t  depth = 0;        /* label count D                              */
    Verdict  verdict{};
    uint8_t  n_steps = 0;
    NrExplainStep steps[NR_MAX_LABELS];
    bool     redirect_hit = false;
    char     redirect_addr[46];  /* INET6_ADDRSTRLEN                          */
    /* The matched rule as text, reconstructed from the winning depth: it is by
     * construction the last `verdict.depth` labels of the canonical name, which
     * is exactly the string the builder hashed. Empty when nothing matched. */
    char     matched_rule[NR_MAX_NAME + 1];
};

void nr_explain(const NrIndex& ix, const char* host, size_t len, NrExplain* out);

/* Steps are ordered most-specific first, matching the matcher's walk. */
static inline const char* nr_explain_suffix(const NrExplain& e, unsigned i) {
    return e.canon + e.steps[i].suffix_off;
}

/* Hagezi (and every other curated list) deliberately omits the apexes users
 * reach for when testing. Returns a one-line explanation for such a domain, or
 * nullptr. Surfacing this at the moment of the surprising answer is the whole
 * point — otherwise every user tests with doubleclick.net and files a bug. */
const char* nr_expected_absence_note(const char* canon_name);

/* ---------------------------------------------------------------------------
 * Verification
 * ------------------------------------------------------------------------- */
struct NrVerifyReport {
    bool        ok = false;
    std::string error;
    std::string path;
    uint64_t    size = 0;
    uint16_t    fmt_version = 0, flags = 0, label_mask = 0;
    uint64_t    generation = 0, built_at_ms = 0, hash_seed = 0;
    uint32_t    n_block = 0, n_allow = 0, n_redirect = 0;
    uint32_t    bt_cap = 0, at_cap = 0, rt_cap = 0;
    uint8_t     min_labels = 0, max_labels = 0;
    uint64_t    sec_off[NR_SEC_COUNT] = {}, sec_len[NR_SEC_COUNT] = {};
    int         sha_state = -1;      /* 1 match, 0 MISMATCH, -1 not set      */
    char        sha_header[65] = {}, sha_actual[65] = {};
    bool        probe_present = false;
    char        probe_addr[46] = {};
};

bool nr_verify_index(const char* path, NrVerifyReport* out);

/* ---------------------------------------------------------------------------
 * Compilation
 *
 * One entry point for all three producers: `nrctl build`, the app's
 * nativeBuild() and the seeder's first-boot baseline compile. They differ only
 * in which inputs they hand it.
 * ------------------------------------------------------------------------- */
#define NR_ROLE_LIST     0u  /* a blocklist; the line's own syntax (@@ @ !) decides */
#define NR_ROLE_ALLOW    1u  /* force every parsed entry into the allow set         */
#define NR_ROLE_FORCE    2u  /* allow as K_FORCE — the never-block floor            */
#define NR_ROLE_REDIRECT 3u  /* "<ip> <domain>" pairs                               */

struct NrCompileInput {
    std::string path;            /* read from disk unless `text` is set          */
    std::string text;            /* pre-loaded content (the seeder decompresses) */
    uint16_t    group    = NR_GROUP_UNKNOWN;
    uint8_t     role     = NR_ROLE_LIST;
    bool        optional = true; /* a missing optional input is recorded, not fatal */
    bool        reversed_labels = false;  /* lines are "com.example.ads"          */
};

struct NrCompileSpec {
    std::vector<NrCompileInput> inputs;
    std::vector<BuildRedirect>  redirects;   /* caller-supplied, e.g. the probes */
    uint64_t generation  = 0;
    uint64_t built_at_ms = 0;
    uint64_t hash_seed   = 0;                /* 0 => the builder's default       */
};

struct NrSourceStat {
    std::string path;
    uint16_t    group = 0;
    uint8_t     role  = NR_ROLE_LIST;
    size_t      lines = 0, parsed = 0, rejected = 0;
    bool        present = false;
    std::string error;
};

struct NrCompileResult {
    BuildStats                stats{};
    std::vector<NrSourceStat> sources;
    uint64_t                  generation = 0;
    uint64_t                  bytes      = 0;
    uint32_t                  block_kept = 0, allow_kept = 0, redirects = 0;
    uint64_t                  elapsed_ms = 0;
    char                      sha256_hex[65] = {};
};

/* Produces a finished NRDX blob with sha256 filled in. Returns false and sets
 * `err` on a hard failure; a per-source read failure is recorded in
 * NrCompileResult::sources and is NOT fatal (a truncated download must degrade
 * visibly, never silently zero the list). */
bool nr_compile(const NrCompileSpec& spec, std::vector<uint8_t>* blob,
                NrCompileResult* result, std::string* err);

/* write to <path>.tmp.<pid>, fsync, rename, fsync(dir). The rename is what makes
 * a reader see either the whole old file or the whole new one. */
bool nr_write_file_atomic(const char* path, const void* data, size_t len, std::string* err);

/* ---------------------------------------------------------------------------
 * manifest.<gen>.json — advisory only
 *
 * The numeric group in the index is authoritative; the manifest merely gives it
 * a name. Parsed with a deliberately narrow scanner (find an object containing
 * "group": N, take its "name") rather than a JSON library: this runs in a boot
 * binary and in the CLI, the file is ours, and a parse failure must cost the
 * name only, never the answer.
 * ------------------------------------------------------------------------- */
bool nr_manifest_group_name(const char* index_dir, uint64_t generation,
                            uint16_t group, std::string* out);

/* ---------------------------------------------------------------------------
 * SHA-256 (FIPS 180-4)
 *
 * Here rather than in a library because the three consumers — `nrctl verify`,
 * the seeder's baseline check and nativeBuild() filling NrHeader::sha256 — must
 * agree, and because pulling libcrypto into a `class core` boot binary to hash
 * 4 MB once is a bad trade. nr_sha256_selftest() is wired into `nrctl selftest`.
 * ------------------------------------------------------------------------- */
void nr_sha256(const void* data, size_t len, uint8_t out[32]);
void nr_sha256_hex(const uint8_t digest[32], char out[65]);
bool nr_sha256_selftest(void);

/* ---------------------------------------------------------------------------
 * JSON
 *
 * Emitted as text from one place so `nrctl --json` and the JNI bridge produce
 * byte-identical shapes; the app's Query screen and the CLI must never be able
 * to disagree about a verdict.
 * ------------------------------------------------------------------------- */
void        nr_json_escape(const char* s, size_t n, std::string* out);
std::string nr_json_query(const NrIndexRO& index, const char* index_path, const char* host);
std::string nr_json_verify(const NrVerifyReport& r);
std::string nr_json_compile(const NrCompileResult& r, const char* out_path);

/* Small helpers the CLI and the bridge share. */
bool nr_read_file(const char* path, std::string* out, std::string* err);
void nr_format_ms(uint64_t epoch_ms, char* out, size_t n);   /* ISO-8601 UTC */

}  // namespace nr
#endif /* NULLROUTE_NR_CTL_H */
