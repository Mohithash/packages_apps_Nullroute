/*
 * Nullroute — the shared control page, /data/misc/nullroute/ctl/control.bin.
 *
 * 128 KiB, MAP_SHARED, mapped read-write by BOTH the app and netd. The label
 * `nullroute_ctl_file` grants rw to both domains; this is deliberately a
 * different label from the index (netd ro) and the ring (app ro), because a
 * single label with the union of the permissions would let netd rewrite the
 * index it is supposed to only read.
 *
 * Layout is by cache line so the app's writes and the resolver's writes never
 * share a line — false sharing here would be a per-query cost on the hot path.
 *
 * IMPORTANT: this file is pre-created at the correct size and ownership by
 * nullroute_seed at post-fs-data. netd only ever open()s and mmap()s an existing
 * file and never creates one, because netd runs as root and would otherwise
 * leave a root-owned file the app cannot write.
 */
#ifndef NULLROUTE_NR_CONTROL_H
#define NULLROUTE_NR_CONTROL_H

#include <stdint.h>
#include <stddef.h>
#include "NrVerdict.h"

#define NR_CONTROL_BYTES   (128u * 1024u)
#define NR_UID_POLICY_OFF  4096u
#define NR_UID_POLICY_LEN  100000u    /* appId space: uid % AID_USER_OFFSET   */
#define NR_AID_USER_OFFSET 100000u

#ifdef __cplusplus
namespace nr {

struct NrControl {
    /* ---- cache line 0: written by the app, read by the resolver ---------- */
    uint64_t want_generation;   /* release-stored AFTER rename() of the new index */
    uint8_t  mode;              /* NR_MODE_*        */
    uint8_t  response_mode;     /* NR_RESP_*        */
    uint8_t  log_level;         /* 0 none, 1 blocked-only, 2 all */
    uint8_t  cname_uncloak;
    uint32_t config_epoch;
    uint8_t  _pad0[48];         /* pad line 0 out to exactly 64 bytes */

    /* ---- cache lines 1-2: written by the resolver, read by the app -------
     * These are TELEMETRY ONLY. They deliberately are not the health signal:
     * a counter that lives inside the page whose mapping is the most likely
     * thing to fail cannot report its own death. The authoritative signals are
     * the dual .invalid probes and the sys.nullroute.filter property. */
    uint64_t mapped_generation;
    uint64_t q_total, q_blocked, q_passed;
    uint64_t last_map_ms;
    uint32_t filter_abi;        /* NR_FMT_VERSION the INSTALLED resolver supports */
    uint32_t map_errors, ring_drops, fault_count;
    uint8_t  _pad1[NR_UID_POLICY_OFF - 120];

    /* ---- offset 4096: written by the app, read by the resolver ----------- */
    uint8_t  uid_policy[NR_UID_POLICY_LEN];   /* NR_POLICY_*, index = appId */
};

/* These offsets are an ABI contract between two independently-built binaries
 * (the app's libnrjni and netd's libnetd_resolv). Assert them rather than
 * trusting that nobody reorders a field. */
static_assert(sizeof(NrControl) <= NR_CONTROL_BYTES, "control page overflows 128 KiB");
static_assert(offsetof(NrControl, mapped_generation) == 64,
              "resolver-written block must start on cache line 1");
static_assert(offsetof(NrControl, uid_policy) == NR_UID_POLICY_OFF,
              "uid_policy must sit at offset 4096");

}  /* namespace nr */
#endif /* __cplusplus */
#endif /* NULLROUTE_NR_CONTROL_H */
