/*
 * Nullroute — the query-log ring, /data/misc/nullroute/log/ring.bin.
 *
 * 256 KiB = 4096 records x 64 bytes. Multi-producer (every netd thread),
 * single-consumer (the app). Overwrite-oldest.
 *
 * Logging is BEST EFFORT and must never block, slow or fail a lookup. If the
 * ring cannot be mapped, logging is silently disabled and filtering continues
 * unaffected. Drops are counted in NrControl::ring_drops and surfaced in
 * Diagnostics — the app does not pretend the log is complete.
 *
 * Label `nullroute_log_file`: netd rw, app ro + map.
 */
#ifndef NULLROUTE_NR_RING_H
#define NULLROUTE_NR_RING_H

#include <stdint.h>

#define NR_RING_SLOTS 4096u
#define NR_RING_REC   64u
#define NR_RING_BYTES (NR_RING_SLOTS * NR_RING_REC + 4096u)  /* + one header page */
#define NR_RING_NAME  45u

#ifdef __cplusplus
namespace nr {

struct NrRingHeader {      /* page 0 */
    uint32_t magic;        /* 'NRRG' */
    uint32_t version;
    uint64_t head;         /* monotonic; slot = head % NR_RING_SLOTS */
    uint8_t  _pad[4096 - 16];
};

struct NrLogRec {          /* exactly 64 bytes, one per record */
    uint64_t seq;          /* release-stored LAST so a consumer can detect a torn record */
    uint64_t ts_ms;
    uint32_t uid;
    uint16_t rule_group;
    uint8_t  verdict;      /* VerdictKind */
    uint8_t  depth;
    uint8_t  name_len;
    uint8_t  flags;        /* bit0 = name truncated */
    char     name[NR_RING_NAME];
    uint8_t  _pad;
};

static_assert(sizeof(NrLogRec) == NR_RING_REC, "log record must be exactly 64 bytes");

}  /* namespace nr */
#endif /* __cplusplus */
#endif /* NULLROUTE_NR_RING_H */
