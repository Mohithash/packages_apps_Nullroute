/*
 * Nullroute — mapping the index and the shared pages, with an RCU-style publish.
 *
 * Compiled into `libnrfilter` and therefore linked by BOTH netd (via
 * whole_static_libs on libnetd_resolv) and the app (via libnrjni / nrctl). It
 * owns every mmap the filter performs and is the only place that turns a path on
 * disk into an `NrIndex` the matcher will trust.
 *
 * Two properties drive the whole design:
 *
 *   1. A query in flight must never have its mapping unmapped underneath it.
 *      The publisher swaps a pointer; the old mapping stays mapped until its
 *      last reader has dropped its reference.
 *
 *   2. Nothing here may ever free the object a reader is about to touch. The
 *      NrMapping control blocks therefore live in a fixed static pool and are
 *      RECYCLED, never deleted. A reader that loses the publish race increments
 *      the refcount of a recycled slot — which is always readable memory — sees
 *      that it is no longer current, and drops it. There is no window in which a
 *      reader can dereference freed memory, which is the only acceptable answer
 *      inside netd, whose init stanza carries `onrestart restart zygote`.
 */
#ifndef NULLROUTE_NR_MAP_H
#define NULLROUTE_NR_MAP_H

#include <stdint.h>
#include <stddef.h>
#include <atomic>

#include "NrControl.h"
#include "NrIndex.h"

/* Canonical on-disk locations. netd only ever open()s these; it never creates
 * one, because netd runs as root and would leave a root-owned file the app
 * cannot write. nullroute_seed pre-creates all three at post-fs-data. */
#define NR_PATH_INDEX_CURRENT  "/data/misc/nullroute/index/current.nrdx"
#define NR_PATH_CONTROL        "/data/misc/nullroute/ctl/control.bin"
#define NR_PATH_RING           "/data/misc/nullroute/log/ring.bin"

/* Slots in the static mapping pool. Publishing happens roughly once a day, so
 * four is generous; the pool exists to bound memory and to make recycling
 * (rather than freeing) possible, not to support a high swap rate. */
#define NR_MAP_SLOTS      4u

/* Refuse absurd files before mmap. AGGRESSIVE measures ~9.1 MB; anything past
 * 64 MiB is a corrupt or hostile artefact, not an index. */
#define NR_MAP_MAX_BYTES  (64ull * 1024ull * 1024ull)

namespace nr {

/* Why an open failed, for the `sys.nullroute.filter` property and the log.
 * Exactly one of the two is set: a syscall failure carries an errno, a
 * structural rejection carries a static field name. */
struct NrMapError {
    int         errno_value;
    const char* field;
};

enum NrSlotState : uint32_t {
    NR_SLOT_FREE    = 0,   /* must be 0: the pool lives in .bss */
    NR_SLOT_BUSY    = 1,   /* claimed by an open() in progress   */
    NR_SLOT_LIVE    = 2,
    NR_SLOT_RETIRED = 3,   /* no longer current; unmapped once refs hits 0 */
};

/*
 * One mapped generation of the index. Allocated from the static pool, never
 * freed. `index` is only meaningful while the slot is LIVE or RETIRED, and only
 * to a caller holding a reference.
 *
 * `refs` outlives the slot's identity. It is a strict +1/-1 discipline that is
 * NEVER reset, because a reader that lost the publish race can still be between
 * its fetch_add and its fetch_sub while the slot is being recycled. Resetting it
 * would swallow the pending +1 and let the matching -1 wrap the next occupant's
 * count to UINT32_MAX — a slot that can never be reclaimed again. A slot is
 * therefore claimable only while refs reads exactly 0, and the publisher takes
 * its own reference with an RMW rather than a store.
 */
struct NrMapping {
    std::atomic<uint32_t> refs;
    std::atomic<uint32_t> state;
    const uint8_t*        base;
    size_t                size;
    uint64_t              generation;
    NrIndex               index;
};

/*
 * Open + fstat + mmap + validate, atomically from the caller's point of view:
 * either a fully validated LIVE slot comes back with one reference already held
 * (the publisher's), or nullptr and `err` says why.
 *
 * Callable only from the slow path — it allocates address space and touches the
 * filesystem. Never call it from a DNS query's fast path.
 */
NrMapping* nr_mapping_open(const char* path, NrMapError* err);

/*
 * Reference counting.
 *
 * seq_cst, not acq_rel, and deliberately so. The publish protocol is a
 * store-buffer (Dekker) pattern across two threads:
 *
 *      reader:     refs.fetch_add(1)   then   load(cur)
 *      publisher:  exchange(cur)       then   load(refs)
 *
 * If either side is allowed to reorder its two operations, the reader can
 * observe `cur == m` while the publisher observes `refs == 0` and unmaps m.
 * Only sequential consistency forbids that outcome. On arm64 this costs an
 * `ldaddal` plus an `ldar` — tens of nanoseconds against a 300-500 ns budget.
 */
static inline void nr_mapping_acquire(NrMapping* m) {
    m->refs.fetch_add(1, std::memory_order_seq_cst);
}
static inline void nr_mapping_release(NrMapping* m) {
    m->refs.fetch_sub(1, std::memory_order_seq_cst);
}

/* Mark a mapping no longer current. Does NOT unmap: the unmap happens in
 * nr_mapping_reclaim(), on the next slow path, once refs has drained. */
void nr_mapping_retire(NrMapping* m);

/* Unmap every retired slot whose refcount has reached zero and return it to the
 * pool. Slow path only; safe to call when there is nothing to do. */
void nr_mapping_reclaim();

/*
 * A short static string naming the first structural problem found in a rejected
 * index, for `badhdr:<field>`.
 *
 * ADVISORY ONLY. nr_index_validate() is the authority and has already returned
 * false by the time this runs; this function exists so the failure is
 * diagnosable from `getprop` and must never be used to decide whether an index
 * is usable. Keeping it strictly downstream of the real validator is what stops
 * it from drifting into a second, disagreeing implementation.
 */
const char* nr_index_fault_field(const uint8_t* base, size_t size);

/*
 * Map an existing, pre-created shared file read-write. Fails (rather than
 * creating) if the file is missing or shorter than `min_bytes` — a short
 * control page would put uid_policy[] partly outside the mapping.
 */
bool nr_map_shared_rw(const char* path, size_t min_bytes,
                      void** out_addr, size_t* out_len, int* out_errno);

void nr_unmap_shared(void* addr, size_t len);

/* CLOCK_REALTIME milliseconds — what the app displays (last_map_ms, log record
 * timestamps). Never use it for backoff. */
uint64_t nr_now_ms();

/* CLOCK_MONOTONIC milliseconds — retry deadlines, immune to a clock step. */
uint64_t nr_mono_ms();

}  // namespace nr
#endif /* NULLROUTE_NR_MAP_H */
