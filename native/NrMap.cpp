/*
 * Nullroute — NrMap: the only code in the project that calls mmap() on the index.
 *
 * Every failure path here falls OPEN. A missing, truncated, wrongly-labelled or
 * deliberately corrupted index must leave DNS working and merely unfiltered;
 * there is no code path in this file that can make a lookup fail.
 */
#include "NrMap.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace nr {

/* The pool. Static storage, so it is zero-initialised before any constructor
 * runs — NR_SLOT_FREE is 0 for exactly that reason — and it is never freed, so
 * a reader racing a publish can always safely touch a slot's refcount. */
static NrMapping g_slots[NR_MAP_SLOTS];

/*
 * Claim a free slot, WITHOUT resetting its refcount.
 *
 * That omission is the whole point. A reader that lost the publish race can
 * still be between its `refs.fetch_add()` and its `refs.fetch_sub()` on a slot
 * this function is recycling — it holds a reference to a mapping it is about to
 * discover is no longer current, and its release is still coming. Storing 0 here
 * would swallow that pending +1, and the matching -1 would then wrap the new
 * occupant's refcount to UINT32_MAX. The slot would never satisfy
 * `refs == 0` again, so it would never be reclaimed; four such events and
 * nr_mapping_open() returns "slots" forever and index updates silently stop on a
 * device whose health property still reads ok:<gen>.
 *
 * So: refs is a monotone +1/-1 discipline that outlives the slot's identity, and
 * a slot is claimable only while it reads exactly 0. A straggler that bumps it
 * between the load and the CAS merely costs us this slot on this pass; the next
 * publish finds it back at 0.
 */
static NrMapping* claim_slot() {
    for (unsigned i = 0; i < NR_MAP_SLOTS; ++i) {
        uint32_t expected = NR_SLOT_FREE;
        if (!g_slots[i].state.compare_exchange_strong(expected, NR_SLOT_BUSY,
                                                      std::memory_order_acq_rel,
                                                      std::memory_order_relaxed))
            continue;
        NrMapping* m = &g_slots[i];
        /* seq_cst, pairing with the reader's seq_cst fetch_add — see NrMap.h. */
        if (m->refs.load(std::memory_order_seq_cst) != 0) {
            m->state.store(NR_SLOT_FREE, std::memory_order_release);
            continue;   /* a straggler is mid-acquire; leave it alone */
        }
        m->base = nullptr;
        m->size = 0;
        m->generation = 0;
        m->index = NrIndex{};
        return m;
    }
    return nullptr;
}

static void abandon_slot(NrMapping* m) {
    m->base = nullptr;
    m->size = 0;
    m->state.store(NR_SLOT_FREE, std::memory_order_release);
}

const char* nr_index_fault_field(const uint8_t* base, size_t size) {
    if (!base || size < NR_PAGE) return "short";
    const NrHeader* h = (const NrHeader*)base;
    if (h->magic != NR_MAGIC) return "magic";
    if (h->fmt_version > NR_FMT_VERSION) return "fmtver";
    if (h->max_labels > NR_MAX_LABELS) return "labels";
    if (h->min_labels > h->max_labels && h->max_labels != 0) return "labels";
    for (unsigned i = 0; i < NR_SEC_COUNT; ++i) {
        const NrSection* s = &h->sec[i];
        if (s->len == 0) continue;
        if (s->off < NR_PAGE || s->off > size || s->len > size - s->off) return "section";
    }
    if ((h->n_block && !nr_is_pow2(h->bt_cap)) || (h->n_allow && !nr_is_pow2(h->at_cap)))
        return "cap";
    if (h->sec[NR_SEC_BT].len < (uint64_t)h->bt_cap * sizeof(NrSlot) ||
        h->sec[NR_SEC_AT].len < (uint64_t)h->at_cap * sizeof(NrSlot) ||
        h->sec[NR_SEC_RT].len < (uint64_t)h->rt_cap * sizeof(NrRedir))
        return "seclen";
    if ((h->bt_cap && h->n_block > (h->bt_cap / 8) * 7) ||
        (h->at_cap && h->n_allow > (h->at_cap / 8) * 7))
        return "load";
    return "unknown";
}

NrMapping* nr_mapping_open(const char* path, NrMapError* err) {
    err->errno_value = 0;
    err->field = nullptr;

    NrMapping* m = claim_slot();
    if (!m) {
        /* Every slot is LIVE or still draining readers. The caller keeps the
         * mapping it already has, which is the correct degradation. */
        err->field = "slots";
        return nullptr;
    }

    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        err->errno_value = errno;
        abandon_slot(m);
        return nullptr;
    }

    struct stat st;
    if (::fstat(fd, &st) != 0) {
        err->errno_value = errno;
        ::close(fd);
        abandon_slot(m);
        return nullptr;
    }
    /* A non-regular file at this path means the directory is not what we think
     * it is; mapping a fifo or a device from inside netd is not something to
     * find out about at the first page fault. */
    if (!S_ISREG(st.st_mode)) {
        err->field = "notreg";
        ::close(fd);
        abandon_slot(m);
        return nullptr;
    }
    if (st.st_size < (off_t)NR_PAGE || (uint64_t)st.st_size > NR_MAP_MAX_BYTES) {
        err->field = "size";
        ::close(fd);
        abandon_slot(m);
        return nullptr;
    }

    const size_t size = (size_t)st.st_size;
    /* MAP_POPULATE moves the whole file's page-fault cost into this one slow-path
     * call instead of paying it as latency spikes on the first few hundred DNS
     * queries after a promotion. The mapping is clean, file-backed and evictable,
     * so the kernel can still reclaim it under pressure.
     *
     * The fd is closed immediately: the mapping keeps the inode alive, and netd
     * must not accumulate a descriptor per generation. Closing it also means a
     * later rename() over current.nrdx cannot change what we already mapped. */
    void* p = ::mmap(nullptr, size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
    const int map_errno = errno;
    ::close(fd);
    if (p == MAP_FAILED) {
        /* The overwhelmingly likely cause here is a missing SELinux `map`
         * permission: open() succeeds, mmap() returns EACCES, and the filter
         * fails open on a device that otherwise looks perfectly healthy. */
        err->errno_value = map_errno;
        abandon_slot(m);
        return nullptr;
    }

    NrIndex ix;
    if (!nr_index_validate((const uint8_t*)p, size, &ix)) {
        err->field = nr_index_fault_field((const uint8_t*)p, size);
        ::munmap(p, size);
        abandon_slot(m);
        return nullptr;
    }

    m->base       = (const uint8_t*)p;
    m->size       = size;
    m->index      = ix;
    m->generation = ix.hdr->generation;
    /* fetch_add, not store: a straggling reader may be holding a transient +1 on
     * this recycled slot (see claim_slot). An RMW composes with it; a plain store
     * would lose it and the straggler's -1 would then wrap the count. */
    m->refs.fetch_add(1, std::memory_order_seq_cst);   /* the publisher's own reference */
    m->state.store(NR_SLOT_LIVE, std::memory_order_release);
    return m;
}

void nr_mapping_retire(NrMapping* m) {
    if (!m) return;
    m->state.store(NR_SLOT_RETIRED, std::memory_order_release);
    nr_mapping_release(m);   /* drop the publisher's reference */
}

void nr_mapping_reclaim() {
    for (unsigned i = 0; i < NR_MAP_SLOTS; ++i) {
        NrMapping* m = &g_slots[i];
        if (m->state.load(std::memory_order_acquire) != NR_SLOT_RETIRED) continue;
        /* seq_cst: pairs with the reader's seq_cst fetch_add. See NrMap.h. */
        if (m->refs.load(std::memory_order_seq_cst) != 0) continue;   /* still in flight */
        uint32_t expected = NR_SLOT_RETIRED;
        if (!m->state.compare_exchange_strong(expected, NR_SLOT_BUSY,
                                              std::memory_order_acq_rel,
                                              std::memory_order_relaxed))
            continue;
        if (m->base) ::munmap((void*)m->base, m->size);
        abandon_slot(m);
    }
}

bool nr_map_shared_rw(const char* path, size_t min_bytes,
                      void** out_addr, size_t* out_len, int* out_errno) {
    *out_addr = nullptr;
    *out_len  = 0;
    *out_errno = 0;

    /* Deliberately no O_CREAT. nullroute_seed creates these files with the right
     * owner, mode and SELinux label at post-fs-data; if netd created one it would
     * be root-owned and the app could never write it again. */
    const int fd = ::open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        *out_errno = errno;
        return false;
    }
    struct stat st;
    if (::fstat(fd, &st) != 0) {
        *out_errno = errno;
        ::close(fd);
        return false;
    }
    if (!S_ISREG(st.st_mode) || (uint64_t)st.st_size < (uint64_t)min_bytes) {
        /* A short file would put the tail of the struct — uid_policy[] on the
         * control page, the last ring records — outside the mapping, and every
         * access to it would be a SIGBUS inside netd. */
        *out_errno = EINVAL;
        ::close(fd);
        return false;
    }
    const size_t len = (size_t)st.st_size;
    void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    const int map_errno = errno;
    ::close(fd);
    if (p == MAP_FAILED) {
        *out_errno = map_errno;
        return false;
    }
    *out_addr = p;
    *out_len  = len;
    return true;
}

void nr_unmap_shared(void* addr, size_t len) {
    if (addr && len) ::munmap(addr, len);
}

uint64_t nr_now_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

uint64_t nr_mono_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

}  // namespace nr
