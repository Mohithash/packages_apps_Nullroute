/*
 * Nullroute — ring consumer (NrRingReader.h).
 */
#include "NrRingReader.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

namespace nr {

static inline uint64_t load_acq_u64(const uint64_t* p) {
    /* The mapping is const to us but is written concurrently by netd, so the
     * load must be an acquire load rather than a plain dereference the compiler
     * is free to hoist or fold. */
    return __atomic_load_n(const_cast<uint64_t*>(p), __ATOMIC_ACQUIRE);
}

bool nr_ring_open(const char* path, NrRingReader* out, std::string* err) {
    *out = NrRingReader{};
    if (!nr_map_file_ro(path, &out->map, err)) return false;

    if (out->map.size < (size_t)NR_RING_BYTES) {
        if (err) *err = "ring.bin is short; nullroute_seed has not formatted it";
        nr_unmap_file(&out->map);
        return false;
    }
    const NrRingHeader* h = (const NrRingHeader*)out->map.base;
    if (h->magic != NR_RING_MAGIC || h->version != NR_RING_VERSION) {
        if (err) *err = "ring.bin header magic/version mismatch";
        nr_unmap_file(&out->map);
        return false;
    }
    out->hdr  = h;
    out->recs = (const NrLogRec*)(out->map.base + NR_PAGE);

    /* Start at the oldest record the producer has not yet lapped. Starting at 0
     * instead would report every slot the ring has ever held as "dropped" on the
     * very first drain of a long-running device. */
    const uint64_t head = load_acq_u64(&h->head);
    out->cursor = head > (uint64_t)NR_RING_SLOTS ? head - NR_RING_SLOTS : 0;
    return true;
}

void nr_ring_close(NrRingReader* r) {
    if (!r) return;
    nr_unmap_file(&r->map);
    r->hdr  = nullptr;
    r->recs = nullptr;
}

uint64_t nr_ring_head(const NrRingReader& r) {
    if (!r.hdr) return 0;
    return load_acq_u64(&r.hdr->head);
}

uint64_t nr_ring_available(const NrRingReader& r) {
    if (!r.hdr) return 0;
    const uint64_t head = load_acq_u64(&r.hdr->head);
    if (head <= r.cursor) return 0;
    const uint64_t n = head - r.cursor;
    return n > (uint64_t)NR_RING_SLOTS ? (uint64_t)NR_RING_SLOTS : n;
}

size_t nr_ring_drain(NrRingReader* r, NrLogRec* out, size_t max) {
    if (!r || !r->hdr || !r->recs || !out || max == 0) return 0;

    const uint64_t head = load_acq_u64(&r->hdr->head);
    if (head <= r->cursor) return 0;

    /* The producer lapped us: everything older than head - NR_RING_SLOTS is
     * already overwritten. Count the loss honestly and jump forward. */
    if (head - r->cursor > (uint64_t)NR_RING_SLOTS) {
        r->dropped += (head - r->cursor) - (uint64_t)NR_RING_SLOTS;
        r->cursor   = head - (uint64_t)NR_RING_SLOTS;
    }

    size_t n = 0;
    while (r->cursor < head && n < max) {
        const NrLogRec* src = &r->recs[r->cursor % NR_RING_SLOTS];
        const uint64_t want = r->cursor + 1;   /* seq == ticket + 1 */

        const uint64_t seq1 = load_acq_u64(&src->seq);
        NrLogRec copy;
        memcpy(&copy, src, sizeof(copy));
        const uint64_t seq2 = load_acq_u64(&src->seq);

        ++r->cursor;

        /* seq1 != want  : the slot holds a different generation of the ring
         * seq1 != seq2  : the producer overwrote it while we were copying
         * Either way the bytes we hold are not a record; dropping is correct and
         * cheap, and retrying would let a hot producer starve the reader. */
        if (seq1 != want || seq2 != seq1) {
            ++r->torn;
            continue;
        }
        out[n++] = copy;
    }
    return n;
}

void nr_ring_rec_name(const NrLogRec& rec, char out[NR_RING_NAME + 1]) {
    size_t len = rec.name_len;
    if (len > NR_RING_NAME) len = NR_RING_NAME;
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = (unsigned char)rec.name[i];
        out[j++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[j] = '\0';
}

int nr_ring_check_header(int fd) {
    NrRingHeader h;
    const ssize_t n = pread(fd, &h, sizeof(h), 0);
    if (n < 0) return -1;
    if ((size_t)n < sizeof(h)) return 0;
    return (h.magic == NR_RING_MAGIC && h.version == NR_RING_VERSION) ? 1 : 0;
}

bool nr_ring_write_header(int fd) {
    NrRingHeader h;
    memset(&h, 0, sizeof(h));
    h.magic   = NR_RING_MAGIC;
    h.version = NR_RING_VERSION;
    h.head    = 0;
    const ssize_t n = pwrite(fd, &h, sizeof(h), 0);
    return n == (ssize_t)sizeof(h);
}

}  // namespace nr
