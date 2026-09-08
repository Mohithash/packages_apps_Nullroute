/*
 * Nullroute — the read-only consumer of /data/misc/nullroute/log/ring.bin.
 *
 * The producer is netd (resolver-patch/nullroute/NrRingWriter.cpp), which is
 * multi-producer, lock-free and best-effort; the consumer is the app, plus
 * `nrctl log`. The consumer never writes to the mapping — the file is mapped
 * PROT_READ and the label `nullroute_log_file` gives the app read+map only.
 *
 * PRODUCER CONTRACT, normative (NrRing.h fixes the record layout but not the
 * protocol, and the two sides are separately-built binaries):
 *
 *   ticket = atomic_fetch_add(&hdr->head, 1)      // monotonic, never wraps
 *   slot   = ticket % NR_RING_SLOTS
 *   write recs[slot] body                          // seq LAST
 *   release-store recs[slot].seq = ticket + 1
 *
 * so `seq == 0` means "never written" (a freshly zeroed file is therefore
 * correctly empty), `hdr->head` is the number of records ever produced, and the
 * record living in slot s at ticket t must carry seq == t + 1. A reader that
 * sees any other seq in that slot was overtaken mid-read and drops the record.
 *
 * Nothing here can fail in a way that matters: the log is telemetry. If the file
 * is missing, short, mis-magicked or full of garbage, the reader reports zero
 * records and the product keeps filtering.
 */
#ifndef NULLROUTE_NR_RING_READER_H
#define NULLROUTE_NR_RING_READER_H

#include <stdint.h>
#include <stddef.h>

#include <string>

#include "NrCtl.h"
#include "NrRing.h"

/* 'N','R','R','G' little-endian. NrRing.h names the magic in a comment but does
 * not define it, and the writer, the reader and the seeder that formats the file
 * must all agree on the bytes — so it is defined once, here. */
#define NR_RING_MAGIC   0x4752524Eu
#define NR_RING_VERSION 1u

namespace nr {

struct NrRingReader {
    NrMapRO             map;
    const NrRingHeader* hdr  = nullptr;
    const NrLogRec*     recs = nullptr;
    uint64_t cursor  = 0;   /* next ticket to consume                        */
    uint64_t dropped = 0;   /* overwritten before we got to them (cumulative) */
    uint64_t torn    = 0;   /* overwritten while we were reading them         */
};

/* Maps the ring and positions the cursor at the oldest record still live, so the
 * first drain returns the whole window rather than nothing. */
bool nr_ring_open(const char* path, NrRingReader* out, std::string* err = nullptr);
void nr_ring_close(NrRingReader* r);

/* Total records ever produced (an acquire load of the shared header). */
uint64_t nr_ring_head(const NrRingReader& r);

/* Records available to this reader right now, capped at the ring size. */
uint64_t nr_ring_available(const NrRingReader& r);

/*
 * Copies up to `max` records into `out`, oldest first, advancing the cursor.
 * Returns how many were copied. Records lost to the producer lapping us are
 * counted into NrRingReader::dropped / ::torn and skipped — a consumer that
 * silently renumbered them would make the Diagnostics screen lie about how
 * complete the log is.
 */
size_t nr_ring_drain(NrRingReader* r, NrLogRec* out, size_t max);

/* Clamps name_len and replaces anything non-printable with '?'. The name came
 * from an arbitrary app's DNS query, so it is attacker-influenced text that ends
 * up in a database and on screen; sanitizing is the reader's job. */
void nr_ring_rec_name(const NrLogRec& rec, char out[NR_RING_NAME + 1]);

/* ---------------------------------------------------------------------------
 * Formatting (nullroute_seed only)
 * ------------------------------------------------------------------------- */

/* 1 = header is ours and current, 0 = it is not, -1 = I/O error. */
int nr_ring_check_header(int fd);

/* Writes a fresh page-0 header (head = 0). Only ever called for a file that was
 * just created, or whose header failed the check — never over a good one. */
bool nr_ring_write_header(int fd);

}  // namespace nr
#endif /* NULLROUTE_NR_RING_READER_H */
