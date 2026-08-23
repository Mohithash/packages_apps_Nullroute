package com.bestrom.nullroute.log

import android.content.Context
import android.util.Log
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.notify.BreakageNotifier
import java.io.RandomAccessFile
import java.lang.invoke.VarHandle
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

/**
 * The app's side of the query-log ring: a **read-only** consumer of
 * `/data/misc/nullroute/log/ring.bin`, written by netd.
 *
 * The file is mapped `PROT_READ` and the SELinux label `nullroute_log_file`
 * grants this process read + map and nothing else. That asymmetry is the whole
 * design: netd must not be able to write the index, and we must not be able to
 * write the log — so the two live under different labels with different grants,
 * and this class could not corrupt the producer's state if it tried.
 *
 * ## The producer's protocol, restated because we are a separately-built binary
 *
 * ```
 *   ticket = atomic_fetch_add(&hdr->head, 1)   // monotonic, never wraps
 *   slot   = ticket % NR_RING_SLOTS
 *   release-store recs[slot].seq = 0           // invalidate
 *   write recs[slot] body
 *   release-store recs[slot].seq = ticket + 1  // publish
 * ```
 *
 * So `seq == 0` means "never written, or being written right now" — a freshly
 * zeroed file is correctly empty — `head` is the number of records ever
 * produced, and the record living in slot `s` for ticket `t` carries
 * `seq == t + 1`.
 *
 * ## The two things this class exists to get right
 *
 * **Torn records.** The producer is lock-free and runs on every netd DNS thread.
 * A record can be overwritten while we are copying it. So: read `seq`, copy the
 * body, read `seq` again, and require both reads to equal the expected ticket.
 * Anything else means the bytes in hand are half of one record and half of
 * another, and are dropped. We do **not** retry — a hot producer would starve
 * the reader, and one lost telemetry record costs nothing.
 *
 * **Being lapped.** 4096 slots at ~40 ns a write is a window the producer can
 * blow through in a busy second. When `head` has advanced more than a full ring
 * past our cursor, everything older is already gone; the count is recorded and
 * the cursor jumps forward. [Drain.dropped] and the producer's own
 * `ctl.ring_drops` are both surfaced, because the alternative — renumbering
 * silently — would make the Log screen claim a completeness it does not have.
 * Before first unlock the ring accumulates and may wrap with nobody draining it
 * at all; that is the deliberate cost of keeping the query log in CE storage
 * (SPEC §7.1), and it is reported rather than hidden.
 */
class RingReader private constructor(
    private val file: RandomAccessFile,
    private val buffer: MappedByteBuffer,
) {

    /** One drained record, already sanitized for storage and display. */
    data class Record(
        val seq: Long,
        val timestampMs: Long,
        val uid: Int,
        val ruleGroup: Int,
        val verdict: Int,
        val depth: Int,
        val name: String,
        /** The producer kept the name's TAIL; render with a leading ellipsis. */
        val truncated: Boolean,
    ) {
        val blocked: Boolean get() = verdict == VERDICT_BLOCK
    }

    /**
     * The result of one drain. Every field is a measurement, not an estimate:
     * `dropped` and `torn` are counted here, `producerDrops` is read from the
     * control page, and a UI that wants to say "your log is complete" has to
     * check all three.
     */
    data class Drain(
        val records: List<Record>,
        val dropped: Long,
        val torn: Long,
        val producerDrops: Int,
        val head: Long,
        val cursor: Long,
    ) {
        val complete: Boolean get() = dropped == 0L && torn == 0L && producerDrops == 0
    }

    /** Next ticket to consume. */
    var cursor: Long = 0L
        private set

    private var dropped = 0L
    private var torn = 0L

    /** Total records the producer has ever written. An acquire load. */
    fun head(): Long {
        VarHandle.fullFence()
        return buffer.getLong(OFF_HEAD)
    }

    /**
     * Positions the cursor, clamped into the window the ring still holds.
     *
     * A saved cursor from a previous process is only usable if the producer has
     * not lapped past it; a cursor from *before* a reformat (head restarts at 0
     * on a factory reset) would otherwise park us in the future and drain
     * nothing, forever.
     */
    fun seekTo(saved: Long) {
        val h = head()
        val oldest = if (h > SLOTS) h - SLOTS else 0L
        cursor = when {
            saved < oldest -> {
                if (saved > 0L) dropped += oldest - saved
                oldest
            }
            saved > h -> h    // a stale cursor from a previous ring generation
            else -> saved
        }
    }

    /**
     * Copies up to [max] records, oldest first, advancing the cursor.
     *
     * **Blocking only on page faults** — there is no lock and no syscall on this
     * path; the producer is never waited on and never blocked.
     */
    fun drain(max: Int = SLOTS.toInt()): Drain {
        val h = head()
        val out = ArrayList<Record>(minOf(max, MAX_BATCH))

        if (h > cursor && h - cursor > SLOTS) {
            dropped += (h - cursor) - SLOTS
            cursor = h - SLOTS
        }

        while (cursor < h && out.size < max) {
            val slot = (cursor % SLOTS).toInt()
            val off = HEADER_BYTES + slot * RECORD_BYTES
            val want = cursor + 1L   // seq == ticket + 1

            val seq1 = buffer.getLong(off + OFF_SEQ)
            VarHandle.fullFence()
            val record = if (seq1 == want) readRecord(off, seq1) else null
            VarHandle.fullFence()
            val seq2 = buffer.getLong(off + OFF_SEQ)

            cursor++

            // seq1 != want : the slot holds a different generation of the ring
            // seq1 != seq2 : the producer overwrote it while we were copying
            if (record == null || seq2 != seq1) {
                torn++
                continue
            }
            out.add(record)
        }

        return Drain(
            records = out,
            dropped = dropped,
            torn = torn,
            producerDrops = if (ControlPage.isMapped) ControlPage.telemetry().ringDrops else 0,
            head = h,
            cursor = cursor,
        )
    }

    fun close() {
        // The MappedByteBuffer keeps the mapping alive until the GC collects it;
        // closing the descriptor is all we can do and all that matters here.
        runCatching { file.close() }
    }

    private fun readRecord(off: Int, seq: Long): Record {
        val nameLen = buffer.get(off + OFF_NAME_LEN).toInt() and 0xFF
        val flags = buffer.get(off + OFF_FLAGS).toInt() and 0xFF

        // Clamp before use. `name_len` is written by netd, but it is derived from
        // a hostname an arbitrary app chose, and a reader that trusted it would
        // be one producer bug away from an IndexOutOfBounds in the log pipeline.
        val len = if (nameLen > NAME_BYTES) NAME_BYTES else nameLen
        val chars = CharArray(len)
        for (i in 0 until len) {
            val c = buffer.get(off + OFF_NAME + i).toInt() and 0xFF
            // The name came from an arbitrary app's DNS query: attacker-influenced
            // text on its way into a database and onto a screen. Sanitizing is the
            // reader's job — the same substitution nr_ring_rec_name() makes on the
            // native side, so `nrctl log` and the Log screen show the same string.
            chars[i] = if (c in 0x20..0x7E) c.toChar() else '?'
        }

        return Record(
            seq = seq,
            timestampMs = buffer.getLong(off + OFF_TS_MS),
            uid = buffer.getInt(off + OFF_UID),
            ruleGroup = buffer.getShort(off + OFF_RULE_GROUP).toInt() and 0xFFFF,
            verdict = buffer.get(off + OFF_VERDICT).toInt() and 0xFF,
            depth = buffer.get(off + OFF_DEPTH).toInt() and 0xFF,
            name = String(chars),
            truncated = (flags and FLAG_TRUNCATED) != 0,
        )
    }

    companion object {

        private const val TAG = "Nullroute"

        // ---- transcribed from native/include/NrRing.h and NrRingReader.h ----
        // These offsets are an ABI between two separately-built binaries. They are
        // pinned by static_assert on the native side; change them in both places
        // or neither.
        //
        //    0  u64  seq          release-stored LAST
        //    8  u64  ts_ms
        //   16  u32  uid
        //   20  u16  rule_group
        //   22  u8   verdict
        //   23  u8   depth
        //   24  u8   name_len
        //   25  u8   flags
        //   26  char name[37]
        //   63  u8   _pad
        private const val OFF_SEQ = 0
        private const val OFF_TS_MS = 8
        private const val OFF_UID = 16
        private const val OFF_RULE_GROUP = 20
        private const val OFF_VERDICT = 22
        private const val OFF_DEPTH = 23
        private const val OFF_NAME_LEN = 24
        private const val OFF_FLAGS = 25
        private const val OFF_NAME = 26

        private const val NAME_BYTES = 37
        private const val RECORD_BYTES = 64
        private const val HEADER_BYTES = 4096
        private const val SLOTS = 4096L
        private const val RING_BYTES = HEADER_BYTES + SLOTS * RECORD_BYTES

        /** Page 0: `u32 magic`, `u32 version`, `u64 head`. */
        private const val OFF_MAGIC = 0
        private const val OFF_VERSION = 4
        private const val OFF_HEAD = 8

        /** "NRRG" little-endian, matching NR_RING_MAGIC. */
        private const val MAGIC = 0x4752524E
        private const val VERSION = 1

        private const val FLAG_TRUNCATED = 0x01

        const val VERDICT_PASS = 0
        const val VERDICT_BLOCK = 1
        const val VERDICT_REDIRECT = 2

        /**
         * Records copied out of the mapping in one pump. A full ring is 4096
         * records; taking them all in one batch is a 256 KiB copy and a single
         * transaction, which is cheaper than the alternative and bounded either
         * way.
         */
        private const val MAX_BATCH = 4096

        /** Own prefs file: the log subsystem's state, on DE so a pre-unlock drain
         * can still record where it got to. Nothing here is a domain name. */
        private const val PREFS = "nullroute_log"
        private const val KEY_CURSOR = "ring_cursor"

        /** Human-readable reason the last [open] failed, for Diagnostics. */
        @Volatile
        var lastError: String? = null
            private set

        /**
         * Maps the ring read-only, or returns `null` and records why.
         *
         * The file is **never created here** — `nullroute_seed` pre-creates it at
         * the right size and ownership, and netd stamps the header. A missing or
         * short file means the seeder did not run, which is a real failure that
         * must surface as one rather than be papered over with an empty log.
         */
        fun open(): RingReader? {
            val f = Paths.ringBin
            if (!f.exists()) {
                lastError = "ring.bin missing (nullroute_seed did not run)"
                return null
            }
            if (f.length() < RING_BYTES) {
                lastError = "ring.bin is ${f.length()} bytes, expected $RING_BYTES"
                return null
            }
            return try {
                val raf = RandomAccessFile(f, "r")
                val map = raf.channel.map(FileChannel.MapMode.READ_ONLY, 0, RING_BYTES)
                map.order(ByteOrder.LITTLE_ENDIAN)

                val magic = map.getInt(OFF_MAGIC)
                val version = map.getInt(OFF_VERSION)
                if (magic == 0) {
                    // netd stamps the header the first time it maps the ring. A
                    // zeroed file means the resolver has not logged anything yet
                    // — which is normal on a fresh boot and is NOT an error.
                    lastError = "ring.bin not yet stamped by the resolver"
                    raf.close()
                    return null
                }
                if (magic != MAGIC || version != VERSION) {
                    lastError = "ring.bin magic/version mismatch (0x%08x v%d)".format(magic, version)
                    raf.close()
                    return null
                }

                lastError = null
                val reader = RingReader(raf, map)
                reader.cursor = reader.head().let { if (it > SLOTS) it - SLOTS else 0L }
                reader
            } catch (t: Throwable) {
                // The classic failure is SELinux allowing `open` but denying
                // `map`; record it verbatim next to the probe result rather than
                // reporting an empty log.
                lastError = "${t.javaClass.simpleName}: ${t.message}"
                Log.e(TAG, "ring.bin mmap failed", t)
                null
            }
        }

        /**
         * One full cycle: drain the ring, store what retention says to store,
         * hand the batch to the breakage notifier, purge if due, and remember
         * where we got to.
         *
         * **Blocking; background thread only.** Returns the drain even when the
         * database was skipped, so Diagnostics can distinguish "nothing was
         * logged" from "we could not store it".
         *
         * Everything after the drain is best-effort and independently guarded:
         * losing the database must not lose the notifier, and losing the
         * notifier must not lose the log.
         */
        fun pump(context: Context): Drain? {
            val reader = open() ?: return null
            return try {
                reader.seekTo(savedCursor(context))
                val drain = reader.drain()

                if (drain.records.isNotEmpty()) {
                    val logMode = Retention.mode(context)
                    val keep = drain.records.filter { Retention.shouldStore(logMode, it) }
                    if (keep.isNotEmpty()) {
                        // CE storage: before first unlock there is nowhere to put
                        // this, and that is the deliberate trade — a
                        // seized-but-locked device exposes no DNS history. The
                        // cursor still advances, so the records are dropped
                        // rather than replayed into a half-written database.
                        if (Paths.ceAvailable(context)) {
                            runCatching { QueryLogDb.get(context)?.insert(keep) }
                                .onFailure { Log.w(TAG, "log insert failed: ${it.message}") }
                        }
                    }
                    runCatching { BreakageNotifier.observe(context, drain.records) }
                        .onFailure { Log.w(TAG, "breakage notifier: ${it.message}") }
                }

                runCatching { Retention.purgeIfDue(context) }
                    .onFailure { Log.w(TAG, "retention purge: ${it.message}") }

                saveCursor(context, drain.cursor)
                drain
            } finally {
                reader.close()
            }
        }

        private fun prefs(context: Context) =
            Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

        private fun savedCursor(context: Context): Long =
            prefs(context).getLong(KEY_CURSOR, 0L)

        /**
         * `commit()`, not `apply()`. This runs on a worker that the job scheduler
         * is free to kill the moment [pump] returns, and a cursor that did not
         * reach disk means the next drain re-ingests everything it already
         * stored.
         */
        private fun saveCursor(context: Context, value: Long) {
            runCatching { prefs(context).edit().putLong(KEY_CURSOR, value).commit() }
        }
    }
}
