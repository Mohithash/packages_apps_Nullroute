package com.bestrom.nullroute.core

import android.os.Process
import android.util.Log
import java.io.RandomAccessFile
import java.lang.invoke.VarHandle
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel

/**
 * The **sole** app-side writer of `control.bin`.
 *
 * `control.bin` is 128 KiB, `MAP_SHARED`, mapped read-write by both this process
 * and netd. Its layout is an ABI between two independently-built binaries, so the
 * offsets below are transcribed from `native/include/NrControl.h` — where they are
 * pinned by `static_assert` — and must be changed in both places or neither.
 *
 * ```
 *    0  u64  want_generation     app -> resolver, release-stored LAST
 *    8  u8   mode                0 ENFORCE  1 PAUSED  2 OFF
 *    9  u8   response_mode       0 EAI_NONAME  1 EAI_NODATA  2 sinkhole
 *   10  u8   log_level           0 none  1 blocked-only  2 all
 *   11  u8   cname_uncloak
 *   12  u32  config_epoch
 *   16       _pad0[48]           line 0 ends at 64
 *   64  u64  mapped_generation   resolver -> app  (telemetry, NOT health)
 *   72  u64  q_total
 *   80  u64  q_blocked
 *   88  u64  q_passed
 *   96  u64  last_map_ms
 *  104  u32  filter_abi          NR_FMT_VERSION the INSTALLED resolver supports
 *  108  u32  map_errors
 *  112  u32  ring_drops
 *  116  u32  fault_count
 * 4096  u8[] uid_policy[100000]  app -> resolver, index = uid % 100000
 * ```
 *
 * **Cache-line 0 is ours, lines 1-2 are the resolver's.** Nothing here writes
 * above offset 64 and below 4096; writing there would corrupt telemetry the
 * resolver is concurrently updating with relaxed atomics, and the false sharing
 * alone would be a per-query cost on the DNS hot path.
 *
 * **These counters are not a health signal.** They live inside the very page
 * whose mapping is the most likely thing to fail (F8) — a counter cannot report
 * its own death. The authoritative signals are the dual `.invalid` probes and
 * the `sys.nullroute.filter` property; see [Probes].
 */
object ControlPage {

    private const val TAG = "Nullroute"

    private const val SIZE = 128 * 1024
    private const val UID_POLICY_OFF = 4096
    private const val UID_POLICY_LEN = 100_000
    private const val AID_USER_OFFSET = 100_000

    private const val OFF_WANT_GENERATION = 0
    private const val OFF_MODE = 8
    private const val OFF_RESPONSE_MODE = 9
    private const val OFF_LOG_LEVEL = 10
    private const val OFF_CNAME_UNCLOAK = 11
    private const val OFF_CONFIG_EPOCH = 12

    private const val OFF_MAPPED_GENERATION = 64
    private const val OFF_Q_TOTAL = 72
    private const val OFF_Q_BLOCKED = 80
    private const val OFF_Q_PASSED = 88
    private const val OFF_LAST_MAP_MS = 96
    private const val OFF_FILTER_ABI = 104
    private const val OFF_MAP_ERRORS = 108
    private const val OFF_RING_DROPS = 112
    private const val OFF_FAULT_COUNT = 116

    const val MODE_ENFORCE = 0
    const val MODE_PAUSED = 1
    const val MODE_OFF = 2

    const val RESP_NONAME = 0
    const val RESP_NODATA = 1
    const val RESP_SINKHOLE = 2

    const val POLICY_ENFORCE: Byte = 0
    const val POLICY_EXEMPT: Byte = 1
    const val POLICY_STRICT: Byte = 2

    /** The property is the durable authority for mode; the byte is derived. */
    const val PROP_MODE = "persist.sys.nullroute.mode"

    @Volatile
    private var buffer: MappedByteBuffer? = null

    /** Human-readable reason the mapping failed, for Diagnostics. Never guessed. */
    @Volatile
    var lastError: String? = null
        private set

    val isMapped: Boolean get() = buffer != null

    /**
     * Maps the control page. Idempotent and safe to call from anywhere.
     *
     * The file is **never created here**. `nullroute_seed` pre-creates it at the
     * right size and ownership precisely so that neither netd (root) nor this app
     * can leave behind a file the other cannot write. A missing file is a seeder
     * failure and must surface as one.
     */
    @Synchronized
    fun open(): Boolean {
        buffer?.let { return true }
        val f = Paths.controlBin
        if (!f.exists()) {
            lastError = "control.bin missing (nullroute_seed did not run)"
            return false
        }
        if (f.length() < SIZE) {
            lastError = "control.bin is ${f.length()} bytes, expected $SIZE"
            return false
        }
        return try {
            RandomAccessFile(f, "rw").use { raf ->
                val mapped = raf.channel.map(FileChannel.MapMode.READ_WRITE, 0, SIZE.toLong())
                mapped.order(ByteOrder.LITTLE_ENDIAN)
                buffer = mapped
            }
            lastError = null
            true
        } catch (t: Throwable) {
            // The classic failure here is SELinux denying `map` while allowing
            // `open` — the mapping fails and everything downstream looks fine.
            // Record it verbatim; Diagnostics shows it next to the probe result.
            lastError = "${t.javaClass.simpleName}: ${t.message}"
            Log.e(TAG, "control.bin mmap failed", t)
            false
        }
    }

    // ---- cache line 0: app-written ------------------------------------------

    /** Live mode as the resolver reads it. Mutated only through [setMode]. */
    val mode: Int get() = readByte(OFF_MODE)

    val responseMode: Int get() = readByte(OFF_RESPONSE_MODE)

    val logLevel: Int get() = readByte(OFF_LOG_LEVEL)

    /**
     * Whether the resolver walks CNAME chains in answers (H5).
     *
     * **This byte is the only authority for the setting.** Unlike `mode` it gets
     * no mirror in preferences and no `persist.` property: init never needs to
     * re-derive it, so a second copy would only be a second thing that can
     * disagree — which is the failure the mode/property split exists to avoid.
     * The page lives on /data and keeps its value across a reboot; a device where
     * it cannot be mapped has no working filter to configure anyway.
     */
    val cnameUncloak: Boolean get() = readByte(OFF_CNAME_UNCLOAK) != 0

    fun setCnameUncloak(enabled: Boolean): Boolean {
        val ok = writeByte(OFF_CNAME_UNCLOAK, if (enabled) 1 else 0)
        bumpEpoch()
        return ok
    }

    val wantGeneration: Long get() = readLong(OFF_WANT_GENERATION)

    val configEpoch: Int get() = readInt(OFF_CONFIG_EPOCH)

    /**
     * Publishes a new index generation. **This is the last write of a promotion**
     * and the only one the resolver polls: it re-maps when `want_generation`
     * changes, so anything the resolver must observe alongside the new index has
     * to be visible before this store retires.
     *
     * [VarHandle.fullFence] rather than a byte-buffer view VarHandle's
     * `setRelease`: a full fence is strictly stronger than the release-store the
     * ABI asks for, it costs nothing on a once-a-day path, and it avoids relying
     * on signature-polymorphic VarHandle accessors on a mapped buffer. The
     * aligned 8-byte `putLong` on a direct little-endian buffer is a single
     * store on aarch64, so the resolver's acquire load never sees a torn value.
     */
    fun setWantGeneration(generation: Long): Boolean {
        val b = buffer ?: return false
        return try {
            VarHandle.fullFence()
            b.putLong(OFF_WANT_GENERATION, generation)
            VarHandle.fullFence()
            true
        } catch (t: Throwable) {
            lastError = "want_generation store failed: ${t.message}"
            false
        }
    }

    /**
     * Sets the filter mode.
     *
     * Two authorities can never be allowed to disagree about a boolean, so the
     * split is explicit: `persist.sys.nullroute.mode` is the **durable** truth
     * (an init `on property:` trigger re-derives the byte at every boot via
     * `nrctl syncprop`), and `ctl.mode` is the **live** derivation the resolver
     * actually reads.
     *
     * The byte goes first because it takes effect on the resolver's very next
     * query; the property follows to make it survive a reboot. If the process
     * dies between the two, the next boot re-derives the byte from the property
     * — i.e. the failure converges on the durable value, never on the volatile
     * one.
     */
    fun setMode(newMode: Int): Boolean {
        val ok = writeByte(OFF_MODE, newMode)
        bumpEpoch()
        SysProp.set(PROP_MODE, newMode.toString())
        return ok
    }

    fun setResponseMode(value: Int): Boolean {
        val ok = writeByte(OFF_RESPONSE_MODE, value)
        bumpEpoch()
        return ok
    }

    fun setLogLevel(value: Int): Boolean {
        val ok = writeByte(OFF_LOG_LEVEL, value)
        bumpEpoch()
        return ok
    }

    /**
     * Re-derives the live byte from the durable property. Called at
     * LOCKED_BOOT_COMPLETED so the app's view and the resolver's view agree even
     * if init's `nrctl syncprop` trigger did not fire.
     */
    fun syncModeFromProperty(): Int {
        val fromProp = SysProp.get(PROP_MODE).toIntOrNull()?.takeIf { it in MODE_ENFORCE..MODE_OFF }
            ?: MODE_ENFORCE
        if (isMapped && readByte(OFF_MODE) != fromProp) {
            writeByte(OFF_MODE, fromProp)
            bumpEpoch()
        }
        return fromProp
    }

    private fun bumpEpoch() {
        val b = buffer ?: return
        runCatching { b.putInt(OFF_CONFIG_EPOCH, b.getInt(OFF_CONFIG_EPOCH) + 1) }
    }

    // ---- uid_policy at 4096: app-written ------------------------------------

    /**
     * Per-app policy, one byte per appId, live on the resolver's next query.
     *
     * Refuses to exempt our own appId. The liveness probe resolves
     * `idx-probe.nullroute.invalid` from *this* process, so an exemption here
     * would make [Probes] report "not filtering" on a perfectly healthy device —
     * the status card would lie, which is the one thing it must never do.
     */
    fun setUidPolicy(appId: Int, policy: Byte): Boolean {
        val b = buffer ?: return false
        if (appId < 0 || appId >= UID_POLICY_LEN) return false
        if (policy == POLICY_EXEMPT && appId == ownAppId()) {
            Log.w(TAG, "refusing to exempt our own appId; probes would lie")
            return false
        }
        return try {
            b.put(UID_POLICY_OFF + appId, policy)
            VarHandle.fullFence()
            bumpEpoch()
            true
        } catch (t: Throwable) {
            lastError = "uid_policy store failed: ${t.message}"
            false
        }
    }

    fun getUidPolicy(appId: Int): Byte {
        val b = buffer ?: return POLICY_ENFORCE
        if (appId < 0 || appId >= UID_POLICY_LEN) return POLICY_ENFORCE
        return runCatching { b.get(UID_POLICY_OFF + appId) }.getOrDefault(POLICY_ENFORCE)
    }

    fun ownAppId(): Int = Process.myUid() % AID_USER_OFFSET

    // ---- cache lines 1-2: resolver-written, read-only here ------------------

    /**
     * Everything the resolver publishes about itself, sampled at one instant.
     * Presented in Diagnostics as *secondary telemetry* and never as the health
     * verdict — see the class comment.
     */
    data class Telemetry(
        val mapped: Boolean,
        val mappedGeneration: Long,
        val queriesTotal: Long,
        val queriesBlocked: Long,
        val queriesPassed: Long,
        val lastMapMs: Long,
        val filterAbi: Int,
        val mapErrors: Int,
        val ringDrops: Int,
        val faultCount: Int,
    )

    fun telemetry(): Telemetry {
        if (!isMapped) return Telemetry(false, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return Telemetry(
            mapped = true,
            mappedGeneration = readLong(OFF_MAPPED_GENERATION),
            queriesTotal = readLong(OFF_Q_TOTAL),
            queriesBlocked = readLong(OFF_Q_BLOCKED),
            queriesPassed = readLong(OFF_Q_PASSED),
            lastMapMs = readLong(OFF_LAST_MAP_MS),
            filterAbi = readInt(OFF_FILTER_ABI),
            mapErrors = readInt(OFF_MAP_ERRORS),
            ringDrops = readInt(OFF_RING_DROPS),
            faultCount = readInt(OFF_FAULT_COUNT),
        )
    }

    /**
     * NRDX format version the *installed resolver* supports, or 0 when it has
     * never published one. [Generation.promote] refuses to hand netd an index
     * newer than this: an app update must never be able to starve a stale
     * resolver.
     */
    fun filterAbi(): Int = if (isMapped) readInt(OFF_FILTER_ABI) else 0

    /**
     * The resolver's heartbeat, or `null` — and null is itself a signal, meaning
     * either the page is unmapped on our side or the resolver has never
     * successfully mapped an index.
     */
    data class Heartbeat(val generation: Long, val lastMapMs: Long)

    fun readHeartbeatOrNull(): Heartbeat? {
        if (!isMapped) return null
        val gen = readLong(OFF_MAPPED_GENERATION)
        val at = readLong(OFF_LAST_MAP_MS)
        return if (gen == 0L && at == 0L) null else Heartbeat(gen, at)
    }

    // ---- primitives ---------------------------------------------------------

    private fun readByte(off: Int): Int =
        buffer?.let { runCatching { it.get(off).toInt() and 0xFF }.getOrNull() } ?: 0

    private fun readInt(off: Int): Int =
        buffer?.let { runCatching { it.getInt(off) }.getOrNull() } ?: 0

    private fun readLong(off: Int): Long =
        buffer?.let { runCatching { it.getLong(off) }.getOrNull() } ?: 0L

    private fun writeByte(off: Int, value: Int): Boolean {
        val b = buffer ?: return false
        return try {
            b.put(off, (value and 0xFF).toByte())
            VarHandle.fullFence()
            true
        } catch (t: Throwable) {
            lastError = "control write failed: ${t.message}"
            false
        }
    }
}
