package com.bestrom.nullroute.core

import android.content.Context
import android.os.StatFs
import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.bestrom.nullroute.build.CanarySet
import com.bestrom.nullroute.data.Settings
import java.io.File
import java.nio.file.Files

/**
 * Publishing an index, and un-publishing it again.
 *
 * The whole point of this file is that **no query is ever dropped and no query
 * ever observes a half-written file**. The resolver holds a refcounted mapping
 * and re-maps only when `want_generation` changes, so the sequence is:
 * verify the artefact, gate it against what the installed resolver can read,
 * gate it against behaviour, `rename()` it into place (atomic within the
 * filesystem), and only then release-store the generation.
 *
 * Every gate below fails **closed on promotion and open on filtering**: a
 * refused promotion leaves the previous index live. The one outcome that is not
 * acceptable is shipping netd an index it will choke on, because netd's init
 * stanza carries `onrestart restart zygote` — a matcher fault there is a UI
 * loop, not a network outage.
 *
 * ## The degradation ladder, and where this file sits on it
 *
 * ```
 *   current.nrdx  ->  previous.nrdx  ->  baseline (recompiled by the seeder)
 *                 ->  L0 hosts only  ->  PASS-ALL
 * ```
 *
 * [promote] moves down a rung only by refusing to move up; [rollback] is the one
 * step this file takes on purpose, and it is announced, never silent.
 */
object Generation {

    private const val TAG = "Nullroute"

    /**
     * A build that lost this much of the previous index's content is a truncated
     * download, not an update. Below the floor we refuse rather than quietly
     * shrinking the user's protection by 90%.
     */
    private const val SANITY_MIN_RATIO = 0.10

    /**
     * How many superseded generations of the side artefacts to keep. One, so that
     * `previous.nrdx` always has its matching strings blob and manifest — a
     * rollback that produces an index whose Rules screen cannot name a single
     * source is a rollback that looks broken.
     */
    private const val KEEP_GENERATIONS = 2

    sealed class PromoteResult {
        object Ok : PromoteResult()
        data class NoSpace(val neededBytes: Long) : PromoteResult()
        data class Corrupt(val reason: String) : PromoteResult()
        data class AbiTooNew(val resolverAbi: Int, val indexAbi: Int) : PromoteResult()
        data class CanaryFailed(val failure: CanarySet.Failure?) : PromoteResult()
        data class SanityFailed(val newCount: Int, val previousCount: Int) : PromoteResult()
        data class IoError(val reason: String) : PromoteResult()

        val succeeded: Boolean get() = this is Ok

        fun describe(): String = when (this) {
            is Ok -> "promoted"
            is NoSpace -> "not enough space (needed ${neededBytes / 1024} KiB)"
            is Corrupt -> "index failed verification: $reason"
            is AbiTooNew ->
                "index format v$indexAbi is newer than the installed resolver (v$resolverAbi)"
            is CanaryFailed ->
                "safety check failed" + (failure?.let { ": ${it.describe()}" } ?: "")
            is SanityFailed -> "only $newCount entries, previous build had $previousCount"
            is IoError -> "I/O error: $reason"
        }

        /**
         * Whether trying again later could plausibly succeed. An ABI mismatch
         * cannot be retried away — it needs a resolver update — and retrying it
         * every 30 minutes would burn wakeups forever.
         */
        val recoverable: Boolean
            get() = when (this) {
                is Ok, is AbiTooNew -> false
                else -> true
            }
    }

    /**
     * Next generation number: monotonic across app data wipes.
     *
     * Taking `max(persisted, on-disk + 1)` matters because `want_generation` is
     * the resolver's only remap trigger. Re-issuing a number the resolver has
     * already mapped would leave it serving the old index forever, with a UI
     * cheerfully reporting the new one.
     */
    fun next(context: Context): Long {
        val persisted = Settings.lastGeneration(context)
        val onDisk = Native.verify(Paths.currentIndex.absolutePath).let {
            if (it.ok) it.generation else 0L
        }
        // The control page is the third authority, and the only one the resolver
        // actually reads. A /data restore can leave preferences behind an index,
        // or an index behind a control page; taking the max of all three is what
        // makes the next number strictly greater than anything netd has mapped.
        val published = if (ControlPage.isMapped) ControlPage.wantGeneration else 0L
        val gen = maxOf(persisted, onDisk, published) + 1
        Settings.setLastGeneration(context, gen)
        return gen
    }

    /** The generation netd is serving right now, or 0 if we cannot tell. */
    fun mappedGeneration(): Long =
        if (ControlPage.isMapped) ControlPage.telemetry().mappedGeneration else 0L

    /**
     * Promotes `staging.<gen>.nrdx` to `current.nrdx`.
     *
     * Call from a background thread; every step touches the filesystem.
     */
    fun promote(context: Context, generation: Long): PromoteResult {
        val staging = Paths.stagingIndex(generation)
        val current = Paths.currentIndex
        val previous = Paths.previousIndex

        if (!staging.isFile) return PromoteResult.Corrupt("staging.$generation.nrdx is missing")

        // 0. Pre-flight. Never half-write into a full /data: we need room for the
        //    staging blob plus the hard link to the outgoing one, plus slack.
        val need = staging.length() * 2 + (4L shl 20)
        val free = runCatching { StatFs(Paths.misc.path).availableBytes }.getOrDefault(Long.MAX_VALUE)
        if (free < need) return PromoteResult.NoSpace(need)

        // 1. Structural + cryptographic verification of the artefact we are about
        //    to hand netd. The resolver validates again on its side and falls
        //    open if it fails, but discovering that inside netd is far too late.
        val info = Native.verify(staging.absolutePath)
        if (!info.ok) return PromoteResult.Corrupt(info.error ?: "unknown")
        if (!info.sha256Ok) return PromoteResult.Corrupt("sha256 mismatch")
        if (info.generation != generation) {
            // A staging file whose header disagrees with its name would be
            // published under one number and remapped under another.
            return PromoteResult.Corrupt(
                "header says generation ${info.generation}, file says $generation"
            )
        }
        // The liveness-probe redirect has to be in the index or the Home screen
        // goes permanently blind — it would report "Limited" on a healthy device
        // and there would be no way for the user to tell the difference from a
        // genuinely dead hook. Checked here as well as by the canary because the
        // two look at it from opposite ends: verify reads the redirect table
        // directly, the canary asks the matcher.
        if (!info.probePresent) {
            return PromoteResult.Corrupt("index carries no ${Probes.IDX} redirect")
        }

        // 2. ABI gate. filter_abi is 0 until the resolver has published one — an
        //    unknown ABI is not a licence to assume the newest, so we only refuse
        //    on a positive, known-too-old answer.
        val resolverAbi = ControlPage.filterAbi()
        if (resolverAbi != 0 && info.formatVersion > resolverAbi) {
            return PromoteResult.AbiTooNew(resolverAbi, info.formatVersion)
        }

        // 3. Behavioural gate, using the SAME NrQuery.cpp the resolver links.
        val canary = CanarySet.run(context, staging.absolutePath)
        if (!canary.ok) return PromoteResult.CanaryFailed(canary.firstFailure)

        // 4. Sanity. Distinct from the canary: the canary asks "is this index
        //    wrong", this asks "is this index suspiciously empty".
        val previousCount = Native.verify(current.absolutePath).let {
            if (it.ok) it.blockCount else 0
        }
        if (previousCount > 0 && info.blockCount < previousCount * SANITY_MIN_RATIO) {
            return PromoteResult.SanityFailed(info.blockCount, previousCount)
        }

        // 5. Publish. The hard link keeps `current.nrdx` continuously present:
        //    rename-away-then-rename-in would leave a window with no current
        //    index at all, and a resolver that happened to remap inside it would
        //    fail open for no reason.
        try {
            runCatching { Files.deleteIfExists(previous.toPath()) }
            if (current.exists()) {
                runCatching { Files.createLink(previous.toPath(), current.toPath()) }
                    .onFailure { Log.w(TAG, "previous.nrdx link failed: ${it.message}") }
            }
            Os.rename(staging.absolutePath, current.absolutePath)
            fsyncDirectory(Paths.index)
        } catch (t: Throwable) {
            return PromoteResult.IoError(t.message ?: t.javaClass.simpleName)
        }

        // 6. Release-store the generation. LAST, and by itself: this is the store
        //    the resolver polls, so everything it must see has to be durable and
        //    visible before it retires.
        if (!ControlPage.setWantGeneration(generation)) {
            // The index is in place and valid; only the notification failed. The
            // resolver will pick it up at the next boot when the seeder republishes.
            Log.e(TAG, "promoted gen=$generation but want_generation store failed")
            return PromoteResult.IoError(ControlPage.lastError ?: "want_generation not stored")
        }

        Settings.setLastPromotedGeneration(context, generation)
        Log.i(TAG, "promoted generation=$generation entries=${info.blockCount}")
        cleanupStaging(generation)
        return PromoteResult.Ok
    }

    /**
     * Step back down the degradation ladder: `current` -> `previous`.
     *
     * Deliberately gets its own generation number rather than restoring the old
     * one — see [next]. The resolver must observe a *change*, and reverting the
     * number to a value it has already mapped is exactly the case where it would
     * not.
     */
    fun rollback(context: Context): PromoteResult {
        val previous = Paths.previousIndex
        if (!previous.isFile) return PromoteResult.Corrupt("no previous.nrdx to roll back to")

        val info = Native.verify(previous.absolutePath)
        if (!info.ok) return PromoteResult.Corrupt(info.error ?: "previous.nrdx is unusable")

        val gen = next(context)
        val staging = Paths.stagingIndex(gen)
        return try {
            runCatching { Files.deleteIfExists(staging.toPath()) }
            Files.createLink(staging.toPath(), previous.toPath())
            Os.rename(staging.absolutePath, Paths.currentIndex.absolutePath)
            fsyncDirectory(Paths.index)
            if (!ControlPage.setWantGeneration(gen)) {
                PromoteResult.IoError(ControlPage.lastError ?: "want_generation not stored")
            } else {
                Settings.setLastPromotedGeneration(context, gen)
                Log.w(TAG, "rolled back to previous.nrdx as generation=$gen")
                PromoteResult.Ok
            }
        } catch (t: Throwable) {
            PromoteResult.IoError(t.message ?: t.javaClass.simpleName)
        }
    }

    /** True when there is something to roll back to, for the Diagnostics button. */
    fun canRollback(): Boolean =
        Paths.previousIndex.isFile && Native.verify(Paths.previousIndex.absolutePath).ok

    /**
     * The side artefacts for a generation: the UI strings blob and the manifest.
     *
     * They are written next to the index and promoted with it, but they are NOT
     * part of the atomic swap: netd never reads either, so a torn or missing one
     * costs a Rules screen that says "unavailable", never a wrong verdict.
     */
    fun sideArtefacts(generation: Long): List<File> =
        listOf(Paths.stringsBlob(generation), Paths.manifestJson(generation))

    /**
     * Removes staging blobs from builds that never made it, and side artefacts
     * older than the two generations still reachable.
     *
     * Keeps the failed artefact of the *current* generation, which Diagnostics
     * may still want to verify, and never touches `quarantine.nrdx` — that one
     * is evidence the boot-loop breaker left behind deliberately.
     */
    fun cleanupStaging(keepGeneration: Long) {
        val keepStaging = Paths.stagingIndex(keepGeneration).name
        val liveGenerations = setOf(
            keepGeneration,
            Native.verify(Paths.currentIndex.absolutePath).let { if (it.ok) it.generation else 0L },
            Native.verify(Paths.previousIndex.absolutePath).let { if (it.ok) it.generation else 0L },
        ).filter { it > 0 }.sortedDescending().take(KEEP_GENERATIONS).toSet()

        Paths.index.listFiles()?.forEach { f ->
            val name = f.name
            when {
                name.startsWith("staging.") && name != keepStaging -> runCatching { f.delete() }

                name.startsWith("strings.") || name.startsWith("manifest.") -> {
                    val gen = name.substringAfter('.').substringBefore('.').toLongOrNull()
                    if (gen != null && gen !in liveGenerations) runCatching { f.delete() }
                }
            }
        }
    }

    /**
     * `rename()` is atomic but the directory entry is not durable until the
     * directory itself is synced. Without this a power loss between promotion and
     * the next writeback can leave `current.nrdx` pointing at nothing.
     */
    private fun fsyncDirectory(dir: File) {
        runCatching {
            val fd = Os.open(dir.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
        }.onFailure { Log.w(TAG, "fsync ${dir.path} failed: ${it.message}") }
    }
}
