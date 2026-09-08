package com.bestrom.nullroute.build

import android.content.Context
import android.os.SystemClock
import android.util.Log
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Generation
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.data.Categories
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.RuleStore
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.net.HotfixFeed
import com.bestrom.nullroute.net.SourceSync
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * The update pipeline: fetch, overlay, compile, check, publish.
 *
 * ## This file orchestrates; it does not compute
 *
 * Every expensive step already exists somewhere better suited to it.
 * [SourceSync] does the version probe, the conditional GET and the per-source
 * disposition. `nativeBuild` parses, external-sorts, k-way merges, suffix
 * collapses and emits the NRDX — in C++, with bounded RSS, because 443,000 Java
 * strings is 60-90 MB of heap and Android's per-app limit would kill the job.
 * [Generation] owns verification, the ABI gate, the canary, the sanity ratio and
 * the atomic publish. What is left, and what is here, is the ordering: which
 * files go into the overlay, in what order, under what name, and what the user is
 * told while it happens.
 *
 * ## What the caller is promised
 *
 *  * **It never throws.** `ui/UpdateFragment` calls this inside a bare
 *    `NullrouteApp.io.execute { }` with no try/catch, and an escaping Throwable
 *    there reaches the thread's default handler and takes the process down.
 *    Every failure comes back as [Outcome.Failure] instead, and
 *    [Outcome.Failure.recoverable] is what tells `JobScheduler` whether a retry
 *    could ever help.
 *  * **It always ends with [BuildStep.Done].** The screen's step line is set from
 *    it, so a path that returned without one would leave the UI mid-sentence.
 *  * **Stopping it is free.** Nothing outside `priv/build` and
 *    `staging.<gen>.nrdx` is written until [Generation.promote] renames, so a
 *    killed job leaves the device with exactly the index it had.
 *
 * Blocking, minutes long, and the listener fires on the calling thread —
 * `UpdateFragment` re-posts to the main looper itself.
 */
object IndexBuilder {

    private const val TAG = "Nullroute"

    /**
     * Bumped when the overlay assembly below changes shape.
     *
     * It is mixed into the configuration fingerprint, so a build whose *inputs*
     * are unchanged but whose *rules for combining them* are not still recompiles
     * once after an update, rather than reporting "already up to date" while
     * serving an index built by the old logic.
     */
    private const val FINGERPRINT_VERSION = 1

    private const val PREFS = "nullroute_build"
    private const val KEY_FINGERPRINT = "config_fingerprint"
    private const val KEY_FINGERPRINT_GEN = "config_fingerprint_generation"

    // ---- what the screen is told --------------------------------------------

    fun interface Listener {
        fun onStep(step: BuildStep)
    }

    /**
     * One point in the pipeline.
     *
     * The subclass set is **closed**: `ui/UpdateFragment` switches over it with no
     * `else` branch, and a ninth subclass would stop that file compiling. New
     * information goes into a new field with a default, the way [Fetched] gained
     * [Fetched.sources].
     */
    sealed class BuildStep {

        object Starting : BuildStep()

        /** [index] is 0-based, as `SourceSync.Listener` reports it. */
        data class Fetching(val index: Int, val total: Int, val label: String) : BuildStep()

        data class Fetched(
            val summary: String,
            val failures: List<String>,
            val sources: List<String> = emptyList(),
            val nothingChanged: Boolean = false,
        ) : BuildStep()

        object Overlaying : BuildStep()

        object Compiling : BuildStep()

        data class Compiled(val stats: Native.BuildStats) : BuildStep()

        object Checking : BuildStep()

        object Promoting : BuildStep()

        data class Done(val outcome: Outcome) : BuildStep()
    }

    /** How the run ended. */
    sealed class Outcome {

        abstract val ok: Boolean

        /** One line for the step display. Already localised; show it unchanged. */
        abstract fun message(): String

        data class Success(
            val generation: Long,
            val elapsedMs: Long,
            val warnings: List<String>,
            /** False on the daily no-op run: nothing changed, nothing recompiled. */
            val changed: Boolean = true,
            val entries: Int = 0,
            val summary: String = "",
        ) : Outcome() {
            override val ok: Boolean get() = true
            override fun message(): String = summary
        }

        /**
         * [recoverable] false means no retry can change the answer — a missing
         * native compiler, an index the installed resolver cannot read. Asking
         * `JobScheduler` to back off exponentially on one of those burns wakeups
         * forever.
         */
        data class Failure(val reason: String, val recoverable: Boolean) : Outcome() {
            override val ok: Boolean get() = false
            override fun message(): String = reason
        }
    }

    // ---- the run ------------------------------------------------------------

    /**
     * Runs one update. Blocking; background thread only.
     *
     * [context] may be any context — the application context is taken from it and
     * held for the duration, so a Fragment context cannot leak through.
     */
    fun run(context: Context, listener: Listener?): Outcome {
        val app = context.applicationContext
        val startedAt = SystemClock.elapsedRealtime()

        val outcome = try {
            compile(app, listener, startedAt)
        } catch (e: OutOfMemoryError) {
            // Retrying a compile that ran the process out of memory, every 30
            // minutes, with exponential backoff, is a battery bill for an answer
            // we already have. The periodic daily job still comes round.
            Log.e(TAG, "out of memory while building", e)
            Outcome.Failure("Ran out of memory while compiling the index.", recoverable = false)
        } catch (t: Throwable) {
            Log.e(TAG, "update failed", t)
            Outcome.Failure(t.message ?: t.javaClass.simpleName, recoverable = true)
        }

        runCatching {
            Settings.recordUpdate(
                app, outcome.ok, outcome.message(),
                (outcome as? Outcome.Success)?.entries ?: 0,
            )
        }
        emit(listener, BuildStep.Done(outcome))
        return outcome
    }

    private fun compile(context: Context, listener: Listener?, startedAt: Long): Outcome {
        emit(listener, BuildStep.Starting)

        // init.nullroute.rc creates /data/misc/nullroute at post-fs-data. Creating
        // it here would give it app ownership and hide a boot failure behind an
        // update that looked like it worked.
        if (!Paths.stateTreeReady()) {
            return Outcome.Failure(
                "Nullroute's storage was not set up at boot. Reboot, then try again.",
                recoverable = false,
            )
        }
        if (!Native.available) {
            return Outcome.Failure(
                "The index compiler is missing from this build.", recoverable = false,
            )
        }
        if (!Paths.ensureAppDirs()) {
            return Outcome.Failure(
                "Could not create ${Paths.buildScratch}.", recoverable = true,
            )
        }

        val warnings = ArrayList<String>()
        val profile = ProfileStore.activeProfile(context)

        // ---- 1-2. version probe and fetch -----------------------------------

        val report = SourceSync.sync(context, profile) { index, total, source ->
            emit(listener, BuildStep.Fetching(index, total, source.label))
        }

        // The hotfix feed is a safety net, not a source: it can only ever add
        // allow rules, and announcing its absence would train people to ignore a
        // message that means nothing on a day when nothing is broken.
        val hotfix = runCatching { HotfixFeed.refresh() }.getOrNull()
        if (hotfix?.ok == false) Log.i(TAG, "hotfix feed: ${hotfix.message}")

        report.stale.forEach {
            warnings += "${it.source.label}: using the cached copy"
        }

        val fingerprint = fingerprint(context, report)
        val unchanged = report.nothingChanged && fingerprint == storedFingerprint(context)

        emit(
            listener,
            BuildStep.Fetched(
                summary = report.summary(),
                failures = report.failures.map { "${it.source.label} — ${it.describe()}" },
                sources = report.all.map { "${it.source.label} — ${it.describe()}" },
                nothingChanged = unchanged,
            ),
        )

        // A failed download is survivable; nothing at all to compile is not. This
        // is the case a build must refuse rather than publish, because an index
        // compiled from no lists blocks nothing and looks exactly like success.
        if (!report.anyBlockContent) {
            return Outcome.Failure(
                "No blocklists could be downloaded, and none are cached yet.",
                recoverable = true,
            )
        }

        if (unchanged) {
            currentIfHealthy()?.let { live ->
                Log.i(TAG, "nothing changed; keeping generation ${live.generation}")
                return Outcome.Success(
                    generation = live.generation,
                    elapsedMs = SystemClock.elapsedRealtime() - startedAt,
                    warnings = warnings,
                    changed = false,
                    entries = live.blockCount,
                    summary = context.getString(R.string.pipeline_outcome_uptodate),
                )
            }
            // The inputs are current but the published index is not usable. Fall
            // through and rebuild: "nothing changed" is a statement about the
            // downloads, never a reason to leave a broken index in place.
            Log.w(TAG, "inputs unchanged but current.nrdx is not usable; rebuilding")
        }

        // ---- 3-7. overlay ---------------------------------------------------

        emit(listener, BuildStep.Overlaying)
        val overlay = writeOverlay(context, report, warnings)

        // Everything downloaded, and none of it compilable — today that can only
        // be the licence gate below. The native compiler would accept it and
        // produce an index that blocks nothing, which is the one outcome that is
        // indistinguishable from success.
        if (overlay.sources.isEmpty()) {
            return Outcome.Failure(
                "No blocklist could be compiled from what is on this device.",
                recoverable = true,
            )
        }

        // ---- 8-9. compile ---------------------------------------------------

        val generation = Generation.next(context)
        val staging = Paths.stagingIndex(generation)

        emit(listener, BuildStep.Compiling)
        val stats = Native.build(
            sourcePaths = overlay.sources.map { it.path.absolutePath },
            allowPath = overlay.allow.absolutePath,
            denyPath = overlay.deny.absolutePath,
            redirectPath = overlay.redirect.absolutePath,
            outPath = staging.absolutePath,
            generation = generation,
        )
        emit(listener, BuildStep.Compiled(relabelled(stats, overlay)))
        stats.sources.filter { it.error != null }.forEach {
            warnings += "${labelFor(it.path, overlay)}: ${it.error}"
        }

        writeManifest(context, generation, report, stats, overlay)

        // ---- the strings sidecar, which this build CANNOT produce -----------
        //
        // strings.<gen>.nrdx is the front-coded rule text the Rules screen reads
        // for "this pattern matches N entries". Everything for it exists on the
        // native side — NrBuilder.h takes a `strings_out` blob and NrStrings.cpp
        // fills it — but nothing reachable from here asks for one: nr_compile()
        // never passes the parameter and nativeBuild has no output path for it.
        // So the sidecar is absent for every generation this builder publishes,
        // Native.stringsPreview reports "unavailable", and the Rules screen shows
        // no counts. That is a real gap, not a degraded mode this file chose, and
        // closing it needs a new JNI parameter or entry point in
        // native/jni_bridge.cpp — outside this package.
        if (!Paths.stringsBlob(generation).isFile) {
            Log.w(
                TAG,
                "no strings.$generation.nrdx: nativeBuild has no output path for the " +
                    "strings sidecar, so the Rules screen has no match counts",
            )
        }

        // ---- 10-11. check and publish ---------------------------------------
        //
        // Both live inside Generation.promote: verification, the ABI gate, the
        // canary and the sanity ratio all run before the rename, and the rename
        // is followed by the release-store of want_generation. The two steps are
        // reported around it rather than inside it because promote is one
        // decision, and splitting it here would mean two callers of the canary.

        emit(listener, BuildStep.Checking)
        val promoted = Generation.promote(context, generation)
        if (!promoted.succeeded) {
            // The staging blob is deliberately left on disk: Diagnostics can still
            // verify it, and cleanupStaging keeps only the current generation's.
            Log.w(TAG, "generation $generation not promoted: ${promoted.describe()}")
            return Outcome.Failure(promoted.describe(), promoted.recoverable)
        }
        emit(listener, BuildStep.Promoting)

        // Only now, and in this order: the cache is pruned after a build that
        // succeeded, so a profile switch that failed to compile can switch back
        // without re-downloading 9 MB.
        val liveUrls = report.all.map { it.source.url } + HotfixFeed.URL
        runCatching { SourceSync.pruneCache(liveUrls) }
        runCatching { Generation.cleanupStaging(generation) }
        storeFingerprint(context, fingerprint, generation)

        Log.i(TAG, "published generation=$generation entries=${stats.effectiveBlockCount}")
        return Outcome.Success(
            generation = generation,
            elapsedMs = SystemClock.elapsedRealtime() - startedAt,
            warnings = warnings,
            changed = true,
            entries = stats.effectiveBlockCount,
            summary = context.getString(
                R.string.pipeline_outcome_updated, stats.effectiveBlockCount,
            ),
        )
    }

    private fun emit(listener: Listener?, step: BuildStep) {
        if (listener == null) return
        // A listener that throws is the screen's problem, not the build's: the
        // compile has to survive a Fragment that went away mid-step.
        runCatching { listener.onStep(step) }
            .onFailure { Log.w(TAG, "build listener threw: ${it.message}") }
    }

    // ---- the overlay files --------------------------------------------------

    /** One fetched blocklist, with the name it is known by. */
    private data class SourceFile(val path: File, val label: String)

    private class Overlay(
        val allow: File,
        val deny: File,
        val redirect: File,
        val sources: List<SourceFile>,
    )

    /**
     * Writes the three overlay files `nativeBuild` takes, in the order SPEC §6.5
     * step 7 defines.
     *
     * The native side takes exactly three: one allow, one deny, one redirect. So
     * everything the spec lists as a separate overlay stage — the user's rules,
     * the hotfix feed, the carve-outs, the floor, the fetched allowlist seeds —
     * is flattened into those three here. Ordering inside a file is documentation
     * rather than precedence: precedence in the matcher is by rule *kind*
     * (`K_FORCE` beats everything, then SUFFIX, WILDCARD_ONLY, EXACT), not by
     * position, which is what makes the floor unbeatable no matter where it sits.
     */
    private fun writeOverlay(
        context: Context,
        report: SourceSync.Report,
        warnings: MutableList<String>,
    ): Overlay {
        val scratch = Paths.buildScratch

        // (a) The fetched block lists, including the category add-ons, which
        //     SourceSync already folded in. Group ids are positional from here
        //     on: sources[i] becomes group 1+i, and manifest.<gen>.json is what
        //     turns that number back into a name.
        val sources = ArrayList<SourceFile>()
        for (result in report.blockSources) {
            val file = result.file
            if (!result.usable || file == null) continue
            // The licensing posture, mechanically checked rather than trusted to a
            // paragraph in a README: a GPL-3.0 or MPL-2.0 list must arrive over the
            // network into priv/cache, so that the compiled derivative work is
            // created on the user's device rather than shipped inside a signed
            // image. A copy of one that turned up on the read-only partition is
            // refused, not compiled.
            if (file.startsWith(Paths.systemExtEtc) &&
                !SourceSync.mayComeFromImage(result.source.licence)
            ) {
                Log.w(TAG, "${result.source.label}: ${result.source.licence.spdx} may not ship in the image")
                warnings += "${result.source.label}: not compiled — its licence forbids shipping it in the ROM"
                continue
            }
            sources += SourceFile(file, result.source.label)
        }

        val allow = File(scratch, "overlay-allow.txt")
        val deny = File(scratch, "overlay-deny.txt")
        val redirect = File(scratch, "overlay-redirect.txt")

        // (b) user deny.txt — pinned, so it survives a profile switch and a reset.
        writeLines(
            deny,
            "# Generated by Nullroute. Rebuilt on every update; edit priv/deny.txt instead.",
            RuleStore.readDeny().map { it.toDenyLine() },
        )

        val allowLines = ArrayList<String>()

        // The fetched allowlist seeds (`@<url>` lines in the profile). Least
        // authoritative of the allow inputs and first in the file for that reason,
        // though nothing in the matcher reads position.
        var seeded = 0
        val allowBuffer = StringBuilder()
        report.allowSources.forEach { result ->
            val file = result.file
            if (!result.usable || file == null) return@forEach
            seeded += SourceSync.appendAllowLines(file, allowBuffer)
        }
        if (seeded > 0) allowLines += allowBuffer.lines().filter { it.isNotBlank() }

        // (c) the user's own allow rules — patterns, never expansions.
        allowLines += RuleStore.readAllow().map { it.toAllowLine() }

        // (d) the BestROM hotfix feed. Allow-only by construction; it cannot
        //     force-allow and it cannot block.
        allowLines += runCatching { HotfixFeed.toAllowLines() }.getOrDefault(emptyList())

        // (e) the anti-fraud and attribution carve-outs the user did NOT opt into
        //     blocking. Kept verbatim — `*.threatmetrix.com` stays a wildcard,
        //     because flattening it would silently widen the carve-out to the apex.
        allowLines += Categories.allowCarveOutDomains(context).map { "@$it" }

        // (f) the never-block floor, as K_FORCE.
        //
        //     The native builder injects /system_ext/etc/nullroute/neverblock.txt
        //     itself, so this is belt and braces there — but its input is optional
        //     and a device without that file (a partial flash, the Gradle parity
        //     build) has no floor at all unless this writes one.
        allowLines += NeverBlockFloor.forceAllowLines(context)

        writeLines(
            allow,
            "# Generated by Nullroute. Rebuilt on every update; edit priv/allow.txt instead.",
            allowLines,
        )

        // (g) redirects: the user's own, plus the index liveness probe.
        //
        //     idx-probe is added by the native builder as well, for the same
        //     reason as the floor. The OTHER probe, hosts-probe.nullroute.invalid,
        //     is deliberately NOT here and must never be: it is answered by
        //     /system/etc/hosts and by nothing else, which is the only reason its
        //     answer proves the L0 layer is intact. An index that redirected it
        //     would report a healthy hosts file on a device whose hosts file had
        //     been replaced.
        val redirects = RuleStore.readRedirects().map { it.toLine() } +
            "${Probes.IDX_EXPECT} ${Probes.IDX}"
        writeLines(
            redirect,
            "# Generated by Nullroute. Rebuilt on every update; edit priv/redirect.txt instead.",
            redirects,
        )

        return Overlay(allow, deny, redirect, sources)
    }

    /**
     * `<file>.tmp` then rename, like [RuleStore] does for the user's own rules: a
     * truncate-in-place that is killed halfway leaves a file the native builder
     * would read as a shorter, valid rule set.
     */
    private fun writeLines(file: File, header: String, lines: List<String>) {
        writeAtomically(file) { out ->
            out.appendLine(header)
            lines.forEach { out.appendLine(it) }
        }
    }

    private fun writeAtomically(file: File, body: (Appendable) -> Unit) {
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.bufferedWriter().use { out -> body(out) }
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw IOException("could not write ${file.name}")
        }
    }

    // ---- manifest.<gen>.json ------------------------------------------------

    /**
     * Writes the per-source manifest for a generation.
     *
     * This is the only place a group id is paired with a name. `nrctl query`, the
     * Rules screen and the log all show "blocked by HaGeZi Multi Pro" by reading
     * it back through `nr_manifest_group_name()`, which is a hand-rolled scanner
     * in a boot binary, not a JSON parser: it walks `{`…`}` pairs and pulls an
     * integer `group` and a string `name` out of each. Two constraints follow, and
     * breaking either costs the names on every row:
     *
     *  * no nested objects, and no `{` or `}` inside any value (stripped below);
     *  * no top-level key called `group` or `name`, or the first source entry
     *    would be read through the preamble.
     */
    private fun writeManifest(
        context: Context,
        generation: Long,
        report: SourceSync.Report,
        stats: Native.BuildStats,
        overlay: Overlay,
    ) {
        val statByPath = stats.sources.associateBy { it.path }
        val resultByPath = report.all.mapNotNull { r -> r.file?.let { it.absolutePath to r } }.toMap()

        val json = StringBuilder(1024)
        json.append("{\n")
        json.append("  \"generation\": ").append(generation).append(",\n")
        json.append("  \"built_at_ms\": ").append(System.currentTimeMillis()).append(",\n")
        json.append("  \"profile_id\": \"").append(esc(ProfileStore.activeProfile(context).id))
            .append("\",\n")
        json.append("  \"entries\": ").append(stats.effectiveBlockCount).append(",\n")
        json.append("  \"allow_entries\": ").append(stats.allowKept).append(",\n")
        json.append("  \"redirects\": ").append(stats.redirects).append(",\n")
        json.append("  \"bytes\": ").append(stats.bytes).append(",\n")
        json.append("  \"sha256\": \"").append(esc(stats.sha256)).append("\",\n")
        json.append("  \"sources\": [\n")

        overlay.sources.forEachIndexed { i, source ->
            val path = source.path.absolutePath
            val stat = statByPath[path]
            val result = resultByPath[path]
            json.append("    { \"group\": ").append(i + 1)
            json.append(", \"name\": \"").append(esc(source.label)).append('"')
            json.append(", \"url\": \"").append(esc(result?.source?.url.orEmpty())).append('"')
            json.append(", \"licence\": \"").append(esc(result?.source?.licence?.spdx.orEmpty()))
                .append('"')
            json.append(", \"disposition\": \"").append(esc(result?.disposition?.name.orEmpty()))
                .append('"')
            json.append(", \"version\": \"").append(esc(result?.version?.describe().orEmpty()))
                .append('"')
            json.append(", \"lines\": ").append(stat?.lines ?: 0)
            json.append(", \"parsed\": ").append(stat?.parsed ?: 0)
            json.append(", \"rejected\": ").append(stat?.rejected ?: 0)
            json.append(", \"error\": \"").append(esc(stat?.error.orEmpty())).append('"')
            json.append(" }")
            if (i != overlay.sources.lastIndex) json.append(',')
            json.append('\n')
        }
        json.append("  ],\n")

        // After the sources array on purpose: everything above is scanned by the
        // native reader looking for the first `{`, and an object here would be
        // read as a source entry.
        json.append("  \"categories\": [")
        Categories.describe(context).forEachIndexed { i, line ->
            if (i > 0) json.append(", ")
            json.append('"').append(esc(line)).append('"')
        }
        json.append("]\n}\n")

        val file = Paths.manifestJson(generation)
        runCatching { writeAtomically(file) { out -> out.append(json) } }
            .onFailure {
                // A missing manifest costs display names, never a verdict. It is
                // not worth failing a build that is otherwise sound.
                Log.w(TAG, "manifest for generation $generation not written: ${it.message}")
            }
    }

    /**
     * JSON string escaping, plus `{` and `}`.
     *
     * Braces are not a JSON problem — they are legal inside a string — but
     * `nr_manifest_group_name()` finds object boundaries by scanning for them, so
     * a list whose label contained one would truncate the entry and lose the name.
     */
    private fun esc(value: String): String {
        val out = StringBuilder(value.length + 8)
        for (c in value) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '{' || c == '}' -> out.append(' ')
                c.code < 0x20 -> out.append(' ')
                else -> out.append(c)
            }
        }
        return out.toString()
    }

    // ---- naming -------------------------------------------------------------

    private fun labelFor(path: String, overlay: Overlay): String =
        overlay.sources.firstOrNull { it.path.absolutePath == path }?.label ?: File(path).name

    /**
     * The stats the screen sees, with cache file names replaced by list names.
     *
     * `Native.SourceStat.name` is `File(path).name`, and the paths handed to the
     * compiler are `priv/cache/<sha1(url)>.raw`. `UpdateFragment` titles a
     * per-source error row with that name, and "a5f3…c1.raw could not be read" is
     * not something a user can act on. Only the copy handed to the listener is
     * relabelled; the manifest keeps the real paths.
     */
    private fun relabelled(stats: Native.BuildStats, overlay: Overlay): Native.BuildStats =
        stats.copy(sources = stats.sources.map { it.copy(path = labelFor(it.path, overlay)) })

    // ---- "nothing changed" --------------------------------------------------

    /**
     * A hash of everything that decides what the index contains, other than the
     * list bodies themselves.
     *
     * `SourceSync.Report.nothingChanged` proves the downloads are current. It says
     * nothing about the user having switched a category on, edited a rule or
     * changed profile since the last build — and skipping a compile in that state
     * would leave the device serving an index that does not match its own
     * settings, with the UI reporting success.
     */
    private fun fingerprint(context: Context, report: SourceSync.Report): String {
        val digest = MessageDigest.getInstance("SHA-256")
        fun mix(value: String) {
            digest.update(value.toByteArray())
            digest.update(0)
        }

        mix(FINGERPRINT_VERSION.toString())
        mix(ProfileStore.activeProfile(context).id)
        report.all.forEach { mix(it.source.url + "|" + it.source.role.name) }
        Categories.describe(context).forEach { mix(it) }
        // The floor as it will actually be applied, which folds in both the
        // shipped file and the live captive-portal URLs.
        mix(NeverBlockFloor.domains(context).joinToString(","))
        listOf(Paths.allowTxt, Paths.denyTxt, Paths.redirectTxt).forEach {
            mix("${it.name}:${it.length()}:${it.lastModified()}")
        }
        SourceSync.cacheBody(HotfixFeed.URL).let {
            mix("hotfix:${it.length()}:${it.lastModified()}")
        }

        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun prefs(context: Context) =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * The fingerprint of the build that produced the index now live, or null.
     *
     * Tied to a generation so that a rollback — which publishes an older index
     * under a new number — cannot be mistaken for "still current".
     */
    private fun storedFingerprint(context: Context): String? {
        val live = Native.verify(Paths.currentIndex.absolutePath)
        if (!live.ok) return null
        val p = prefs(context)
        if (p.getLong(KEY_FINGERPRINT_GEN, -1L) != live.generation) return null
        return p.getString(KEY_FINGERPRINT, null)
    }

    private fun storeFingerprint(context: Context, fingerprint: String, generation: Long) {
        prefs(context).edit()
            .putString(KEY_FINGERPRINT, fingerprint)
            .putLong(KEY_FINGERPRINT_GEN, generation)
            .apply()
    }

    /**
     * The live index, if it is one we would still be willing to publish.
     *
     * Anything less than fully sound here means the skip is refused and a real
     * build runs: "the downloads are current" is never a reason to leave a
     * damaged index in place.
     */
    private fun currentIfHealthy(): Native.IndexInfo? {
        val info = Native.verify(Paths.currentIndex.absolutePath)
        return if (info.ok && info.sha256Ok && info.probePresent && info.generation > 0) info else null
    }
}
