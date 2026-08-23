package com.bestrom.nullroute.core

import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * Typed facade over `libnrjni.so`.
 *
 * ============================================================================
 *  JNI SURFACE — CONTRACT WITH native/jni_bridge.cpp. Three methods, no more.
 * ============================================================================
 *
 * Class: `com.bestrom.nullroute.core.Native` (a Kotlin `object`, so the natives
 * are instance methods on the singleton; register them against the class as
 * usual — `RegisterNatives` on `Native` works unchanged).
 *
 * ```
 * nativeBuild(sourcePaths: Array<String>, allowPath: String, denyPath: String,
 *             redirectPath: String, outPath: String, generation: Long): String
 * ```
 * Parses every file in `sourcePaths` (format auto-detected per line by
 * `nr_parse_line`), applies `allowPath` / `denyPath` / `redirectPath`, external
 * sorts, collapses, and writes a complete NRDX blob to `outPath`, fsync'ing the
 * file **and** its directory before returning. Returns a JSON object; throws
 * `java.io.IOException` on any failure that leaves no usable output.
 *
 * ```json
 * { "ok": true, "generation": 42, "out_path": "/data/misc/.../staging.42.nrdx",
 *   "fmt_version": 1, "bytes": 4587520, "elapsed_ms": 8123,
 *   "parsed_lines": 592006, "block_in": 274412, "block_collapsed": 226398,
 *   "allow_in": 1712, "redirects": 2, "rejected": 91,
 *   "bt_cap": 524288, "at_cap": 4096, "rt_cap": 256,
 *   "sources": [ { "path": "...", "parsed": 188355, "rejected": 12,
 *                  "error": null } ] }
 * ```
 * A per-source failure is **non-fatal**: it appears as a non-null
 * `sources[].error` and the build continues. A source that vanishes must never
 * be silently treated as an empty list — that is how a truncated download turns
 * into "protection quietly stopped".
 *
 * ```
 * nativeQuery(indexPath: String, host: String): String
 * ```
 * Maps and validates `indexPath`, then runs `nr_evaluate_index()` — the same
 * object file the resolver links, so `nrctl query`, the build canary and the
 * live filter can never disagree. No control page is consulted (no mode, no
 * per-uid policy): this answers "what does the INDEX say", which is what a
 * canary and a diagnostics screen need.
 *
 * ```json
 * { "verdict": "pass"|"block"|"redirect", "depth": 2, "group": 3,
 *   "address": "127.0.0.7",     // redirect only
 *   "rule": "doubleclick.net" } // optional, only if the strings blob is present
 * { "error": "validate" }       // index unusable; caller must treat as PASS
 * ```
 *
 * ```
 * nativeVerify(indexPath: String): String
 * ```
 * Structural + cryptographic validation: `nr_index_validate()` plus the sha256
 * over `[4096, EOF)`. Never throws — a corrupt index is data, not an exception.
 *
 * ```json
 * { "ok": true, "fmt_version": 1, "generation": 42, "built_at_ms": 1756...,
 *   "n_block": 226398, "n_allow": 1712, "n_redirect": 2, "bytes": 4587520,
 *   "sha256_ok": true }
 * { "ok": false, "error": "magic" }
 * ```
 * `error` is one of: `open`, `size`, `mmap`, `magic`, `fmt_version`, `section`,
 * `capacity`, `load_factor`, `sha256`.
 * ============================================================================
 *
 * Everything here fails **open**. If the library is absent (the Gradle parity
 * build has no `.so`), if a JSON field is missing, if a call throws — the app
 * reports "unknown" and refuses to promote anything. It never guesses, and it
 * never reports health it did not measure.
 */
object Native {

    private const val TAG = "Nullroute"
    private const val LIB = "nrjni"

    /**
     * Whether `libnrjni.so` loaded. Checked before every native call rather than
     * relying on a static initializer, because a `System.loadLibrary` failure in
     * an `init` block would take the whole app process down with it — and an app
     * that cannot start is an app that cannot tell the user filtering is broken.
     */
    val available: Boolean by lazy {
        try {
            System.loadLibrary(LIB)
            true
        } catch (t: Throwable) {
            Log.w(TAG, "libnrjni unavailable: ${t.message}")
            false
        }
    }

    // ---- typed results ------------------------------------------------------

    data class SourceStat(
        val path: String,
        val parsed: Int,
        val rejected: Int,
        val error: String?,
    ) {
        val name: String get() = File(path).name
    }

    data class BuildStats(
        val generation: Long,
        val outPath: String,
        val bytes: Long,
        val elapsedMs: Long,
        val parsedLines: Long,
        val blockIn: Int,
        val blockCollapsed: Int,
        val allowIn: Int,
        val redirects: Int,
        val rejected: Int,
        val sources: List<SourceStat>,
    ) {
        /** Entries the resolver will actually map. The number the UI may show. */
        val effectiveBlockCount: Int get() = blockCollapsed
    }

    enum class VerdictKind { PASS, BLOCK, REDIRECT, UNKNOWN }

    data class QueryVerdict(
        val kind: VerdictKind,
        val depth: Int,
        val group: Int,
        val address: String?,
        val rule: String?,
        val error: String?,
    ) {
        val ok: Boolean get() = error == null
    }

    data class IndexInfo(
        val ok: Boolean,
        val error: String?,
        val formatVersion: Int,
        val generation: Long,
        val builtAtMs: Long,
        val blockCount: Int,
        val allowCount: Int,
        val redirectCount: Int,
        val bytes: Long,
        val sha256Ok: Boolean,
    ) {
        companion object {
            fun unavailable(reason: String) =
                IndexInfo(false, reason, 0, 0L, 0L, 0, 0, 0, 0L, false)
        }
    }

    // ---- public API ---------------------------------------------------------

    /**
     * Compiles a new index. Blocking and CPU/IO heavy — call from a background
     * thread only. Throws [IOException] if no usable artefact was produced.
     */
    @Throws(IOException::class)
    fun build(
        sourcePaths: List<String>,
        allowPath: String,
        denyPath: String,
        redirectPath: String,
        outPath: String,
        generation: Long,
    ): BuildStats {
        if (!available) throw IOException("libnrjni not loaded")
        val json = JSONObject(
            nativeBuild(
                sourcePaths.toTypedArray(), allowPath, denyPath,
                redirectPath, outPath, generation,
            )
        )
        if (!json.optBoolean("ok", false)) {
            throw IOException(json.optString("error", "build failed"))
        }
        val sources = ArrayList<SourceStat>()
        val arr = json.optJSONArray("sources")
        if (arr != null) {
            for (i in 0 until arr.length()) {
                val s = arr.optJSONObject(i) ?: continue
                sources += SourceStat(
                    path = s.optString("path"),
                    parsed = s.optInt("parsed"),
                    rejected = s.optInt("rejected"),
                    error = if (s.isNull("error")) null else s.optString("error"),
                )
            }
        }
        return BuildStats(
            generation = json.optLong("generation", generation),
            outPath = json.optString("out_path", outPath),
            bytes = json.optLong("bytes"),
            elapsedMs = json.optLong("elapsed_ms"),
            parsedLines = json.optLong("parsed_lines"),
            blockIn = json.optInt("block_in"),
            blockCollapsed = json.optInt("block_collapsed"),
            allowIn = json.optInt("allow_in"),
            redirects = json.optInt("redirects"),
            rejected = json.optInt("rejected"),
            sources = sources,
        )
    }

    /**
     * Asks the index — not the live filter — what it would do with [host].
     * Returns a verdict carrying [QueryVerdict.error] rather than throwing, so a
     * canary loop over a few hundred domains cannot be derailed by one bad name.
     */
    fun query(indexPath: String, host: String): QueryVerdict {
        if (!available) return QueryVerdict(VerdictKind.UNKNOWN, 0, 0, null, null, "no-jni")
        return try {
            val json = JSONObject(nativeQuery(indexPath, host))
            val err = if (json.isNull("error")) null else json.optString("error")
            if (err != null) return QueryVerdict(VerdictKind.UNKNOWN, 0, 0, null, null, err)
            QueryVerdict(
                kind = when (json.optString("verdict")) {
                    "block" -> VerdictKind.BLOCK
                    "redirect" -> VerdictKind.REDIRECT
                    "pass" -> VerdictKind.PASS
                    else -> VerdictKind.UNKNOWN
                },
                depth = json.optInt("depth"),
                group = json.optInt("group"),
                address = if (json.isNull("address")) null else json.optString("address"),
                rule = if (json.isNull("rule")) null else json.optString("rule"),
                error = null,
            )
        } catch (t: Throwable) {
            QueryVerdict(VerdictKind.UNKNOWN, 0, 0, null, null, t.message ?: "query failed")
        }
    }

    /** Structural + sha256 validation. Never throws. */
    fun verify(indexPath: String): IndexInfo {
        if (!available) return IndexInfo.unavailable("no-jni")
        return try {
            val json = JSONObject(nativeVerify(indexPath))
            IndexInfo(
                ok = json.optBoolean("ok", false),
                error = if (json.isNull("error")) null else json.optString("error"),
                formatVersion = json.optInt("fmt_version"),
                generation = json.optLong("generation"),
                builtAtMs = json.optLong("built_at_ms"),
                blockCount = json.optInt("n_block"),
                allowCount = json.optInt("n_allow"),
                redirectCount = json.optInt("n_redirect"),
                bytes = json.optLong("bytes"),
                sha256Ok = json.optBoolean("sha256_ok", false),
            )
        } catch (t: Throwable) {
            IndexInfo.unavailable(t.message ?: "verify failed")
        }
    }

    /**
     * Format version of an on-disk index, or 0 if it cannot be read. Used by the
     * ABI gate in [Generation.promote] — deliberately derived from [verify]
     * rather than given its own JNI entry point, so there is one parser of the
     * header on this side and no second one to drift.
     */
    fun formatVersion(indexPath: String): Int = verify(indexPath).let {
        if (it.ok) it.formatVersion else 0
    }

    // ---- raw JNI ------------------------------------------------------------

    private external fun nativeBuild(
        sourcePaths: Array<String>,
        allowPath: String,
        denyPath: String,
        redirectPath: String,
        outPath: String,
        generation: Long,
    ): String

    private external fun nativeQuery(indexPath: String, host: String): String

    private external fun nativeVerify(indexPath: String): String
}
