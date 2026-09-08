package com.bestrom.nullroute.core

import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * Typed facade over `libnrjni.so`.
 *
 * ============================================================================
 *  JNI SURFACE — the contract with native/jni_bridge.cpp. Three methods.
 * ============================================================================
 *
 * All three are declared on this Kotlin `object`, so they bind as
 * `Java_com_bestrom_nullroute_core_Native_native*` with a `jobject` receiver.
 *
 * ```
 * nativeBuild(sourcePaths: Array<String>, allowPath: String, denyPath: String,
 *             redirectPath: String, outPath: String, generation: Long): String
 * ```
 * Parses every file in `sourcePaths` (format sniffed per line by
 * `nr_parse_line`), applies the allow / deny / redirect overlays, external
 * sorts, collapses, and writes a complete NRDX to `outPath`, fsync'ing the file
 * and its directory. It does **not** publish — promotion is `rename()` plus the
 * release-store of `want_generation`, and that sequencing belongs to
 * [Generation].
 *
 * Group ids are positional: `sourcePaths[i]` becomes group `1 + i`, so a
 * verdict's group indexes straight back into the array we passed.
 *
 * **Two inputs are deliberately not parameters.** The never-block floor and the
 * `idx-probe` redirect are injected by the native side itself, so no caller can
 * build an index without them. [com.bestrom.nullroute.build.IndexBuilder] writes
 * them into the overlay files anyway — belt and braces on the two things whose
 * absence is unrecoverable from (a device that cannot reach a captive portal;
 * a liveness probe that can never go green).
 *
 * Returns JSON; **throws** `IllegalArgumentException`, `IOException`,
 * `IllegalStateException` or `OutOfMemoryError` on failure, so `ok` is always
 * true on a normal return:
 * ```json
 * { "ok": true, "path": "…/staging.42.nrdx", "generation": 42,
 *   "bytes": 4587520, "elapsed_ms": 8123, "sha256": "…",
 *   "block_in": 274412, "block_collapsed": 226398, "block_kept": 226398,
 *   "allow_in": 1712, "allow_kept": 1712, "redirects": 2,
 *   "bt_cap": 524288, "at_cap": 4096, "rt_cap": 256,
 *   "sources": [ { "path": "…", "group": 1, "role": 0, "present": true,
 *                  "lines": 188400, "parsed": 188355, "rejected": 12,
 *                  "error": "" } ] }
 * ```
 * A per-source failure is **non-fatal**: it appears as a non-empty
 * `sources[].error` with `present: false`, and the build continues. A source
 * that vanished must never be silently treated as an empty list — that is how a
 * truncated download becomes "protection quietly stopped".
 *
 * ```
 * nativeQuery(indexPath: String, host: String): String
 * ```
 * Maps and validates the index, then runs the same `nr_evaluate()` the resolver
 * runs inside netd, so the canary and the Query screen cannot tell the user
 * something different from what the device will actually do. Throws
 * `IOException` if the index cannot be read or does not validate.
 * ```json
 * { "ok": true, "host": "…", "canonical": "…", "evaluated": true,
 *   "verdict": "pass"|"block"|"redirect", "blocked": false,
 *   "labels": 3, "depth": 2, "group": 1, "group_name": "HaGeZi Multi Pro",
 *   "matched_rule": "doubleclick.net",
 *   "allow":    { "hit": false, "depth": 0, "kind": "", "group": 0, "rule": "" },
 *   "redirect": { "hit": true,  "address": "127.0.0.7" },
 *   "trace":    [ … per-depth walk … ] }
 * ```
 * `evaluated: false` is not an error — it is a name the matcher declines to look
 * at (IP literal, single label, `.local` and friends), and PASS is exactly what
 * the resolver would do with it.
 *
 * ```
 * nativeVerify(indexPath: String): String
 * ```
 * Structural validation, the sha256 seal, and the liveness-probe check. A file
 * that fails validation is **not** an exception — an unpublishable index is a
 * normal outcome of a compile and the caller needs the reason to show the user.
 * Only a file that cannot be read at all throws.
 * ```json
 * { "ok": true, "path": "…", "error": "", "size": 4587520, "fmt_version": 1,
 *   "generation": 42, "built_at_ms": 1756…, "hash_seed": …,
 *   "n_block": 226398, "n_allow": 1712, "n_redirect": 2,
 *   "bt_cap": …, "at_cap": …, "rt_cap": …,
 *   "min_labels": 2, "max_labels": 10, "label_mask": …,
 *   "sha256_state": "match"|"MISMATCH"|"unset",
 *   "sha256_header": "…", "sha256_actual": "…",
 *   "probe_present": true, "probe_address": "127.0.0.7",
 *   "sections": [ { "index": 0, "off": …, "len": … }, … ] }
 * ```
 * ============================================================================
 *
 * Everything here fails **open**. If the library is absent (the Gradle parity
 * build has no `.so`), if a field is missing, if a call throws — the app reports
 * "unknown" and refuses to promote anything. It never guesses, and it never
 * reports health it did not measure.
 */
object Native {

    private const val TAG = "Nullroute"
    private const val LIB = "nrjni"

    /**
     * Whether `libnrjni.so` loaded. Checked before every native call rather than
     * relying on a static initialiser: a `System.loadLibrary` failure in an
     * `init` block takes the whole process down, and an app that cannot start is
     * an app that cannot tell the user filtering is broken.
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
        val group: Int,
        val present: Boolean,
        val lines: Int,
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
        val sha256: String,
        val blockIn: Int,
        val blockCollapsed: Int,
        val blockKept: Int,
        val allowIn: Int,
        val allowKept: Int,
        val redirects: Int,
        val sources: List<SourceStat>,
    ) {
        /**
         * Entries the resolver will actually map — `n_block` straight out of the
         * written header, not the pre-collapse input count. This is the only
         * number the UI is allowed to call "domains blocked".
         */
        val effectiveBlockCount: Int get() = blockKept

        val rejected: Int get() = sources.sumOf { it.rejected }
    }

    enum class VerdictKind { PASS, BLOCK, REDIRECT, UNKNOWN }

    data class QueryVerdict(
        val kind: VerdictKind,
        val evaluated: Boolean,
        val depth: Int,
        val group: Int,
        val groupName: String,
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
        /**
         * Whether the `idx-probe` redirect made it into the index. Verified
         * natively as well as by the canary: without it the Home screen can
         * never observe the filter, so an index missing it is unpublishable no
         * matter how structurally sound it is.
         */
        val probePresent: Boolean,
        val probeAddress: String?,
    ) {
        companion object {
            fun unavailable(reason: String) =
                IndexInfo(false, reason, 0, 0L, 0L, 0, 0, 0, 0L, false, false, null)
        }
    }

    // ---- public API ---------------------------------------------------------

    /**
     * Compiles a new index. Blocking and CPU/IO heavy — background thread only.
     * Throws [IOException] if no usable artefact was produced.
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
        val json = try {
            JSONObject(
                nativeBuild(
                    sourcePaths.toTypedArray(), allowPath, denyPath,
                    redirectPath, outPath, generation,
                )
            )
        } catch (e: IOException) {
            throw e
        } catch (t: Throwable) {
            // The native side signals failure with IllegalArgumentException /
            // IllegalStateException / OutOfMemoryError as well. The caller only
            // has one recovery path for all of them, so they arrive as one type.
            throw IOException(t.message ?: t.javaClass.simpleName, t)
        }

        if (!json.optBoolean("ok", false)) {
            throw IOException(text(json, "error") ?: "build failed")
        }

        val sources = ArrayList<SourceStat>()
        val arr = json.optJSONArray("sources")
        if (arr != null) {
            for (i in 0 until arr.length()) {
                val s = arr.optJSONObject(i) ?: continue
                sources += SourceStat(
                    path = s.optString("path"),
                    group = s.optInt("group"),
                    present = s.optBoolean("present", true),
                    lines = s.optInt("lines"),
                    parsed = s.optInt("parsed"),
                    rejected = s.optInt("rejected"),
                    error = text(s, "error"),
                )
            }
        }

        return BuildStats(
            generation = json.optLong("generation", generation),
            outPath = json.optString("path", outPath),
            bytes = json.optLong("bytes"),
            elapsedMs = json.optLong("elapsed_ms"),
            sha256 = json.optString("sha256"),
            blockIn = json.optInt("block_in"),
            blockCollapsed = json.optInt("block_collapsed"),
            blockKept = json.optInt("block_kept"),
            allowIn = json.optInt("allow_in"),
            allowKept = json.optInt("allow_kept"),
            redirects = json.optInt("redirects"),
            sources = sources,
        )
    }

    /**
     * Asks the index — not the live filter — what it would do with [host].
     *
     * Returns a verdict carrying [QueryVerdict.error] rather than throwing, so a
     * canary loop over a few hundred domains cannot be derailed by one bad name.
     */
    fun query(indexPath: String, host: String): QueryVerdict {
        if (!available) return unknownVerdict("no-jni")
        return try {
            val json = JSONObject(nativeQuery(indexPath, host))
            val err = text(json, "error")
            if (!json.optBoolean("ok", true) || err != null) {
                return unknownVerdict(err ?: "query failed")
            }
            val redirect = json.optJSONObject("redirect")
            QueryVerdict(
                // `verdict_wire()` in NrCtlCore.cpp emits LOWERCASE — "pass",
                // "block", "redirect" — deliberately, so the wire form is
                // distinct from nr_verdict_name()'s human spelling. Matching the
                // human form here made every lookup fall through to UNKNOWN, and
                // because the canary reads must-allow as "kind == PASS", that
                // turned every promotion into an abort. Normalise rather than
                // matching a literal case, so neither spelling can break it.
                kind = when (json.optString("verdict").uppercase()) {
                    "BLOCK" -> VerdictKind.BLOCK
                    "REDIRECT" -> VerdictKind.REDIRECT
                    "PASS" -> VerdictKind.PASS
                    else -> VerdictKind.UNKNOWN
                },
                evaluated = json.optBoolean("evaluated", true),
                depth = json.optInt("depth"),
                group = json.optInt("group"),
                groupName = json.optString("group_name"),
                address = redirect?.let {
                    if (it.optBoolean("hit")) it.optString("address").ifEmpty { null } else null
                },
                rule = json.optString("matched_rule").ifEmpty { null },
                error = null,
            )
        } catch (t: Throwable) {
            unknownVerdict(t.message ?: "query failed")
        }
    }

    private fun unknownVerdict(reason: String) =
        QueryVerdict(VerdictKind.UNKNOWN, false, 0, 0, "", null, null, reason)

    /** Structural + sha256 + probe validation. Never throws. */
    fun verify(indexPath: String): IndexInfo {
        if (!available) return IndexInfo.unavailable("no-jni")
        return try {
            val json = JSONObject(nativeVerify(indexPath))
            IndexInfo(
                ok = json.optBoolean("ok", false),
                error = text(json, "error"),
                formatVersion = json.optInt("fmt_version"),
                generation = json.optLong("generation"),
                builtAtMs = json.optLong("built_at_ms"),
                blockCount = json.optInt("n_block"),
                allowCount = json.optInt("n_allow"),
                redirectCount = json.optInt("n_redirect"),
                bytes = json.optLong("size"),
                // "unset" is not "match". An index whose header carries no digest
                // has not been sealed, and treating that as verified would make
                // the seal optional in practice.
                sha256Ok = json.optString("sha256_state") == "match",
                probePresent = json.optBoolean("probe_present", false),
                probeAddress = json.optString("probe_address").ifEmpty { null },
            )
        } catch (t: Throwable) {
            IndexInfo.unavailable(t.message ?: "verify failed")
        }
    }

    /**
     * Format version of an on-disk index, or 0 if it cannot be read. Feeds the
     * ABI gate in [Generation.promote] — derived from [verify] rather than given
     * its own entry point, so there is one header parser on this side and no
     * second one to drift from it.
     */
    fun formatVersion(indexPath: String): Int = verify(indexPath).let {
        if (it.ok) it.formatVersion else 0
    }


    // ---- the strings sidecar (Phase 2 Rules screen) -------------------------
    //
    // `strings.<gen>.nrdx` is NOT the index. netd never maps it; it exists so the
    // app can answer a question the index structurally cannot — the index stores
    // 46-bit fingerprints, so it can say "blocked" but never "here are the twelve
    // rules that say so". Both calls below therefore take the SIDECAR path, not
    // Paths.currentIndex, and [stringsPathFor] is the only thing allowed to pair
    // a generation with its blob.

    /**
     * What a pattern typed on the Rules screen would actually cover.
     *
     * [ok] false is a normal outcome, not a failure to hide: the sidecar for a
     * generation is legitimately absent after a rollback that pruned it, or on a
     * device that has never completed a build. The screen then says the count is
     * unavailable and still accepts the rule — a rule the user cannot preview is
     * still a rule they are entitled to add.
     */
    data class RulePreview(
        val ok: Boolean,
        val error: String?,
        val base: String,
        /** Rules in the whole corpus, for "12 of 226,398". */
        val corpus: Int,
        val apex: Int,
        val subdomains: Int,
        val blocks: Int,
        val allows: Int,
        /** Rules in the range, before the scan budget was applied. */
        val range: Int,
        /**
         * The walk stopped at the budget, so [blocks] and [allows] are floors.
         * Presented as "at least N" — an undercount shown as exact is the same
         * class of lie as a status card that says "Protected" without measuring.
         */
        val truncated: Boolean,
        // Public rather than private because a data class exposes every
        // constructor property through componentN() and copy() anyway; hiding
        // them would only be decorative. [matchedFor] is still the accessor to
        // use — picking one of these by hand is how the apex/wildcard
        // distinction gets lost again.
        val matchSuffix: Int,
        val matchWildcard: Int,
        val matchExact: Int,
    ) {
        /**
         * The count to show for a rule of this kind, keyed on
         * `RuleStore.RuleKind.wire` — the same ABI value the native `RuleKind`
         * enum uses.
         *
         * Three numbers rather than one because they are genuinely different: a
         * `*.example.com` rule does not cover the apex, and showing it the total
         * would claim credit for a rule the matcher will never apply.
         */
        fun matchedFor(kindWire: Int): Int = when (kindWire) {
            0, 3 -> matchSuffix          // K_SUFFIX, K_FORCE
            1 -> matchWildcard           // K_WILDCARD_ONLY
            2 -> matchExact              // K_EXACT
            else -> matchSuffix
        }

        companion object {
            fun unavailable(reason: String, base: String = "") =
                RulePreview(false, reason, base, 0, 0, 0, 0, 0, 0, false, 0, 0, 0)
        }
    }

    /** One rule from the corpus, with the list that contributed it. */
    data class RuleRow(
        val rule: String,
        /** True when this row IS the base name rather than something below it. */
        val apex: Boolean,
        val kindWire: Int,
        val kindName: String,
        val allow: Boolean,
        val group: Int,
        /** Empty when the manifest for this generation is gone; never guessed. */
        val groupName: String,
    )

    data class RuleListing(
        val ok: Boolean,
        val error: String?,
        val range: Int,
        val truncated: Boolean,
        val rules: List<RuleRow>,
    ) {
        companion object {
            fun unavailable(reason: String) =
                RuleListing(false, reason, 0, false, emptyList())
        }
    }

    /**
     * The sidecar that belongs to [generation]. Deliberately a path and not a
     * lookup: pairing a strings blob with an index of a *different* generation
     * would show counts from a corpus the device is not serving, which is worse
     * than showing none.
     */
    fun stringsPathFor(generation: Long): String =
        Paths.stringsBlob(generation).absolutePath

    /**
     * Counts, for the live preview under the rule input. Never throws — this runs
     * from a text watcher on every keystroke, and an exception per keystroke for
     * the ordinary "no sidecar yet" state would be noise.
     */
    fun stringsPreview(stringsPath: String, base: String): RulePreview {
        if (!available) return RulePreview.unavailable("no-jni", base)
        if (base.isBlank()) return RulePreview.unavailable("empty", base)
        return try {
            val json = JSONObject(nativeStringsPreview(stringsPath, base))
            if (!json.optBoolean("ok", false)) {
                return RulePreview.unavailable(text(json, "error") ?: "unavailable", base)
            }
            RulePreview(
                ok = true,
                error = null,
                base = json.optString("base", base),
                corpus = json.optInt("corpus"),
                apex = json.optInt("apex"),
                subdomains = json.optInt("subdomains"),
                blocks = json.optInt("blocks"),
                allows = json.optInt("allows"),
                range = json.optInt("range"),
                truncated = json.optBoolean("truncated", false),
                matchSuffix = json.optInt("match_suffix"),
                matchWildcard = json.optInt("match_wildcard"),
                matchExact = json.optInt("match_exact"),
            )
        } catch (t: Throwable) {
            RulePreview.unavailable(t.message ?: "preview failed", base)
        }
    }

    /**
     * The rules themselves, so a count can be checked instead of believed.
     * Blocking on a mapping and a decode — background thread. Never throws.
     */
    fun stringsList(stringsPath: String, base: String, limit: Int): RuleListing {
        if (!available) return RuleListing.unavailable("no-jni")
        if (base.isBlank()) return RuleListing.unavailable("empty")
        return try {
            val json = JSONObject(nativeStringsList(stringsPath, base, limit))
            if (!json.optBoolean("ok", false)) {
                return RuleListing.unavailable(text(json, "error") ?: "unavailable")
            }
            val rows = ArrayList<RuleRow>()
            val arr = json.optJSONArray("rules")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val r = arr.optJSONObject(i) ?: continue
                    rows += RuleRow(
                        rule = r.optString("rule"),
                        apex = r.optBoolean("apex", false),
                        kindWire = r.optInt("kind"),
                        kindName = r.optString("kind_name"),
                        allow = r.optBoolean("allow", false),
                        group = r.optInt("group"),
                        groupName = r.optString("group_name"),
                    )
                }
            }
            RuleListing(
                ok = true,
                error = null,
                range = json.optInt("range"),
                truncated = json.optBoolean("truncated", false),
                rules = rows,
            )
        } catch (t: Throwable) {
            RuleListing.unavailable(t.message ?: "listing failed")
        }
    }

    /**
     * "No error" reaches us in two shapes: `jstr_or_null()` writes JSON `null`
     * and `jstr()` writes `""`, and both appear in the emitters. Both have to
     * mean absent.
     *
     * The `isNull` check is load-bearing, not defensive: `JSONObject.optString`
     * on a JSON null returns the four-character String "null", so dropping it
     * would make every clean verify report an error whose message is "null".
     */
    private fun text(json: JSONObject, key: String): String? {
        if (json.isNull(key)) return null
        val value = json.optString(key)
        return value.ifEmpty { null }
    }

    // ---- Deep mode (Phase 4) — native/jni_deep.cpp --------------------------
    //
    // A different shape from the three calls below, deliberately. Those answer
    // cold questions and return JSON so that `nrctl --json` and the app cannot
    // drift. These answer ONE question per DNS query on the Deep-mode packet
    // path, so the verdict comes back as a packed Long (decoded by
    // deep/DeepVerdict) with any redirect address written into a caller-owned
    // array, and only the diagnostics call emits JSON.
    //
    // The session handle names a slot in a fixed native pool plus the generation
    // that occupied it, so a call racing a close finds valid memory and a stale
    // generation rather than a freed pointer.

    /**
     * Maps [indexPath] read-only for the Deep-mode tunnel, plus [controlPath]
     * when the device has a control page. Returns 0 if the index could not be
     * mapped — Deep mode must not establish a tunnel it cannot filter with.
     * Never throws.
     */
    fun deepOpen(indexPath: String, controlPath: String?): Long {
        if (!available) return 0L
        return nativeDeepOpen(indexPath, controlPath)
    }

    /** Releases a session. Idempotent; safe with a stale handle. */
    fun deepClose(handle: Long) {
        if (available) nativeDeepClose(handle)
    }

    /**
     * The verdict for one hostname, as raw canonical bytes. Returns a negative
     * value for "no verdict", on which the caller relays the query untouched.
     *
     * [uid] must be a real application uid or a negative value; a negative uid
     * skips the per-app policy gate rather than indexing it with a wrapped
     * `uid_t`.
     */
    fun deepEvaluate(
        handle: Long,
        name: ByteArray,
        len: Int,
        uid: Int,
        outAddr: ByteArray,
    ): Long = nativeDeepEvaluate(handle, name, len, uid, outAddr)

    /** 1 if a newer index generation was mapped, 0 if unchanged, -1 on failure. */
    fun deepRefresh(handle: Long): Int = if (available) nativeDeepRefresh(handle) else -1

    /** JSON session state for Diagnostics. Cold path. */
    fun deepStatus(handle: Long): String = nativeDeepStatus(handle)

    // ---- raw JNI ------------------------------------------------------------
    //
    // These must stay inside `object Native` and keep these exact names.
    // jni_deep.cpp exports
    // Java_com_bestrom_nullroute_core_Native_nativeDeep{Open,Close,Evaluate,Refresh,Status}
    // with a jobject receiver, which is what a Kotlin `object` member compiles
    // to. Moving them to a different class changes the symbol and the failure is
    // an UnsatisfiedLinkError at the first blocked query — not at load, and not
    // at build.

    private external fun nativeDeepOpen(indexPath: String, controlPath: String?): Long

    private external fun nativeDeepClose(handle: Long)

    private external fun nativeDeepEvaluate(
        handle: Long,
        name: ByteArray,
        len: Int,
        uid: Int,
        outAddr: ByteArray,
    ): Long

    private external fun nativeDeepRefresh(handle: Long): Int

    private external fun nativeDeepStatus(handle: Long): String

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

    // The Phase 2 pair. Same `object Native` receiver and the same
    // Java_com_bestrom_nullroute_core_Native_native* symbols as everything above
    // — jni_bridge.cpp exports them next to nativeQuery.

    private external fun nativeStringsPreview(stringsPath: String, base: String): String

    private external fun nativeStringsList(
        stringsPath: String,
        base: String,
        limit: Int,
    ): String
}
