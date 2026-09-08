package com.bestrom.nullroute.net

import android.util.Log
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.data.RuleStore
import java.io.File

/**
 * The BestROM-hosted **allow** hotfix feed.
 *
 * ## What it is for
 *
 * A blocklist maintainer ships a rule that breaks a popular app. Upstream will
 * fix it, eventually; the user's bank does not work today. An OTA takes weeks.
 * This feed closes that gap to about an hour: one small text file, fetched on the
 * same schedule as everything else, whose entries are compiled in as allow rules
 * for the affected domains (§10.3.7).
 *
 * ## Why it can only ever ALLOW
 *
 * This is the one input to the index that comes from us rather than from the
 * user or from a list they chose, so it is the one input whose compromise would
 * be most valuable. A feed that could add *block* rules could switch off any
 * domain on the device — a bank, an update server, a messaging backend — from a
 * server, silently, for every BestROM user at once.
 *
 * So it structurally cannot. [parse] discards anything that is not an allow rule
 * and caps what remains. The worst a hostile or compromised feed can do is stop
 * some ad domains from being blocked, which is a bad day and not a security
 * incident; and the never-block floor, the user's own rules and the canary all
 * still run downstream of it.
 *
 * That is also why there is no signature check here and no pretending there is
 * one. HTTPS to a host we control, a strict grammar, a hard cap, and a blast
 * radius chosen so that the worst case is tolerable.
 */
object HotfixFeed {

    private const val TAG = "Nullroute"

    /**
     * The feed. A GitHub Pages URL rather than raw.githubusercontent because
     * Pages serves both an `ETag` and a `Last-Modified`, which makes the 600-byte
     * version probe work properly (see [Downloader]).
     */
    const val URL = "https://bestrom.github.io/nullroute/hotfix/allow.txt"

    /**
     * Hard cap on entries. The feed exists for breakage of the week, not as a
     * second allowlist: if it ever legitimately needs more than this, the fix
     * belongs upstream or in the shipped carve-out files.
     */
    private const val MAX_ENTRIES = 2_000

    data class Result(
        val applied: Int,
        val skipped: Int,
        val fetched: Boolean,
        val message: String?,
    ) {
        val ok: Boolean get() = message == null
    }

    private fun bodyFile(): File = SourceSync.cacheBody(URL)
    private fun metaFile(): File = SourceSync.cacheMeta(URL)

    /**
     * Refreshes the cached feed. Never fatal: a missing hotfix feed means the
     * previous copy (or none) is used, and the build carries on.
     */
    fun refresh(): Result {
        Paths.ensureAppDirs()
        val body = bodyFile()
        val meta = metaFile()

        val probe = Downloader.probe(URL, body, meta)
        if (!probe.changed) {
            return Result(cached().size, 0, fetched = false, message = null)
        }

        val fetch = Downloader.fetch(URL, body, meta)
        if (fetch.status == Downloader.Status.FAILED) {
            // Deliberately not an error the user sees. The feed is a safety net;
            // announcing its absence would train people to ignore a message that
            // means nothing to them on a day when nothing is broken.
            Log.i(TAG, "hotfix feed unavailable: ${fetch.message}")
            return Result(cached().size, 0, fetched = false, message = fetch.message)
        }
        val parsed = cached()
        Log.i(TAG, "hotfix feed: ${parsed.size} allow rules")
        return Result(parsed.size, 0, fetched = true, message = null)
    }

    /** The rules currently on disk, parsed. Safe to call with no network. */
    fun cached(): List<RuleStore.Pattern> {
        val body = bodyFile()
        if (!body.isFile) return emptyList()
        return runCatching { parse(body.readLines()) }.getOrDefault(emptyList())
    }

    /**
     * Parses the feed.
     *
     * The grammar is the ordinary rule syntax, but every line is forced through
     * [RuleStore.parseAllow] and anything that does not come back as an allow is
     * dropped. Two rules that look like nitpicks and are not:
     *
     *  * `!domain` (K_FORCE) is **rejected**. Force-allow outranks the user's own
     *    block rules at every depth, and a remote feed must never be able to
     *    override something the user typed.
     *  * A bare domain is read as an allow, not a block, because in this file the
     *    role is fixed by the file and not by the line — which is the same
     *    reasoning that makes `@<url>` a profile-line property rather than
     *    something sniffed from a list's contents.
     */
    fun parse(lines: List<String>): List<RuleStore.Pattern> {
        val out = ArrayList<RuleStore.Pattern>()
        for (raw in lines) {
            if (out.size >= MAX_ENTRIES) break
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith("!")) continue          // no remote force-allows
            val pattern = RuleStore.parseAllow(line).getOrNull() ?: continue
            if (pattern.kind == RuleStore.RuleKind.K_FORCE) continue
            if (out.none { it == pattern }) out += pattern
        }
        return out
    }

    /** The feed as `@domain` lines for the merged allow overlay. */
    fun toAllowLines(): List<String> = cached().map { it.toAllowLine() }
}
