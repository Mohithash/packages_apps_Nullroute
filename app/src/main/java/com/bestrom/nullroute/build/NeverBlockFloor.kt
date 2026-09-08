package com.bestrom.nullroute.build

import android.content.Context
import android.provider.Settings
import android.util.Log
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.data.RuleStore
import java.net.URI

/**
 * The compiled-in `ALLOW_FORCE` floor: the names that are never blocked, whatever
 * a list, a profile or the user says.
 *
 * ## What is on it, and why it is not a setting
 *
 * Everything here is something whose failure does **not** look like an ad blocker
 * misbehaving — it looks like a broken phone, and the user will never connect the
 * two. A blocked `mtalk.google.com` stops every push notification on the device
 * with no error anywhere; a blocked connectivity check makes Android conclude it
 * is behind a captive portal forever. Both have happened in the wild with shipped
 * blocklists (SPEC §10.3.5).
 *
 * ## This object is the READ side, not the enforcement side
 *
 * Enforcement is native and unconditional: `nativeBuild` injects
 * `/system_ext/etc/nullroute/neverblock.txt` as `NR_ROLE_FORCE` itself, so no
 * caller — and no user — can build an index without it (jni_bridge.cpp). This
 * object exists so that
 *
 *  * [IndexBuilder] can write the same set into the allow overlay as well (belt
 *    and braces, and the *only* floor there is when the shipped file is absent —
 *    the native input is `optional`, so a stock-Android or partially flashed
 *    device would otherwise have none), and
 *  * `importer/ImportModel` can tell a user, before they import 40,000 rules,
 *    which of them will never take effect.
 *
 * ## Element shape is load-bearing
 *
 * `ImportModel.floorShadow` tests `domain == entry || domain.endsWith(".$entry")`.
 * A returned entry that still carried its `!` prefix or a `*.` prefix would match
 * nothing, and the import preview would quietly tell the user a rule works when
 * the matcher will force-allow it. So every entry that leaves this object is a
 * bare, lowercased apex name, run through the one parser in [RuleStore].
 */
object NeverBlockFloor {

    private const val TAG = "Nullroute"

    /**
     * The floor when `/system_ext/etc/nullroute/neverblock.txt` is not there.
     *
     * Not an empty list, deliberately. The shipped file is the authority and this
     * is never used on a BestROM build, but on the Gradle parity build, a stock
     * Android install or a partial flash the native side finds no floor either
     * (its input is `optional`), so returning nothing would mean a device with no
     * floor *and* an import preview that cheerfully reports no conflicts.
     *
     * Content is SPEC §10.3.5 exactly — the subset whose absence is
     * unrecoverable-from — and not a second copy of the shipped file, which would
     * be two lists to keep in step.
     */
    private val FALLBACK: List<String> = listOf(
        "mtalk.google.com",
        "alt1-mtalk.google.com",
        "alt2-mtalk.google.com",
        "alt3-mtalk.google.com",
        "alt4-mtalk.google.com",
        "alt5-mtalk.google.com",
        "alt6-mtalk.google.com",
        "alt7-mtalk.google.com",
        "alt8-mtalk.google.com",
        "android.clients.google.com",
        "googleapis.com",
        "gstatic.com",
        "gvt1.com",
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "clients3.google.com",
        "www.google.com",
    )

    /**
     * The live captive-portal settings, read by key rather than through the
     * `Settings.Global` constants: those constants are `@hide`, and this app is
     * compiled against `system_current` here and against the public SDK in the
     * Gradle parity build. The key strings are ABI in exactly the same way the
     * constants are, and they resolve in both.
     *
     * `captive_portal_other_fallback_urls` is a comma-separated list; the rest are
     * single URLs. All four are parsed the same way.
     */
    private val CAPTIVE_PORTAL_KEYS = listOf(
        "captive_portal_http_url",
        "captive_portal_https_url",
        "captive_portal_fallback_url",
        "captive_portal_other_fallback_urls",
    )

    /**
     * The floor, as bare apex names.
     *
     * Read fresh on every call rather than cached: the file is 43 entries, the
     * captive-portal URLs can be changed by the user or an RRO at any moment, and
     * this is called once per build and once per import — a cache would only add
     * a way to serve a stale floor.
     */
    fun domains(context: Context): List<String> {
        val out = LinkedHashSet<String>()

        val fromFile = fileDomains()
        if (fromFile.isEmpty()) {
            Log.w(TAG, "${Paths.neverBlockTxt} is missing or unreadable; using the built-in floor")
            out += FALLBACK
        } else {
            out += fromFile
        }

        // Not in the shipped file on purpose (see its header): a static copy of
        // these goes stale the moment a user or an RRO changes them.
        out += captivePortalHosts(context)

        return out.toList()
    }

    /**
     * The floor in the text form `nr_parse_line()` reads back, for the allow
     * overlay [IndexBuilder] hands to the native builder.
     *
     * `!domain` is `K_FORCE` with suffix semantics — apex and every subdomain —
     * which is what beats a block at any depth (SPEC §7.5).
     */
    fun forceAllowLines(context: Context): List<String> = domains(context).map { "!$it" }

    // ---- the shipped file ---------------------------------------------------

    /**
     * Every entry in `neverblock.txt`, or an empty list if the file is absent or
     * unreadable.
     *
     * A line this parser does not understand is dropped, not guessed at, and
     * dropping it costs only the *preview* and the belt-and-braces overlay copy:
     * the native side reads the same file itself, so a floor entry cannot be lost
     * from the index by a parse failure here. That is the one direction this is
     * allowed to fail in.
     */
    private fun fileDomains(): List<String> {
        val file = Paths.neverBlockTxt
        if (!file.isFile) return emptyList()
        val out = LinkedHashSet<String>()
        runCatching {
            file.forEachLine { raw ->
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) return@forEachLine
                val pattern = RuleStore.parseAllow(line).getOrNull()
                if (pattern == null) {
                    Log.w(TAG, "neverblock.txt: ignoring \"$line\"")
                    return@forEachLine
                }
                // `*.x` in the source file is deliberately widened to the apex —
                // the file's own header says so, and for these operators a missed
                // apex is a silent hole in the floor.
                out += pattern.domain
            }
        }.onFailure { Log.w(TAG, "neverblock.txt unreadable: ${it.message}") }
        return out.toList()
    }

    // ---- the live captive-portal hosts --------------------------------------

    /** Host names from the four captive-portal URL settings. Never throws. */
    private fun captivePortalHosts(context: Context): List<String> {
        val resolver = runCatching { context.contentResolver }.getOrNull() ?: return emptyList()
        val out = LinkedHashSet<String>()
        for (key in CAPTIVE_PORTAL_KEYS) {
            val value = runCatching { Settings.Global.getString(resolver, key) }.getOrNull()
            if (value.isNullOrBlank()) continue
            for (candidate in value.split(',', ' ', '\t')) {
                hostOf(candidate)?.let { out += it }
            }
        }
        return out.toList()
    }

    /**
     * The host part of a URL, as a rule domain.
     *
     * Run through [RuleStore.parseAllow] like everything else, which is what
     * rejects an IP literal — a captive-portal URL pointing at an address is
     * perfectly legal and simply is not a name the matcher can hold a rule for.
     */
    private fun hostOf(url: String): String? {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) return null
        val host = runCatching { URI(trimmed).host }.getOrNull()
            ?: trimmed.substringAfter("//", trimmed).substringBefore('/').substringBefore(':')
        if (host.isBlank()) return null
        return RuleStore.parseAllow(host).getOrNull()?.domain
    }
}
