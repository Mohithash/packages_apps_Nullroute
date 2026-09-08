package com.bestrom.nullroute.export

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Process
import android.os.StatFs
import android.util.Log
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.core.SysProp
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.RuleStore
import com.bestrom.nullroute.data.SourceCatalog
import com.bestrom.nullroute.data.SourceRef
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.job.DeviceConfigFixups
import com.bestrom.nullroute.net.Downloader
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The diagnostics bundle: everything needed to tell "the filter is dead" from
 * "the filter is working and this domain simply is not on the list", in one file
 * a user can attach to a bug report.
 *
 * The failures this product can have are almost all of the shape *success and
 * failure look identical from userspace* (SPEC §10.7). A resolver that never
 * mapped the index answers DNS perfectly. A control page that failed to mmap
 * leaves every counter at zero, which is also what an idle device looks like. An
 * index missing its probe redirect is structurally valid. None of that is
 * diagnosable from a screenshot of the status card, and all of it is diagnosable
 * from the raw values collected here — the exact `sys.nullroute.filter` string,
 * the exact mmap error, the supplementary group list, both probe results, the
 * index header, and the per-source download record with its validators.
 *
 * ## Redaction
 *
 * A diagnostics bundle is sent to a stranger. Domains are therefore **redacted by
 * default**:
 *
 *  * The **query log is never included at all**, redacted or not — this file
 *    holds no reference to it. It lives in CE storage so that a locked device
 *    exposes no DNS history, and a bundle that could carry it would undo that.
 *  * The user's own **rules** are reported as counts and a kind histogram. Their
 *    domains appear only when the user explicitly asks for an unredacted bundle,
 *    which stamps a banner across the top of the report saying so.
 *  * **Source URLs** are verbatim when they are one of the catalogue's own public
 *    constants, and reduced to scheme and host otherwise. A private list is
 *    usually `https://host/<token>.txt` — the path is the secret, and the host is
 *    what makes "my custom list stopped parsing" diagnosable.
 *
 * What is deliberately absent is listed in the report itself, so a maintainer
 * reading it never has to wonder whether a missing section means "not collected"
 * or "collected and empty".
 */
object DiagnosticsBundle {

    private const val TAG = "Nullroute"

    /** Same container as the settings archive, and the same reasons. */
    const val MIME_TYPE = SettingsArchive.MIME_TYPE

    private const val REPORT_TXT = "report.txt"
    private const val REPORT_JSON = "report.json"
    private const val SOURCES_JSON = "sources.json"
    private const val INDEX_MANIFEST_JSON = "index-manifest.json"

    private const val UNREDACTED_BANNER =
        "!! THIS BUNDLE IS NOT REDACTED. It lists the domains in this user's own " +
            "allow and block rules. Treat it as personal data."

    fun suggestedFileName(): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
        return "nullroute-diagnostics-$stamp.tar.gz"
    }

    // ---- the collected report -----------------------------------------------

    data class Section(val title: String, val rows: List<Pair<String, String>>, val json: JSONObject)

    data class Report(
        val redacted: Boolean,
        val sections: List<Section>,
        val sources: JSONArray,
        /** `manifest.<gen>.json` from the live index, if the builder wrote one. */
        val indexManifest: String?,
        /**
         * Extra archive members, by name. **Empty in a redacted bundle**, which
         * is what carries the user's rule domains when they are carried at all.
         *
         * They are members rather than report rows on purpose: fifty thousand
         * domains inside one key-value row is not a diagnostic, and keeping
         * [sections] free of them means [render] and [json] stay readable and
         * stay reusable by the Diagnostics screen.
         */
        val extraMembers: Map<String, String> = emptyMap(),
    ) {
        fun json(): JSONObject {
            val root = JSONObject()
                .put("kind", "nullroute-diagnostics")
                .put("redacted", redacted)
            sections.forEach { root.put(it.title, it.json) }
            root.put("sources", sources)
            return root
        }

        /** The plain-text report, and what the "copy" button copies. */
        fun render(): String = buildString {
            if (!redacted) appendLine(UNREDACTED_BANNER).appendLine()
            appendLine("Nullroute diagnostics")
            appendLine("=====================")
            sections.forEach { section ->
                appendLine()
                appendLine("== ${section.title} ==")
                val width = section.rows.maxOfOrNull { it.first.length } ?: 0
                section.rows.forEach { (key, value) ->
                    appendLine("${key.padEnd(width)}  $value")
                }
            }
            appendLine()
            appendLine(FOOTER)
        }
    }

    private val FOOTER = """
        Not included, on purpose:
          * the query log — it is never written to a bundle in any mode
          * logcat — reading it needs READ_LOGS, which this app does not hold
          * a full getprop dump — only Nullroute's own properties are listed
    """.trimIndent()

    // ---- collection ---------------------------------------------------------

    /**
     * Samples every signal. **Blocking**: [Probes.sample] issues real DNS lookups
     * and a failing probe walks all the way out to the network before it gives
     * up. Background thread only.
     */
    fun collect(context: Context, redactDomains: Boolean = true): Report {
        val sections = ArrayList<Section>()

        val health = runCatching { Probes.sample() }.getOrNull()
        val mapped = ControlPage.open()
        val telemetry = ControlPage.telemetry()

        sections += bundleSection(context, redactDomains)
        sections += buildSection()
        sections += healthSection(health)
        sections += switchesSection()
        sections += controlSection(mapped, telemetry)
        sections += ringSection(telemetry)
        sections += indexSection()
        sections += hostsSection()
        sections += storageSection()
        sections += configSection(context)
        sections += rulesSection(redactDomains)

        val profile = runCatching { ProfileStore.activeProfile(context) }.getOrNull()
        val sources = sourcesJson(profile?.sources.orEmpty(), redactDomains)

        return Report(
            redacted = redactDomains,
            sections = sections,
            sources = sources,
            indexManifest = readIndexManifest(),
            extraMembers = ruleMembers(redactDomains),
        )
    }

    /**
     * Collects and writes the bundle to a document the user created. Blocking;
     * background thread only.
     */
    @Throws(IOException::class)
    fun write(context: Context, uri: Uri, redactDomains: Boolean = true): Report {
        val report = collect(context, redactDomains)
        val out = context.contentResolver.openOutputStream(uri, "wt")
            ?: throw IOException("cannot write to the chosen file")
        out.use { raw ->
            TarGz.Writer(raw).use { tar ->
                tar.add(REPORT_TXT, report.render().toByteArray())
                tar.add(REPORT_JSON, report.json().toString(2).toByteArray())
                tar.add(SOURCES_JSON, report.sources.toString(2).toByteArray())
                report.indexManifest?.let { tar.add(INDEX_MANIFEST_JSON, it.toByteArray()) }
                report.extraMembers.forEach { (name, text) -> tar.add(name, text.toByteArray()) }
            }
        }
        Log.i(TAG, "wrote diagnostics bundle (redacted=$redactDomains)")
        return report
    }

    // ---- sections -----------------------------------------------------------

    private fun bundleSection(context: Context, redacted: Boolean) = section("bundle") {
        put("collected_at", stamp(System.currentTimeMillis()))
        put("app_version", appVersion(context))
        put("redacted", redacted)
        if (!redacted) put("warning", UNREDACTED_BANNER)
    }

    private fun buildSection() = section("build") {
        // ROM identity, not device identity: this is the build the resolver patch
        // shipped in, and it is the first thing anyone reading a bug report needs.
        put("fingerprint", Build.FINGERPRINT)
        put("device", Build.DEVICE)
        put("build_id", Build.ID)
        put("sdk_int", Build.VERSION.SDK_INT)
        put("release", Build.VERSION.RELEASE)
    }

    private fun healthSection(health: Probes.Health?) = section("health") {
        // "no answer" and "not run" are different diagnoses and must not share a
        // string: Probes.sample skips probe A whenever the kill switch is set or
        // the mode is not ENFORCE, because nr_evaluate() returns PASS before it
        // reaches the redirect table in both cases. Reporting a skipped probe as
        // a failed one sends the reader hunting for a hook that is switched off.
        put(
            "idx_probe",
            health?.let {
                when {
                    it.resolverHookLive -> "${Probes.IDX_EXPECT} OK"
                    it.killSwitch -> "not run (kill switch)"
                    it.mode != ControlPage.MODE_ENFORCE -> "not run (mode=${modeName(it.mode)})"
                    else -> "NO ANSWER"
                }
            } ?: "not sampled",
        )
        put(
            "hosts_probe",
            health?.let { if (it.hostsLayerLive) "${Probes.HOSTS_EXPECT} OK" else "NO ANSWER" }
                ?: "not sampled",
        )
        put("status", health?.status()?.name ?: "UNKNOWN")
        put(Probes.PROP_FILTER_STATE, SysProp.get(Probes.PROP_FILTER_STATE, "(unset)"))
        put(Probes.PROP_SEED, SysProp.get(Probes.PROP_SEED, "(unset)"))
        put("heartbeat_generation", health?.heartbeat?.generation ?: -1L)
        put("heartbeat_at", health?.heartbeat?.lastMapMs?.let { stamp(it) } ?: "never")
    }

    private fun switchesSection() = section("switches") {
        put(Probes.PROP_KILL, SysProp.get(Probes.PROP_KILL, "0"))
        put(ControlPage.PROP_MODE, SysProp.get(ControlPage.PROP_MODE, "(unset)"))
        // fail_streak reaching 3 quarantines the index at the next post-fs-data,
        // so 1 or 2 here is the warning that something is restarting the device
        // before the app can disarm the boot-loop breaker.
        put(Probes.PROP_FAIL_STREAK, SysProp.get(Probes.PROP_FAIL_STREAK, "0"))
        put(Probes.PROP_BOOT_OK, SysProp.get(Probes.PROP_BOOT_OK, "0"))
    }

    private fun controlSection(mapped: Boolean, t: ControlPage.Telemetry) = section("control_page") {
        put("mapped", if (mapped) "rw" else (ControlPage.lastError ?: "NOT MAPPED"))
        if (mapped) {
            put("mode", modeName(ControlPage.mode))
            put("response_mode", ControlPage.responseMode)
            put("log_level", ControlPage.logLevel)
            put("config_epoch", ControlPage.configEpoch)
            put("want_generation", ControlPage.wantGeneration)
            put("mapped_generation", t.mappedGeneration)
            put("filter_abi", t.filterAbi)
            put("q_total", t.queriesTotal)
            put("q_blocked", t.queriesBlocked)
            put("q_passed", t.queriesPassed)
            put("last_map_at", if (t.lastMapMs == 0L) "never" else stamp(t.lastMapMs))
            put("map_errors", t.mapErrors)
            put("fault_count", t.faultCount)
        }
    }

    /**
     * The ring is netd's to write and ours to read. Its **drop counter lives in
     * the control page**, not in the ring, precisely so that a ring we cannot map
     * still reports how much it lost — the same reasoning that keeps the health
     * verdict out of the counters.
     */
    private fun ringSection(t: ControlPage.Telemetry) = section("ring") {
        val ring = Paths.ringBin
        put("path", ring.path)
        put("present", ring.isFile)
        put("bytes", if (ring.isFile) ring.length() else 0L)
        put("readable", ring.isFile && ring.canRead())
        put("ring_drops", t.ringDrops)
    }

    private fun indexSection() = section("index") {
        put("libnrjni", if (Native.available) "loaded" else "NOT LOADED")
        put("current_bytes", sizeOf(Paths.currentIndex))
        put("previous_bytes", sizeOf(Paths.previousIndex))
        put("quarantine_present", Paths.quarantineIndex.exists())
        put("staging_leftovers", Paths.index.listFiles()?.count { it.name.startsWith("staging.") } ?: 0)

        if (Native.available && Paths.currentIndex.isFile) {
            val info = Native.verify(Paths.currentIndex.absolutePath)
            put("verify", if (info.ok) "OK" else "FAILED: ${info.error}")
            if (info.ok) {
                put("generation", info.generation)
                put("fmt_version", info.formatVersion)
                put("built_at", stamp(info.builtAtMs))
                put("sha256", if (info.sha256Ok) "match" else "MISMATCH")
                // Without this redirect the Home screen is permanently blind: it
                // reports "Limited" on a healthy device with no way to tell that
                // apart from a genuinely dead hook.
                put("idx_probe_redirect", if (info.probePresent) (info.probeAddress ?: "present") else "MISSING")
                put("n_block", info.blockCount)
                put("n_allow", info.allowCount)
                put("n_redirect", info.redirectCount)
            }
        }
    }

    private fun hostsSection() = section("hosts_l0") {
        val hosts = Paths.hostsFile
        put("path", hosts.path)
        put("bytes", sizeOf(hosts))
        put("probe_line", hostsProbePresent(hosts))
    }

    private fun storageSection() = section("storage") {
        put("misc_present", Paths.misc.isDirectory)
        put("state_tree_ready", Paths.stateTreeReady())
        put("priv_writable", Paths.buildScratch.canWrite())
        put("free_bytes", runCatching { StatFs(Paths.misc.path).availableBytes }.getOrDefault(-1L))
        put("uid", Process.myUid())
        // AID_MISC (9998) must appear here. It arrives via the <group gid="misc"/>
        // mapping on com.bestrom.nullroute.permission.STATE; without it every
        // open() under /data/misc/nullroute is EACCES before SELinux is consulted.
        put("groups", supplementaryGroups())
    }

    private fun configSection(context: Context) = section("configuration") {
        val profile = runCatching { ProfileStore.activeProfile(context) }.getOrNull()
        put("profile", profile?.id ?: "(unavailable)")
        put("profile_sources", profile?.sources?.size ?: 0)
        put("profile_enabled_sources", profile?.enabledSources?.size ?: 0)
        put("auto_update", Settings.autoUpdate(context))
        put("unmetered_only", Settings.unmeteredOnly(context))
        put("response_mode", Settings.responseMode(context))
        put("log_level", Settings.logLevel(context))

        val record = Settings.lastUpdate(context)
        put("last_update", if (!record.everRan) "never" else stamp(record.whenMs))
        put("last_update_ok", record.ok)
        put("last_update_message", record.message)
        put("last_entry_count", record.entryCount)
        put(
            "close_quic_connection",
            DeviceConfigFixups.getProperty("tethering", "close_quic_connection") ?: "(unset)",
        )
    }

    /**
     * User rules, as counts. Domains appear only in an unredacted bundle.
     *
     * The counts alone answer most of what a maintainer needs — "did their own
     * allow rule shadow the block they are complaining about" is a question about
     * whether any allow rules exist at all far more often than about which.
     */
    private fun rulesSection(redacted: Boolean) = section("user_rules") {
        val allow = RuleStore.readAllow()
        val deny = RuleStore.readDeny()
        val redirects = RuleStore.readRedirects()

        put("allow_total", allow.size)
        put("deny_total", deny.size)
        put("redirect_total", redirects.size)
        RuleStore.RuleKind.values().forEach { kind ->
            put("allow_${kind.name.lowercase()}", allow.count { it.kind == kind })
            put("deny_${kind.name.lowercase()}", deny.count { it.kind == kind })
        }
        put("domains_included", if (redacted) "no (redacted)" else "yes, in rules-*.txt")
    }

    /** The rule text itself, as its own members, and only when not redacted. */
    private fun ruleMembers(redacted: Boolean): Map<String, String> {
        if (redacted) return emptyMap()
        return linkedMapOf(
            "rules-allow.txt" to RuleStore.readAllow().joinToString("\n") { it.toAllowLine() },
            "rules-deny.txt" to RuleStore.readDeny().joinToString("\n") { it.toDenyLine() },
            "rules-redirect.txt" to RuleStore.readRedirects().joinToString("\n") { it.toLine() },
        )
    }

    // ---- per-source manifest ------------------------------------------------

    /**
     * One record per source in the active profile: what it is, what its licence
     * says about where it may be compiled, and — the part that actually diagnoses
     * a stale list — the download record from `priv/cache`, validators included.
     *
     * A source whose `.meta` says it was last fetched three weeks ago while the
     * profile claims a daily update is a scheduling failure; one with a body of
     * zero bytes is a truncated download; one with no cache entry at all has
     * never succeeded. All three present identically on the status card.
     */
    private fun sourcesJson(sources: List<SourceRef>, redacted: Boolean): JSONArray {
        val out = JSONArray()
        for (ref in sources) {
            val entry = SourceCatalog.byUrl(ref.url)
            val key = runCatching { Downloader.cacheKey(ref.url) }.getOrNull()
            val body = key?.let { File(Paths.downloadCache, "$it.raw") }
            val meta = key?.let { File(Paths.downloadCache, "$it.meta") }
                ?.takeIf { it.isFile }
                ?.let { runCatching { JSONObject(it.readText()) }.getOrNull() }

            out.put(
                JSONObject()
                    .put("label", ref.label)
                    .put("url", redactUrl(ref.url, redacted))
                    .put("catalogued", entry != null)
                    .put("group_id", entry?.groupId ?: 0)
                    .put("role", ref.role.name)
                    .put("enabled", ref.enabled)
                    .put("user_added", ref.userAdded)
                    .put("licence", ref.licence.spdx)
                    .put("bakeable", ref.licence.bakeable)
                    .put("format", ref.format.name)
                    .put("approx_domains", entry?.approxDomains ?: 0)
                    .put("cached", body?.isFile ?: false)
                    .put("cached_bytes", if (body?.isFile == true) body.length() else 0L)
                    .put("etag", meta?.optString("etag").orEmpty())
                    .put("last_modified", meta?.optString("last_modified").orEmpty())
                    .put(
                        "fetched_at",
                        meta?.optLong("fetched_at", 0L)?.takeIf { it > 0L }?.let { stamp(it) }
                            ?: "never",
                    )
            )
        }
        return out
    }

    /**
     * A catalogued URL is a constant out of our own source and is safe verbatim.
     * Anything else is the user's, and a private list is usually
     * `https://host/<token>.txt` — so the path goes and the host stays, because
     * the host is what makes "my own list stopped parsing" diagnosable at all.
     */
    private fun redactUrl(url: String, redact: Boolean): String {
        if (!redact || SourceCatalog.byUrl(url) != null) return url
        return runCatching {
            val u = URI(url)
            "${u.scheme}://${u.host}/… (path redacted)"
        }.getOrDefault("(custom source, redacted)")
    }

    /** The builder's own per-source counts, if it wrote them for this generation. */
    private fun readIndexManifest(): String? {
        val generation = Native.verify(Paths.currentIndex.absolutePath)
            .takeIf { it.ok }?.generation ?: return null
        val file = Paths.manifestJson(generation)
        if (!file.isFile || file.length() > (1L shl 20)) return null
        return runCatching { file.readText() }.getOrNull()
    }

    // ---- helpers ------------------------------------------------------------

    private class SectionBuilder(val title: String) {
        val rows = ArrayList<Pair<String, String>>()
        val json = JSONObject()

        /**
         * One key, two renderings. Using the same identifier in the text report
         * and the JSON is deliberate: a maintainer who greps the human file for
         * `ring_drops` finds the same name in the machine file, and there is no
         * second vocabulary to keep in step.
         */
        fun put(key: String, value: Any?) {
            rows += key to (value?.toString() ?: "null")
            runCatching { json.put(key, value ?: JSONObject.NULL) }
        }
    }

    private fun section(title: String, build: SectionBuilder.() -> Unit): Section {
        val b = SectionBuilder(title)
        b.build()
        return Section(b.title, b.rows, b.json)
    }

    private fun stamp(ms: Long): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(ms))

    private fun sizeOf(file: File): Long = if (file.isFile) file.length() else -1L

    private fun modeName(mode: Int): String = when (mode) {
        ControlPage.MODE_ENFORCE -> "0 ENFORCE"
        ControlPage.MODE_PAUSED -> "1 PAUSED"
        ControlPage.MODE_OFF -> "2 OFF"
        else -> mode.toString()
    }

    private fun appVersion(context: Context): String = runCatching {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        "${info.versionName} (${info.longVersionCode})"
    }.getOrDefault("unknown")

    /** Streams rather than reads: the L0 file is ~56 KB now and may grow. */
    private fun hostsProbePresent(hosts: File): Boolean = runCatching {
        hosts.isFile && hosts.useLines { lines -> lines.any { it.contains(Probes.HOSTS) } }
    }.getOrDefault(false)

    private fun supplementaryGroups(): String = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("Groups:") }?.removePrefix("Groups:")?.trim()
                ?: "(unreadable)"
        }
    }.getOrDefault("(unreadable)")
}
