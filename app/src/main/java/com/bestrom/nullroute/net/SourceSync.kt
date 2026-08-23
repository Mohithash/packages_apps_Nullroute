package com.bestrom.nullroute.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.data.Licence
import com.bestrom.nullroute.data.Profile
import com.bestrom.nullroute.data.SourceCatalog
import com.bestrom.nullroute.data.SourceRef
import com.bestrom.nullroute.data.SourceRole
import java.io.File

/**
 * Fetches every source a profile names, and reports honestly on each one.
 *
 * **A per-source failure is non-fatal and is never silently zeroed.** If HaGeZi
 * is unreachable we build from what we do have and say so; what we must never do
 * is treat a failed download as an empty list, which would quietly delete a
 * quarter of a million rules and present the result as a successful update.
 *
 * **Connectivity is a `ConnectivityManager` question**, not `ping -c 1 8.8.8.8`:
 * that check hardcodes Google's resolver, fails on IPv6-only carriers and on
 * every network that drops ICMP, and tells you nothing about whether the link is
 * metered.
 */
object SourceSync {

    private const val TAG = "Nullroute"

    /**
     * Ceiling on how many lines we will transcode from a fetched *allowlist*
     * inside the JVM. Blocklists never come through here — they go straight to
     * the native external-sort path — but allowlists are small (the referral list
     * is 1,604 domains) and it is worth one bounded pass in Kotlin to prefix them
     * correctly. The cap exists so that a source that changes shape upstream
     * cannot turn into a 60 MB `ArrayList<String>` and get the job killed.
     */
    private const val MAX_ALLOW_LINES = 100_000

    data class SourceResult(
        val source: SourceRef,
        val status: Downloader.Status,
        val file: File?,
        val bytes: Long,
        val message: String?,
    ) {
        val usable: Boolean get() = status != Downloader.Status.FAILED && file?.isFile == true
    }

    data class Report(
        val blockSources: List<SourceResult>,
        val allowSources: List<SourceResult>,
    ) {
        val all: List<SourceResult> get() = blockSources + allowSources
        val failures: List<SourceResult> get() = all.filterNot { it.usable }
        val usableBlockFiles: List<File> get() = blockSources.mapNotNull { if (it.usable) it.file else null }
        val usableAllowFiles: List<File> get() = allowSources.mapNotNull { if (it.usable) it.file else null }

        /** Nothing downloaded and nothing cached: there is no build to attempt. */
        val anyBlockContent: Boolean get() = usableBlockFiles.isNotEmpty()

        fun summary(): String {
            val ok = all.count { it.usable }
            val fresh = all.count { it.status == Downloader.Status.OK }
            return "$ok/${all.size} lists available, $fresh downloaded"
        }
    }

    fun interface Listener {
        fun onSource(index: Int, total: Int, source: SourceRef)
    }

    /**
     * Downloads (or revalidates) everything [profile] needs, plus the allowlist
     * seeds that are applied to every build regardless of profile.
     */
    fun sync(context: Context, profile: Profile, listener: Listener?): Report {
        Paths.ensureAppDirs()

        val blockRefs = profile.blockSources

        // The shipped profile files carry the allowlist seeds as `@<url>` lines,
        // so an OTA can change them without an APK. The catalogue is the fallback
        // for the case where the profile came from SourceCatalog itself (no
        // /system_ext profile directory — the Gradle/stock variant, or a partial
        // flash). The two lists are documented as having to stay identical; this
        // prefers the file, because that is the one an OTA can fix.
        val allowRefs = profile.allowSources.ifEmpty {
            SourceCatalog.alwaysAllowSources.map {
                SourceRef(url = it.url, label = it.label, role = SourceRole.ALLOW)
            }
        }
        val total = blockRefs.size + allowRefs.size

        val blockResults = ArrayList<SourceResult>(blockRefs.size)
        blockRefs.forEachIndexed { i, ref ->
            listener?.onSource(i, total, ref)
            blockResults += fetchOne(ref)
        }

        val allowResults = ArrayList<SourceResult>(allowRefs.size)
        allowRefs.forEachIndexed { i, ref ->
            listener?.onSource(blockRefs.size + i, total, ref)
            allowResults += fetchOne(ref)
        }

        val report = Report(blockResults, allowResults)
        Log.i(TAG, "sync: ${report.summary()}")
        return report
    }

    private fun fetchOne(ref: SourceRef): SourceResult {
        val key = Downloader.cacheKey(ref.url)
        val body = File(Paths.downloadCache, "$key.raw")
        val meta = File(Paths.downloadCache, "$key.meta")

        val result = Downloader.fetch(ref.url, body, meta)

        // A failed revalidation is survivable if we still hold the previous body:
        // a stale list is protection, a missing one is not.
        if (result.status == Downloader.Status.FAILED && body.isFile && body.length() > 0) {
            Log.w(TAG, "${ref.label}: ${result.message}; reusing cached copy")
            return SourceResult(
                source = ref,
                status = Downloader.Status.NOT_MODIFIED,
                file = body,
                bytes = body.length(),
                message = "using cached copy (${result.message})",
            )
        }

        return SourceResult(
            source = ref,
            status = result.status,
            file = result.file,
            bytes = result.bytes,
            message = result.message,
        )
    }

    /**
     * Rewrites a fetched allowlist into the `@domain` form `nr_parse_line()`
     * reads, appending to [out].
     *
     * Lines are passed through nearly untouched — the native parser recognises
     * bare domains, `*.d`, `=d` and ABP `@@||d^` on its own — the prefix is added
     * only so that the merged allow file is unambiguous no matter which side
     * reads it.
     */
    fun appendAllowLines(source: File, out: Appendable): Int {
        var written = 0
        runCatching {
            source.forEachLine { raw ->
                if (written >= MAX_ALLOW_LINES) return@forEachLine
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) return@forEachLine
                val domain = line.substringBefore('#').trim()
                if (domain.isEmpty()) return@forEachLine
                out.append('@').append(domain).append('\n')
                written++
            }
        }
        return written
    }

    // ---- connectivity -------------------------------------------------------

    data class Connectivity(val connected: Boolean, val unmetered: Boolean)

    fun connectivity(context: Context): Connectivity {
        val cm = context.getSystemService(ConnectivityManager::class.java)
            ?: return Connectivity(false, false)
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
            ?: return Connectivity(false, false)
        val connected = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val unmetered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        return Connectivity(connected, unmetered)
    }

    /**
     * True when this source's content is allowed to have come from the read-only
     * image. Used by the builder as a mechanical check on the licensing posture:
     * a GPL-3.0 or MPL-2.0 list must always arrive over the network, into
     * `priv/cache`, so that the compiled derivative work is created on the user's
     * device rather than distributed inside a signed image.
     */
    fun mayComeFromImage(licence: Licence): Boolean = licence.bakeable
}
