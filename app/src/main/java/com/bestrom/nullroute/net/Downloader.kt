package com.bestrom.nullroute.net

import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/**
 * Blocklist fetcher, built on `HttpURLConnection`.
 *
 * No OkHttp: the platform stack is already in every process, and adding a
 * networking library to a system_ext app so it can download text files is a
 * maintenance liability with no upside.
 *
 * ## The version probe is the point of this file
 *
 * A BALANCED update is four lists totalling ~9 MB, and on a typical day none of
 * them has changed. [probe] spends **~600 bytes** deciding that: a
 * `Range: bytes=0-511` GET returns the list's own header block, which every one
 * of these projects stamps with a version and an entry count, and that is
 * compared against what the last successful compile recorded.
 *
 * Four host quirks, each measured rather than assumed, and each of which
 * silently defeats the probe if ignored:
 *
 *  * **raw.githubusercontent.com** returns a weak `ETag` and **no**
 *    `Last-Modified`, so revalidation must use `If-None-Match`.
 *  * **GitHub Pages** (`*.github.io`) returns both, so `If-Modified-Since` works.
 *  * **jsDelivr** caches for a week; without `Cache-Control: no-cache` on the
 *    probe you cheerfully confirm that the copy you already have is current.
 *  * **OISD** answers a `Range` request with **416**, so it needs `HEAD`.
 *
 * ## Three more things that are less obvious than they look
 *
 *  * **We ask for gzip and decode it ourselves.** `HttpURLConnection`
 *    transparently gunzips only when *it* added the `Accept-Encoding` header. The
 *    moment we set it by hand, the body arrives compressed and the decode becomes
 *    our problem. We take that trade because these lists are 3-5 MB of text that
 *    compresses about 4:1. We do **not** advertise `br`: the platform has no
 *    brotli decoder, and asking for an encoding we cannot read produces a
 *    perfectly successful download of unusable bytes.
 *  * **A `Range` request must ask for `identity`.** Ranges are byte offsets into
 *    the *encoded* body, so `Range: bytes=0-511` plus `Accept-Encoding: gzip`
 *    yields 512 bytes of gzip stream — a header we cannot read, from a server
 *    that did nothing wrong.
 *  * **Redirects are followed by hand.** `HttpURLConnection` refuses to follow
 *    across protocols, which is right, but its silence about it looks like a 404.
 *    Following manually also lets us refuse an https -> http downgrade outright.
 */
object Downloader {

    private const val TAG = "Nullroute"

    private const val CONNECT_TIMEOUT_MS = 20_000
    private const val READ_TIMEOUT_MS = 60_000
    private const val PROBE_TIMEOUT_MS = 15_000
    private const val MAX_REDIRECTS = 5

    private const val USER_AGENT = "Nullroute/1.0 (BestROM)"

    /** How much of a list's head the probe reads. Every source's header fits. */
    private const val PROBE_BYTES = 512

    /**
     * Ceiling on what we will read from a server that ignored `Range` and sent
     * the whole file. Without it a probe against a misbehaving host downloads the
     * 5 MB it exists to avoid.
     */
    private const val PROBE_MAX_READ = 8 * 1024

    /**
     * Hard ceiling on a single list. The largest source we know of is ~5.2 MB
     * raw; 64 MB is a wide margin that still stops a misconfigured or hostile URL
     * from filling /data. Exceeding it fails the source rather than truncating
     * it — a truncated blocklist is a silently weakened one.
     */
    private const val MAX_BODY_BYTES = 64L * 1024 * 1024

    enum class Status { OK, NOT_MODIFIED, FAILED }

    data class Result(
        val status: Status,
        val file: File?,
        val bytes: Long,
        val message: String?,
        /** Bytes actually pulled over the network, for the update summary. */
        val transferred: Long = 0L,
        val version: Version? = null,
    ) {
        val usable: Boolean get() = status != Status.FAILED && file != null && file.isFile
    }

    /**
     * What a list says about itself, from its own header block. Every field is
     * optional — a list that stamps nothing is fetched on the validators alone.
     */
    data class Version(
        val etag: String = "",
        val lastModified: String = "",
        val stamp: String = "",
        val entries: Int = 0,
    ) {
        val known: Boolean get() = stamp.isNotEmpty() || entries > 0

        fun describe(): String = when {
            stamp.isNotEmpty() && entries > 0 -> "$stamp, ${"%,d".format(entries)} entries"
            stamp.isNotEmpty() -> stamp
            entries > 0 -> "${"%,d".format(entries)} entries"
            else -> ""
        }
    }

    /**
     * A probe never fails the update. `changed = true` with a message is how an
     * inconclusive probe is reported: we spend the download rather than skip an
     * update we could not prove was unnecessary.
     */
    data class ProbeResult(
        val changed: Boolean,
        val version: Version?,
        val message: String?,
        val probedBytes: Long = 0L,
    )

    /**
     * Stable per-URL cache key. SHA-1 of the URL, not a sanitised filename: URLs
     * contain characters that are legal in a path on one filesystem and not
     * another, and two sources that differ only in query string must not collide.
     */
    fun cacheKey(url: String): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(url.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    // ---- host quirks --------------------------------------------------------

    private fun hostOf(url: String): String =
        runCatching { URL(url).host.lowercase() }.getOrDefault("")

    /** Hosts that answer a `Range` request with 416 and need `HEAD` instead. */
    private fun rejectsRange(url: String): Boolean {
        val h = hostOf(url)
        return h == "oisd.nl" || h.endsWith(".oisd.nl")
    }

    /** Hosts whose `Last-Modified` is trustworthy. raw.githubusercontent has none. */
    private fun hasLastModified(url: String): Boolean =
        hostOf(url) != "raw.githubusercontent.com"

    // ---- the version probe --------------------------------------------------

    /**
     * Decides whether [url] is worth downloading, for the cost of one small
     * request. [cached] is the body we already hold; when it is absent or empty
     * the answer is always "changed", because there is nothing to reuse.
     */
    fun probe(url: String, cached: File, meta: File): ProbeResult {
        if (!cached.isFile || cached.length() == 0L) {
            return ProbeResult(changed = true, version = null, message = "no cached copy")
        }
        val stored = readMeta(meta)
        val storedVersion = versionFromMeta(stored)

        val conn = open(url) ?: return ProbeResult(true, null, "cannot open connection")
        return try {
            conn.connectTimeout = PROBE_TIMEOUT_MS
            conn.readTimeout = PROBE_TIMEOUT_MS
            conn.instanceFollowRedirects = true      // a probe has nothing to protect
            // jsDelivr will otherwise hand back a week-old cached header and we
            // will confirm our own staleness.
            conn.setRequestProperty("Cache-Control", "no-cache")
            conn.setRequestProperty("Pragma", "no-cache")

            if (rejectsRange(url)) {
                conn.requestMethod = "HEAD"
            } else {
                conn.requestMethod = "GET"
                // identity: a byte range is a range of the ENCODED body.
                conn.setRequestProperty("Accept-Encoding", "identity")
                conn.setRequestProperty("Range", "bytes=0-${PROBE_BYTES - 1}")
            }
            applyValidators(conn, url, stored)

            when (val code = conn.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED ->
                    ProbeResult(changed = false, version = storedVersion, message = null)

                HttpURLConnection.HTTP_PARTIAL, HttpURLConnection.HTTP_OK -> {
                    val head = if (conn.requestMethod == "HEAD") "" else readHead(conn)
                    val fresh = Version(
                        etag = conn.getHeaderField("ETag").orEmpty(),
                        lastModified = conn.getHeaderField("Last-Modified").orEmpty(),
                        stamp = parseStamp(head),
                        entries = parseEntryCount(head),
                    )
                    ProbeResult(
                        changed = differs(storedVersion, fresh),
                        version = fresh,
                        message = null,
                        probedBytes = head.length.toLong(),
                    )
                }

                // 416 from a host we did not know rejects ranges. Do not guess
                // again next time either — just fetch, and record why.
                416 -> ProbeResult(true, storedVersion, "server refused a range request")

                else -> ProbeResult(true, storedVersion, "probe returned HTTP $code")
            }
        } catch (t: Throwable) {
            ProbeResult(true, storedVersion, t.message ?: t.javaClass.simpleName)
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    /**
     * Compares what the server just said with what we recorded.
     *
     * Deliberately conservative: it returns "changed" unless something positively
     * matches. A probe that cannot tell must cost a download, never a skipped
     * update — the cost of being wrong in one direction is 4 MB of Wi-Fi and in
     * the other it is protection that silently stopped improving.
     */
    private fun differs(stored: Version?, fresh: Version): Boolean {
        if (stored == null) return true
        if (fresh.stamp.isNotEmpty() && stored.stamp.isNotEmpty()) {
            return fresh.stamp != stored.stamp || fresh.entries != stored.entries
        }
        if (fresh.etag.isNotEmpty() && stored.etag.isNotEmpty()) {
            return normalizeEtag(fresh.etag) != normalizeEtag(stored.etag)
        }
        if (fresh.lastModified.isNotEmpty() && stored.lastModified.isNotEmpty()) {
            return fresh.lastModified != stored.lastModified
        }
        return true
    }

    /** `W/"abc"` and `"abc"` are the same entity for our purposes. */
    private fun normalizeEtag(etag: String): String =
        etag.trim().removePrefix("W/").removePrefix("w/").trim('"')

    private fun readHead(conn: HttpURLConnection): String {
        val stream = runCatching { conn.inputStream }.getOrNull() ?: return ""
        return stream.use { input ->
            val buf = ByteArray(PROBE_MAX_READ)
            var n = 0
            while (n < buf.size) {
                val r = input.read(buf, n, buf.size - n)
                if (r < 0) break
                n += r
            }
            String(buf, 0, n, Charsets.UTF_8)
        }
    }

    /**
     * The version line every one of these projects stamps into its header, in
     * the several spellings they actually use.
     *
     * HaGeZi writes `# Version: 2026.08.23-1`; StevenBlack writes `# Date: …`;
     * 1Hosts uses `! Updated: …`. Matching a fixed prefix would work for one of
     * them and silently disable the probe for the other two, which is exactly the
     * failure mode a probe is supposed to prevent.
     */
    private fun parseStamp(head: String): String {
        val keys = listOf("version", "last modified", "updated", "date", "generated")
        for (raw in head.lineSequence()) {
            val line = raw.trim().trimStart('#', '!', ';').trim()
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val key = line.substring(0, colon).trim().lowercase()
            if (key in keys) {
                val value = line.substring(colon + 1).trim()
                if (value.isNotEmpty()) return value
            }
        }
        return ""
    }

    private fun parseEntryCount(head: String): Int {
        for (raw in head.lineSequence()) {
            val line = raw.trim().trimStart('#', '!', ';').trim()
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val key = line.substring(0, colon).trim().lowercase()
            if (!key.startsWith("number of") && !key.startsWith("total number")) continue
            val digits = line.substring(colon + 1).filter { it in '0'..'9' }
            digits.toIntOrNull()?.let { if (it > 0) return it }
        }
        return 0
    }

    // ---- fetching -----------------------------------------------------------

    /**
     * Fetches [url] into [dest], honouring the validators recorded in [meta].
     *
     * Writes to `<dest>.part` and renames, so an interrupted download can never
     * be mistaken for a complete list — and, when the server supports it, the
     * next attempt **resumes** that partial instead of starting again. Blocking;
     * call from a background thread.
     */
    fun fetch(url: String, dest: File, meta: File): Result {
        var current = url
        var redirects = 0

        while (true) {
            if (!current.startsWith("https://")) {
                return Result(Status.FAILED, null, 0, "refusing non-HTTPS URL")
            }

            val stored = readMeta(meta)
            val part = File(dest.parentFile, dest.name + ".part")
            val resumeFrom = resumableBytes(part, stored, current)

            val conn = open(current)
                ?: return Result(Status.FAILED, null, 0, "cannot open connection")

            try {
                conn.requestMethod = "GET"
                conn.connectTimeout = CONNECT_TIMEOUT_MS
                conn.readTimeout = READ_TIMEOUT_MS
                conn.instanceFollowRedirects = false

                if (resumeFrom > 0) {
                    // A range is a range of the encoded body, so a resumed
                    // transfer must be identity all the way through — including
                    // the part already on disk, which is why resumableBytes()
                    // refuses unless the interrupted attempt was identity too.
                    conn.setRequestProperty("Accept-Encoding", "identity")
                    conn.setRequestProperty("Range", "bytes=$resumeFrom-")
                    stored.optString("part_etag").takeIf { it.isNotEmpty() }
                        ?.let { conn.setRequestProperty("If-Range", it) }
                } else {
                    conn.setRequestProperty("Accept-Encoding", "gzip")
                }

                // Only send validators when we still hold the body they describe;
                // a 304 against a missing cache file is unrecoverable.
                if (resumeFrom == 0L && dest.isFile && dest.length() > 0) {
                    applyValidators(conn, current, stored)
                }

                when (val code = conn.responseCode) {
                    HttpURLConnection.HTTP_NOT_MODIFIED ->
                        return Result(
                            Status.NOT_MODIFIED, dest, dest.length(), null,
                            version = versionFromMeta(stored),
                        )

                    HttpURLConnection.HTTP_OK ->
                        return readBody(conn, dest, part, meta, append = false)

                    HttpURLConnection.HTTP_PARTIAL -> {
                        // Verify the server resumed where we asked. A 206 that
                        // starts anywhere else would be appended blind, and the
                        // result is a file that is half one version of a
                        // blocklist and half another: it parses, it compiles, and
                        // it blocks the wrong things.
                        val start = contentRangeStart(conn.getHeaderField("Content-Range"))
                        if (resumeFrom > 0 && start != resumeFrom) {
                            runCatching { part.delete() }
                            clearPartState(meta)
                            return Result(
                                Status.FAILED, null, 0,
                                "server resumed at $start, not $resumeFrom; will restart",
                            )
                        }
                        return readBody(conn, dest, part, meta, append = resumeFrom > 0)
                    }

                    HttpURLConnection.HTTP_MOVED_PERM,
                    HttpURLConnection.HTTP_MOVED_TEMP,
                    HttpURLConnection.HTTP_SEE_OTHER,
                    307, 308,
                    -> {
                        val location = conn.getHeaderField("Location")
                            ?: return Result(Status.FAILED, null, 0, "redirect without Location")
                        if (++redirects > MAX_REDIRECTS) {
                            return Result(Status.FAILED, null, 0, "too many redirects")
                        }
                        current = URL(URL(current), location).toString()
                    }

                    416 -> {
                        // Our resume offset is past the end of what the server
                        // now has: the file shrank. Start over rather than
                        // stitching two different versions together.
                        runCatching { part.delete() }
                        clearPartState(meta)
                        return Result(Status.FAILED, null, 0, "resume offset rejected; will restart")
                    }

                    else -> return Result(
                        Status.FAILED, null, 0,
                        "HTTP $code ${conn.responseMessage.orEmpty()}".trim(),
                    )
                }
            } catch (t: Throwable) {
                Log.w(TAG, "fetch $current failed: ${t.message}")
                return Result(Status.FAILED, null, 0, t.message ?: t.javaClass.simpleName)
            } finally {
                runCatching { conn.disconnect() }
            }
        }
    }

    /** `bytes 1024-4095/4096` -> 1024, or -1 when the header is absent or odd. */
    private fun contentRangeStart(header: String?): Long {
        val value = header?.trim().orEmpty()
        if (!value.startsWith("bytes ", ignoreCase = true)) return -1
        return value.removePrefix("bytes ").substringBefore('-').trim().toLongOrNull() ?: -1
    }

    private fun open(url: String): HttpURLConnection? = runCatching {
        (URL(url).openConnection() as HttpURLConnection).apply {
            setRequestProperty("User-Agent", USER_AGENT)
        }
    }.getOrNull()

    private fun applyValidators(conn: HttpURLConnection, url: String, stored: JSONObject) {
        stored.optString("etag").takeIf { it.isNotEmpty() }
            ?.let { conn.setRequestProperty("If-None-Match", it) }
        if (hasLastModified(url)) {
            stored.optString("last_modified").takeIf { it.isNotEmpty() }
                ?.let { conn.setRequestProperty("If-Modified-Since", it) }
        }
    }

    /**
     * How many bytes of `<dest>.part` may be reused.
     *
     * Zero unless the interrupted attempt recorded a strong-enough validator AND
     * was an identity transfer AND was for this same URL. Resuming on a weak
     * assumption produces a file that is half one version of a blocklist and half
     * another, which validates as text, compiles without complaint, and blocks
     * the wrong things.
     */
    private fun resumableBytes(part: File, stored: JSONObject, url: String): Long {
        if (!part.isFile || part.length() == 0L) return 0
        if (stored.optString("part_url") != url) return 0
        if (!stored.optBoolean("part_identity", false)) return 0
        if (stored.optString("part_etag").isEmpty()) return 0
        return part.length()
    }

    private fun readBody(
        conn: HttpURLConnection,
        dest: File,
        part: File,
        meta: File,
        append: Boolean,
    ): Result {
        val encoding = conn.getHeaderField("Content-Encoding").orEmpty()
        val gzipped = encoding.contains("gzip", ignoreCase = true)
        val identity = !gzipped
        val etag = conn.getHeaderField("ETag").orEmpty()

        if (!append) runCatching { part.delete() }
        val startedAt = if (append) part.length() else 0L

        var transferred = 0L
        var oversize = false
        try {
            val raw: InputStream = conn.inputStream
            val stream = if (gzipped) GZIPInputStream(raw) else raw
            stream.use { input ->
                FileOutputStream(part, append).use { output ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        transferred += n
                        if (startedAt + transferred > MAX_BODY_BYTES) {
                            oversize = true
                            break
                        }
                        output.write(buf, 0, n)
                    }
                    output.flush()
                }
            }
        } catch (t: Throwable) {
            // Keep the partial ONLY when it can be resumed safely; otherwise it
            // is 3 MB of /data with no way to tell it apart from a whole list.
            if (identity && etag.isNotEmpty() && part.length() > 0) {
                writePartState(meta, conn.url.toString(), etag, identity = true)
                return Result(
                    Status.FAILED, null, part.length(),
                    "${t.message ?: "read failed"} (will resume)", transferred,
                )
            }
            runCatching { part.delete() }
            clearPartState(meta)
            return Result(Status.FAILED, null, 0, t.message ?: "read failed", transferred)
        }

        // Delete the partial here rather than relying on the next attempt's
        // opening delete: a source that grew past the cap may never be fetched
        // again, and leaving up to 64 MiB of a rejected list behind in priv/cache
        // surfaces only as a full /data with nothing to blame.
        if (oversize) {
            runCatching { part.delete() }
            clearPartState(meta)
            return Result(
                Status.FAILED, null, startedAt + transferred,
                "list exceeds ${MAX_BODY_BYTES / (1024 * 1024)} MiB", transferred,
            )
        }

        val total = part.length()
        if (total == 0L) {
            runCatching { part.delete() }
            clearPartState(meta)
            return Result(Status.FAILED, null, 0, "empty response", transferred)
        }

        runCatching { dest.delete() }
        if (!part.renameTo(dest)) {
            runCatching { part.delete() }
            clearPartState(meta)
            return Result(Status.FAILED, null, total, "could not commit download", transferred)
        }

        val version = Version(
            etag = etag,
            lastModified = conn.getHeaderField("Last-Modified").orEmpty(),
            stamp = "",
            entries = 0,
        )
        writeMeta(meta, version, total)
        return Result(Status.OK, dest, total, null, transferred, version)
    }

    // ---- meta sidecar -------------------------------------------------------

    private fun readMeta(meta: File): JSONObject =
        runCatching { JSONObject(meta.readText()) }.getOrDefault(JSONObject())

    fun versionFor(meta: File): Version? = versionFromMeta(readMeta(meta))

    private fun versionFromMeta(json: JSONObject): Version? {
        val v = Version(
            etag = json.optString("etag"),
            lastModified = json.optString("last_modified"),
            stamp = json.optString("stamp"),
            entries = json.optInt("entries"),
        )
        return if (v.etag.isEmpty() && v.lastModified.isEmpty() && !v.known) null else v
    }

    private fun writeMeta(meta: File, version: Version, bytes: Long) {
        val existing = readMeta(meta)
        runCatching {
            meta.writeText(
                JSONObject()
                    .put("etag", version.etag)
                    .put("last_modified", version.lastModified)
                    // The header stamp comes from the probe, which runs before
                    // the fetch; carry it forward so a fetch does not erase what
                    // the probe learned and force a download next time.
                    .put("stamp", existing.optString("stamp"))
                    .put("entries", existing.optInt("entries"))
                    .put("bytes", bytes)
                    .put("fetched_at", System.currentTimeMillis())
                    .toString()
            )
        }
    }

    /** Records what the probe learned, so the next probe has something to compare. */
    fun recordVersion(meta: File, version: Version) {
        val existing = readMeta(meta)
        runCatching {
            meta.writeText(
                existing
                    .put("etag", version.etag.ifEmpty { existing.optString("etag") })
                    .put(
                        "last_modified",
                        version.lastModified.ifEmpty { existing.optString("last_modified") },
                    )
                    .put("stamp", version.stamp.ifEmpty { existing.optString("stamp") })
                    .put("entries", if (version.entries > 0) version.entries else existing.optInt("entries"))
                    .put("probed_at", System.currentTimeMillis())
                    .toString()
            )
        }
    }

    private fun writePartState(meta: File, url: String, etag: String, identity: Boolean) {
        val existing = readMeta(meta)
        runCatching {
            meta.writeText(
                existing
                    .put("part_url", url)
                    .put("part_etag", etag)
                    .put("part_identity", identity)
                    .toString()
            )
        }
    }

    private fun clearPartState(meta: File) {
        val existing = readMeta(meta)
        existing.remove("part_url")
        existing.remove("part_etag")
        existing.remove("part_identity")
        runCatching { meta.writeText(existing.toString()) }
    }
}
