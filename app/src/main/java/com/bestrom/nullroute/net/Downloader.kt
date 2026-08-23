package com.bestrom.nullroute.net

import android.util.Log
import org.json.JSONObject
import java.io.File
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
 * Three things here are less obvious than they look:
 *
 *  * **We ask for gzip and decode it ourselves.** `HttpURLConnection`
 *    transparently gunzips only when *it* added the `Accept-Encoding` header. The
 *    moment we set it by hand, the body arrives compressed and the decode becomes
 *    our problem. We take that trade because these lists are 3-5 MB of text that
 *    compresses about 4:1. We do **not** advertise `br`: the platform has no
 *    brotli decoder, and asking for an encoding we cannot read produces a
 *    perfectly successful download of unusable bytes.
 *  * **Redirects are followed by hand.** `HttpURLConnection` refuses to follow
 *    across protocols, which is right, but its silence about it looks like a
 *    404. Following manually also lets us refuse an https -> http downgrade
 *    outright instead of inheriting whatever the platform default happens to be.
 *  * **A conditional GET that comes back 304 is a success**, not a no-op failure.
 *    The cached body stays valid and the caller reuses it.
 */
object Downloader {

    private const val TAG = "Nullroute"

    private const val CONNECT_TIMEOUT_MS = 20_000
    private const val READ_TIMEOUT_MS = 60_000
    private const val MAX_REDIRECTS = 5

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
    ) {
        val usable: Boolean get() = status != Status.FAILED && file != null && file.isFile
    }

    /**
     * Stable per-URL cache key. SHA-1 of the URL, not a sanitised filename: URLs
     * contain characters that are legal in a path on one filesystem and not
     * another, and two sources that differ only in query string must not collide.
     */
    fun cacheKey(url: String): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(url.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    /**
     * Fetches [url] into [dest], honouring the validators recorded in [meta].
     *
     * Writes to `<dest>.part` and renames, so an interrupted download can never
     * be mistaken for a complete list. Blocking; call from a background thread.
     */
    fun fetch(url: String, dest: File, meta: File): Result {
        var current = url
        var redirects = 0

        while (true) {
            if (!current.startsWith("https://")) {
                return Result(Status.FAILED, null, 0, "refusing non-HTTPS URL")
            }

            val conn = try {
                (URL(current).openConnection() as HttpURLConnection)
            } catch (t: Throwable) {
                return Result(Status.FAILED, null, 0, t.message ?: "cannot open connection")
            }

            try {
                conn.requestMethod = "GET"
                conn.connectTimeout = CONNECT_TIMEOUT_MS
                conn.readTimeout = READ_TIMEOUT_MS
                conn.instanceFollowRedirects = false
                conn.setRequestProperty("Accept-Encoding", "gzip")
                conn.setRequestProperty("User-Agent", "Nullroute/1.0 (BestROM)")

                val validators = readMeta(meta)
                // Only send validators when we still hold the body they describe;
                // a 304 against a missing cache file is unrecoverable.
                if (dest.isFile && dest.length() > 0) {
                    validators.optString("etag").takeIf { it.isNotEmpty() }
                        ?.let { conn.setRequestProperty("If-None-Match", it) }
                    validators.optString("last_modified").takeIf { it.isNotEmpty() }
                        ?.let { conn.setRequestProperty("If-Modified-Since", it) }
                }

                when (val code = conn.responseCode) {
                    HttpURLConnection.HTTP_NOT_MODIFIED ->
                        return Result(Status.NOT_MODIFIED, dest, dest.length(), null)

                    HttpURLConnection.HTTP_OK ->
                        return readBody(conn, dest, meta)

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

    private fun readBody(conn: HttpURLConnection, dest: File, meta: File): Result {
        val gzipped = conn.getHeaderField("Content-Encoding")?.contains("gzip", true) == true
        val part = File(dest.parentFile, dest.name + ".part")
        runCatching { part.delete() }

        var written = 0L
        var oversize = false
        try {
            val raw: InputStream = conn.inputStream
            val stream = if (gzipped) GZIPInputStream(raw) else raw
            stream.use { input ->
                part.outputStream().use { output ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        written += n
                        if (written > MAX_BODY_BYTES) {
                            oversize = true
                            break
                        }
                        output.write(buf, 0, n)
                    }
                    output.flush()
                }
            }
        } catch (t: Throwable) {
            runCatching { part.delete() }
            return Result(Status.FAILED, null, written, t.message ?: "read failed")
        }

        // Delete the partial here rather than relying on the next attempt's
        // opening `part.delete()`: a source that grew past the cap may never be
        // fetched again, and leaving up to 64 MiB of a rejected list behind in
        // priv/cache surfaces only as a full /data with nothing to blame.
        if (oversize) {
            runCatching { part.delete() }
            return Result(
                Status.FAILED, null, written,
                "list exceeds ${MAX_BODY_BYTES / (1024 * 1024)} MiB",
            )
        }

        if (written == 0L) {
            runCatching { part.delete() }
            return Result(Status.FAILED, null, 0, "empty response")
        }

        runCatching { dest.delete() }
        if (!part.renameTo(dest)) {
            runCatching { part.delete() }
            return Result(Status.FAILED, null, written, "could not commit download")
        }

        writeMeta(
            meta,
            etag = conn.getHeaderField("ETag").orEmpty(),
            lastModified = conn.getHeaderField("Last-Modified").orEmpty(),
            bytes = written,
        )
        return Result(Status.OK, dest, written, null)
    }

    private fun readMeta(meta: File): JSONObject =
        runCatching { JSONObject(meta.readText()) }.getOrDefault(JSONObject())

    private fun writeMeta(meta: File, etag: String, lastModified: String, bytes: Long) {
        runCatching {
            meta.writeText(
                JSONObject()
                    .put("etag", etag)
                    .put("last_modified", lastModified)
                    .put("bytes", bytes)
                    .put("fetched_at", System.currentTimeMillis())
                    .toString()
            )
        }
    }

    // TODO(Phase 2): the `Range: bytes=0-511` version probe. ~600 bytes of header
    // decides whether to pull 4 MB, by comparing the "# Version:" / "# Number of
    // entries:" line against the compiled manifest. It needs per-host quirk
    // handling that Phase 1 does not: raw.githubusercontent returns a weak ETag
    // and no Last-Modified; jsDelivr caches for a week unless the probe sends
    // no-cache; OISD rejects Range with 416 and needs a HEAD instead.
}
