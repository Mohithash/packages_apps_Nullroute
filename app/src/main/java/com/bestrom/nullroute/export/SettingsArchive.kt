package com.bestrom.nullroute.export

import android.content.Context
import android.net.Uri
import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.RuleStore
import com.bestrom.nullroute.data.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * Settings backup and restore: a `tar.gz` written through the Storage Access
 * Framework, holding **configuration and nothing else**.
 *
 * Re-Malwack's equivalent is `tar -czf /sdcard/Download/…`, which needs broad
 * storage permission, lands in a fixed public directory, and is a root shell's
 * idea of a backup. This writes to a document the user picked, with no storage
 * permission at all, and the app never learns where the file went.
 *
 * ## What is in it
 *
 * Everything under `/data/misc/nullroute/priv/` except the two directories that
 * are not configuration — `cache/` (downloaded list bodies: several megabytes,
 * refetchable, and mostly GPL-3.0 content that has no business being copied into
 * a user's backup file) and `build/` (the native builder's scratch space). Taking
 * `priv/` wholesale rather than naming files one by one is deliberate: it is the
 * directory the design already defines as "user state, never mapped by netd", so
 * anything a later phase persists there is backed up the day it lands, with no
 * schema change here and no chance of a new file being quietly forgotten.
 *
 * Plus the handful of preferences that are genuinely configuration, listed
 * explicitly in [SETTINGS_KEYS].
 *
 * ## What is deliberately not in it
 *
 * **The query log.** Not by default, not as an option, not at all — this file
 * contains no reference to the log database, which lives in CE storage precisely
 * so that a seized-but-locked device exposes no DNS history. A backup that could
 * be made to carry it would defeat that in one tap.
 *
 * **Filter mode.** `persist.sys.nullroute.mode` is not a preference and is not
 * restored. Restoring "paused" from a six-month-old backup would silently
 * un-protect a device whose owner believed they had just restored their settings,
 * and there is no reading of "restore my configuration" that means "and turn
 * filtering off".
 *
 * **Generation numbers and last-update state.** Those describe *this* device's
 * index, not the user's choices. See [Settings].
 *
 * Restoring rules does not change what is blocked until the next compile; the
 * index on disk is untouched by everything in this file.
 */
object SettingsArchive {

    private const val TAG = "Nullroute"

    /** Bump only for a change a v1 reader could not survive. */
    const val SCHEMA = 1

    /**
     * `.tar.gz` already matches this type, so `ACTION_CREATE_DOCUMENT` will not
     * append a second extension to the suggested name.
     */
    const val MIME_TYPE = "application/gzip"

    private const val MANIFEST = "manifest.json"
    private const val SETTINGS_MEMBER = "settings.json"
    private const val README = "README.txt"
    private const val PRIV_PREFIX = "priv/"

    /** Directories under `priv/` that are cache, not configuration. */
    private val EXCLUDED_DIRS = setOf("cache", "build")

    /**
     * The preferences that are configuration. Anything not named here is device
     * state and is neither exported nor restored — an allowlist rather than a
     * denylist, so a preference added later is excluded until someone decides
     * otherwise, which is the safe direction.
     */
    private val SETTINGS_KEYS = listOf(
        "profile", "response_mode", "log_level", "auto_update", "unmetered_only",
    )

    private const val MAX_MEMBER_BYTES = 8L shl 20
    private const val MAX_TOTAL_BYTES = 64L shl 20
    private const val MAX_MEMBERS = 512

    /** Segments we will create on restore. No `..`, no separators, no surprises. */
    private val SAFE_SEGMENT = Regex("^[A-Za-z0-9._-]{1,64}$")

    // ---- export -------------------------------------------------------------

    data class ExportResult(val bytes: Long, val members: List<String>)

    fun suggestedFileName(): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
        return "nullroute-settings-$stamp.tar.gz"
    }

    /**
     * Writes the archive to a document the user created. Blocking; background
     * thread only.
     *
     * Opened with mode `"wt"` — truncate. Overwriting an existing document without
     * it leaves the tail of the previous, longer file behind, which for a gzip
     * stream produces a file that decompresses and then fails halfway through with
     * a CRC error nobody can explain.
     */
    @Throws(IOException::class)
    fun export(context: Context, uri: Uri): ExportResult {
        val out = context.contentResolver.openOutputStream(uri, "wt")
            ?: throw IOException("cannot write to the chosen file")

        val members = ArrayList<String>()
        var counted = 0L

        out.use { raw ->
            val counting = CountingOutputStream(raw)
            TarGz.Writer(counting).use { tar ->
                tar.add(README, readme().toByteArray())
                members += README

                val files = collectPrivFiles()
                for ((name, file) in files) {
                    val bytes = readBounded(file) ?: continue
                    tar.add(name, bytes)
                    members += name
                }

                val settings = settingsJson(context)
                tar.add(SETTINGS_MEMBER, settings.toString(2).toByteArray())
                members += SETTINGS_MEMBER

                tar.add(MANIFEST, manifestJson(context, members).toString(2).toByteArray())
                members += MANIFEST
            }
            counted = counting.count
        }

        Log.i(TAG, "exported ${members.size} members, $counted bytes")
        return ExportResult(counted, members)
    }

    /**
     * Every regular file under `priv/` that is configuration, as
     * `priv/<relative>` -> file.
     *
     * Two levels deep and no further: that is the whole of the layout — loose
     * `.txt` files in `priv/`, and the profile overlays in `priv/profiles/` — and
     * an unbounded walk over a directory tree is an unbounded walk.
     */
    private fun collectPrivFiles(): List<Pair<String, File>> {
        val out = ArrayList<Pair<String, File>>()
        val root = Paths.priv
        if (!root.isDirectory) return out

        root.listFiles()?.sortedBy { it.name }?.forEach { entry ->
            if (entry.isFile) {
                out += "$PRIV_PREFIX${entry.name}" to entry
            } else if (entry.isDirectory && entry.name !in EXCLUDED_DIRS) {
                entry.listFiles()?.sortedBy { it.name }?.forEach { child ->
                    if (child.isFile) out += "$PRIV_PREFIX${entry.name}/${child.name}" to child
                }
            }
        }
        return out.take(MAX_MEMBERS)
    }

    private fun readBounded(file: File): ByteArray? = try {
        if (file.length() > MAX_MEMBER_BYTES) {
            Log.w(TAG, "skipping ${file.name}: ${file.length()} bytes")
            null
        } else {
            // Read whole rather than streaming: a tar header states the size
            // before the payload, and a file that changes size between the
            // `length()` and the copy would produce a corrupt archive.
            file.readBytes()
        }
    } catch (t: Throwable) {
        Log.w(TAG, "cannot read ${file.path}: ${t.message}")
        null
    }

    private fun settingsJson(context: Context): JSONObject = JSONObject()
        .put("profile", Settings.profileId(context))
        .put("response_mode", Settings.responseMode(context))
        .put("log_level", Settings.logLevel(context))
        .put("auto_update", Settings.autoUpdate(context))
        .put("unmetered_only", Settings.unmeteredOnly(context))

    private fun manifestJson(context: Context, members: List<String>): JSONObject {
        val profile = runCatching { ProfileStore.activeProfile(context) }.getOrNull()
        return JSONObject()
            .put("schema", SCHEMA)
            .put("kind", "nullroute-settings")
            .put("created_at_ms", System.currentTimeMillis())
            .put("package", context.packageName)
            .put("app_version", appVersion(context))
            .put("profile", profile?.id ?: "")
            .put("profile_sources", profile?.sources?.size ?: 0)
            .put("allow_rules", RuleStore.readAllow().size)
            .put("deny_rules", RuleStore.readDeny().size)
            .put("redirect_rules", RuleStore.readRedirects().size)
            .put("members", JSONArray(members))
            .put("contains_query_log", false)
    }

    private fun appVersion(context: Context): String = runCatching {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        "${info.versionName} (${info.longVersionCode})"
    }.getOrDefault("unknown")

    private fun readme(): String = """
        Nullroute settings backup
        =========================

        This archive contains your Nullroute configuration: your allow, block and
        redirect rules, your profile and any lists you added to it, and a handful
        of preferences.

        It does NOT contain your query log, or any record of which domains this
        device has looked up. That log lives in encrypted per-user storage and is
        never written to a backup.

        It also does not carry the pause / off state. Restoring a backup never
        switches filtering off.

        Restore it from Nullroute > Settings > Restore settings. Rules take effect
        at the next list update, not the moment they are restored.
    """.trimIndent()

    // ---- restore ------------------------------------------------------------

    /** What a picked archive holds, read without writing anything. */
    data class ArchiveInfo(
        val schema: Int,
        val createdAtMs: Long,
        val appVersion: String,
        val profile: String,
        val allowRules: Int,
        val denyRules: Int,
        val redirectRules: Int,
        val members: List<String>,
        val settings: Map<String, String>,
        val warnings: List<String>,
    ) {
        val ruleFiles: List<String> get() = members.filter { it.startsWith(PRIV_PREFIX) }

        val usable: Boolean get() = schema in 1..SCHEMA && ruleFiles.isNotEmpty()

        fun describe(): String = if (!usable) {
            "This file is not a Nullroute settings backup Nullroute can read."
        } else {
            "$denyRules blocked, $allowRules allowed, $redirectRules redirected, " +
                "profile “$profile”"
        }
    }

    data class RestoreResult(val ok: Boolean, val filesWritten: Int, val error: String?) {
        /**
         * Restored rules reach the resolver at the next compile, never sooner.
         * Not gated on [ok]: a restore that failed half way still replaced the
         * files it got to, and the index has to be rebuilt to match them.
         */
        val needsRebuild: Boolean get() = filesWritten > 0
    }

    /**
     * Reads the archive and reports what a restore would replace. Nothing is
     * written. Blocking; background thread only.
     */
    @Throws(IOException::class)
    fun inspect(context: Context, uri: Uri): ArchiveInfo {
        val members = readMembers(context, uri)
        val warnings = ArrayList<String>()

        val manifest = members[MANIFEST]?.let {
            runCatching { JSONObject(String(it)) }.getOrNull()
        }
        if (manifest == null) warnings += "The archive has no manifest; reading it anyway."

        val schema = manifest?.optInt("schema", 0) ?: 0
        if (schema > SCHEMA) {
            warnings += "Written by a newer version of Nullroute (format $schema). " +
                "Only the parts this version understands will be restored."
        }

        val settings = LinkedHashMap<String, String>()
        members[SETTINGS_MEMBER]?.let { raw ->
            runCatching { JSONObject(String(raw)) }.getOrNull()?.let { json ->
                SETTINGS_KEYS.forEach { key ->
                    if (json.has(key) && !json.isNull(key)) settings[key] = json.optString(key)
                }
            }
        }

        val names = members.keys.filter { it.startsWith(PRIV_PREFIX) }.sorted()
        if (names.isEmpty()) warnings += "The archive contains no rule files."

        return ArchiveInfo(
            schema = if (schema == 0) 1 else schema,
            createdAtMs = manifest?.optLong("created_at_ms", 0L) ?: 0L,
            appVersion = manifest?.optString("app_version").orEmpty(),
            profile = manifest?.optString("profile").orEmpty(),
            allowRules = manifest?.optInt("allow_rules", -1) ?: -1,
            denyRules = manifest?.optInt("deny_rules", -1) ?: -1,
            redirectRules = manifest?.optInt("redirect_rules", -1) ?: -1,
            members = members.keys.sorted(),
            settings = settings,
            warnings = warnings,
        )
    }

    /**
     * Replaces the user's configuration with the archive's. Blocking; background
     * thread only.
     *
     * **This replaces rather than merges**, and the UI has to say so — a restore
     * that quietly unioned two rule sets would make removing a rule impossible
     * and would be a different feature wearing this one's name. Merging is what
     * the importers are for.
     */
    @Throws(IOException::class)
    fun restore(context: Context, uri: Uri): RestoreResult {
        if (!Paths.priv.isDirectory) {
            return RestoreResult(
                false, 0,
                "Nullroute's storage was not set up at boot. Reboot, then try again.",
            )
        }

        val members = readMembers(context, uri)
        var written = 0

        // A newer archive is readable in part, but only in part, and writing the
        // parts we understood while ignoring the rest would leave a configuration
        // that is neither the old one nor the backed-up one.
        val schema = members[MANIFEST]
            ?.let { runCatching { JSONObject(String(it)).optInt("schema", 1) }.getOrNull() }
            ?: 1
        if (schema > SCHEMA) {
            return RestoreResult(
                false, 0,
                "This backup was written by a newer version of Nullroute (format $schema). " +
                    "Update Nullroute, then restore it.",
            )
        }

        val touched = LinkedHashSet<File>()
        try {
            for ((name, bytes) in members) {
                if (!name.startsWith(PRIV_PREFIX)) continue
                val target = File(Paths.priv, name.removePrefix(PRIV_PREFIX))
                val parent = target.parentFile ?: continue
                if (!parent.isDirectory && !parent.mkdirs()) {
                    throw IOException("cannot create ${parent.path}")
                }
                val tmp = File(parent, "${target.name}.tmp")
                tmp.writeBytes(bytes)
                Os.rename(tmp.absolutePath, target.absolutePath)
                touched += parent
                written++
            }
            touched.forEach { fsyncDirectory(it) }

            members[SETTINGS_MEMBER]?.let { raw ->
                runCatching { JSONObject(String(raw)) }.getOrNull()
                    ?.let { applySettings(context, it) }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "restore failed", t)
            return RestoreResult(false, written, t.message ?: t.javaClass.simpleName)
        }

        Log.i(TAG, "restored $written configuration files")
        return RestoreResult(true, written, null)
    }

    /**
     * `rename()` is atomic, but the directory entry is not durable until the
     * directory itself is synced — the same reason
     * [com.bestrom.nullroute.core.Generation] does this after promoting an index.
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

    /**
     * Applies the restored preferences.
     *
     * Response mode goes through [Settings], which mirrors it into `control.bin`
     * for the resolver's next query. Mode is not here and never will be — see the
     * class comment.
     */
    private fun applySettings(context: Context, json: JSONObject) {
        if (json.has("profile")) {
            json.optString("profile").takeIf { it.isNotBlank() }
                ?.let { Settings.setProfileId(context, it) }
        }
        if (json.has("response_mode")) {
            val value = json.optInt("response_mode", ControlPage.RESP_NONAME)
            if (value in ControlPage.RESP_NONAME..ControlPage.RESP_SINKHOLE) {
                Settings.setResponseMode(context, value)
            }
        }
        if (json.has("log_level")) {
            val value = json.optInt("log_level", 0)
            if (value in 0..2) Settings.setLogLevel(context, value)
        }
        if (json.has("auto_update")) {
            Settings.setAutoUpdate(context, json.optBoolean("auto_update", true))
        }
        if (json.has("unmetered_only")) {
            Settings.setUnmeteredOnly(context, json.optBoolean("unmetered_only", true))
        }
    }

    /**
     * Decompresses the archive into memory, applying every bound before anything
     * is retained.
     *
     * A tar member name is attacker-controlled text that this code is about to
     * turn into a path under `/data/misc`, so [sanitize] is not hygiene — it is
     * the whole defence against `../../../system/etc/hosts`. Names that do not
     * survive it are dropped, not corrected: a "fixed" path is a path nobody
     * chose.
     */
    @Throws(IOException::class)
    private fun readMembers(context: Context, uri: Uri): Map<String, ByteArray> {
        val input = context.contentResolver.openInputStream(uri)
            ?: throw IOException("cannot open the chosen file")
        val out = LinkedHashMap<String, ByteArray>()
        try {
            input.use { raw ->
                TarGz.read(raw, MAX_MEMBERS, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES) { name, bytes ->
                    val safe = sanitize(name)
                    if (safe == null) {
                        // Refused, not corrected: a "fixed" path is a path nobody
                        // chose, and this is where `../../../system/etc/hosts`
                        // would arrive if it were ever going to.
                        Log.w(TAG, "archive member refused: $name")
                    } else {
                        out[safe] = bytes
                    }
                }
            }
        } catch (e: java.util.zip.ZipException) {
            throw IOException("That file is not a Nullroute settings backup (it is not gzipped).")
        }
        if (out.isEmpty()) throw IOException("The archive is empty or is not a Nullroute backup.")
        return out
    }

    /** The member name we will accept, or null. See [readMembers]. */
    private fun sanitize(name: String): String? {
        val n = name.replace('\\', '/').trim()
        if (n.isEmpty() || n.startsWith("/") || n.endsWith("/")) return null
        if (n.contains('\u0000') || n.contains(' ') || n.contains("..")) return null
        if (n == MANIFEST || n == SETTINGS_MEMBER || n == README) return n
        if (!n.startsWith(PRIV_PREFIX)) return null

        val segments = n.removePrefix(PRIV_PREFIX).split('/')
        if (segments.isEmpty() || segments.size > 2) return null
        if (!segments.all { SAFE_SEGMENT.matches(it) }) return null
        if (segments.size == 2 && segments[0] in EXCLUDED_DIRS) return null
        return n
    }

    private class CountingOutputStream(private val inner: OutputStream) : OutputStream() {
        var count: Long = 0L
            private set

        override fun write(b: Int) {
            inner.write(b)
            count++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            inner.write(b, off, len)
            count += len
        }

        override fun flush() = inner.flush()

        /** Counts the *compressed* bytes, which is the size of the saved file. */
        override fun close() = inner.flush()
    }
}

/**
 * A minimal USTAR writer and reader over gzip.
 *
 * There is no tar implementation in the platform and `commons-compress` is not
 * among the static libraries this app may link, so this is the whole of it: about
 * a hundred lines for a format whose header has been frozen since 1988. `zip`
 * would have come free with `java.util.zip`, but the parity target is
 * Re-Malwack's `tar -czf` and a `.tar.gz` is what a user — or a maintainer
 * reading a bug report — expects to be able to open with `tar -xzf`.
 *
 * Shared by [SettingsArchive] and [DiagnosticsBundle]; it lives here rather than
 * in a file of its own so that the two features that need it share one
 * implementation.
 */
internal object TarGz {

    private const val BLOCK = 512
    private const val TYPE_REGULAR = '0'.code.toByte()
    private const val TYPE_REGULAR_OLD: Byte = 0

    private val ZEROES = ByteArray(BLOCK)

    class Writer(out: OutputStream) : Closeable {

        // Wrapped so that finishing the archive frees the Deflater without
        // closing the caller's stream. The caller opened it — usually a document
        // through the Storage Access Framework — and closes it with its own
        // `use`; closing it twice from two places is how a stream ends up
        // half-flushed in exactly one implementation of `OutputStream`.
        private val gz = GZIPOutputStream(NonClosing(out), 16 * 1024)
        private val mtime = System.currentTimeMillis() / 1000L

        /** Adds one regular file. Names must fit the 100-byte USTAR name field. */
        fun add(name: String, content: ByteArray) {
            val encoded = name.toByteArray()
            require(encoded.size in 1..100) { "archive member name too long: $name" }
            gz.write(header(encoded, content.size.toLong(), mtime))
            gz.write(content)
            val remainder = content.size % BLOCK
            if (remainder != 0) gz.write(ZEROES, 0, BLOCK - remainder)
        }

        /**
         * Writes the two zero blocks that end a tar, then finishes the gzip.
         *
         * `close()` rather than `finish()`: it also frees the native `Deflater`,
         * and thanks to [NonClosing] it stops at the archive rather than
         * propagating to the caller's stream.
         */
        override fun close() {
            gz.write(ZEROES)
            gz.write(ZEROES)
            gz.close()
        }
    }

    private class NonClosing(private val inner: OutputStream) : OutputStream() {
        override fun write(b: Int) = inner.write(b)
        override fun write(b: ByteArray, off: Int, len: Int) = inner.write(b, off, len)
        override fun flush() = inner.flush()
        override fun close() = inner.flush()
    }

    private fun header(name: ByteArray, size: Long, mtime: Long): ByteArray {
        val h = ByteArray(BLOCK)
        System.arraycopy(name, 0, h, 0, name.size)
        putOctal(h, 100, 8, 420L)          // mode 0644
        putOctal(h, 108, 8, 0L)            // uid
        putOctal(h, 116, 8, 0L)            // gid
        putOctal(h, 124, 12, size)
        putOctal(h, 136, 12, mtime)
        // The checksum is computed with its own field read as eight spaces; that
        // is the definition, not a convention, and getting it wrong produces an
        // archive GNU tar rejects outright.
        for (i in 148 until 156) h[i] = ' '.code.toByte()
        h[156] = TYPE_REGULAR
        putAscii(h, 257, "ustar")          // magic, NUL-terminated by the zero fill
        h[263] = '0'.code.toByte()         // version "00"
        h[264] = '0'.code.toByte()
        putAscii(h, 265, "root")           // uname
        putAscii(h, 297, "root")           // gname

        var sum = 0
        for (b in h) sum += b.toInt() and 0xFF
        val chk = String.format(Locale.US, "%06o", sum)
        for (i in chk.indices) h[148 + i] = chk[i].code.toByte()
        h[154] = 0
        h[155] = ' '.code.toByte()
        return h
    }

    private fun putOctal(h: ByteArray, off: Int, len: Int, value: Long) {
        val text = String.format(Locale.US, "%0${len - 1}o", value)
        for (i in 0 until len - 1) h[off + i] = text[i].code.toByte()
        h[off + len - 1] = 0
    }

    private fun putAscii(h: ByteArray, off: Int, text: String) {
        val bytes = text.toByteArray()
        System.arraycopy(bytes, 0, h, off, bytes.size)
    }

    /**
     * Reads every regular member, subject to hard bounds on member count, member
     * size and total decompressed size.
     *
     * All three bounds matter: the input is a file the user picked, and a few
     * kilobytes of gzip can decompress to gigabytes. Non-regular members
     * (directories, symlinks, GNU long-name and pax extension records) are
     * skipped rather than interpreted — a symlink member in an archive is only
     * ever an attempt to make the extractor write somewhere it did not intend to.
     */
    @Throws(IOException::class)
    fun read(
        input: InputStream,
        maxMembers: Int,
        maxMemberBytes: Long,
        maxTotalBytes: Long,
        onMember: (String, ByteArray) -> Unit,
    ) {
        val gz = GZIPInputStream(input, 16 * 1024)
        val header = ByteArray(BLOCK)
        var members = 0
        var total = 0L

        while (true) {
            if (!readFully(gz, header)) return
            if (header.all { it.toInt() == 0 }) return          // end-of-archive block

            val prefix = ascii(header, 345, 155)
            val base = ascii(header, 0, 100)
            if (base.isEmpty()) return
            val name = if (prefix.isEmpty()) base else "$prefix/$base"

            val size = octal(header, 124, 12)
            if (size < 0) throw IOException("archive member “$name” has an unreadable size")
            if (size > maxMemberBytes) throw IOException("archive member “$name” is too large")
            total += size
            if (total > maxTotalBytes) throw IOException("archive is too large to read")

            val type = header[156]
            val regular = type == TYPE_REGULAR || type == TYPE_REGULAR_OLD

            if (regular) {
                if (++members > maxMembers) throw IOException("archive has too many members")
                val body = ByteArray(size.toInt())
                if (!readFully(gz, body)) throw IOException("archive is truncated")
                onMember(name, body)
            } else {
                skipFully(gz, size)
            }
            val remainder = (size % BLOCK).toInt()
            if (remainder != 0) skipFully(gz, (BLOCK - remainder).toLong())
        }
    }

    private fun ascii(h: ByteArray, off: Int, len: Int): String {
        var end = off
        while (end < off + len && h[end].toInt() != 0) end++
        return String(h, off, end - off, Charsets.UTF_8).trim()
    }

    /**
     * A USTAR numeric field: octal digits, then NUL or space padding. Returns -1
     * for anything else rather than throwing, so a malformed header is refused by
     * the caller's size check instead of by an exception from deep inside a parse.
     */
    private fun octal(h: ByteArray, off: Int, len: Int): Long {
        var value = 0L
        var seen = false
        for (i in off until off + len) {
            val c = h[i].toInt() and 0xFF
            if (c == 0 || c == ' '.code) {
                if (seen) break else continue
            }
            if (c < '0'.code || c > '7'.code) return -1
            value = value * 8 + (c - '0'.code)
            seen = true
            if (value > Int.MAX_VALUE) return -1
        }
        return if (seen) value else 0L
    }

    /**
     * True when [buf] was filled, false at a clean end of stream.
     *
     * The distinction is the whole point: nothing read means the archive ended,
     * which is normal; a partial read means it was cut off mid-record, which is
     * a corrupt file and must not be mistaken for the end.
     */
    @Throws(IOException::class)
    private fun readFully(input: InputStream, buf: ByteArray): Boolean {
        // A zero-length member is not an end of stream and not a truncation: an
        // untouched `allow.txt` is exactly that, and reading it as either would
        // make an ordinary backup unrestorable.
        if (buf.isEmpty()) return true
        var read = 0
        while (read < buf.size) {
            val n = input.read(buf, read, buf.size - read)
            if (n < 0) break
            read += n
        }
        if (read == 0) return false
        if (read < buf.size) throw IOException("archive is truncated")
        return true
    }

    private fun skipFully(input: InputStream, count: Long) {
        var left = count
        val scratch = ByteArray(8192)
        while (left > 0) {
            val n = input.read(scratch, 0, minOf(left, scratch.size.toLong()).toInt())
            if (n < 0) return
            left -= n
        }
    }
}
