package com.bestrom.nullroute.data

import android.content.Context
import android.util.Log
import com.bestrom.nullroute.core.Paths
import java.io.File

/**
 * Reads the shipped profile files and applies the user's overlay.
 *
 * ## The three-file model
 *
 * ```
 *   /system_ext/etc/nullroute/profiles/balanced.txt        immutable, signed image
 *   /data/misc/nullroute/priv/profiles/balanced_added.txt  the user's additions
 *   /data/misc/nullroute/priv/profiles/balanced_removed.txt tombstones, by URL
 * ```
 *
 * The base file cannot be written — it is inside a verity-protected image — and
 * that turns out to be the right design rather than a limitation. An OTA can
 * change what BALANCED means without touching the user's edits, and a source the
 * user removed does not come back the next time upstream adds it. A tombstone
 * matches on **URL, not position**, so reordering the base file resurrects
 * nothing.
 *
 * ## The line format
 *
 * Re-Malwack-compatible, because it is a good format: it survives an OTA, it is
 * diffable, and a user can read it.
 *
 * ```
 * # DESC: Balanced — the default. Blocks most ads and trackers.
 * https://…/multi-onlydomains.txt # HaGeZi Multi Pro
 * @https://…/whitelist-referral-onlydomains.txt # Referral allowlist
 * # OFF # https://example.com/list.txt # Switched off by the user
 * ```
 *
 * `# OFF #` is **disabled but remembered**, not deletion: toggling a source off
 * and on again keeps its label and its position, and — more importantly — a
 * source the user switched off does not silently return when the profile is
 * re-read. A leading `@` marks an **allowlist seed**, a property of how we chose
 * to consume the list rather than of its contents, which is why it must be
 * recorded rather than sniffed: HaGeZi's `blocklist-referral` and
 * `whitelist-referral` are the same 1,604 domains with opposite intent, and no
 * amount of parsing tells them apart.
 *
 * **Profile files carry URLs and nothing else.** No list body is ever shipped for
 * a copyleft source — see [Licence].
 */
object ProfileStore {

    private const val TAG = "Nullroute"
    private const val DESC_PREFIX = "# DESC:"
    private const val OFF_MARKER = "# OFF #"

    /**
     * Every profile the device knows about, base plus overlay.
     *
     * Falls back to [SourceCatalog.builtInProfiles] when the shipped directory is
     * missing — which is the normal case for the Gradle/stock-Android variant, and
     * an abnormal but survivable case for a partial flash. It must never produce
     * an empty list: a profile picker with nothing in it tells the user the
     * product is broken when the real problem is one missing directory.
     */
    fun profiles(context: Context): List<Profile> {
        val fromDisk = readShippedProfiles()
        val base = fromDisk.ifEmpty {
            Log.w(TAG, "no profiles in ${Paths.builtinProfiles}; using the built-in table")
            SourceCatalog.builtInProfiles
        }
        return (base + customProfiles(base)).map { applyOverlay(it) }
    }

    fun profile(context: Context, id: String): Profile? =
        profiles(context).firstOrNull { it.id == id }

    /** The profile the user selected, or BALANCED. Never null: something must build. */
    fun activeProfile(context: Context): Profile {
        val id = Settings.profileId(context)
        return profile(context, id)
            ?: profile(context, SourceCatalog.DEFAULT_PROFILE)
            ?: SourceCatalog.builtInProfiles.first { it.id == SourceCatalog.DEFAULT_PROFILE }
    }

    // ---- reading ------------------------------------------------------------

    private fun readShippedProfiles(): List<Profile> {
        val dir = Paths.builtinProfiles
        if (!dir.isDirectory) return emptyList()
        val files = dir.listFiles { f: File -> f.isFile && f.name.endsWith(".txt") }
            ?: return emptyList()
        return files.sortedBy { orderOf(it.nameWithoutExtension) }
            .mapNotNull { parseProfileFile(it.nameWithoutExtension, it, builtIn = true) }
    }

    /**
     * A "custom" profile is nothing but an overlay with no base: an
     * `<id>_added.txt` whose id matches no shipped file. That is the whole
     * feature — there is no separate storage format and no migration when a
     * future OTA starts shipping a base for the same id.
     */
    private fun customProfiles(base: List<Profile>): List<Profile> {
        val dir = Paths.userProfiles
        if (!dir.isDirectory) return emptyList()
        val known = base.map { it.id }.toSet()
        val files = dir.listFiles { f: File -> f.isFile && f.name.endsWith("_added.txt") }
            ?: return emptyList()
        return files.mapNotNull { f ->
            val id = f.name.removeSuffix("_added.txt")
            if (id.isEmpty() || id in known) return@mapNotNull null
            Profile(
                id = id,
                displayName = id.replaceFirstChar { it.uppercase() },
                description = readDescription(f).ifEmpty { "Your own list of sources." },
                sources = emptyList(),
                builtIn = false,
            )
        }
    }

    /** Lite < Balanced < Aggressive, then anything else alphabetically. */
    private fun orderOf(id: String): String = when (id) {
        SourceCatalog.PROFILE_LITE -> "0$id"
        SourceCatalog.PROFILE_BALANCED -> "1$id"
        SourceCatalog.PROFILE_AGGRESSIVE -> "2$id"
        else -> "3$id"
    }

    private fun parseProfileFile(id: String, file: File, builtIn: Boolean): Profile? = try {
        var description = ""
        val sources = ArrayList<SourceRef>()
        file.forEachLine { raw ->
            val line = raw.trim()
            if (description.isEmpty() && line.startsWith(DESC_PREFIX)) {
                description = line.removePrefix(DESC_PREFIX).trim()
            } else {
                parseLine(raw)?.let { sources += it }
            }
        }
        Profile(
            id = id,
            displayName = SourceCatalog.builtInProfile(id)?.displayName
                ?: id.replaceFirstChar { it.uppercase() },
            description = description.ifEmpty {
                SourceCatalog.builtInProfile(id)?.description.orEmpty()
            },
            sources = sources,
            builtIn = builtIn,
        )
    } catch (t: Throwable) {
        Log.w(TAG, "unreadable profile ${file.path}: ${t.message}")
        null
    }

    private fun readDescription(file: File): String {
        var out = ""
        runCatching {
            file.forEachLine { raw ->
                val line = raw.trim()
                if (out.isEmpty() && line.startsWith(DESC_PREFIX)) {
                    out = line.removePrefix(DESC_PREFIX).trim()
                }
            }
        }
        return out
    }

    /**
     * Parses one source line. Returns null for blanks and for comments that are
     * not an `# OFF #` marker.
     *
     * The label after `#` is optional; when it is absent the catalogue supplies
     * one, and when the catalogue does not know the URL either we show the host.
     */
    private fun parseLine(raw: String): SourceRef? {
        var line = raw.trim()
        if (line.isEmpty()) return null

        var enabled = true
        if (line.startsWith(OFF_MARKER)) {
            enabled = false
            line = line.removePrefix(OFF_MARKER).trim()
        } else if (line.startsWith("#")) {
            return null
        }
        if (line.isEmpty()) return null

        // A leading '@' marks an allowlist seed. Stripped before the URL check,
        // because "@https://…" is a perfectly ordinary URL wearing a role.
        var role = SourceRole.BLOCK
        if (line.startsWith("@")) {
            role = SourceRole.ALLOW
            line = line.substring(1).trim()
        }

        val hash = line.indexOf('#')
        val url = (if (hash >= 0) line.substring(0, hash) else line).trim()
        val label = if (hash >= 0) line.substring(hash + 1).trim() else ""
        if (!url.startsWith("https://") && !url.startsWith("http://")) return null

        return SourceRef(
            url = url,
            label = label.ifEmpty { SourceCatalog.byUrl(url)?.label ?: hostOf(url) },
            enabled = enabled,
            role = role,
        )
    }

    private fun hostOf(url: String): String =
        runCatching { java.net.URI(url).host ?: url }.getOrDefault(url)

    private fun formatLine(ref: SourceRef): String {
        val prefix = if (ref.enabled) "" else "$OFF_MARKER "
        val role = if (ref.role == SourceRole.ALLOW) "@" else ""
        return "$prefix$role${ref.url} # ${ref.label}"
    }

    // ---- user overlay -------------------------------------------------------

    private fun addedFile(id: String) = File(Paths.userProfiles, "${id}_added.txt")
    private fun removedFile(id: String) = File(Paths.userProfiles, "${id}_removed.txt")

    private fun applyOverlay(base: Profile): Profile {
        val added = readOverlayFile(addedFile(base.id)).map { it.copy(userAdded = true) }
        val removed = readTombstones(removedFile(base.id))
        return if (added.isEmpty() && removed.isEmpty()) base
        else base.withOverlay(added, removed)
    }

    private fun readOverlayFile(file: File): List<SourceRef> {
        if (!file.isFile) return emptyList()
        val out = ArrayList<SourceRef>()
        runCatching { file.forEachLine { raw -> parseLine(raw)?.let { out += it } } }
        return out
    }

    private fun readTombstones(file: File): Set<String> {
        if (!file.isFile) return emptySet()
        val out = HashSet<String>()
        runCatching {
            file.forEachLine { raw ->
                val line = raw.trim()
                if (line.isNotEmpty() && !line.startsWith("#")) out += line
            }
        }
        return out
    }

    // ---- writing the overlay ------------------------------------------------

    /**
     * Adds a source the user typed in.
     *
     * Everything a user adds lands in `_added.txt` even when the URL is one the
     * catalogue knows: the catalogue is a description of what we ship, and
     * conflating "we ship this" with "you asked for this" would make a later OTA
     * that drops a source silently drop the user's choice with it.
     */
    fun addSource(profileId: String, ref: SourceRef): Boolean {
        val existing = readOverlayFile(addedFile(profileId))
        if (existing.any { it.url == ref.url }) return false
        // Adding back something previously removed has to lift the tombstone, or
        // the addition is written and then immediately filtered out again.
        clearTombstone(profileId, ref.url)
        return writeLines(
            addedFile(profileId), ADDED_HEADER,
            (existing + ref).map { formatLine(it) },
        )
    }

    /**
     * Removes a source. A user-added one is deleted outright; a shipped one gets
     * a tombstone, because the base file is read-only.
     */
    fun removeSource(profileId: String, url: String): Boolean {
        val existing = readOverlayFile(addedFile(profileId))
        if (existing.any { it.url == url }) {
            return writeLines(
                addedFile(profileId), ADDED_HEADER,
                existing.filterNot { it.url == url }.map { formatLine(it) },
            )
        }
        val tombstones = readTombstones(removedFile(profileId))
        if (url in tombstones) return false
        return writeLines(
            removedFile(profileId), REMOVED_HEADER,
            (tombstones + url).toList(),
        )
    }

    /**
     * Switches a source off or on **without forgetting it** — the `# OFF #`
     * marker rather than a tombstone.
     *
     * A shipped source that the user disables is recorded as a disabled copy in
     * `_added.txt`, which shadows the base entry through
     * [Profile.withOverlay]'s URL match plus the tombstone. That is one more file
     * write than a "disabled URLs" list would need, and it buys the property that
     * matters: the state is expressible in the same text format the user and
     * `nrctl` already read.
     */
    fun setSourceEnabled(
        context: Context,
        profileId: String,
        url: String,
        enabled: Boolean,
    ): Boolean {
        val base = profile(context, profileId) ?: return false
        val ref = base.sources.firstOrNull { it.url == url } ?: return false
        if (ref.enabled == enabled) return false

        val overlay = readOverlayFile(addedFile(profileId))
        val updated = ref.copy(enabled = enabled)
        val merged = if (overlay.any { it.url == url }) {
            overlay.map { if (it.url == url) updated else it }
        } else {
            overlay + updated
        }
        if (!writeLines(addedFile(profileId), ADDED_HEADER, merged.map { formatLine(it) })) {
            return false
        }

        // The shipped entry has to be shadowed, or withOverlay() keeps the base
        // copy and drops ours as a duplicate, and nothing appears to change.
        return if (ref.userAdded) true else tombstone(profileId, url)
    }

    private fun tombstone(profileId: String, url: String): Boolean {
        val tombstones = readTombstones(removedFile(profileId))
        if (url in tombstones) return true
        return writeLines(removedFile(profileId), REMOVED_HEADER, (tombstones + url).toList())
    }

    private fun clearTombstone(profileId: String, url: String) {
        val tombstones = readTombstones(removedFile(profileId))
        if (url !in tombstones) return
        writeLines(removedFile(profileId), REMOVED_HEADER, (tombstones - url).toList())
    }

    /** Drops every user edit for a profile, returning it to what the ROM ships. */
    fun resetOverlay(profileId: String): Boolean {
        val a = addedFile(profileId)
        val r = removedFile(profileId)
        var ok = true
        if (a.exists()) ok = a.delete() && ok
        if (r.exists()) ok = r.delete() && ok
        return ok
    }

    /** True when this profile has been edited, for the "Reset" affordance. */
    fun hasOverlay(profileId: String): Boolean =
        addedFile(profileId).isFile || removedFile(profileId).isFile

    private const val ADDED_HEADER =
        "# Nullroute — sources you added or switched off for this profile.\n" +
            "# The shipped profile is read-only; this file overlays it.\n" +
            "# \"# OFF # <url>\" means disabled but remembered."

    private const val REMOVED_HEADER =
        "# Nullroute — sources removed from the shipped profile, one URL per line.\n" +
            "# Matched by URL, not position, so reordering the base file changes nothing."

    private fun writeLines(file: File, header: String, lines: List<String>): Boolean {
        val tmp = File(file.parentFile, "${file.name}.tmp")
        return try {
            file.parentFile?.mkdirs()
            tmp.bufferedWriter().use { out ->
                out.appendLine(header)
                lines.forEach { out.appendLine(it) }
            }
            if (!tmp.renameTo(file)) {
                tmp.delete()
                Log.w(TAG, "could not commit ${file.name}")
                false
            } else {
                true
            }
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            Log.w(TAG, "writing ${file.name} failed: ${t.message}")
            false
        }
    }
}
