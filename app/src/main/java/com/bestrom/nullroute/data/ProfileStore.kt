package com.bestrom.nullroute.data

import android.content.Context
import android.util.Log
import com.bestrom.nullroute.core.Paths
import java.io.File

/**
 * Reads the shipped profile files and applies the user's overlay.
 *
 * The file model is deliberately Re-Malwack-compatible — a profile is a text file
 * of source URLs, one per line, with a `# DESC:` header and a `# OFF #` prefix for
 * "disabled but remembered". Compatibility is worth keeping because it is a good
 * format: it survives an OTA, it is diffable, and a user can read it.
 *
 * ```
 * # DESC: Balanced — the default. Blocks most ads and trackers.
 * https://raw.githubusercontent.com/hagezi/.../multi-onlydomains.txt # HaGeZi Multi Pro
 * # OFF # https://example.com/list.txt # Switched off by the user
 * ```
 *
 * The base file is read-only (it is in the signed image); edits go to
 * `/data/misc/nullroute/priv/profiles/<id>_added.txt` and `<id>_removed.txt`.
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
        return base.map { applyOverlay(it) }
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

    // ---- user overlay -------------------------------------------------------

    private fun applyOverlay(base: Profile): Profile {
        val added = readOverlayFile(File(Paths.userProfiles, "${base.id}_added.txt"))
            .map { it.copy(userAdded = true) }
        val removed = readTombstones(File(Paths.userProfiles, "${base.id}_removed.txt"))
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

    // TODO(Phase 2): writing the overlay — enable/disable a source, add a custom
    // URL, remove a shipped one, and the "custom" profile that is nothing but an
    // overlay with no base. Phase 1 ships the picker read-only, because a source
    // editor without the per-source counts, licence chips and version probe that
    // make it comprehensible is worse than no editor at all.
}
