package com.bestrom.nullroute.data

/**
 * A profile is a *strictness* choice, not a *performance* choice.
 *
 * That is the structural difference from Re-Malwack, where the profile decided
 * how big a text file gets linearly scanned on every cache-missing lookup and
 * therefore how slow the device was. Here every profile compiles to the same
 * open-addressed table shape and the same ~200 ns lookup; AGGRESSIVE costs about
 * 8 MB more clean, evictable, file-backed page cache in netd and nothing else.
 */
data class Profile(
    val id: String,
    val displayName: String,
    val description: String,
    val sources: List<SourceRef>,
    val builtIn: Boolean,
) {
    val enabledSources: List<SourceRef> get() = sources.filter { it.enabled }

    /** Lists whose entries become block rules. */
    val blockSources: List<SourceRef>
        get() = enabledSources.filter { it.role == SourceRole.BLOCK }

    /**
     * Lists whose entries become allow rules regardless of the list's own
     * syntax. Written `@<url>` in a profile file.
     */
    val allowSources: List<SourceRef>
        get() = enabledSources.filter { it.role == SourceRole.ALLOW }

    /**
     * Applies the user's overlay to a shipped profile.
     *
     * The shipped file is immutable — it lives in the signed image — so user
     * intent is expressed as two side files: `<name>_added.txt` (extra sources)
     * and `<name>_removed.txt` (tombstones). An OTA that changes the base profile
     * therefore keeps the user's edits instead of silently reverting them, and a
     * source the user removed does not come back when upstream adds it again.
     *
     * A tombstone matches on URL, not on position: reordering the base file must
     * not resurrect anything.
     */
    fun withOverlay(added: List<SourceRef>, removedUrls: Set<String>): Profile {
        val kept = sources.filterNot { removedUrls.contains(it.url) }
        val extra = added.filterNot { a -> kept.any { it.url == a.url } }
        return copy(sources = kept + extra)
    }
}

/**
 * One entry in a profile file. The line format is Re-Malwack-compatible:
 *
 * ```
 * # DESC: Balanced — the default. Blocks most ads and trackers.
 * https://example.com/list.txt # HaGeZi Multi
 * @https://example.com/allow.txt # Referral allowlist
 * # OFF # https://example.com/other.txt # Something the user switched off
 * ```
 *
 * `# OFF #` is "disabled but remembered" rather than deletion, so toggling a
 * source off and on again does not lose its label or its position.
 *
 * A leading `@` marks the list as an **allowlist seed**: every entry in it
 * becomes an allow rule whatever syntax the list itself uses. That is a property
 * of how we chose to consume the list, not of the list's contents, so it has to
 * be recorded here rather than sniffed — HaGeZi's `blocklist-referral` and
 * `whitelist-referral` are the same 1,604 domains with opposite intent, and no
 * amount of parsing tells them apart.
 */
data class SourceRef(
    val url: String,
    val label: String,
    val enabled: Boolean = true,
    val userAdded: Boolean = false,
    val role: SourceRole = SourceRole.BLOCK,
) {
    /** What the catalogue knows about this URL, if anything. */
    val catalogEntry: SourceCatalog.Entry? get() = SourceCatalog.byUrl(url)

    /**
     * Licence of record. An unknown URL — one the user typed in — is treated as
     * NOT bakeable, because we cannot prove otherwise and the whole licensing
     * posture depends on never guessing in the permissive direction.
     */
    val licence: Licence get() = catalogEntry?.licence ?: Licence.UNKNOWN

    val format: SourceFormat get() = catalogEntry?.format ?: SourceFormat.AUTO
}

/** How a profile's entries are consumed, independent of the list's own syntax. */
enum class SourceRole { BLOCK, ALLOW }

/**
 * Wire format of a fetched list. The native parser (`nr_parse_line`) sniffs each
 * line individually and does not need to be told, so this is a UI hint and a
 * sanity check: a source the catalogue calls DOMAINS that arrives full of `||…^`
 * has been replaced upstream and is worth surfacing.
 */
enum class SourceFormat {
    /** `0.0.0.0 ads.example.com` — every field after the IP is a hostname. */
    HOSTS,

    /** One bare domain per line. */
    DOMAINS,

    /** HaGeZi's wildcard lists: `*.example.com`, subdomains only. */
    WILDCARDS,

    /** AdGuard / ABP: `||example.com^`, `@@||example.com^`. */
    ABP,

    /** dnsmasq: `address=/example.com/0.0.0.0`. */
    DNSMASQ,

    /** Let the parser decide per line. */
    AUTO,
}

/**
 * Licence of a blocklist, and — the part that actually matters — whether its
 * content may be compiled into the signed system image.
 *
 * **This is the whole licensing posture of the product, in one enum.**
 *
 * Only MIT / CC BY 3.0 / Unlicense material is baked. HaGeZi, AdGuard and r-a-y
 * are GPL-3.0; 1Hosts is MPL-2.0. A merged, compiled index derived from GPLv3
 * lists is arguably a derivative work of them, and GPLv3 §6 (Installation
 * Information / anti-tivoization) is aimed squarely at "GPLv3 material inside a
 * verity-protected, signed image" — a BestROM build is exactly that.
 *
 * So the copyleft lists are **fetched and compiled on the device**. The
 * derivative work is then created by the user, on their own hardware, from
 * sources they retrieved themselves; we distribute only URLs. It fixes list
 * staleness in the same move, which is why this is a good design and not merely
 * a cautious one.
 *
 * IANAL — flagged for legal review, and deliberately encoded as a machine-checked
 * flag rather than a paragraph in a README, so that
 * [com.bestrom.nullroute.build.IndexBuilder] can refuse to compile a
 * non-bakeable source that arrived from a read-only image path.
 */
enum class Licence(val spdx: String, val bakeable: Boolean) {
    MIT("MIT", true),
    CC_BY_3_0("CC-BY-3.0", true),
    UNLICENSE("Unlicense", true),

    GPL_3_0("GPL-3.0-only", false),
    MPL_2_0("MPL-2.0", false),

    /** User-supplied URL, or a source whose licence we could not establish. */
    UNKNOWN("unknown", false);

    /** One line for the UI, next to the source name. */
    fun summary(): String = when (this) {
        MIT, CC_BY_3_0, UNLICENSE -> "$spdx — may ship with the ROM"
        GPL_3_0, MPL_2_0 -> "$spdx — compiled on this device, never shipped"
        UNKNOWN -> "licence unknown — compiled on this device only"
    }
}
