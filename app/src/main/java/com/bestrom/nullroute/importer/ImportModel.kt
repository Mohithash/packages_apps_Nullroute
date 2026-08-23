package com.bestrom.nullroute.importer

import android.content.Context
import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.bestrom.nullroute.build.NeverBlockFloor
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.RuleStore
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.URI
import java.util.Date

/**
 * The shared preview model every importer produces: **what would change, and
 * nothing changes until the user says so.**
 *
 * Re-Malwack's importer writes first and reports afterwards — and, worse, its
 * AdAway import refuses to run at all when AdAway is installed, on the theory
 * that two hosts-file writers cannot coexist. That is true of two hosts-file
 * writers. It is not true here: nothing in this package looks at what else is
 * installed, and nothing in it can disable another app. Nullroute filters inside
 * the resolver, AdAway and bindhosts write `/system/etc/hosts`, Blokada and
 * RethinkDNS hold the VPN slot. All four can run at once, and importing someone's
 * rules is not a reason to evict them.
 *
 * ## Semantics of an imported entry
 *
 * The one decision that makes or breaks a faithful import is what a bare hostname
 * means, and it is deliberately **not** the same answer in both directions:
 *
 *  * A **hosts-file block** (`0.0.0.0 ads.example.com`) blocks exactly that name.
 *    A hosts file has no wildcards, so translating it to
 *    [RuleStore.RuleKind.K_SUFFIX] would quietly start blocking subdomains the
 *    user was never blocking — which is how an import breaks an app a week later
 *    with nothing to point at. Hosts entries therefore import as
 *    [RuleStore.RuleKind.K_EXACT], and broadening is an explicit choice
 *    ([ImportOptions.broadenHostsToSubdomains]) with its own count in the preview.
 *  * A **bare-domain list** (the `-onlydomains` shape: one name per line, no
 *    address) means apex and subdomains — the documented default for domain
 *    sources in SPEC §7.5 — so those import as `K_SUFFIX`.
 *  * An **allowlist entry** always imports as `K_SUFFIX`, whichever file shape it
 *    came from. The asymmetry is the point. An over-narrow block merely fails to
 *    block; an over-narrow allow leaves an app broken while the user stares at a
 *    rule they can see and that visibly is not working. Allow errs wide, block
 *    errs narrow, and both errors point away from breakage.
 *
 * Everything is stored as a **pattern**, never expanded — see [RuleStore].
 *
 * ## What this model is not
 *
 * The line sniffing in the importers is a *preview* parser. `nr_parse_line()` in
 * `native/NrParse.cpp` remains the authority over what enters an index, and
 * `nr_canonicalize()` over which names the matcher will even look at;
 * [Admissibility] mirrors the latter so the preview cannot promise a rule the
 * matcher would decline, but it does not replace it. Where the two disagree, the
 * native side is right.
 */
object ImportModel {

    private const val TAG = "Nullroute"

    /**
     * Ceiling on rules one import may add.
     *
     * User rules are not a blocklist. They are re-read and re-written into the
     * merge overlay on **every** compile
     * ([com.bestrom.nullroute.build.IndexBuilder]), they live in a file the user
     * is expected to be able to read by hand, and the whole set is held in memory
     * while the preview is on screen. A 250k-entry blocklist pasted in here would
     * work and would be the wrong shape — that is what a *source* is for. The cap
     * is generous for anything hand-curated and refuses the case that should have
     * been a subscription, saying so rather than truncating in silence.
     */
    const val MAX_RULES = 50_000

    /** Hard stop on lines read, so a pathological file cannot pin a thread. */
    const val MAX_LINES = 2_000_000

    /** Subscriptions one import may adopt. Higher than any real backup. */
    const val MAX_SOURCES = 128

    private const val MAX_SKIP_SAMPLES = 25
    private const val MAX_CONFLICTS = 200
    private const val SAMPLE_CHARS = 120

    /** Rule files are small by construction; anything larger is a previous mess. */
    private const val MAX_RULE_FILE_BYTES = 8L shl 20

    // ---- vocabulary ---------------------------------------------------------

    enum class RuleList { ALLOW, DENY }

    /** Where an import came from. Recorded verbatim in the rule file's header. */
    enum class OriginKind(val label: String) {
        ADAWAY("AdAway backup"),
        BINDHOSTS("bindhosts"),
        HOSTS_FILE("hosts / domain list"),
        SETTINGS_ARCHIVE("Nullroute settings archive"),
    }

    data class Origin(val kind: OriginKind, val displayName: String) {
        override fun toString(): String = "${kind.label} — $displayName"
    }

    data class ImportOptions(
        /**
         * Turn every hosts-format block into apex-and-subdomains. Off by default;
         * see the class comment for why widening is never the silent choice.
         */
        val broadenHostsToSubdomains: Boolean = false,

        /**
         * Also adopt the list subscriptions the backup names. Off by default:
         * adopting a URL means this device starts downloading from an address the
         * user has not seen yet, which is a change to network behaviour and
         * belongs in the confirmation rather than in a default.
         */
        val includeSources: Boolean = false,
    )

    /** A list subscription named by a backup. Never fetched during a preview. */
    data class ImportedSource(val url: String, val label: String) {
        /** The line shape `ProfileStore.parseLine()` reads back. */
        fun toProfileLine(): String = "$url # $label"
    }

    enum class SkipReason(val describe: String) {
        NOT_A_DOMAIN("not a domain name"),
        IP_LITERAL("an IP address, not a name"),
        NOT_EVALUATED("a suffix the resolver never filters (.local, .onion, .arpa, .localhost)"),
        LOOPBACK("a loopback or broadcast alias from the file's own header"),
        PROBE_RESERVED("reserved for Nullroute's own liveness probes"),
        UNSUPPORTED_SYNTAX("a rule shape a DNS blocker cannot evaluate"),
        FILTER_MODIFIER("a filter-list modifier that depends on page context"),
        OVER_LIMIT("beyond the $MAX_RULES-rule import limit"),
    }

    data class SkipSample(
        val line: Int,
        val text: String,
        val reason: SkipReason,
        val detail: String?,
    )

    enum class ConflictKind {
        /** Already in the user's rules, identically. Nothing will be written. */
        ALREADY_PRESENT,

        /** Importing a block for something the user allows. The allow wins. */
        BLOCK_OVER_EXISTING_ALLOW,

        /** Importing an allow for something the user blocks. The allow wins. */
        ALLOW_OVER_EXISTING_BLOCK,

        /**
         * Blocked by the import, force-allowed by the compiled-in never-block
         * floor. `K_FORCE` beats a block at any depth, so the rule is inert — and
         * a user who is not told that believes they blocked something.
         */
        SHADOWED_BY_FLOOR,

        /** A redirect for a name that already has a different address. */
        REDIRECT_REPLACED,
    }

    data class Conflict(val domain: String, val kind: ConflictKind, val detail: String)

    // ---- the plan -----------------------------------------------------------

    /**
     * What an import **would** do. The pending lists are not a summary of the
     * plan; they are the plan — [commit] writes exactly these and recomputes
     * nothing, so the confirmation the user saw cannot drift from what lands.
     */
    data class Plan(
        val origin: Origin,
        val options: ImportOptions,
        val pendingAllow: List<RuleStore.Pattern>,
        val pendingDeny: List<RuleStore.Pattern>,
        val pendingRedirects: List<RuleStore.Redirect>,
        val pendingSources: List<ImportedSource>,
        /** Understood, but the user already has it. Nothing will be written. */
        val alreadyPresent: Int,
        val conflicts: List<Conflict>,
        val conflictsOmitted: Int,
        val skipped: Map<SkipReason, Int>,
        val skipSamples: List<SkipSample>,
        val notes: List<String>,
        /** Input ran past [MAX_RULES] or [MAX_LINES] and was cut short. */
        val truncated: Boolean,
        val linesRead: Long,
    ) {
        val totalPending: Int
            get() = pendingAllow.size + pendingDeny.size + pendingRedirects.size +
                pendingSources.size

        val totalSkipped: Int get() = skipped.values.sum()

        val nothingToDo: Boolean get() = totalPending == 0

        /** One line for the confirmation button's supporting text. */
        fun summary(): String {
            if (nothingToDo) {
                return if (alreadyPresent > 0) {
                    "Nothing to add — all $alreadyPresent rules are already in your list."
                } else {
                    "Nothing to add."
                }
            }
            val parts = ArrayList<String>(4)
            if (pendingDeny.isNotEmpty()) parts += "${pendingDeny.size} blocked"
            if (pendingAllow.isNotEmpty()) parts += "${pendingAllow.size} allowed"
            if (pendingRedirects.isNotEmpty()) parts += "${pendingRedirects.size} redirected"
            if (pendingSources.isNotEmpty()) parts += "${pendingSources.size} lists"
            return parts.joinToString(", ")
        }

        /**
         * Writes the plan. Background thread — this fsyncs.
         *
         * **Nothing here changes what is blocked.** Rules enter the index at the
         * next compile, which is also why a failed import cannot degrade
         * protection: the live index is untouched either way.
         */
        fun commit(context: Context): CommitResult = ImportModel.commit(context, this)
    }

    data class CommitResult(
        val ok: Boolean,
        val allowWritten: Int,
        val denyWritten: Int,
        val redirectsWritten: Int,
        val redirectsReplaced: Int,
        val sourcesWritten: Int,
        val error: String?,
    ) {
        val totalWritten: Int
            get() = allowWritten + denyWritten + redirectsWritten + sourcesWritten

        /**
         * True whenever a rebuild is needed before what landed takes effect —
         * deliberately not gated on [ok]. A partial import still changed the rule
         * files, and offering "Update now" only on complete success would leave
         * the device running an index that does not match what is on disk.
         */
        val needsRebuild: Boolean get() = totalWritten > 0
    }

    // ---- admissibility ------------------------------------------------------

    /**
     * The names the matcher will never look at, mirrored here so the preview does
     * not offer a rule that provably cannot fire.
     *
     * Authority is `nr_canonicalize()` / `nr_is_ip_literal()` /
     * `nr_has_skip_suffix()` in `native/NrCanon.cpp`. This is a copy of that
     * decision, kept deliberately small so it stays a copy.
     */
    object Admissibility {

        /** The zone both `.invalid` probes live in. Derived, never spelled twice. */
        private val PROBE_ZONE: String =
            Probes.IDX.substringAfter('.').ifEmpty { "nullroute.invalid" }

        /** `.invalid` is NOT here, on purpose: the liveness probes live in it. */
        private val SKIP_SUFFIX = listOf(".local", ".onion", ".arpa", ".localhost")

        /** Names every hosts file opens with, which are not blocklist entries. */
        private val LOOPBACK_NAMES = setOf(
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
            "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
        )

        /** Sinkhole addresses: a hosts line carrying one is a block, not a map. */
        private val SINKHOLE = setOf("0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0")

        fun isSinkhole(address: String): Boolean = address.trim().lowercase() in SINKHOLE

        /**
         * Deliberately hand-rolled and deliberately loose: this only has to
         * recognise the shapes that appear on the left of a hosts line, and it
         * must never call `InetAddress` — that method issues a DNS query for
         * anything it cannot parse as a literal, which is not something a file
         * parser may do.
         */
        fun isIpLiteral(s: String): Boolean {
            if (s.isEmpty()) return false
            if (s.contains(':')) {
                return s.all {
                    it == ':' || it == '%' || it == '.' || it in '0'..'9' || it in "abcdefABCDEF"
                }
            }
            val parts = s.split('.')
            if (parts.size != 4) return false
            return parts.all { p ->
                p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && p.toInt() in 0..255
            }
        }

        /**
         * Why this name cannot become a rule, or null if it can. Call it with the
         * domain **as [RuleStore] parsed it**, not with the raw text: `*.d` and
         * `=d` have to be reduced to `d` first or the probe-zone check below can
         * be walked straight past.
         *
         * That check is not paranoia. `idx-probe.nullroute.invalid` is the only
         * end-to-end evidence the Home screen has that the resolver hook fired,
         * and a user rule sitting over it would make a healthy device report
         * "Limited" with no way to tell that apart from a genuinely dead hook.
         */
        fun reject(domain: String): SkipReason? {
            val n = domain.trim().lowercase().removeSuffix(".")
            if (n.isEmpty()) return SkipReason.NOT_A_DOMAIN
            if (n in LOOPBACK_NAMES) return SkipReason.LOOPBACK
            if (isIpLiteral(n)) return SkipReason.IP_LITERAL
            if (!n.contains('.')) return SkipReason.NOT_A_DOMAIN
            if (SKIP_SUFFIX.any { n.endsWith(it) }) return SkipReason.NOT_EVALUATED
            if (n == PROBE_ZONE || n.endsWith(".$PROBE_ZONE")) return SkipReason.PROBE_RESERVED
            return null
        }
    }

    // ---- collector ----------------------------------------------------------

    /**
     * What an importer pushes lines into. One instance per import; not
     * thread-safe and does not need to be.
     */
    class Collector(private val options: ImportOptions) {

        private val allow = LinkedHashSet<RuleStore.Pattern>()
        private val deny = LinkedHashSet<RuleStore.Pattern>()
        private val redirects = LinkedHashMap<String, RuleStore.Redirect>()
        private val sources = LinkedHashMap<String, ImportedSource>()
        private val skipCounts = LinkedHashMap<SkipReason, Int>()
        private val samples = ArrayList<SkipSample>(MAX_SKIP_SAMPLES)
        private val notes = ArrayList<String>()

        var linesRead: Long = 0L
            private set

        var truncated: Boolean = false
            private set

        private val full: Boolean get() = allow.size + deny.size + redirects.size >= MAX_RULES

        /** Call once per input line, before parsing it. False means stop reading. */
        fun beginLine(): Boolean {
            if (linesRead >= MAX_LINES) {
                truncated = true
                return false
            }
            linesRead++
            return true
        }

        /** A remark for the preview that is not tied to any one line. Deduped. */
        fun note(text: String) {
            if (notes.none { it == text }) notes += text
        }

        fun skip(reason: SkipReason, lineNo: Int, text: String?, detail: String? = null) {
            skipCounts[reason] = (skipCounts[reason] ?: 0) + 1
            if (samples.size < MAX_SKIP_SAMPLES && !text.isNullOrBlank()) {
                samples += SkipSample(lineNo, text.trim().take(SAMPLE_CHARS), reason, detail)
            }
        }

        /**
         * A rule whose kind the file stated explicitly (`*.d`, `=d`, `@d`, `||d^`).
         * Taken at face value: the file said what it meant.
         */
        fun rule(
            domain: String,
            kind: RuleStore.RuleKind,
            list: RuleList,
            lineNo: Int,
            text: String?,
        ) {
            // RuleStore is the only judge of whether a domain is admissible, and
            // it also normalises `*.`/`=`/`@`/`!` away — which has to happen
            // before Admissibility sees the name, or `*.nullroute.invalid` walks
            // straight past the probe-zone guard below.
            //
            // On refusal, Admissibility gets a look at the raw token anyway: the
            // things a hosts file opens with — `localhost`, `0.0.0.0` — are all
            // single-label or IP-shaped, so RuleStore turns every one of them
            // into the same "not a domain", and the preview would tell a user
            // their file had three unparseable lines instead of naming the
            // header they were never importing in the first place.
            val parsed = RuleStore.parseAllow(domain).getOrElse { badPattern ->
                skip(
                    Admissibility.reject(domain) ?: SkipReason.NOT_A_DOMAIN,
                    lineNo, text, badPattern.message,
                )
                return
            }
            val rejection = Admissibility.reject(parsed.domain)
            if (rejection != null) {
                skip(rejection, lineNo, text)
                return
            }
            val pattern = RuleStore.Pattern(parsed.domain, kind)
            val target = if (list == RuleList.ALLOW) allow else deny
            if (!target.contains(pattern) && full) {
                skip(SkipReason.OVER_LIMIT, lineNo, text)
                truncated = true
                return
            }
            target += pattern
        }

        /**
         * A bare hostname off a hosts line or a domain list, where the *file
         * shape* decides the kind rather than the entry itself. See the class
         * comment for the exact-versus-suffix reasoning.
         */
        fun bareName(
            name: String,
            list: RuleList,
            fromHostsLine: Boolean,
            lineNo: Int,
            text: String?,
        ) {
            val kind = when {
                list == RuleList.ALLOW -> RuleStore.RuleKind.K_SUFFIX
                !fromHostsLine -> RuleStore.RuleKind.K_SUFFIX
                options.broadenHostsToSubdomains -> RuleStore.RuleKind.K_SUFFIX
                else -> RuleStore.RuleKind.K_EXACT
            }
            rule(name, kind, list, lineNo, text)
        }

        /**
         * A hosts-style mapping. A sinkhole address is a **block**, not a
         * redirect: `0.0.0.0 ads.example.com` says "do not resolve this", and
         * putting it in the redirect table instead would hand the app a
         * routable-looking answer and buy a failed connection attempt per lookup.
         */
        fun mapping(address: String, name: String, lineNo: Int, text: String?) {
            if (Admissibility.isSinkhole(address)) {
                bareName(name, RuleList.DENY, fromHostsLine = true, lineNo = lineNo, text = text)
                return
            }
            val redirect = RuleStore.parseRedirect("$address $name").getOrElse {
                skip(SkipReason.UNSUPPORTED_SYNTAX, lineNo, text, it.message)
                return
            }
            val rejection = Admissibility.reject(redirect.domain)
            if (rejection != null) {
                skip(rejection, lineNo, text)
                return
            }
            if (!redirects.containsKey(redirect.domain) && full) {
                skip(SkipReason.OVER_LIMIT, lineNo, text)
                truncated = true
                return
            }
            redirects[redirect.domain] = redirect
        }

        fun source(url: String, label: String) {
            val u = url.trim()
            if (!u.startsWith("https://") && !u.startsWith("http://")) return
            if (sources.containsKey(u)) return
            if (sources.size >= MAX_SOURCES) {
                truncated = true
                return
            }
            sources[u] = ImportedSource(u, label.trim().ifEmpty { hostOf(u) })
        }

        /** Resolves what was collected against what the user already has. */
        fun build(context: Context, origin: Origin): Plan =
            plan(context, origin, options, snapshot())

        private fun snapshot() = Snapshot(
            allow.toList(), deny.toList(), redirects.values.toList(), sources.values.toList(),
            skipCounts, samples, notes, truncated, linesRead,
        )
    }

    private data class Snapshot(
        val allow: List<RuleStore.Pattern>,
        val deny: List<RuleStore.Pattern>,
        val redirects: List<RuleStore.Redirect>,
        val sources: List<ImportedSource>,
        val skipped: Map<SkipReason, Int>,
        val samples: List<SkipSample>,
        val notes: List<String>,
        val truncated: Boolean,
        val linesRead: Long,
    )

    // ---- resolution against existing state ----------------------------------

    private fun plan(
        context: Context,
        origin: Origin,
        options: ImportOptions,
        s: Snapshot,
    ): Plan {
        val existingAllow = RuleStore.readAllow().toSet()
        val existingDeny = RuleStore.readDeny().toSet()
        val existingRedirects = RuleStore.readRedirects().associateBy { it.domain }
        val floor = NeverBlockFloor.domains(context)

        val existingAllowDomains = existingAllow.mapTo(HashSet()) { it.domain }
        val existingDenyDomains = existingDeny.mapTo(HashSet()) { it.domain }

        val conflicts = ArrayList<Conflict>()
        var conflictsOmitted = 0
        var alreadyPresent = 0

        fun conflict(domain: String, kind: ConflictKind, detail: String) {
            if (conflicts.size < MAX_CONFLICTS) conflicts += Conflict(domain, kind, detail)
            else conflictsOmitted++
        }

        val pendingAllow = ArrayList<RuleStore.Pattern>(s.allow.size)
        for (p in s.allow) {
            if (p in existingAllow) {
                alreadyPresent++
                continue
            }
            if (p.domain in existingDenyDomains) {
                conflict(
                    p.domain, ConflictKind.ALLOW_OVER_EXISTING_BLOCK,
                    "You block this. Allowing wins, so your block stops applying.",
                )
            }
            pendingAllow += p
        }

        val pendingDeny = ArrayList<RuleStore.Pattern>(s.deny.size)
        for (p in s.deny) {
            if (p in existingDeny) {
                alreadyPresent++
                continue
            }
            val shadow = floorShadow(p.domain, floor)
            if (shadow != null) {
                conflict(
                    p.domain, ConflictKind.SHADOWED_BY_FLOOR,
                    "Will never block — $shadow is on the built-in never-block list.",
                )
            } else if (p.domain in existingAllowDomains) {
                conflict(
                    p.domain, ConflictKind.BLOCK_OVER_EXISTING_ALLOW,
                    "You allow this, and allowing wins. The block will not apply.",
                )
            }
            pendingDeny += p
        }

        val pendingRedirects = ArrayList<RuleStore.Redirect>(s.redirects.size)
        for (r in s.redirects) {
            val existing = existingRedirects[r.domain]
            if (existing != null && existing.address == r.address) {
                alreadyPresent++
                continue
            }
            if (existing != null) {
                conflict(
                    r.domain, ConflictKind.REDIRECT_REPLACED,
                    "Currently sent to ${existing.address}; this changes it to ${r.address}.",
                )
            }
            pendingRedirects += r
        }

        val pendingSources = if (!options.includeSources) {
            emptyList()
        } else {
            val known = HashSet<String>()
            runCatching { ProfileStore.activeProfile(context).sources.forEach { known += it.url } }
            s.sources.filterNot { known.contains(it.url) }
        }

        return Plan(
            origin = origin,
            options = options,
            pendingAllow = pendingAllow,
            pendingDeny = pendingDeny,
            pendingRedirects = pendingRedirects,
            pendingSources = pendingSources,
            alreadyPresent = alreadyPresent,
            conflicts = conflicts,
            conflictsOmitted = conflictsOmitted,
            skipped = s.skipped,
            skipSamples = s.samples,
            notes = s.notes + derivedNotes(s, options),
            truncated = s.truncated,
            linesRead = s.linesRead,
        )
    }

    private fun derivedNotes(s: Snapshot, options: ImportOptions): List<String> {
        val out = ArrayList<String>(2)
        if (s.truncated) {
            out += "This file is larger than Nullroute imports as personal rules " +
                "($MAX_RULES). A list that size belongs in your profile as a " +
                "subscription, where it is compiled rather than re-read on every update."
        }
        if (s.sources.isNotEmpty() && !options.includeSources) {
            out += "${s.sources.size} list subscriptions were found and are not being " +
                "added. Turn that on if you want this device to download from them."
        }
        return out
    }

    /**
     * The never-block entry that swallows [domain], or null.
     *
     * A plain suffix test, not a matcher: the floor is compiled in as `K_FORCE`,
     * and SPEC §7.5 defines `K_FORCE` as beating any block at any depth, so a
     * block at or under a floor entry is inert. `nr_evaluate()` still decides
     * every real query; this only decides what the preview says.
     */
    private fun floorShadow(domain: String, floor: List<String>): String? =
        floor.firstOrNull { domain == it || domain.endsWith(".$it") }

    // ---- writing ------------------------------------------------------------

    private fun commit(context: Context, plan: Plan): CommitResult {
        if (!Paths.priv.isDirectory) {
            // init.nullroute.rc creates priv/ at post-fs-data. Creating it here
            // would give it app ownership and hide a boot failure behind an
            // import that looked like it worked.
            return CommitResult(
                false, 0, 0, 0, 0, 0,
                "Nullroute's storage was not set up at boot. Reboot, then try again.",
            )
        }

        val stamp = "# imported from ${plan.origin} on ${Date()}"

        // Counted as each file lands rather than assumed at the end. Every write
        // below is individually atomic, so a failure part-way through leaves some
        // of the import applied — and reporting that as "0 written, failed" would
        // send the user to re-import rules they already have. Each file is either
        // wholly there or wholly not; the count says which.
        var allowWritten = 0
        var denyWritten = 0
        var redirectsWritten = 0
        var replaced = 0
        var sourcesWritten = 0

        try {
            if (plan.pendingAllow.isNotEmpty()) {
                appendRules(Paths.allowTxt, stamp, plan.pendingAllow.map { it.toAllowLine() })
                allowWritten = plan.pendingAllow.size
            }
            if (plan.pendingDeny.isNotEmpty()) {
                appendRules(Paths.denyTxt, stamp, plan.pendingDeny.map { it.toDenyLine() })
                denyWritten = plan.pendingDeny.size
            }
            if (plan.pendingRedirects.isNotEmpty()) {
                replaced = rewriteRedirects(stamp, plan.pendingRedirects)
                redirectsWritten = plan.pendingRedirects.size
            }
            if (plan.pendingSources.isNotEmpty()) {
                appendSources(context, stamp, plan.pendingSources)
                sourcesWritten = plan.pendingSources.size
            }
        } catch (t: Throwable) {
            Log.e(TAG, "import write failed after $allowWritten/$denyWritten/$redirectsWritten", t)
            return CommitResult(
                ok = false,
                allowWritten = allowWritten,
                denyWritten = denyWritten,
                redirectsWritten = redirectsWritten,
                redirectsReplaced = replaced,
                sourcesWritten = sourcesWritten,
                error = t.message ?: t.javaClass.simpleName,
            )
        }

        Log.i(
            TAG,
            "imported from ${plan.origin.kind.name}: $denyWritten deny, $allowWritten allow, " +
                "$redirectsWritten redirect, $sourcesWritten sources",
        )
        return CommitResult(
            ok = true,
            allowWritten = allowWritten,
            denyWritten = denyWritten,
            redirectsWritten = redirectsWritten,
            redirectsReplaced = replaced,
            sourcesWritten = sourcesWritten,
            error = null,
        )
    }

    /**
     * Appends, preserving the file byte-for-byte.
     *
     * Read-parse-rewrite would be shorter and would silently delete every comment
     * the user wrote, because [RuleStore] drops comments on read. These files are
     * meant to be edited by hand and by `nrctl`; an import is not entitled to
     * reformat them.
     */
    private fun appendRules(file: File, header: String, lines: List<String>) {
        val existing = readExisting(file)
        writeAtomically(file) { out ->
            out.append(existing)
            if (existing.isNotEmpty() && !existing.endsWith("\n")) out.append('\n')
            out.append(header).append('\n')
            lines.forEach { out.append(it).append('\n') }
        }
    }

    /**
     * Redirects cannot simply be appended: the redirect table is keyed on the
     * FQDN fingerprint, so two lines for one name are two entries under one key
     * and which of them answers is arbitrary. A superseded line is commented out
     * rather than deleted — [RuleStore] skips `#`, and the user can still see
     * what their redirect used to be.
     */
    private fun rewriteRedirects(header: String, pending: List<RuleStore.Redirect>): Int {
        val file = Paths.redirectTxt
        val superseded = pending.mapTo(HashSet()) { it.domain }
        val existing = readExisting(file)
        var replaced = 0

        writeAtomically(file) { out ->
            if (existing.isNotEmpty()) {
                existing.trimEnd('\n').lineSequence().forEach { line ->
                    val parsed =
                        if (line.isBlank() || line.trimStart().startsWith("#")) null
                        else RuleStore.parseRedirect(line).getOrNull()
                    if (parsed != null && superseded.contains(parsed.domain)) {
                        out.append("# replaced by import: ").append(line.trim()).append('\n')
                        replaced++
                    } else {
                        out.append(line).append('\n')
                    }
                }
            }
            out.append(header).append('\n')
            pending.forEach { out.append(it.toLine()).append('\n') }
        }
        return replaced
    }

    /**
     * Adopted subscriptions land in the profile overlay the shipped profile
     * already reads (`<id>_added.txt`), so they are live at the next update with
     * no further wiring — the base profile file is in the signed image and cannot
     * be written to at all.
     */
    private fun appendSources(context: Context, header: String, sources: List<ImportedSource>) {
        val dir = Paths.userProfiles
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("cannot create ${dir.path}")
        val id = ProfileStore.activeProfile(context).id
        val file = File(dir, "${id}_added.txt")
        val existing = readExisting(file)
        writeAtomically(file) { out ->
            out.append(existing)
            if (existing.isNotEmpty() && !existing.endsWith("\n")) out.append('\n')
            out.append(header).append('\n')
            sources.forEach { out.append(it.toProfileLine()).append('\n') }
        }
    }

    private fun readExisting(file: File): String {
        if (!file.isFile) return ""
        if (file.length() > MAX_RULE_FILE_BYTES) {
            throw IOException(
                "${file.name} is ${file.length() / 1024} KiB — refusing to rewrite it"
            )
        }
        return file.readText()
    }

    /**
     * Write-to-temp, fsync, rename, fsync the directory.
     *
     * These files are the user's own rules and there is no second copy of them. A
     * truncating in-place write interrupted by a low-memory kill would leave a
     * half file that [RuleStore] would happily read as a shorter rule set, so the
     * live file is never opened for writing at all.
     */
    private fun writeAtomically(file: File, body: (Appendable) -> Unit) {
        val dir = file.parentFile ?: throw IOException("no parent for ${file.path}")
        val tmp = File(dir, "${file.name}.tmp")
        FileOutputStream(tmp).use { fos ->
            val writer = fos.writer().buffered()
            body(writer)
            writer.flush()
            fos.fd.sync()
        }
        Os.rename(tmp.absolutePath, file.absolutePath)
        runCatching {
            val fd = Os.open(dir.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(fd)
            } finally {
                Os.close(fd)
            }
        }.onFailure { Log.w(TAG, "fsync ${dir.path} failed: ${it.message}") }
    }

    internal fun hostOf(url: String): String =
        runCatching { URI(url).host ?: url }.getOrDefault(url)
}
