package com.bestrom.nullroute.data

import com.bestrom.nullroute.core.Paths
import java.io.File

/**
 * User rules: allow, deny, redirect.
 *
 * **The pattern is stored, never expanded.** This is the single most important
 * correction to Re-Malwack, whose `-w add "*.doubleclick.net"` expands the
 * wildcard against the blocklist *as it exists at that instant*, persists only
 * the concrete domains it found, and then silently stops covering anything added
 * upstream afterwards. The user is never told; their allowlist just quietly
 * decays. Here the pattern goes into the allow table as a `K_WILDCARD_ONLY` rule
 * and `kind_applies()` evaluates it per query, so there is no expansion step and
 * nothing to go stale.
 */
object RuleStore {

    /** Mirror of `enum RuleKind` in native/include/NrVerdict.h. Values are ABI. */
    enum class RuleKind(val wire: Int) {
        /** `example.com` — apex and every subdomain. */
        K_SUFFIX(0),

        /** `*.example.com` — subdomains only, NOT the apex. */
        K_WILDCARD_ONLY(1),

        /** `=a.example.com` — that FQDN and nothing else. */
        K_EXACT(2),

        /** `!example.com` — absolute allow, beats any block at any depth. */
        K_FORCE(3),
    }

    /** A parsed, admissible pattern. `domain` is lowercased and dot-trimmed. */
    data class Pattern(val domain: String, val kind: RuleKind) {

        /** The text form `nr_parse_line()` reads back, as an allow rule. */
        fun toAllowLine(): String = when (kind) {
            RuleKind.K_SUFFIX -> "@$domain"
            RuleKind.K_WILDCARD_ONLY -> "@*.$domain"
            RuleKind.K_EXACT -> "@=$domain"
            RuleKind.K_FORCE -> "!$domain"
        }

        /** The text form `nr_parse_line()` reads back, as a block rule. */
        fun toDenyLine(): String = when (kind) {
            RuleKind.K_SUFFIX -> domain
            RuleKind.K_WILDCARD_ONLY -> "*.$domain"
            RuleKind.K_EXACT -> "=$domain"
            // A force-allow in the deny file is a contradiction; emit the allow
            // form so the builder's precedence rules see what the user meant.
            RuleKind.K_FORCE -> "!$domain"
        }

        /** How the pattern reads to a human, for the confirmation line in the UI. */
        fun describe(): String = when (kind) {
            RuleKind.K_SUFFIX -> "$domain and all subdomains"
            RuleKind.K_WILDCARD_ONLY -> "subdomains of $domain only"
            RuleKind.K_EXACT -> "exactly $domain"
            RuleKind.K_FORCE -> "$domain and all subdomains, always allowed"
        }
    }

    data class Redirect(val domain: String, val address: String) {
        fun toLine(): String = "$address $domain"
    }

    class BadPattern(message: String) : IllegalArgumentException(message)

    private val LABEL = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

    /**
     * Parses an allowlist pattern.
     *
     * Fails with a user-facing reason rather than guessing. Re-Malwack has three
     * divergent regex builders for add / guard / remove and they do not agree
     * with each other; the resulting mis-handling is invisible until a domain the
     * user allowed is blocked anyway. One parser, one answer, and a refusal is a
     * legitimate answer.
     */
    fun parseAllow(raw: String): Result<Pattern> {
        var s = raw.trim().lowercase().removeSuffix(".")
        if (s.isEmpty()) return Result.failure(BadPattern("Empty."))

        var force = false
        if (s.startsWith("!")) {
            force = true
            s = s.substring(1)
        }
        if (s.startsWith("@")) s = s.substring(1)   // '@' is optional in the allow UI

        val kind: RuleKind
        when {
            s.startsWith("*.") -> {
                kind = if (force) RuleKind.K_FORCE else RuleKind.K_WILDCARD_ONLY
                s = s.removePrefix("*.")
            }
            s.startsWith("=") -> {
                kind = RuleKind.K_EXACT
                s = s.removePrefix("=")
            }
            else -> kind = if (force) RuleKind.K_FORCE else RuleKind.K_SUFFIX
        }

        // Deliberately unsupported, and rejected with an explanation rather than
        // silently mis-handled: a suffix index cannot evaluate an infix or prefix
        // wildcard at all, and pretending otherwise produces a rule the user
        // believes is active and that never matches anything.
        if (s.contains('*')) {
            return Result.failure(
                BadPattern(
                    "Only a leading \"*.\" is supported. \"ads*\" and \"*ads.net\" cannot " +
                        "be evaluated by a suffix index; list the domains, or use a " +
                        "broader suffix."
                )
            )
        }

        val labels = s.split('.')
        if (labels.size < 2) return Result.failure(BadPattern("Needs at least two labels."))
        if (labels.any { !LABEL.matches(it) }) {
            return Result.failure(BadPattern("Not a valid domain label: \"$s\"."))
        }
        if (s.length > 253) return Result.failure(BadPattern("Too long."))

        return Result.success(Pattern(s, kind))
    }

    /**
     * Parses a blocklist pattern. Same grammar minus `@`; `!` still means
     * force-allow, because a user who types `!` in either box means the same
     * thing and refusing it there would be pedantry.
     */
    fun parseDeny(raw: String): Result<Pattern> = parseAllow(raw).map { p ->
        if (p.kind == RuleKind.K_FORCE && !raw.trim().startsWith("!")) {
            Pattern(p.domain, RuleKind.K_SUFFIX)
        } else {
            p
        }
    }

    /** `1.2.3.4 example.com`, or the bare domain with an address supplied. */
    fun parseRedirect(raw: String): Result<Redirect> {
        val parts = raw.trim().split(Regex("\\s+"))
        if (parts.size != 2) {
            return Result.failure(BadPattern("Expected \"<ip> <domain>\"."))
        }
        val (addr, dom) = parts
        if (!isIpLiteral(addr)) return Result.failure(BadPattern("\"$addr\" is not an IP address."))
        val pattern = parseAllow(dom).getOrElse { return Result.failure(it) }
        // The redirect table is keyed on the full-FQDN hash — there is no suffix
        // walk for redirects — so anything but an exact name would be a rule the
        // matcher can never hit.
        if (pattern.kind != RuleKind.K_SUFFIX && pattern.kind != RuleKind.K_EXACT) {
            return Result.failure(BadPattern("Redirects apply to one exact name; no wildcards."))
        }
        return Result.success(Redirect(pattern.domain, addr))
    }

    /**
     * Hand-rolled rather than `InetAddress.getByName()`: that method issues a DNS
     * query for anything it cannot parse as a literal, which would make a rule
     * parser hit the network — on the UI thread, in a text watcher, for every
     * keystroke.
     */
    private fun isIpLiteral(s: String): Boolean {
        if (s.isEmpty()) return false
        if (s.contains(':')) {
            return s.count { it == ':' } >= 2 &&
                s.all { it == ':' || it in '0'..'9' || it in "abcdefABCDEF" }
        }
        val parts = s.split('.')
        if (parts.size != 4) return false
        // '0'..'9', not Char.isDigit(): the latter is Unicode-aware and accepts
        // Arabic-Indic digits, which then make String.toInt() throw — out of a
        // parser whose callers wrap a whole file in one runCatching, so a single
        // odd line would silently discard every rule after it.
        return parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && p.toInt() in 0..255
        }
    }

    // ---- persistence --------------------------------------------------------
    //
    // Plain text under priv/, one rule per line, `#` comments preserved on read
    // and dropped on write. Text because the user can read it, `nrctl` can edit
    // it, and a corrupt line costs one rule instead of the whole file.

    fun readAllow(): List<Pattern> = readPatterns(Paths.allowTxt, ::parseAllow)

    fun readDeny(): List<Pattern> = readPatterns(Paths.denyTxt, ::parseDeny)

    fun readRedirects(): List<Redirect> {
        val file = Paths.redirectTxt
        if (!file.isFile) return emptyList()
        val out = ArrayList<Redirect>()
        runCatching {
            file.forEachLine { line ->
                if (line.isNotBlank() && !line.trimStart().startsWith("#")) {
                    parseRedirect(line).getOrNull()?.let { out += it }
                }
            }
        }
        return out
    }

    private fun readPatterns(
        file: File,
        parse: (String) -> Result<Pattern>,
    ): List<Pattern> {
        if (!file.isFile) return emptyList()
        val out = ArrayList<Pattern>()
        runCatching {
            file.forEachLine { line ->
                if (line.isNotBlank() && !line.trimStart().startsWith("#")) {
                    parse(line).getOrNull()?.let { out += it }
                }
            }
        }
        return out
    }

    // TODO(Phase 2): the Rules screen, add/remove, and the live "this pattern
    // matches N entries" preview (SPEC §6.2). The preview needs the front-coded
    // strings blob and two more JNI entry points (stringsRangeForSuffix /
    // forEachInRange); until those exist the honest thing is to have no Rules
    // screen rather than one that adds patterns whose effect it cannot show.
}
