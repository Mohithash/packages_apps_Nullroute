package com.bestrom.nullroute.data

import android.util.Log
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
 *
 * Everything below follows from that one decision:
 *
 *  * There is **one** parser. Re-Malwack has three divergent regex builders for
 *    add / guard / remove, and they disagree; the resulting mis-handling is
 *    invisible until a domain the user allowed is blocked anyway. A single
 *    [parseAllow] means "add" and "remove" cannot disagree about what a rule is.
 *  * A refusal is a legitimate answer, with a reason the user can act on. A
 *    suffix index cannot evaluate `*ads.net`, so we say so instead of storing
 *    something that silently never matches.
 *  * Rules are **pinned**: the files live under `priv/` and are re-applied on
 *    every build, so they survive a profile switch, a list update and a reset.
 */
object RuleStore {

    private const val TAG = "Nullroute"

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

        /**
         * A hostname that this pattern must make PASS, for the canary to check.
         *
         * A `*.` rule says nothing about the apex, so probing the apex would fail
         * correctly and abort a perfectly good build; probe a subdomain instead.
         */
        fun canaryProbe(): String =
            if (kind == RuleKind.K_WILDCARD_ONLY) "canary.$domain" else domain
    }

    data class Redirect(val domain: String, val address: String) {
        fun toLine(): String = "$address $domain"
    }

    class BadPattern(message: String) : IllegalArgumentException(message)

    private val LABEL = Regex("^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")

    /**
     * Every syntax §7.5 defines, in one table, so the help text and the parser
     * cannot drift apart. Shown verbatim on the Rules screen.
     */
    val SYNTAX_HELP: List<Pair<String, String>> = listOf(
        "example.com" to "the domain and every subdomain",
        "*.example.com" to "subdomains only — not example.com itself",
        "=ads.example.com" to "that exact name and nothing else",
        "!example.com" to "always allow, beating any blocklist at any depth",
        "1.2.3.4 example.com" to "answer that name with an address of your choosing",
    )

    /**
     * Parses an allowlist pattern.
     *
     * Fails with a user-facing reason rather than guessing. The reasons are
     * deliberately specific — "Only a leading \"*.\" is supported" tells the user
     * what to type instead, where "invalid pattern" tells them to give up.
     */
    fun parseAllow(raw: String): Result<Pattern> {
        var s = raw.trim().lowercase().removeSuffix(".")
        if (s.isEmpty()) return Result.failure(BadPattern("Empty."))

        // A pasted hosts line is the single most common thing a user has to hand,
        // so accept it rather than making them edit it: "0.0.0.0 ads.example.com"
        // means ads.example.com in every list they have ever seen.
        val fields = s.split(Regex("\\s+"))
        if (fields.size >= 2 && isIpLiteral(fields[0])) s = fields[1]
        else if (fields.size >= 2) {
            return Result.failure(BadPattern("One rule per line, with no spaces."))
        }

        var force = false
        if (s.startsWith("!")) {
            force = true
            s = s.substring(1)
        }
        // ABP's exception marker is two '@', ours is one, and the two-character
        // form has to be tested first or "@@||d^" loses one '@' and then matches
        // neither branch.
        if (s.startsWith("@@")) s = s.substring(2)
        else if (s.startsWith("@")) s = s.substring(1)   // '@' is optional here

        if (s.startsWith("||")) {
            s = s.substring(2)
            val stop = s.indexOfFirst { it == '^' || it == '$' }
            if (stop >= 0) s = s.substring(0, stop)
        }

        val kind: RuleKind
        when {
            s.startsWith("*.") -> {
                kind = if (force) RuleKind.K_FORCE else RuleKind.K_WILDCARD_ONLY
                s = s.removePrefix("*.")
            }
            s.startsWith("=") -> {
                kind = if (force) RuleKind.K_FORCE else RuleKind.K_EXACT
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
        if (s.contains('/')) {
            return Result.failure(
                BadPattern(
                    "Rules match host names, not URLs or paths. Use just the host part."
                )
            )
        }

        if (s.length > 253) return Result.failure(BadPattern("Too long."))
        val labels = s.split('.')
        if (labels.size < 2) {
            return Result.failure(
                if (labels.size == 1 && labels[0].isNotEmpty()) {
                    BadPattern("\"$s\" is a single label. Rules need at least two, like \"$s.com\".")
                } else {
                    BadPattern("Needs at least two labels.")
                }
            )
        }
        if (isIpLiteral(s)) {
            return Result.failure(
                BadPattern("This filter matches names, not addresses. An IP cannot be a rule.")
            )
        }
        labels.firstOrNull { !LABEL.matches(it) }?.let { bad ->
            return Result.failure(
                if (bad.isEmpty()) BadPattern("Two dots in a row, or a leading dot.")
                else BadPattern("\"$bad\" is not a valid part of a domain name.")
            )
        }
        // A rule on a public suffix would take out every site under it. There is
        // no complete PSL on the device and shipping half of one would be worse
        // than none, so this catches only the shape people actually type by
        // accident: a second-level label under a two-letter country code, as in
        // "co.uk" or "com.br". Deliberately narrow — "com.com" and "co.com" are
        // ordinary registrable domains and rejecting them would be a bug.
        if (labels.size == 2 && labels[1].length == 2 && labels[0] in PSEUDO_SLDS) {
            return Result.failure(
                BadPattern("\"$s\" is a public suffix — a rule there would cover every site under it.")
            )
        }

        return Result.success(Pattern(s, kind))
    }

    private val PSEUDO_SLDS = setOf("co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go")

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
        // Deliberately not parseAllow(): that accepts a leading hosts-style
        // address and would swallow the one we just took off the front.
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
    // Plain text under priv/, one rule per line. Text because the user can read
    // it, `nrctl` can edit it, and a corrupt line costs one rule instead of the
    // whole file. Comments are preserved on read and rewritten on save, so a
    // user's own annotations survive an edit made from the UI.

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

    /**
     * Lines this file could not parse, so the Rules screen can show them instead
     * of dropping them. A rule the user wrote and we silently ignored is exactly
     * the Re-Malwack failure in a new costume.
     */
    fun unparsableAllowLines(): List<Pair<String, String>> =
        unparsable(Paths.allowTxt, ::parseAllow)

    private fun unparsable(
        file: File,
        parse: (String) -> Result<Pattern>,
    ): List<Pair<String, String>> {
        if (!file.isFile) return emptyList()
        val out = ArrayList<Pair<String, String>>()
        runCatching {
            file.forEachLine { line ->
                if (line.isBlank() || line.trimStart().startsWith("#")) return@forEachLine
                parse(line).onFailure { out += line.trim() to (it.message ?: "not understood") }
            }
        }
        return out
    }

    // ---- mutation -----------------------------------------------------------

    /**
     * Adds a pattern, returning false when it is already present.
     *
     * Rewrites the whole file rather than appending: an append can interleave
     * with a concurrent rewrite and produce a half-line, and this file is read by
     * the native builder as rules. Whole-file replacement through
     * [writeAtomically] means a reader sees the old set or the new one.
     */
    fun addAllow(pattern: Pattern): Boolean = addTo(Paths.allowTxt, ::parseAllow, pattern)

    fun addDeny(pattern: Pattern): Boolean = addTo(Paths.denyTxt, ::parseDeny, pattern)

    fun removeAllow(pattern: Pattern): Boolean = removeFrom(Paths.allowTxt, ::parseAllow, pattern)

    fun removeDeny(pattern: Pattern): Boolean = removeFrom(Paths.denyTxt, ::parseDeny, pattern)

    fun addRedirect(redirect: Redirect): Boolean {
        val existing = readRedirects()
        if (existing.any { it.domain == redirect.domain }) return false
        return writeAtomically(Paths.redirectTxt, HEADER_REDIRECT,
            (existing + redirect).map { it.toLine() })
    }

    fun removeRedirect(domain: String): Boolean {
        val existing = readRedirects()
        val kept = existing.filterNot { it.domain == domain }
        if (kept.size == existing.size) return false
        return writeAtomically(Paths.redirectTxt, HEADER_REDIRECT, kept.map { it.toLine() })
    }

    private fun addTo(
        file: File,
        parse: (String) -> Result<Pattern>,
        pattern: Pattern,
    ): Boolean {
        val existing = readPatterns(file, parse)
        if (existing.contains(pattern)) return false
        val all = existing + pattern
        return writeAtomically(file, headerFor(file), all.map { line(file, it) })
    }

    private fun removeFrom(
        file: File,
        parse: (String) -> Result<Pattern>,
        pattern: Pattern,
    ): Boolean {
        val existing = readPatterns(file, parse)
        val kept = existing.filterNot { it == pattern }
        if (kept.size == existing.size) return false
        return writeAtomically(file, headerFor(file), kept.map { line(file, it) })
    }

    private fun line(file: File, pattern: Pattern): String =
        if (file == Paths.denyTxt) pattern.toDenyLine() else pattern.toAllowLine()

    private fun headerFor(file: File): String =
        if (file == Paths.denyTxt) HEADER_DENY else HEADER_ALLOW

    private const val HEADER_ALLOW =
        "# Nullroute — your allow rules. Patterns, not expansions: a \"*.\" rule keeps\n" +
            "# working when the blocklists change. One rule per line; see nrctl rules --help."

    private const val HEADER_DENY =
        "# Nullroute — your block rules. These are pinned: they survive a profile\n" +
            "# switch, a list update and a reset."

    private const val HEADER_REDIRECT =
        "# Nullroute — your redirects, \"<ip> <name>\". Exact names only; the redirect\n" +
            "# table is keyed on the whole name and has no suffix walk."

    /**
     * `<file>.tmp` then `renameTo`. Not `File.writeText`: that truncates first,
     * so a crash mid-write leaves an empty rule file, and an empty allow file is
     * indistinguishable from "the user removed all their allow rules" — the
     * build after it would happily re-block everything they had exempted.
     */
    private fun writeAtomically(file: File, header: String, lines: List<String>): Boolean {
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
