package com.bestrom.nullroute.importer

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import com.bestrom.nullroute.data.RuleStore
import com.bestrom.nullroute.importer.ImportModel.Admissibility
import com.bestrom.nullroute.importer.ImportModel.Collector
import com.bestrom.nullroute.importer.ImportModel.ImportOptions
import com.bestrom.nullroute.importer.ImportModel.Origin
import com.bestrom.nullroute.importer.ImportModel.OriginKind
import com.bestrom.nullroute.importer.ImportModel.Plan
import com.bestrom.nullroute.importer.ImportModel.RuleList
import com.bestrom.nullroute.importer.ImportModel.SkipReason
import java.io.IOException
import java.io.InputStream
import java.io.Reader

/**
 * The generic text importer: hosts files, bare-domain lists, AdGuard/ABP filter
 * syntax and dnsmasq configuration, picked through the Storage Access Framework.
 *
 * It is also the line engine the other two importers reuse, so there is exactly
 * one place that decides what `||example.com^` means.
 *
 * ## Two things this parser refuses to guess
 *
 * **`!` is a comment, not a force-allow.** In every filter list in the wild a
 * leading `!` starts a comment, and that is what it means here. Nullroute's own
 * `!example.com` force-allow syntax is honoured in the app's rule boxes, in
 * `nrctl`, and by the settings-archive restore path — which reads rule files
 * verbatim rather than through this parser, precisely so the round trip is
 * lossless — but not in a third-party file, where reading `!` as a rule would
 * turn a list's own header into an instruction to stop blocking something.
 *
 * **A filter carrying a modifier is skipped, not approximated.**
 * `||ads.example^$third-party` and `||x^$domain=y.com` are decisions about a
 * *request in a page context*; a resolver sees neither the referrer nor the
 * resource type. Importing them as plain blocks would over-block, so they are
 * counted under [SkipReason.FILTER_MODIFIER] and shown with a reason.
 *
 * Element-hiding rules (`example.com##.ad`), regex rules and address-anchored
 * rules (`|http://…`) are skipped on the same grounds: a DNS blocker cannot
 * express them, and pretending otherwise is worse than admitting it.
 */
object HostsImporter {

    private const val TAG = "Nullroute"

    /**
     * Largest document we will read. Comfortably above every published blocklist
     * (HaGeZi Ultimate is 5.2 MB) and small enough that a wrong pick — a video, a
     * disk image — is refused instead of streamed for a minute.
     */
    const val MAX_BYTES = 64L shl 20

    /**
     * Longest single line. A hosts line with a dozen aliases is under 400 bytes;
     * past this it is a file with no newlines in it, and reading it whole would
     * build a multi-megabyte `String` out of untrusted input.
     */
    private const val MAX_LINE_CHARS = 4096

    /** UTF-8 byte-order mark, as it arrives after decoding. */
    private const val BOM = "\uFEFF"

    /** Modifiers that do not change what a *name-level* block means. */
    private val DNS_SAFE_MODIFIERS = setOf("important", "all", "document", "popup", "badfilter")

    /** What the file turned out to be. Reported so a mis-picked file is obvious. */
    enum class Shape(val label: String) {
        HOSTS("hosts file"),
        DOMAINS("domain list"),
        ABP("filter list"),
        DNSMASQ("dnsmasq configuration"),
        MIXED("mixed formats"),
        EMPTY("nothing recognisable"),
    }

    // ---- SAF entry point ----------------------------------------------------

    /**
     * Reads a picked document and reports what importing it would do.
     *
     * Blocking; background thread only. Throws [IOException] only when the
     * document cannot be read at all — a file full of syntax we do not support is
     * a valid, nearly empty plan with the reasons attached, not an exception.
     */
    @Throws(IOException::class)
    fun preview(
        context: Context,
        uri: Uri,
        options: ImportOptions = ImportOptions(),
        defaultList: RuleList = RuleList.DENY,
    ): Plan {
        val meta = describe(context, uri)
        if (meta.size > MAX_BYTES) {
            throw IOException(
                "${meta.name} is ${meta.size / (1L shl 20)} MB. Nullroute reads files up to " +
                    "${MAX_BYTES / (1L shl 20)} MB as personal rules; a list that big belongs " +
                    "in your profile as a subscription."
            )
        }
        val stream = context.contentResolver.openInputStream(uri)
            ?: throw IOException("cannot open ${meta.name}")
        val collector = Collector(options)
        val shape = stream.use { feed(collector, it.reader(), defaultList) }
        collector.note("Read as a ${shape.label}.")
        return collector.build(context, Origin(OriginKind.HOSTS_FILE, meta.name))
    }

    /** Convenience for callers that already hold a stream. */
    fun previewStream(
        context: Context,
        input: InputStream,
        displayName: String,
        options: ImportOptions = ImportOptions(),
        defaultList: RuleList = RuleList.DENY,
    ): Plan {
        val collector = Collector(options)
        val shape = input.use { feed(collector, it.reader(), defaultList) }
        collector.note("Read as a ${shape.label}.")
        return collector.build(context, Origin(OriginKind.HOSTS_FILE, displayName))
    }

    // ---- the line engine ----------------------------------------------------

    /**
     * Pushes every line of [reader] into [collector]. Closes nothing — the caller
     * owns the stream, because [BindhostsImporter] feeds several members of one
     * directory into a single collector.
     *
     * [defaultList] decides where a bare domain lands: a `blacklist.txt` is fed
     * with `DENY`, a `whitelist.txt` with `ALLOW`. Explicit syntax in the line
     * always overrides it.
     */
    fun feed(collector: Collector, reader: Reader, defaultList: RuleList): Shape {
        val tally = LinkedHashMap<Shape, Int>()
        var lineNo = 0

        forEachBoundedLine(reader) { raw, overlong ->
            if (!collector.beginLine()) return@forEachBoundedLine false
            lineNo++
            if (overlong) {
                collector.skip(
                    SkipReason.UNSUPPORTED_SYNTAX, lineNo,
                    "(line longer than $MAX_LINE_CHARS characters)",
                )
                return@forEachBoundedLine true
            }
            parseLine(collector, raw, defaultList, lineNo)?.let { shape ->
                tally[shape] = (tally[shape] ?: 0) + 1
            }
            true
        }

        if (tally.isEmpty()) return Shape.EMPTY
        val total = tally.values.sum()
        val top = tally.maxByOrNull { it.value } ?: return Shape.EMPTY
        // "Mixed" is a real and useful answer. A hosts file with a handful of ABP
        // lines in it is usually something someone concatenated by hand, and
        // saying so is more helpful than picking the majority and staying quiet.
        return if (top.value * 10 >= total * 9) top.key else Shape.MIXED
    }

    /**
     * Parses one line, returning the shape it looked like, or null when the line
     * carried no rule at all — blank, comment, header, or skipped with a reason.
     */
    private fun parseLine(
        collector: Collector,
        raw: String,
        defaultList: RuleList,
        lineNo: Int,
    ): Shape? {
        // A UTF-8 BOM on line 1 arrives here as U+FEFF and would otherwise make
        // the first entry of every Windows-authored list an unparseable domain.
        val line = raw.removePrefix(BOM).trim()
        if (line.isEmpty()) return null
        if (line.startsWith("#") || line.startsWith(";")) return null
        if (line.startsWith("!") || line.startsWith("[")) return null   // ABP comment / header

        // ---- AdGuard / ABP --------------------------------------------------
        // The cosmetic markers are recognised only on a line with no spaces in
        // it. `example.com##.ad` never has one; `0.0.0.0 ads.example.com ## note`
        // is a hosts line with a comment, and routing that into the filter parser
        // would drop a perfectly good entry as "cosmetic".
        val cosmetic = !line.contains(' ') &&
            (line.contains("##") || line.contains("#@#") || line.contains("#?#"))
        if (line.startsWith("@@") || line.startsWith("|") || cosmetic) {
            parseAbp(collector, line, lineNo)
            return Shape.ABP
        }

        // ---- dnsmasq ---------------------------------------------------------
        if (line.startsWith("address=/") || line.startsWith("server=/") ||
            line.startsWith("local=/")
        ) {
            parseDnsmasq(collector, line, lineNo)
            return Shape.DNSMASQ
        }

        // ---- Nullroute's own syntax, so an exported rule file round-trips ----
        // Before the hosts branch because none of these can start with an IP
        // literal, and after ABP because `@@` is two of them.
        if (line.startsWith("@")) {
            val token = line.substring(1)
            collector.rule(token, kindOf(token), RuleList.ALLOW, lineNo, line)
            return Shape.DOMAINS
        }
        if (line.startsWith("*.") || line.startsWith("=")) {
            collector.rule(line, kindOf(line), RuleList.DENY, lineNo, line)
            return Shape.DOMAINS
        }

        // ---- hosts / plain domain -------------------------------------------
        val body = line.substringBefore('#').trim()
        val fields = body.split(' ', '\t').filter { it.isNotEmpty() }
        if (fields.isEmpty()) return null

        if (fields.size == 1) {
            val token = fields[0]
            // An address alone on a line is the tail of a wrapped hosts entry or
            // a stray; either way it is not a name.
            if (Admissibility.isIpLiteral(token)) {
                collector.skip(SkipReason.IP_LITERAL, lineNo, line)
                return null
            }
            collector.bareName(token, defaultList, fromHostsLine = false, lineNo = lineNo, text = line)
            return Shape.DOMAINS
        }

        val address = fields[0]
        if (!Admissibility.isIpLiteral(address)) {
            // Several names separated by spaces and no address: not a hosts line,
            // not a domain list, and guessing which name was meant is exactly the
            // silent mis-import this parser exists to avoid.
            collector.skip(SkipReason.UNSUPPORTED_SYNTAX, lineNo, line)
            return null
        }
        for (i in 1 until fields.size) {
            collector.mapping(address, fields[i], lineNo, line)
        }
        return Shape.HOSTS
    }

    private fun parseAbp(collector: Collector, line: String, lineNo: Int) {
        if (line.contains("##") || line.contains("#@#") || line.contains("#?#")) {
            collector.skip(
                SkipReason.UNSUPPORTED_SYNTAX, lineNo, line,
                "a cosmetic rule — it hides page elements, which DNS cannot do",
            )
            return
        }

        val allow = line.startsWith("@@")
        var body = if (allow) line.substring(2) else line

        val dollar = body.indexOf('$')
        if (dollar >= 0) {
            val modifiers = body.substring(dollar + 1)
                .split(',')
                .map { it.trim().substringBefore('=').removePrefix("~").lowercase() }
                .filter { it.isNotEmpty() }
            val offender = modifiers.firstOrNull { it !in DNS_SAFE_MODIFIERS }
            if (offender != null) {
                collector.skip(
                    SkipReason.FILTER_MODIFIER, lineNo, line,
                    "\$$offender depends on page context, which a resolver never sees",
                )
                return
            }
            body = body.substring(0, dollar)
        }

        if (!body.startsWith("||")) {
            // `|http://x`, `/regex/`, plain substring rules. All of them match on
            // a URL, and a resolver only ever sees a name.
            collector.skip(
                SkipReason.UNSUPPORTED_SYNTAX, lineNo, line,
                "matches on a URL, not on a hostname",
            )
            return
        }
        body = body.removePrefix("||").trimEnd('^', '|', '/')

        if (body.isEmpty() || body.contains('/') || body.contains('*') || body.contains('|')) {
            collector.skip(SkipReason.UNSUPPORTED_SYNTAX, lineNo, line, "not a plain hostname")
            return
        }

        // `||example.com^` is "this domain and everything under it" — exactly
        // K_SUFFIX, and in both directions.
        collector.rule(
            body,
            RuleStore.RuleKind.K_SUFFIX,
            if (allow) RuleList.ALLOW else RuleList.DENY,
            lineNo,
            line,
        )
    }

    /**
     * `address=/a.com/b.com/0.0.0.0`, `server=/a.com/`, `server=/a.com/#`.
     *
     * dnsmasq's semantics here are suffix semantics — `address=/example.com/`
     * covers every subdomain too — so these are `K_SUFFIX` regardless of the
     * hosts-format exactness rule that applies elsewhere in this file.
     */
    private fun parseDnsmasq(collector: Collector, line: String, lineNo: Int) {
        val parts = line.substringAfter('=').trim().split('/').filter { it.isNotEmpty() }
        if (parts.isEmpty()) {
            collector.skip(SkipReason.UNSUPPORTED_SYNTAX, lineNo, line)
            return
        }

        val last = parts.last()
        val hasTail = last == "#" || Admissibility.isIpLiteral(last)
        val names = if (hasTail) parts.dropLast(1) else parts
        if (names.isEmpty()) {
            collector.skip(SkipReason.UNSUPPORTED_SYNTAX, lineNo, line)
            return
        }

        for (name in names) {
            when {
                // `/#` is dnsmasq for "use the normal upstream servers for this
                // domain" — an explicit carve-out, so it imports as an allow. A
                // sinkhole address, or no address at all, is a block.
                last == "#" && hasTail ->
                    collector.rule(name, RuleStore.RuleKind.K_SUFFIX, RuleList.ALLOW, lineNo, line)

                hasTail && !Admissibility.isSinkhole(last) ->
                    collector.mapping(last, name, lineNo, line)

                else ->
                    collector.rule(name, RuleStore.RuleKind.K_SUFFIX, RuleList.DENY, lineNo, line)
            }
        }
    }

    /**
     * The kind a Nullroute-syntax token states about itself. `!` is absent on
     * purpose — it never reaches here, because a leading `!` is a comment in an
     * imported file. See the class comment.
     */
    private fun kindOf(token: String): RuleStore.RuleKind = when {
        token.startsWith("*.") -> RuleStore.RuleKind.K_WILDCARD_ONLY
        token.startsWith("=") -> RuleStore.RuleKind.K_EXACT
        else -> RuleStore.RuleKind.K_SUFFIX
    }

    // ---- bounded reading ----------------------------------------------------

    /**
     * `BufferedReader.readLine()` with a length bound.
     *
     * The stock reader will happily build a single `String` the size of the whole
     * document when the document has no newlines in it, and this parser's input
     * is a file the user picked from anywhere on the device. Overlong lines reach
     * [body] with `overlong = true` and their content discarded rather than
     * buffered. [body] returns false to stop reading.
     *
     * Shared with [BindhostsImporter], which reads `sources.txt` off the same
     * untrusted picker and has no more right than this to assume a file the user
     * chose has newlines in it.
     */
    internal fun forEachBoundedLine(reader: Reader, body: (String, Boolean) -> Boolean) {
        val buf = CharArray(8192)
        val sb = StringBuilder(256)
        var overlong = false
        var n = reader.read(buf)
        while (n > 0) {
            for (i in 0 until n) {
                val c = buf[i]
                if (c == '\n') {
                    if (!body(sb.toString(), overlong)) return
                    sb.setLength(0)
                    overlong = false
                } else if (c != '\r') {
                    if (sb.length < MAX_LINE_CHARS) sb.append(c) else overlong = true
                }
            }
            n = reader.read(buf)
        }
        if (sb.isNotEmpty() || overlong) body(sb.toString(), overlong)
    }

    // ---- SAF metadata -------------------------------------------------------

    data class DocumentInfo(val name: String, val size: Long)

    /**
     * Display name and size of a picked document.
     *
     * Both columns are optional in the `DocumentsProvider` contract, so a missing
     * size is reported as 0: "unknown" must not become "too big", or a perfectly
     * good file from a provider that does not report sizes becomes unimportable.
     */
    fun describe(context: Context, uri: Uri): DocumentInfo {
        val projection = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        var name = uri.lastPathSegment ?: "document"
        var size = 0L
        runCatching {
            context.contentResolver.query(uri, projection, null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val nameCol = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameCol >= 0 && !c.isNull(nameCol)) name = c.getString(nameCol)
                    val sizeCol = c.getColumnIndex(OpenableColumns.SIZE)
                    if (sizeCol >= 0 && !c.isNull(sizeCol)) size = c.getLong(sizeCol)
                }
            }
        }.onFailure { Log.w(TAG, "cannot describe $uri: ${it.message}") }
        return DocumentInfo(name, size)
    }
}
