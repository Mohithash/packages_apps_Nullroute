package com.bestrom.nullroute.importer

import android.content.Context
import android.net.Uri
import com.bestrom.nullroute.data.RuleStore
import com.bestrom.nullroute.importer.ImportModel.Collector
import com.bestrom.nullroute.importer.ImportModel.ImportOptions
import com.bestrom.nullroute.importer.ImportModel.Origin
import com.bestrom.nullroute.importer.ImportModel.OriginKind
import com.bestrom.nullroute.importer.ImportModel.Plan
import com.bestrom.nullroute.importer.ImportModel.RuleList
import com.bestrom.nullroute.importer.ImportModel.SkipReason
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream

/**
 * Imports an AdAway backup (`.json`), and **leaves AdAway alone**.
 *
 * Re-Malwack's equivalent refuses to run at all when AdAway is installed, and
 * shells out to a bundled per-ABI `jq` binary to read the file. Both of those go.
 * `org.json` is in the platform, and the abort was a symptom of the hosts-file
 * architecture rather than a safety measure: two apps cannot own
 * `/system/etc/hosts`, but Nullroute does not want it — it filters inside the
 * resolver, so AdAway, bindhosts, Blokada and RethinkDNS can all carry on doing
 * exactly what they were doing. Nothing in this file touches `PackageManager`,
 * another app's data, or another app's enabled state, and that is a structural
 * property rather than a promise.
 *
 * ## Why the parser is shape-tolerant rather than key-exact
 *
 * AdAway's backup schema has moved between 4.x, 5.x and the community forks, and
 * a key-exact reader that meets a schema it does not know imports **nothing** and
 * reports "0 rules found" — which reads to a user as "my backup is empty", the
 * least actionable failure available. So the whole document is walked instead,
 * host-shaped entries are recognised wherever they are, and the role (blocked /
 * allowed / redirected / subscription) comes from an entry's own `type` or
 * `redirection` field when it has one and from the enclosing key when it does not.
 *
 * The tolerance is bounded on the other side by [RuleStore]: every candidate has
 * to survive the same domain parser the rest of the app uses, so a walk that
 * strays into an array of timestamps or file paths contributes nothing but a skip
 * count. And the plan reports which JSON paths supplied how many entries, so "it
 * read the wrong part of the file" is visible *before* anything is written rather
 * than discovered afterwards.
 *
 * ## Semantics
 *
 * An AdAway blocked host is a `/system/etc/hosts` line, and a hosts line blocks
 * exactly that name. It therefore imports as [RuleStore.RuleKind.K_EXACT] unless
 * the user asks for [ImportOptions.broadenHostsToSubdomains] — see [ImportModel]
 * for why widening is never the silent default. AdAway's own `*.example.com`
 * entries import as `K_WILDCARD_ONLY` and, unlike in AdAway, are stored as a
 * pattern rather than expanded once against whatever the lists happened to
 * contain on the day.
 */
object AdAwayImporter {

    /**
     * Largest backup we will parse. `org.json` builds the entire tree in memory
     * and the platform has no streaming parser, so this is a real ceiling on peak
     * heap rather than a formality. A real AdAway backup is tens of kilobytes;
     * one with a hand-maintained list of everything is still under a megabyte.
     */
    const val MAX_JSON_BYTES = 16L shl 20

    /** Nesting a backup can never legitimately reach. Guards the recursive walk. */
    private const val MAX_DEPTH = 32

    /** Keys whose value is the host itself, in the order we prefer them. */
    private val HOST_KEYS = listOf("host", "hostname", "domain", "name", "value")

    /** Keys carrying the address a host is redirected to. */
    private val REDIRECT_KEYS = listOf("redirection", "redirect", "ip", "address", "target")

    /** Keys carrying a subscription address. */
    private val URL_KEYS = listOf("url", "uri", "link")

    /** Keys carrying a human label for a subscription. */
    private val LABEL_KEYS = listOf("label", "title", "name", "description")

    private enum class Role { BLOCK, ALLOW, REDIRECT, SOURCE, UNKNOWN }

    // ---- entry points -------------------------------------------------------

    /**
     * Reads a picked backup and reports what importing it would do. Blocking;
     * background thread only.
     *
     * Throws [IOException] when the document cannot be read or is not JSON at
     * all — and says which, because "use the hosts importer instead" is the right
     * advice for a plain hosts file and useless advice for a truncated backup.
     */
    @Throws(IOException::class)
    fun preview(
        context: Context,
        uri: Uri,
        options: ImportOptions = ImportOptions(),
    ): Plan {
        val meta = HostsImporter.describe(context, uri)
        if (meta.size > MAX_JSON_BYTES) {
            throw IOException(
                "${meta.name} is ${meta.size / (1L shl 20)} MB, far larger than any AdAway " +
                    "backup. If this is a hosts file, use \"Import a hosts or domain list\"."
            )
        }
        val stream = context.contentResolver.openInputStream(uri)
            ?: throw IOException("cannot open ${meta.name}")
        return previewText(context, stream.use { readBounded(it) }, meta.name, options)
    }

    /** The parsing half, separated so it is testable without a content provider. */
    @Throws(IOException::class)
    fun previewText(
        context: Context,
        text: String,
        displayName: String,
        options: ImportOptions = ImportOptions(),
    ): Plan {
        val trimmed = text.trimStart('\uFEFF', ' ', '\t', '\r', '\n')
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
            throw IOException(
                "$displayName is not an AdAway backup — it does not contain JSON. If it is a " +
                    "hosts file, use \"Import a hosts or domain list\"."
            )
        }

        val root: Any = try {
            if (trimmed.startsWith("[")) JSONArray(trimmed) else JSONObject(trimmed)
        } catch (t: Throwable) {
            // StackOverflowError included, on purpose: org.json parses recursively
            // and this input is a file the user picked from anywhere on the device.
            throw IOException("$displayName is not readable JSON (${t.javaClass.simpleName}).")
        }

        val collector = Collector(options)
        val walk = Walk(collector)
        walk.node(root, "", Role.UNKNOWN, 0)

        if (walk.consumed.isEmpty()) {
            collector.note(
                "No host entries were recognised anywhere in this file. It parses as JSON, " +
                    "but nothing in it looks like an AdAway host list."
            )
        } else {
            walk.consumed.forEach { (path, n) ->
                collector.note("Found $n entries under “$path”.")
            }
        }
        collector.note("AdAway itself is not modified, disabled, or even looked at.")

        return collector.build(context, Origin(OriginKind.ADAWAY, displayName))
    }

    // ---- the walk -----------------------------------------------------------

    private class Walk(private val collector: Collector) {

        /** JSON path -> entries taken from it. Surfaced so a mis-read is visible. */
        val consumed = LinkedHashMap<String, Int>()

        fun node(value: Any?, path: String, role: Role, depth: Int) {
            if (depth > MAX_DEPTH || value == null || value === JSONObject.NULL) return
            when (value) {
                is JSONArray -> {
                    for (i in 0 until value.length()) {
                        if (!collector.beginLine()) return
                        node(value.opt(i), path, role, depth + 1)
                    }
                }

                is JSONObject -> obj(value, path, role, depth)

                // A bare string only means something where the enclosing key
                // already said what it is. Guessing a direction for a loose
                // string is how an allowlist gets imported as a blocklist.
                is String -> if (role != Role.UNKNOWN) entry(value, null, role, path)

                else -> Unit  // numbers and booleans are never hosts
            }
        }

        private fun obj(o: JSONObject, path: String, role: Role, depth: Int) {
            // A subscription entry: recognised by carrying an address, whatever
            // key it was found under, because a source object usually also has a
            // `name` and would otherwise be read as a host called "AdAway".
            val url = URL_KEYS.firstNotNullOfOrNull { str(o, it) }
            if (url != null && url.startsWith("http")) {
                if (!o.has("enabled") || o.optBoolean("enabled", true)) {
                    val label = LABEL_KEYS.firstNotNullOfOrNull { str(o, it) }
                    collector.source(url, label ?: ImportModel.hostOf(url))
                    count(path)
                }
                return
            }

            // An object that *is* a host entry, rather than a container of them.
            val hostKey = HOST_KEYS.firstOrNull { str(o, it) != null }
            if (hostKey != null) {
                hostEntry(o, hostKey, path, role)
                return
            }

            val keys = o.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val childPath = if (path.isEmpty()) key else "$path.$key"
                node(o.opt(key), childPath, roleFor(key, role), depth + 1)
            }
        }

        /**
         * One host entry. Its own fields outrank the key it was found under: a
         * `redirection` value means redirect wherever the object happens to live,
         * and a *string* `type` is honoured because it is self-describing.
         *
         * A numeric `type` is deliberately **not** honoured. The integer-to-role
         * mapping differs between AdAway versions, and guessing it wrong turns
         * every block into an allow — the one import error that silently switches
         * filtering off for the domains the user cared most about.
         */
        private fun hostEntry(o: JSONObject, hostKey: String, path: String, role: Role) {
            if (o.has("enabled") && !o.optBoolean("enabled", true)) return
            val host = str(o, hostKey) ?: return

            val redirectTo = REDIRECT_KEYS.firstNotNullOfOrNull { str(o, it) }
            val typed = str(o, "type")?.let { roleForTypeName(it) }
            val effective = when {
                redirectTo != null -> Role.REDIRECT
                typed != null -> typed
                role != Role.UNKNOWN -> role
                // No direction from the entry and none from the key. Importing it
                // anyway would be a coin flip between blocking and allowing.
                else -> return
            }
            entry(host, redirectTo, effective, path)
        }

        private fun entry(raw: String, redirectTo: String?, role: Role, path: String) {
            val host = raw.trim()
            if (host.isEmpty()) return
            when (role) {
                Role.SOURCE -> {
                    if (!host.startsWith("http")) return
                    collector.source(host, ImportModel.hostOf(host))
                }

                Role.REDIRECT -> {
                    if (redirectTo.isNullOrBlank()) {
                        collector.skip(SkipReason.UNSUPPORTED_SYNTAX, 0, host, "no address given")
                        return
                    }
                    collector.mapping(redirectTo, host, 0, "$path: $redirectTo $host")
                }

                Role.ALLOW -> emit(host, RuleList.ALLOW, path)
                Role.BLOCK -> emit(host, RuleList.DENY, path)
                Role.UNKNOWN -> return
            }
            count(path)
        }

        /**
         * AdAway supports `*` and `?` in a host and expands them once against the
         * lists as they stand — the same decaying-allowlist bug Nullroute exists
         * to fix. A leading `*.` maps cleanly onto `K_WILDCARD_ONLY` and is stored
         * as a pattern; anything else is left to [RuleStore] to refuse, with its
         * reason shown to the user rather than swallowed.
         */
        private fun emit(host: String, list: RuleList, path: String) {
            if (host.startsWith("*.")) {
                collector.rule(host, RuleStore.RuleKind.K_WILDCARD_ONLY, list, 0, "$path: $host")
            } else {
                collector.bareName(
                    host, list, fromHostsLine = true, lineNo = 0, text = "$path: $host",
                )
            }
        }

        private fun count(path: String) {
            val key = path.ifEmpty { "(root)" }
            consumed[key] = (consumed[key] ?: 0) + 1
        }

        private fun roleFor(key: String, inherited: Role): Role {
            val k = key.lowercase()
            return when {
                k.contains("redirect") -> Role.REDIRECT
                k.contains("allow") || k.contains("white") || k.contains("except") -> Role.ALLOW
                k.contains("block") || k.contains("deny") || k.contains("black") -> Role.BLOCK
                k.contains("source") || k.contains("subscription") || k.contains("feed") -> Role.SOURCE
                else -> inherited
            }
        }

        private fun roleForTypeName(type: String): Role? {
            val t = type.lowercase()
            return when {
                t.contains("redirect") -> Role.REDIRECT
                t.contains("allow") || t.contains("white") -> Role.ALLOW
                t.contains("block") || t.contains("deny") || t.contains("black") -> Role.BLOCK
                else -> null
            }
        }

        /**
         * A present, non-null, non-blank string field, or null.
         *
         * The `isNull` check is load-bearing exactly as it is in
         * [com.bestrom.nullroute.core.Native]: `optString` on an explicit JSON
         * null returns the four-character String "null", which would otherwise
         * become a host named `null` in every entry that has an empty field.
         */
        private fun str(o: JSONObject, key: String): String? {
            if (!o.has(key) || o.isNull(key)) return null
            return o.optString(key).trim().ifEmpty { null }
        }
    }

    // ---- IO -----------------------------------------------------------------

    /**
     * Reads at most [MAX_JSON_BYTES] and refuses anything longer, rather than
     * trusting the size the document provider reported — that column is optional
     * in the provider contract, and a provider that omits it must not become a
     * way past the ceiling.
     */
    private fun readBounded(input: InputStream): String {
        val out = StringBuilder(16 * 1024)
        val reader = input.reader()
        val buf = CharArray(8192)
        var total = 0L
        var n = reader.read(buf)
        while (n > 0) {
            total += n
            if (total > MAX_JSON_BYTES) {
                throw IOException("file is larger than ${MAX_JSON_BYTES / (1L shl 20)} MB")
            }
            out.append(buf, 0, n)
            n = reader.read(buf)
        }
        return out.toString()
    }
}
