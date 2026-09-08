package com.bestrom.nullroute.importer

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import com.bestrom.nullroute.importer.ImportModel.Collector
import com.bestrom.nullroute.importer.ImportModel.ImportOptions
import com.bestrom.nullroute.importer.ImportModel.Origin
import com.bestrom.nullroute.importer.ImportModel.OriginKind
import com.bestrom.nullroute.importer.ImportModel.Plan
import com.bestrom.nullroute.importer.ImportModel.RuleList
import java.io.IOException
import java.io.Reader

/**
 * Imports a **bindhosts** configuration directory.
 *
 * bindhosts keeps its state as a handful of flat text files — `blacklist.txt`,
 * `whitelist.txt`, `sources.txt`, `custom.txt` — plus the `hosts` file it
 * generates from them. Nullroute cannot read them where they live:
 * `/data/adb/bindhosts` is root-owned and SELinux-labelled for the module system,
 * and a privileged `system_ext` app has no business reaching in there even if it
 * could. So the user copies the directory somewhere they can pick it from and
 * chooses it with the folder picker; nothing here needs root and nothing here
 * touches bindhosts' own files.
 *
 * As with [AdAwayImporter], coexistence is the design. bindhosts goes on writing
 * `/system/etc/hosts` through its own mount; Nullroute filters inside the
 * resolver. Both work at once, and importing someone's rules is not a licence to
 * switch their module off.
 *
 * ## The trap this importer exists to avoid
 *
 * The directory holds the user's four **inputs** and bindhosts' one generated
 * **output** side by side. Importing `hosts` would drag a couple of hundred
 * thousand generated entries in as *personal rules* — re-read and re-merged on
 * every compile, unreadable by hand, and stale from the moment they land, because
 * the thing that keeps them fresh is the source URL and not the snapshot. So
 * `hosts` is recognised and deliberately declined, with `sources.txt` offered
 * instead: subscribing to the list is what the snapshot was standing in for.
 */
object BindhostsImporter {

    private const val TAG = "Nullroute"

    /** Children we will look at in one directory. A config dir has under a dozen. */
    private const val MAX_CHILDREN = 200

    /** What a member of the directory turned out to be. */
    private enum class Member {
        BLACKLIST, WHITELIST, SOURCES, CUSTOM,

        /** bindhosts' generated output. Recognised so it can be refused. */
        GENERATED_HOSTS,

        IGNORED,
    }

    // ---- entry points -------------------------------------------------------

    /**
     * Reads a picked directory (`ACTION_OPEN_DOCUMENT_TREE`) and reports what
     * importing it would do. Blocking; background thread only.
     */
    @Throws(IOException::class)
    fun previewTree(
        context: Context,
        treeUri: Uri,
        options: ImportOptions = ImportOptions(),
    ): Plan {
        val rootId = try {
            DocumentsContract.getTreeDocumentId(treeUri)
        } catch (t: Throwable) {
            throw IOException("That is not a folder. Pick the bindhosts folder itself.")
        }

        val collector = Collector(options)
        var read = 0
        var sawGenerated = false

        val children = listChildren(context, treeUri, rootId)

        // One level of descent, for the very common case of picking the parent of
        // the copied folder rather than the folder itself.
        val nested = children.firstOrNull {
            it.isDirectory && it.name.equals("bindhosts", ignoreCase = true)
        }
        val members = if (nested != null) listChildren(context, treeUri, nested.id) else children
        val where = nested?.name ?: displayNameOf(context, treeUri)

        for (child in members) {
            if (child.isDirectory) continue
            when (val kind = classify(child.name)) {
                Member.GENERATED_HOSTS -> sawGenerated = true
                Member.IGNORED -> Unit
                else -> if (feed(context, treeUri, child, kind, collector)) read++
            }
        }

        if (read == 0) {
            throw IOException(
                "No bindhosts files in that folder. Nullroute looks for blacklist.txt, " +
                    "whitelist.txt, sources.txt and custom.txt" +
                    (if (sawGenerated) ", and ignores the generated hosts file." else ".")
            )
        }
        if (sawGenerated) {
            collector.note(
                "The generated hosts file was ignored on purpose — it is bindhosts' output, " +
                    "not your rules. Import sources.txt to subscribe to the same lists instead."
            )
        }
        collector.note("bindhosts is not modified or disabled.")

        return collector.build(context, Origin(OriginKind.BINDHOSTS, where))
    }

    /**
     * Reads one picked bindhosts file, taking its role from its name.
     *
     * A name we do not recognise is not an error — it is handed to
     * [HostsImporter], which sniffs the content instead. Refusing a file because
     * it was renamed would be pedantry.
     */
    @Throws(IOException::class)
    fun previewFile(
        context: Context,
        uri: Uri,
        options: ImportOptions = ImportOptions(),
    ): Plan {
        val meta = HostsImporter.describe(context, uri)
        val kind = classify(meta.name)

        if (kind == Member.GENERATED_HOSTS) {
            throw IOException(
                "That is bindhosts' generated hosts file, not your rules — it holds every " +
                    "domain from every list it downloaded. Import sources.txt to subscribe to " +
                    "the same lists, or blacklist.txt for the entries you added yourself."
            )
        }
        if (kind == Member.IGNORED) {
            return HostsImporter.preview(context, uri, options)
        }
        if (meta.size > HostsImporter.MAX_BYTES) {
            throw IOException("${meta.name} is ${meta.size / (1L shl 20)} MB — too large to import.")
        }

        val collector = Collector(options)
        val stream = context.contentResolver.openInputStream(uri)
            ?: throw IOException("cannot open ${meta.name}")
        stream.use { consume(it.reader(), kind, collector) }
        collector.note("bindhosts is not modified or disabled.")
        return collector.build(context, Origin(OriginKind.BINDHOSTS, meta.name))
    }

    // ---- members ------------------------------------------------------------

    /**
     * bindhosts names its files plainly, and forks rename them slightly. Matching
     * on a contained word rather than an exact name costs nothing and survives
     * `blacklist`, `blacklist.txt` and `my-blacklist.txt` alike.
     */
    private fun classify(name: String): Member {
        val n = name.lowercase().substringBeforeLast('.')
        return when {
            n == "hosts" -> Member.GENERATED_HOSTS
            n.contains("blacklist") || n.contains("blocklist") -> Member.BLACKLIST
            n.contains("whitelist") || n.contains("allowlist") -> Member.WHITELIST
            n.contains("source") -> Member.SOURCES
            n.contains("custom") -> Member.CUSTOM
            else -> Member.IGNORED
        }
    }

    private fun feed(
        context: Context,
        treeUri: Uri,
        child: Child,
        kind: Member,
        collector: Collector,
    ): Boolean {
        if (child.size > HostsImporter.MAX_BYTES) {
            collector.note("${child.name} is too large to import and was skipped.")
            return false
        }
        val uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, child.id)
        return try {
            val stream = context.contentResolver.openInputStream(uri) ?: return false
            stream.use { consume(it.reader(), kind, collector) }
            true
        } catch (t: Throwable) {
            Log.w(TAG, "cannot read ${child.name}: ${t.message}")
            collector.note("${child.name} could not be read (${t.javaClass.simpleName}).")
            false
        }
    }

    /**
     * Feeds one member into the shared line engine.
     *
     * `blacklist.txt` and `custom.txt` are hosts-file semantics — bindhosts turns
     * both into `0.0.0.0 <name>` lines — so they import exactly, per [ImportModel].
     * `whitelist.txt` is fed as an allow list, where a bare name always means the
     * domain **and** its subdomains: an over-narrow allow is the one that leaves
     * an app broken.
     */
    private fun consume(reader: Reader, kind: Member, collector: Collector) {
        when (kind) {
            Member.SOURCES -> readSources(reader, collector)
            Member.WHITELIST -> HostsImporter.feed(collector, reader, RuleList.ALLOW)
            else -> HostsImporter.feed(collector, reader, RuleList.DENY)
        }
    }

    /** `sources.txt`: one URL per line, `#` comments, occasionally a trailing label. */
    private fun readSources(reader: Reader, collector: Collector) {
        HostsImporter.forEachBoundedLine(reader) { raw, overlong ->
            if (!collector.beginLine()) return@forEachBoundedLine false
            if (!overlong) {
                val line = raw.trim()
                if (line.isNotEmpty() && !line.startsWith("#")) {
                    val hash = line.indexOf('#')
                    val url = (if (hash >= 0) line.substring(0, hash) else line).trim()
                    val label = if (hash >= 0) line.substring(hash + 1).trim() else ""
                    collector.source(url, label)
                }
            }
            true
        }
    }

    // ---- SAF directory listing ----------------------------------------------

    private data class Child(
        val id: String,
        val name: String,
        val size: Long,
        val isDirectory: Boolean,
    )

    /**
     * Lists one directory with `DocumentsContract` directly.
     *
     * `androidx.documentfile` would be two lines shorter and is not among the
     * static libraries this app is allowed to link (see Android.bp), so the
     * framework API it wraps is used as-is. It is also the cheaper call: a
     * `DocumentFile.listFiles()` re-queries per child for every attribute.
     */
    private fun listChildren(context: Context, treeUri: Uri, parentId: String): List<Child> {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE,
        )
        val out = ArrayList<Child>()
        runCatching {
            context.contentResolver.query(childrenUri, projection, null, null, null)?.use { c ->
                while (c.moveToNext() && out.size < MAX_CHILDREN) {
                    val id = c.getString(0) ?: continue
                    val name = c.getString(1) ?: continue
                    val mime = if (c.isNull(2)) "" else c.getString(2)
                    val size = if (c.isNull(3)) 0L else c.getLong(3)
                    out += Child(id, name, size, mime == DocumentsContract.Document.MIME_TYPE_DIR)
                }
            }
        }.onFailure { Log.w(TAG, "cannot list $childrenUri: ${it.message}") }
        return out
    }

    private fun displayNameOf(context: Context, treeUri: Uri): String = runCatching {
        val docUri = DocumentsContract.buildDocumentUriUsingTree(
            treeUri, DocumentsContract.getTreeDocumentId(treeUri),
        )
        HostsImporter.describe(context, docUri).name
    }.getOrElse { treeUri.lastPathSegment ?: "folder" }
}
