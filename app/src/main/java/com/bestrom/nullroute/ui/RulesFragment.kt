package com.bestrom.nullroute.ui

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.data.RuleStore
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

/**
 * Allow / block / redirect rules, with the effect of a pattern shown **before**
 * it is committed.
 *
 * ## The live count is the point of the screen
 *
 * §6.2's correction to Re-Malwack is that a wildcard rule is stored as a pattern
 * instead of being expanded against the blocklist as it stands at that instant.
 * That is strictly better — the rule cannot decay when upstream adds domains —
 * but it costs the user the one thing expansion gave them: they could see what
 * they had just done. Nothing in the index can give it back, because the index
 * stores 46-bit fingerprints and not text.
 *
 * So the count comes from the strings sidecar, through
 * [Native.stringsPreview], and it is shown between the input and the Add button:
 * the number is what the user is deciding on, so it belongs before the commit,
 * not in a toast afterwards. [Native.RulePreview.matchedFor] gives the count for
 * *this rule kind* rather than one total, because `*.example.com` deliberately
 * does not cover the apex and a single number would claim credit for a rule the
 * matcher will never apply.
 *
 * ## A refusal is an answer
 *
 * [RuleStore.parseAllow] rejects `ads*` and `*ads.net` because a suffix index
 * cannot evaluate an infix or prefix wildcard *at all*. The reason it returns
 * says what to type instead, and it is shown verbatim in the field error. The
 * failure mode this replaces is not a crash — it is a rule that is accepted,
 * stored, and never matches anything, which the user only discovers by noticing
 * that a site they allowed is still blocked.
 *
 * For the same reason the lines `allow.txt` could not parse are listed on this
 * screen rather than dropped on read: a rule the user wrote and we silently
 * ignored is the Re-Malwack failure in a new costume.
 */
class RulesFragment : Fragment() {

    private enum class Tab { ALLOW, DENY, REDIRECT }

    private val main = Handler(Looper.getMainLooper())

    private lateinit var tabs: MaterialButtonToggleGroup
    private lateinit var inputLayout: TextInputLayout
    private lateinit var input: TextInputEditText
    private lateinit var preview: TextView
    private lateinit var previewDetail: TextView
    private lateinit var addButton: MaterialButton
    private lateinit var showMatches: MaterialButton
    private lateinit var list: RecyclerView

    private val items = ArrayList<Item>()
    private val adapter = ItemAdapter(items) { pattern, redirect -> remove(pattern, redirect) }

    private var tab = Tab.ALLOW

    /**
     * Path to the strings sidecar for the generation currently on disk, or null.
     * Resolved once per resume off the main thread: it is two file reads and a
     * header validation, and it changes only when an index is promoted.
     */
    @Volatile
    private var stringsPath: String? = null

    /** Last pattern that parsed, or null when the field is empty or refused. */
    private var parsedPattern: RuleStore.Pattern? = null
    private var parsedRedirect: RuleStore.Redirect? = null

    /**
     * Monotonic id of the newest preview request. A background result whose id
     * is stale is dropped rather than rendered: the user has typed since, and a
     * count for a pattern that is no longer in the field is worse than none.
     */
    private var previewSeq = 0

    private val debounce = Runnable { parseAndPreview() }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_rules, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        tabs = view.findViewById(R.id.rules_tabs)
        inputLayout = view.findViewById(R.id.rules_input_layout)
        input = view.findViewById(R.id.rules_input)
        preview = view.findViewById(R.id.rules_preview)
        previewDetail = view.findViewById(R.id.rules_preview_detail)
        addButton = view.findViewById(R.id.rules_add)
        showMatches = view.findViewById(R.id.rules_show_matches)
        list = view.findViewById(R.id.rules_list)

        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter

        tabs.check(R.id.rules_tab_allow)
        tabs.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            tab = when (checkedId) {
                R.id.rules_tab_deny -> Tab.DENY
                R.id.rules_tab_redirect -> Tab.REDIRECT
                else -> Tab.ALLOW
            }
            inputLayout.hint = getString(
                when (tab) {
                    Tab.ALLOW -> R.string.rules_input_allow
                    Tab.DENY -> R.string.rules_input_deny
                    Tab.REDIRECT -> R.string.rules_input_redirect
                }
            )
            parseAndPreview()
            reload()
        }

        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                // Parsing is cheap and deliberately network-free (see
                // RuleStore.isIpLiteral), but the preview is a mapping plus a
                // binary search, so both are debounced together to keep the
                // count and the error from disagreeing mid-keystroke.
                main.removeCallbacks(debounce)
                main.postDelayed(debounce, DEBOUNCE_MS)
            }
        })

        addButton.setOnClickListener { add() }
        showMatches.setOnClickListener { showMatchedRules() }
    }

    override fun onResume() {
        super.onResume()
        resolveStringsPath()
        reload()
    }

    override fun onDestroyView() {
        main.removeCallbacks(debounce)
        super.onDestroyView()
    }

    // ---- the live preview ---------------------------------------------------

    private fun resolveStringsPath() {
        NullrouteApp.io.execute {
            val info = Native.verify(Paths.currentIndex.absolutePath)
            val path = if (info.ok && info.generation > 0) {
                Native.stringsPathFor(info.generation)
            } else {
                null
            }
            stringsPath = path
            main.post { if (isAdded) parseAndPreview() }
        }
    }

    private fun parseAndPreview() {
        if (!isAdded) return
        val raw = input.text?.toString().orEmpty()
        parsedPattern = null
        parsedRedirect = null
        showMatches.visibility = View.GONE
        previewDetail.visibility = View.GONE

        if (raw.isBlank()) {
            inputLayout.error = null
            preview.text = ""
            addButton.isEnabled = false
            return
        }

        if (tab == Tab.REDIRECT) {
            val result = RuleStore.parseRedirect(raw)
            val redirect = result.getOrElse { failure ->
                showRefusal(failure)
                return
            }
            inputLayout.error = null
            parsedRedirect = redirect
            addButton.isEnabled = true
            // A redirect is keyed on the whole name — there is no suffix walk for
            // the redirect table — so the count that matters is the EXACT one.
            requestPreview(redirect.domain, RuleStore.RuleKind.K_EXACT,
                "${redirect.address} answers ${redirect.domain}")
            return
        }

        val parse = if (tab == Tab.ALLOW) RuleStore.parseAllow(raw) else RuleStore.parseDeny(raw)
        val pattern = parse.getOrElse { failure ->
            showRefusal(failure)
            return
        }
        inputLayout.error = null
        parsedPattern = pattern
        addButton.isEnabled = true
        requestPreview(pattern.domain, pattern.kind, pattern.describe())
    }

    /**
     * The reason, verbatim, in the field. Not a Toast and not "invalid pattern":
     * the messages [RuleStore] returns name the specific thing that cannot work
     * and what to type instead, and paraphrasing them here would throw that away.
     */
    private fun showRefusal(failure: Throwable) {
        inputLayout.error = failure.message ?: getString(R.string.rules_write_failed)
        preview.text = ""
        addButton.isEnabled = false
    }

    private fun requestPreview(domain: String, kind: RuleStore.RuleKind, describe: String) {
        val path = stringsPath
        if (path == null) {
            preview.setText(R.string.rules_preview_unavailable)
            return
        }
        val seq = ++previewSeq
        preview.setText(R.string.rules_preview_checking)
        NullrouteApp.io.execute {
            val result = Native.stringsPreview(path, domain)
            main.post {
                // A result for a pattern the user has already typed past is
                // dropped: showing it would attach a count to the wrong rule.
                if (!isAdded || seq != previewSeq) return@post
                renderPreview(result, kind, describe)
            }
        }
    }

    private fun renderPreview(
        result: Native.RulePreview,
        kind: RuleStore.RuleKind,
        describe: String,
    ) {
        if (!result.ok) {
            preview.setText(R.string.rules_preview_unavailable)
            previewDetail.visibility = View.GONE
            showMatches.visibility = View.GONE
            return
        }

        val matched = result.matchedFor(kind.wire)
        preview.text = when {
            matched == 0 -> getString(R.string.rules_preview_none, describe)
            // The native walk stops at a budget so that a base like "com" cannot
            // stall the UI thread. When it did, the number is a floor and has to
            // be presented as one — a truncated count shown as exact is the same
            // class of lie as a status card that reports health it never
            // measured.
            result.truncated -> getString(R.string.rules_preview_matches_at_least, matched, describe)
            else -> getString(R.string.rules_preview_matches, matched, describe)
        }

        if (matched > 0) {
            previewDetail.visibility = View.VISIBLE
            previewDetail.text = getString(
                R.string.rules_preview_breakdown,
                result.blocks, result.allows, result.corpus,
            )
            showMatches.visibility = View.VISIBLE
        } else {
            previewDetail.visibility = View.GONE
            showMatches.visibility = View.GONE
        }
    }

    /** The rules themselves, so the count above can be checked rather than believed. */
    private fun showMatchedRules() {
        val path = stringsPath ?: return
        val base = parsedPattern?.domain ?: parsedRedirect?.domain ?: return
        NullrouteApp.io.execute {
            val listing = Native.stringsList(path, base, DIALOG_ROWS)
            main.post {
                if (!isAdded) return@post
                if (!listing.ok) {
                    toast(getString(R.string.rules_preview_unavailable))
                    return@post
                }
                val body = StringBuilder()
                for (row in listing.rules) {
                    val source = row.groupName.ifEmpty { "" }
                    body.append(row.rule).append('\n').append("    ")
                    body.append(
                        when {
                            source.isEmpty() -> getString(R.string.rules_matched_row_unknown)
                            row.allow -> getString(R.string.rules_matched_row_allow, source)
                            else -> getString(R.string.rules_matched_row_block, source)
                        }
                    )
                    body.append('\n')
                }
                if (listing.truncated) {
                    body.append('\n').append(
                        getString(R.string.rules_matched_more, listing.range - listing.rules.size)
                    )
                }
                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.rules_matched_title)
                    .setMessage(body.toString())
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
        }
    }

    // ---- mutation -----------------------------------------------------------

    private fun add() {
        val redirect = parsedRedirect
        val pattern = parsedPattern
        NullrouteApp.io.execute {
            val added = when {
                redirect != null -> RuleStore.addRedirect(redirect)
                pattern != null && tab == Tab.ALLOW -> RuleStore.addAllow(pattern)
                pattern != null -> RuleStore.addDeny(pattern)
                else -> false
            }
            // addX() returns false for BOTH "already present" and "the write
            // failed", and those need different words: one is a no-op the user
            // should shrug at, the other means the rule is not saved at all.
            val present = when {
                redirect != null -> RuleStore.readRedirects().any { it.domain == redirect.domain }
                pattern != null && tab == Tab.ALLOW -> RuleStore.readAllow().contains(pattern)
                pattern != null -> RuleStore.readDeny().contains(pattern)
                else -> false
            }
            main.post {
                if (!isAdded) return@post
                when {
                    added -> {
                        input.setText("")
                        toast(getString(R.string.rules_added))
                    }
                    present -> toast(getString(R.string.rules_duplicate))
                    else -> toast(getString(R.string.rules_write_failed))
                }
                reload()
            }
        }
    }

    private fun remove(pattern: RuleStore.Pattern?, redirect: RuleStore.Redirect?) {
        NullrouteApp.io.execute {
            val ok = when {
                redirect != null -> RuleStore.removeRedirect(redirect.domain)
                pattern != null && tab == Tab.ALLOW -> RuleStore.removeAllow(pattern)
                pattern != null -> RuleStore.removeDeny(pattern)
                else -> false
            }
            main.post {
                if (!isAdded) return@post
                toast(getString(if (ok) R.string.rules_removed else R.string.rules_write_failed))
                reload()
            }
        }
    }

    // ---- the list -----------------------------------------------------------

    private fun reload() {
        val current = tab
        // The context is captured here, on the main thread. requireContext() from
        // the executor throws once the fragment detaches, and a background read
        // that outlives the screen is the normal case, not the rare one.
        val context = requireContext().applicationContext
        NullrouteApp.io.execute {
            val built = buildItems(context, current)
            main.post {
                if (!isAdded || tab != current) return@post
                items.clear()
                items.addAll(built)
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun buildItems(context: Context, forTab: Tab): List<Item> {
        val out = ArrayList<Item>()
        when (forTab) {
            Tab.ALLOW -> {
                val rules = RuleStore.readAllow()
                if (rules.isEmpty()) {
                    out += Item.Note(context.getString(R.string.rules_empty_allow), "")
                }
                rules.forEach { out += Item.Rule(it.toAllowLine(), it.describe(), it, null) }

                // Only allow.txt exposes its unreadable lines today; that is the
                // file users hand-edit and the one whose silent drops matter most.
                val bad = RuleStore.unparsableAllowLines()
                if (bad.isNotEmpty()) {
                    out += Item.Header(context.getString(R.string.rules_unparsable_header))
                    out += Item.Note(context.getString(R.string.rules_unparsable_note), "")
                    bad.forEach { (line, reason) -> out += Item.Note(line, reason) }
                }
            }

            Tab.DENY -> {
                val rules = RuleStore.readDeny()
                if (rules.isEmpty()) {
                    out += Item.Note(context.getString(R.string.rules_empty_deny), "")
                }
                rules.forEach { out += Item.Rule(it.toDenyLine(), it.describe(), it, null) }
            }

            Tab.REDIRECT -> {
                val rules = RuleStore.readRedirects()
                if (rules.isEmpty()) {
                    out += Item.Note(context.getString(R.string.rules_empty_redirect), "")
                }
                rules.forEach { out += Item.Rule(it.toLine(), it.domain, null, it) }
            }
        }

        // The syntax table comes straight from RuleStore.SYNTAX_HELP so the help
        // and the parser cannot drift apart — a help text that documents a form
        // the parser rejects is worse than no help text.
        out += Item.Header(context.getString(R.string.rules_syntax_header))
        RuleStore.SYNTAX_HELP.forEach { (form, meaning) -> out += Item.Note(form, meaning) }
        return out
    }

    private fun toast(text: String) {
        Toast.makeText(requireContext(), text, Toast.LENGTH_SHORT).show()
    }

    // ---- adapter ------------------------------------------------------------

    private sealed class Item {
        /**
         * [display] is rendered rather than derived in the holder: the same
         * pattern is written `@example.com` in the allow file and `example.com`
         * in the deny file, and only the caller knows which list this row is in.
         * A holder that guessed would show every block rule with an `@` on it.
         */
        data class Rule(
            val display: String,
            val describe: String,
            val pattern: RuleStore.Pattern?,
            val redirect: RuleStore.Redirect?,
        ) : Item()

        data class Header(val text: String) : Item()
        data class Note(val title: String, val detail: String) : Item()
    }

    private class ItemAdapter(
        private val items: List<Item>,
        private val onRemove: (RuleStore.Pattern?, RuleStore.Redirect?) -> Unit,
    ) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

        class RuleHolder(view: View) : RecyclerView.ViewHolder(view) {
            val pattern: TextView = view.findViewById(R.id.rule_pattern)
            val describe: TextView = view.findViewById(R.id.rule_describe)
            val remove: MaterialButton = view.findViewById(R.id.rule_remove)
        }

        class HeaderHolder(view: View) : RecyclerView.ViewHolder(view) {
            val text: TextView = view.findViewById(R.id.ui2_header_text)
        }

        class NoteHolder(view: View) : RecyclerView.ViewHolder(view) {
            val title: TextView = view.findViewById(R.id.ui2_note_title)
            val detail: TextView = view.findViewById(R.id.ui2_note_detail)
        }

        override fun getItemCount(): Int = items.size

        override fun getItemViewType(position: Int): Int = when (items[position]) {
            is Item.Rule -> TYPE_RULE
            is Item.Header -> TYPE_HEADER
            is Item.Note -> TYPE_NOTE
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val inflater = LayoutInflater.from(parent.context)
            return when (viewType) {
                TYPE_RULE -> RuleHolder(inflater.inflate(R.layout.item_rule, parent, false))
                TYPE_HEADER ->
                    HeaderHolder(inflater.inflate(R.layout.item_ui2_header, parent, false))
                else -> NoteHolder(inflater.inflate(R.layout.item_ui2_note, parent, false))
            }
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val item = items[position]) {
                is Item.Rule -> {
                    val h = holder as RuleHolder
                    h.pattern.text = item.display
                    h.describe.text = item.describe
                    h.remove.setOnClickListener { onRemove(item.pattern, item.redirect) }
                }

                is Item.Header -> (holder as HeaderHolder).text.text = item.text

                is Item.Note -> {
                    val h = holder as NoteHolder
                    h.title.text = item.title
                    h.detail.text = item.detail
                    h.detail.visibility = if (item.detail.isEmpty()) View.GONE else View.VISIBLE
                }
            }
        }

        companion object {
            const val TYPE_RULE = 0
            const val TYPE_HEADER = 1
            const val TYPE_NOTE = 2
        }
    }

    companion object {
        private const val DEBOUNCE_MS = 200L

        /** Enough rows to check a count against, few enough to fit in a dialog. */
        private const val DIALOG_ROWS = 50
    }
}
