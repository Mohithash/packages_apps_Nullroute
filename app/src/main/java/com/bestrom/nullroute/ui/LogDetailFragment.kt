package com.bestrom.nullroute.ui

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ForegroundAppTracker
import com.bestrom.nullroute.log.QueryLogDb
import com.bestrom.nullroute.log.RingReader
import com.google.android.material.button.MaterialButton

/**
 * One domain, or one app, and the recovery actions for it.
 *
 * ## The three buttons do three different things, and say so
 *
 * *Allow this domain* writes a pattern to `allow.txt` and is **not live** until
 * the index is recompiled — the button that does that appears only after a rule
 * has been written, so "compile" is never offered as busywork.
 *
 * *Exempt this app* flips one byte in `uid_policy` and is live on the resolver's
 * next lookup, with no rebuild at all. It is the fast path and the one the
 * breakage notification uses.
 *
 * *Force stop app* exists because neither of the first two can reach the app's
 * own DNS cache. See [RecoveryActions] for why that cache is unreachable rather
 * than merely inconvenient.
 *
 * ## Why the evidence is above the buttons
 *
 * Exempting an app switches filtering off for everything it does, forever, and
 * the log lines that justify it are cheap to show. A screen that offered the
 * button without them would be asking the user to trust a verdict they cannot
 * see.
 */
class LogDetailFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var title: TextView
    private lateinit var truncatedNote: TextView
    private lateinit var stats: TextView
    private lateinit var exemptState: TextView
    private lateinit var recentHeader: TextView
    private lateinit var recentContainer: LinearLayout
    private lateinit var recentEmpty: TextView
    private lateinit var allowButton: MaterialButton
    private lateinit var rebuildButton: MaterialButton
    private lateinit var exemptButton: MaterialButton
    private lateinit var forceStopButton: MaterialButton
    private lateinit var status: TextView

    private var domain: String? = null
    private var uid: Int = UNKNOWN_UID

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        domain = arguments?.getString(ARG_DOMAIN)
        uid = arguments?.getInt(ARG_UID, UNKNOWN_UID) ?: UNKNOWN_UID
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_logdetail, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        title = view.findViewById(R.id.detail_title)
        truncatedNote = view.findViewById(R.id.detail_truncated)
        stats = view.findViewById(R.id.detail_stats)
        exemptState = view.findViewById(R.id.detail_exempt_state)
        recentHeader = view.findViewById(R.id.detail_recent_header)
        recentContainer = view.findViewById(R.id.detail_recent_container)
        recentEmpty = view.findViewById(R.id.detail_recent_empty)
        allowButton = view.findViewById(R.id.detail_allow)
        rebuildButton = view.findViewById(R.id.detail_rebuild)
        exemptButton = view.findViewById(R.id.detail_exempt)
        forceStopButton = view.findViewById(R.id.detail_force_stop)
        status = view.findViewById(R.id.detail_status)

        allowButton.setOnClickListener { onAllow() }
        rebuildButton.setOnClickListener { onRebuild() }
        exemptButton.setOnClickListener { onExempt() }
        forceStopButton.setOnClickListener { confirmForceStop() }

        // A domain screen reached from the Domains tab has no single app to act
        // on, and a button that cannot know which app to exempt is a button that
        // will exempt the wrong one.
        val hasApp = uid >= 0
        allowButton.visibility = if (domain != null) View.VISIBLE else View.GONE
        exemptButton.visibility = if (hasApp) View.VISIBLE else View.GONE
        forceStopButton.visibility = if (hasApp) View.VISIBLE else View.GONE

        recentHeader.setText(
            if (domain == null) R.string.logui_detail_app_header
            else R.string.logui_detail_recent_header
        )
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    private fun load() {
        val app = requireContext().applicationContext
        val wantDomain = domain
        val wantUid = uid

        NullrouteApp.io.execute {
            val data = gather(app, wantDomain, wantUid)
            main.post { if (isAdded) render(data) }
        }
    }

    /** Blocking. Background thread only. */
    private fun gather(app: Context, forDomain: String?, forUid: Int): Detail {
        val db = QueryLogDb.get(app)
        if (db == null) {
            return Detail(
                available = false,
                lines = emptyList(),
                stored = 0,
                lastMs = 0L,
                ruleGroup = -1,
                latestVerdict = -1,
                truncated = false,
                uids = emptyList(),
            )
        }

        return runCatching {
            if (forDomain != null) {
                // The log API has no per-name query — the indices it does have
                // are the ones the aggregation screens need. Totals therefore
                // come from the exact aggregate, and the sample lines from a
                // bounded scan of the newest records, which is what "recent"
                // means anyway.
                val totals = db.topDomains(0L, DOMAIN_SCAN)
                    .firstOrNull { it.name == forDomain }
                val entries = db.recent(RECENT_SCAN, uid = null, blockedOnly = false)
                    .filter { it.name == forDomain }
                Detail(
                    available = true,
                    lines = entries.take(SAMPLE_LINES),
                    stored = totals?.blocked ?: entries.count { it.verdict != RingReader.VERDICT_PASS },
                    lastMs = totals?.lastMs ?: entries.firstOrNull()?.timestampMs ?: 0L,
                    ruleGroup = totals?.ruleGroup ?: -1,
                    latestVerdict = entries.firstOrNull()?.verdict ?: -1,
                    truncated = entries.any { it.truncated },
                    uids = entries.map { it.uid }.distinct(),
                )
            } else {
                val entries = db.recent(SAMPLE_LINES, uid = forUid, blockedOnly = true)
                val totals = db.topApps(0L, DOMAIN_SCAN).firstOrNull { it.uid == forUid }
                Detail(
                    available = true,
                    lines = entries,
                    stored = totals?.blocked ?: entries.size,
                    lastMs = entries.firstOrNull()?.timestampMs ?: 0L,
                    ruleGroup = -1,
                    latestVerdict = entries.firstOrNull()?.verdict ?: -1,
                    truncated = entries.any { it.truncated },
                    uids = if (forUid >= 0) listOf(forUid) else emptyList(),
                )
            }
        }.getOrElse {
            Detail(false, emptyList(), 0, 0L, -1, -1, false, emptyList())
        }
    }

    private fun render(detail: Detail) {
        val context = requireContext()
        val name = domain
        title.text = name ?: appLabel(context, uid)
        truncatedNote.visibility = if (detail.truncated) View.VISIBLE else View.GONE

        val lines = ArrayList<String>(5)
        if (!detail.available) {
            lines += getString(R.string.logui_db_unavailable)
        } else {
            lines += getString(R.string.logui_detail_stored, detail.stored)
            if (detail.lastMs > 0L) {
                lines += getString(R.string.logui_detail_last_seen, LogFragment.relative(detail.lastMs))
            }
            if (detail.latestVerdict >= 0) {
                lines += getString(
                    R.string.logui_detail_latest,
                    LogFragment.verdictLabel(context, detail.latestVerdict),
                )
            }
            if (detail.ruleGroup >= 0) {
                lines += getString(R.string.logui_group, detail.ruleGroup)
            }
            if (name != null) {
                lines += when (detail.uids.size) {
                    0 -> getString(R.string.logui_detail_asked_by_many, 0)
                    1 -> getString(R.string.logui_detail_asked_by, appLabel(context, detail.uids[0]))
                    else -> getString(R.string.logui_detail_asked_by_many, detail.uids.size)
                }
            }
        }
        stats.text = lines.joinToString("\n")

        renderActionState(context)
        renderLines(context, detail.lines)
    }

    private fun renderActionState(context: Context) {
        if (uid >= 0) {
            val exempt = RecoveryActions.isExempt(uid)
            exemptState.setText(
                if (exempt) R.string.rec_exempt_state_on else R.string.rec_exempt_state_off
            )
            exemptButton.setText(
                if (exempt) R.string.rec_action_unexempt else R.string.log_action_exempt
            )
            // Present but disabled, with the reason in the status line, rather
            // than hidden: "why is there no force stop here" is a question the
            // user would otherwise have to answer by guessing.
            forceStopButton.isEnabled = RecoveryActions.canForceStop(context)
            if (!forceStopButton.isEnabled) {
                showStatus(getString(R.string.rec_force_stop_unavailable))
            }
        } else {
            exemptState.text = ""
        }

        val name = domain
        if (name != null && RecoveryActions.isAllowed(name)) {
            allowButton.isEnabled = false
            showStatus(getString(R.string.rec_allow_duplicate, name))
        }
    }

    private fun renderLines(context: Context, entries: List<QueryLogDb.Entry>) {
        recentContainer.removeAllViews()
        recentEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE

        val inflater = LayoutInflater.from(context)
        for (entry in entries) {
            val row = inflater.inflate(R.layout.item_log, recentContainer, false)
            row.findViewById<TextView>(R.id.log_row_title).text =
                if (domain == null) LogFragment.displayName(context, entry.name, entry.truncated)
                else appLabel(context, entry.uid)
            row.findViewById<TextView>(R.id.log_row_subtitle).text =
                LogFragment.verdictLabel(context, entry.verdict)
            row.findViewById<TextView>(R.id.log_row_badge).text =
                LogFragment.relative(entry.timestampMs)
            // Not clickable: this IS the detail screen, there is nowhere deeper.
            row.isClickable = false
            recentContainer.addView(row)
        }
    }

    // ---- actions -------------------------------------------------------------

    /**
     * "Allow + retry" is one tap, not two.
     *
     * A user who has just been told the block broke their app does not want a
     * rule written and left inert — they want the domain to work. So the compile
     * starts by itself, and the explicit compile button only appears if it
     * fails, where it is a retry rather than a second half of the same action.
     */
    private fun onAllow() {
        val name = domain ?: return
        val app = requireContext().applicationContext
        allowButton.isEnabled = false
        NullrouteApp.io.execute {
            val outcome = RecoveryActions.allowDomain(app, name)
            main.post {
                if (!isAdded) return@post
                showStatus(outcome.message)
                allowButton.isEnabled = !outcome.ok
                if (outcome.pending) {
                    startRebuild(outcome.message)
                } else {
                    rebuildButton.visibility = View.GONE
                }
            }
        }
    }

    private fun onRebuild() = startRebuild(null)

    private fun startRebuild(prefix: String?) {
        val app = requireContext().applicationContext
        rebuildButton.isEnabled = false
        rebuildButton.visibility = View.GONE
        val running = getString(R.string.rec_rebuild_running)
        showStatus(if (prefix == null) running else "$prefix\n\n$running")
        NullrouteApp.io.execute {
            val outcome = RecoveryActions.rebuild(app)
            main.post {
                if (!isAdded) return@post
                rebuildButton.isEnabled = true
                // Offered again only on failure: after a successful promotion
                // there is nothing left to compile, and a button that recompiles
                // an unchanged config invites minutes of CPU for no effect.
                rebuildButton.visibility = if (outcome.ok) View.GONE else View.VISIBLE
                showStatus(outcome.message)
            }
        }
    }

    private fun onExempt() {
        if (uid < 0) return
        val app = requireContext().applicationContext
        val target = uid
        val makeExempt = !RecoveryActions.isExempt(target)
        exemptButton.isEnabled = false
        NullrouteApp.io.execute {
            val outcome = RecoveryActions.setExempt(app, target, makeExempt)
            main.post {
                if (!isAdded) return@post
                exemptButton.isEnabled = true
                showStatus(outcome.message)
                renderActionState(requireContext())
            }
        }
    }

    /**
     * Force stop is destructive and irreversible for whatever the app had in
     * flight, so it is the one action here that asks first.
     */
    private fun confirmForceStop() {
        if (uid < 0) return
        val context = requireContext()
        val label = appLabel(context, uid)
        AlertDialog.Builder(context)
            .setTitle(getString(R.string.rec_force_stop_title, label))
            .setMessage(R.string.rec_force_stop_body)
            .setNegativeButton(R.string.rec_cancel, null)
            .setPositiveButton(R.string.rec_confirm) { _, _ -> onForceStop() }
            .show()
    }

    private fun onForceStop() {
        val app = requireContext().applicationContext
        val target = uid
        NullrouteApp.io.execute {
            val outcome = RecoveryActions.forceStop(app, target)
            main.post { if (isAdded) showStatus(outcome.message) }
        }
    }

    private fun showStatus(message: String) {
        status.text = message
        status.visibility = View.VISIBLE
    }

    private fun appLabel(context: Context, forUid: Int): String =
        ForegroundAppTracker.label(context, forUid)
            ?: context.getString(R.string.log_row_unknown_app, forUid)

    private data class Detail(
        val available: Boolean,
        val lines: List<QueryLogDb.Entry>,
        val stored: Int,
        val lastMs: Long,
        val ruleGroup: Int,
        val latestVerdict: Int,
        val truncated: Boolean,
        val uids: List<Int>,
    )

    companion object {
        private const val ARG_DOMAIN = "domain"
        private const val ARG_UID = "uid"

        private const val UNKNOWN_UID = -1

        /** Bounded so a 50,000-row log cannot make this screen slow to open. */
        private const val RECENT_SCAN = 500
        private const val DOMAIN_SCAN = 500
        private const val SAMPLE_LINES = 12

        fun forDomain(domain: String, uid: Int): LogDetailFragment = LogDetailFragment().apply {
            arguments = Bundle().apply {
                putString(ARG_DOMAIN, domain)
                putInt(ARG_UID, uid)
            }
        }

        fun forApp(uid: Int): LogDetailFragment = LogDetailFragment().apply {
            arguments = Bundle().apply { putInt(ARG_UID, uid) }
        }
    }
}
