package com.bestrom.nullroute.ui

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.ForegroundAppTracker
import com.bestrom.nullroute.log.QueryLogDb
import com.bestrom.nullroute.log.Retention
import com.bestrom.nullroute.log.RingReader
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup

/**
 * The query log: what was blocked, for whom, and — the part that matters — what
 * is **missing** from it.
 *
 * ## The completeness banner is not optional
 *
 * Three separate things make this log a sample rather than a record, and all
 * three are measured rather than assumed:
 *
 *  * the resolver's ring holds 4,096 slots and overwrites the oldest rather than
 *    blocking a lookup, so a burst outruns us and `ctl.ring_drops` counts it;
 *  * a slot can be read while it is being rewritten, which [RingReader.Drain]
 *    reports as `torn`;
 *  * before the first unlock there is nowhere to store anything at all, because
 *    the database is on credential-encrypted storage on purpose.
 *
 * Whenever any of those is non-zero the banner says so, with the count. A log
 * that quietly omits records is worse than no log: it is evidence the user will
 * reason from.
 *
 * ## Aggregation, not a firehose
 *
 * Per-app and per-domain totals are what a user acts on ("which app is doing
 * this", "what is this domain"); the raw stream is a third tab rather than the
 * default. Blocked-only is on by default and, when logging is set to
 * blocked-only at the source, passes were never recorded — the note under the
 * switch says so instead of leaving an empty list to be read as "nothing passed".
 */
class LogFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var group: MaterialButtonToggleGroup
    private lateinit var blockedOnly: SwitchCompat
    private lateinit var banner: TextView
    private lateinit var state: TextView
    private lateinit var list: RecyclerView
    private lateinit var window: TextView
    private lateinit var refresh: MaterialButton
    private lateinit var privacy: MaterialButton

    private val adapter = RowAdapter { row -> openDetail(row) }

    private var viewMode = VIEW_APPS

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_log, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        group = view.findViewById(R.id.log_view_group)
        blockedOnly = view.findViewById(R.id.log_blocked_only)
        banner = view.findViewById(R.id.log_incomplete_banner)
        state = view.findViewById(R.id.log_state)
        list = view.findViewById(R.id.log_list)
        window = view.findViewById(R.id.log_window)
        refresh = view.findViewById(R.id.log_refresh)
        privacy = view.findViewById(R.id.log_privacy)

        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter

        viewMode = savedInstanceState?.getInt(KEY_VIEW) ?: VIEW_APPS
        group.check(buttonFor(viewMode))
        group.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            viewMode = viewFor(checkedId)
            load()
        }

        blockedOnly.isChecked = savedInstanceState?.getBoolean(KEY_BLOCKED_ONLY) ?: true
        blockedOnly.setOnCheckedChangeListener { _, _ -> load() }

        refresh.setOnClickListener { load() }
        privacy.setOnClickListener { push(PrivacyFragment()) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(KEY_VIEW, viewMode)
        outState.putBoolean(KEY_BLOCKED_ONLY, blockedOnly.isChecked)
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    private fun load() {
        val app = requireContext().applicationContext
        val wantView = viewMode
        val wantBlockedOnly = blockedOnly.isChecked

        NullrouteApp.io.execute {
            val snapshot = snapshot(app, wantView, wantBlockedOnly)
            main.post { if (isAdded) render(snapshot) }
        }
    }

    /** Blocking: drains the ring, then queries. Background thread only. */
    private fun snapshot(
        app: Context,
        which: Int,
        onlyBlocked: Boolean,
    ): Snapshot {
        // Drain first, so the list reflects what happened up to this instant
        // rather than up to the last time the watchdog happened to run.
        val drain = runCatching { RingReader.pump(app) }.getOrNull()
        val telemetry = ControlPage.telemetry()

        // ring_drops (control page) and Drain.producerDrops are the same producer
        // counter read from two places; taking the max avoids reporting a lost
        // record twice. `dropped` and `torn` are consumer-side and additional.
        val producer = maxOf(telemetry.ringDrops.toLong(), (drain?.producerDrops ?: 0).toLong())
        val missing = producer + (drain?.dropped ?: 0L) + (drain?.torn ?: 0L)

        val db = QueryLogDb.get(app)
        if (db == null) {
            return Snapshot(
                dbAvailable = false,
                ringAvailable = drain != null,
                missing = missing,
                rows = emptyList(),
                storedRows = 0,
                oldestMs = 0L,
                mode = Retention.mode(app),
            )
        }

        return runCatching {
            Snapshot(
                dbAvailable = true,
                ringAvailable = drain != null,
                missing = missing,
                rows = rowsFor(app, db, which, onlyBlocked),
                storedRows = db.rowCount(),
                oldestMs = db.oldestMs(),
                mode = Retention.mode(app),
            )
        }.getOrElse {
            Snapshot(false, drain != null, missing, emptyList(), 0, 0L, Retention.mode(app))
        }
    }

    private fun rowsFor(
        app: Context,
        db: QueryLogDb,
        which: Int,
        onlyBlocked: Boolean,
    ): List<Row> = when (which) {
        VIEW_APPS -> db.topApps(0L, AGGREGATE_LIMIT)
            .filter { !onlyBlocked || it.blocked > 0 }
            .map { totals ->
                Row(
                    title = ForegroundAppTracker.label(app, totals.uid)
                        ?: app.getString(R.string.log_row_unknown_app, totals.uid),
                    subtitle = app.getString(R.string.logui_app_row, totals.blocked, totals.total),
                    badge = totals.blocked.toString(),
                    uid = totals.uid,
                    domain = null,
                )
            }

        VIEW_DOMAINS -> db.topDomains(0L, AGGREGATE_LIMIT)
            .filter { !onlyBlocked || it.blocked > 0 }
            .map { totals ->
                Row(
                    title = totals.name,
                    subtitle = app.getString(
                        R.string.logui_domain_row,
                        totals.blocked,
                        relative(totals.lastMs),
                    ),
                    badge = app.getString(R.string.logui_group, totals.ruleGroup),
                    uid = null,
                    domain = totals.name,
                )
            }

        else -> db.recent(RECENT_LIMIT, uid = null, blockedOnly = onlyBlocked)
            .map { entry ->
                Row(
                    title = displayName(app, entry.name, entry.truncated),
                    subtitle = app.getString(
                        R.string.logui_recent_row,
                        verdictLabel(app, entry.verdict),
                        ForegroundAppTracker.label(app, entry.uid)
                            ?: app.getString(R.string.log_row_unknown_app, entry.uid),
                    ),
                    badge = relative(entry.timestampMs),
                    uid = entry.uid,
                    domain = entry.name,
                )
            }
    }

    private fun render(snapshot: Snapshot) {
        adapter.submit(snapshot.rows)

        // The banner precedes everything the list says about itself.
        if (snapshot.missing > 0L) {
            banner.text = getString(R.string.log_incomplete, snapshot.missing)
            banner.visibility = View.VISIBLE
        } else {
            banner.visibility = View.GONE
        }

        val stateText: String? = when {
            snapshot.mode == Retention.LogMode.OFF -> getString(R.string.log_off)
            !snapshot.dbAvailable -> getString(R.string.logui_db_unavailable)
            !snapshot.ringAvailable -> getString(R.string.logui_ring_unavailable)
            snapshot.storedRows == 0 -> getString(R.string.log_empty)
            snapshot.rows.isEmpty() -> getString(R.string.logui_empty_filtered)
            else -> null
        }
        state.text = stateText.orEmpty()
        state.visibility = if (stateText == null) View.GONE else View.VISIBLE

        window.text = if (snapshot.storedRows == 0) {
            getString(R.string.logui_window_empty)
        } else {
            getString(R.string.logui_window, snapshot.storedRows, relative(snapshot.oldestMs))
        }
    }

    private fun openDetail(row: Row) {
        val fragment = when {
            row.domain != null -> LogDetailFragment.forDomain(row.domain, row.uid ?: -1)
            row.uid != null -> LogDetailFragment.forApp(row.uid)
            else -> return
        }
        push(fragment)
    }

    /**
     * Pushes onto the activity's single container with a back-stack entry, so
     * the system back gesture returns to the list. MainActivity owns the
     * container and the tabs; nothing here changes the selected tab, because a
     * detail screen is not a tab.
     */
    private fun push(fragment: Fragment) {
        parentFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, fragment)
            .addToBackStack(null)
            .commit()
    }

    private fun buttonFor(which: Int): Int = when (which) {
        VIEW_DOMAINS -> R.id.log_view_domains
        VIEW_RECENT -> R.id.log_view_recent
        else -> R.id.log_view_apps
    }

    private fun viewFor(buttonId: Int): Int = when (buttonId) {
        R.id.log_view_domains -> VIEW_DOMAINS
        R.id.log_view_recent -> VIEW_RECENT
        else -> VIEW_APPS
    }

    private data class Snapshot(
        val dbAvailable: Boolean,
        val ringAvailable: Boolean,
        val missing: Long,
        val rows: List<Row>,
        val storedRows: Int,
        val oldestMs: Long,
        val mode: Retention.LogMode,
    )

    private data class Row(
        val title: String,
        val subtitle: String,
        // CharSequence, not String: relative() hands back what DateUtils
        // produces and TextView consumes it directly, so narrowing here would only
        // buy an allocation per row.
        val badge: CharSequence,
        val uid: Int?,
        val domain: String?,
    )

    private class RowAdapter(
        private val onClick: (Row) -> Unit,
    ) : RecyclerView.Adapter<RowAdapter.Holder>() {

        private var rows: List<Row> = emptyList()

        fun submit(newRows: List<Row>) {
            rows = newRows
            notifyDataSetChanged()
        }

        class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val title: TextView = view.findViewById(R.id.log_row_title)
            val subtitle: TextView = view.findViewById(R.id.log_row_subtitle)
            val badge: TextView = view.findViewById(R.id.log_row_badge)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false))

        override fun getItemCount(): Int = rows.size

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val row = rows[position]
            holder.title.text = row.title
            holder.subtitle.text = row.subtitle
            holder.badge.text = row.badge
            holder.itemView.setOnClickListener { onClick(row) }
        }
    }

    companion object {
        private const val VIEW_APPS = 0
        private const val VIEW_DOMAINS = 1
        private const val VIEW_RECENT = 2

        private const val KEY_VIEW = "log_view"
        private const val KEY_BLOCKED_ONLY = "log_blocked_only"

        private const val AGGREGATE_LIMIT = 200
        private const val RECENT_LIMIT = 300

        fun relative(ms: Long): CharSequence =
            if (ms <= 0L) "—"
            else DateUtils.getRelativeTimeSpanString(
                ms,
                System.currentTimeMillis(),
                DateUtils.MINUTE_IN_MILLIS,
            )

        fun verdictLabel(context: Context, verdict: Int): String = when (verdict) {
            RingReader.VERDICT_BLOCK -> context.getString(R.string.log_row_blocked)
            RingReader.VERDICT_REDIRECT -> context.getString(R.string.log_row_redirected)
            else -> context.getString(R.string.log_row_allowed)
        }

        /**
         * The resolver stores the tail of an over-long name, cut at a label
         * boundary. The leading ellipsis is the difference between "we blocked
         * this name" and "we blocked something ending in this".
         */
        fun displayName(context: Context, name: String, truncated: Boolean): String =
            if (truncated) context.getString(R.string.log_row_truncated_prefix, name) else name
    }
}
