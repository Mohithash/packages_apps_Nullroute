package com.bestrom.nullroute.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.log.Retention
import com.google.android.material.button.MaterialButton

/**
 * Privacy and retention: what is logged, for how long, and where it lives.
 *
 * ## Why the storage sentence is on the screen and not in an About page
 *
 * The query log is the only thing Nullroute keeps in **credential-encrypted**
 * storage; everything else it owns is device-encrypted so that filtering works
 * before first unlock. That asymmetry is the entire privacy story — a locked or
 * powered-off phone exposes no browsing history, at the cost of not logging
 * anything until it is unlocked — and it is a fact about the device the user is
 * holding, not a policy anyone can change later. So it is stated as plainly as
 * the controls that follow it.
 *
 * ## Off means off
 *
 * [Retention.setMode] with [Retention.LogMode.OFF] writes `log_level = 0` to the
 * control page, so the **resolver stops writing records** — this app is not
 * merely declining to store them — and it drops what is already stored. A user
 * who turns logging off means "stop having this", not "stop adding to this", and
 * the note under the radio group says so before they tap.
 */
class PrivacyFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var modeGroup: RadioGroup
    private lateinit var daysGroup: RadioGroup
    private lateinit var retentionNote: TextView
    private lateinit var stats: TextView
    private lateinit var purge: MaterialButton
    private lateinit var clear: MaterialButton
    private lateinit var status: TextView

    private var binding = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_privacy, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        modeGroup = view.findViewById(R.id.priv_mode_group)
        daysGroup = view.findViewById(R.id.priv_days_group)
        retentionNote = view.findViewById(R.id.priv_retention_note)
        stats = view.findViewById(R.id.priv_stats)
        purge = view.findViewById(R.id.priv_purge)
        clear = view.findViewById(R.id.priv_clear)
        status = view.findViewById(R.id.priv_status)

        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            if (binding) return@setOnCheckedChangeListener
            onModeChosen(modeFor(checkedId))
        }

        daysGroup.setOnCheckedChangeListener { _, checkedId ->
            if (binding) return@setOnCheckedChangeListener
            onDaysChosen(daysFor(checkedId))
        }

        purge.setOnClickListener { onPurge() }
        clear.setOnClickListener { confirmClear() }
    }

    override fun onResume() {
        super.onResume()
        bind()
    }

    private fun bind() {
        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            val snapshot = Retention.stats(app)
            main.post {
                if (!isAdded) return@post
                binding = true
                modeGroup.check(buttonFor(snapshot.mode))
                daysGroup.check(buttonForDays(snapshot.days))
                binding = false

                retentionNote.text = getString(R.string.priv_retention_note, snapshot.maxRows)
                stats.text = when {
                    !snapshot.available -> getString(R.string.priv_stats_unavailable)
                    snapshot.rows == 0 -> getString(R.string.priv_stats_empty)
                    else -> getString(
                        R.string.priv_stats,
                        snapshot.rows,
                        relative(snapshot.oldestMs),
                    )
                }
                // Nothing to purge or clear when the database cannot be opened —
                // an enabled button that can only ever fail is a lie about state.
                purge.isEnabled = snapshot.available
                clear.isEnabled = snapshot.available
            }
        }
    }

    private fun onModeChosen(mode: Retention.LogMode) {
        if (mode == Retention.LogMode.ALL) {
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.priv_mode_all_confirm_title)
                .setMessage(R.string.log_mode_all_warning)
                .setNegativeButton(R.string.rec_cancel) { _, _ -> bind() }
                .setOnCancelListener { bind() }
                .setPositiveButton(R.string.rec_confirm) { _, _ -> applyMode(mode) }
                .show()
            return
        }
        applyMode(mode)
    }

    private fun applyMode(mode: Retention.LogMode) {
        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            // OFF also deletes the stored rows, which is database work.
            Retention.setMode(app, mode)
            main.post { if (isAdded) bind() }
        }
    }

    private fun onDaysChosen(days: Int) {
        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            // setDays purges immediately: a shorter window that took effect
            // "eventually" would leave records the user has just asked to be rid
            // of sitting on disk for up to an hour.
            Retention.setDays(app, days)
            main.post { if (isAdded) bind() }
        }
    }

    private fun onPurge() {
        val app = requireContext().applicationContext
        purge.isEnabled = false
        NullrouteApp.io.execute {
            val result = Retention.purgeNow(app)
            main.post {
                if (!isAdded) return@post
                purge.isEnabled = true
                showStatus(
                    when {
                        result == null -> getString(R.string.priv_stats_unavailable)
                        result.total == 0 -> getString(R.string.priv_purge_none)
                        else -> getString(R.string.priv_purged, result.total)
                    }
                )
                bind()
            }
        }
    }

    private fun confirmClear() {
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.priv_clear_confirm_title)
            .setMessage(R.string.priv_clear_confirm_body)
            .setNegativeButton(R.string.rec_cancel, null)
            .setPositiveButton(R.string.rec_confirm) { _, _ -> onClear() }
            .show()
    }

    private fun onClear() {
        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            Retention.clear(app)
            main.post {
                if (!isAdded) return@post
                showStatus(getString(R.string.log_cleared))
                bind()
            }
        }
    }

    private fun showStatus(message: String) {
        status.text = message
        status.visibility = View.VISIBLE
    }

    private fun relative(ms: Long): CharSequence =
        if (ms <= 0L) "—"
        else DateUtils.getRelativeTimeSpanString(
            ms,
            System.currentTimeMillis(),
            DateUtils.MINUTE_IN_MILLIS,
        )

    private fun buttonFor(mode: Retention.LogMode): Int = when (mode) {
        Retention.LogMode.OFF -> R.id.priv_mode_off
        Retention.LogMode.ALL -> R.id.priv_mode_all
        else -> R.id.priv_mode_blocked
    }

    private fun modeFor(buttonId: Int): Retention.LogMode = when (buttonId) {
        R.id.priv_mode_off -> Retention.LogMode.OFF
        R.id.priv_mode_all -> Retention.LogMode.ALL
        else -> Retention.LogMode.BLOCKED
    }

    /**
     * Four fixed windows rather than a slider. [Retention.MIN_DAYS] is 1 because
     * "keep for zero days" would mean logging and then discarding, which is
     * strictly worse than not logging; the maximum is [Retention.MAX_DAYS].
     */
    private fun buttonForDays(days: Int): Int = when {
        days <= 1 -> R.id.priv_days_1
        days <= 7 -> R.id.priv_days_7
        days <= 30 -> R.id.priv_days_30
        else -> R.id.priv_days_90
    }

    private fun daysFor(buttonId: Int): Int = when (buttonId) {
        R.id.priv_days_1 -> 1
        R.id.priv_days_30 -> 30
        R.id.priv_days_90 -> 90
        else -> 7
    }
}
