package com.bestrom.nullroute.ui

import android.content.ActivityNotFoundException
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.selftest.BlockingSelfTest
import com.bestrom.nullroute.selftest.Lane
import com.bestrom.nullroute.selftest.LaneResult
import com.bestrom.nullroute.selftest.Outcome
import com.bestrom.nullroute.selftest.SelfTestReport
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView

/**
 * "Test my blocking".
 *
 * The screen's whole job is to stay out of the way of the numbers. It shows the
 * domain, the three lanes with the evidence for each, and the conditions the run
 * happened under — and it never converts an [Outcome.INCONCLUSIVE] into anything
 * friendlier. A self-test that rounds "cannot determine" up to a green tick is
 * worse than no self-test, because the user ends up with evidence for a belief
 * that is false.
 *
 * The browser lane is filled in by the user, and is labelled as their report
 * rather than a measurement, because no app on Android can observe another app's
 * name resolution. Presenting a guess in the same typeface as a measurement is
 * how a diagnostic becomes a decoration.
 */
class SelfTestFragment : Fragment() {

    private lateinit var runButton: MaterialButton
    private lateinit var progress: ProgressBar
    private lateinit var progressLabel: TextView

    private lateinit var domainCard: MaterialCardView
    private lateinit var domainText: TextView
    private lateinit var domainSource: TextView

    private lateinit var lanesCard: MaterialCardView
    private lateinit var laneTitles: List<TextView>
    private lateinit var laneOutcomes: List<TextView>
    private lateinit var laneDetails: List<TextView>

    private lateinit var browserActions: ViewGroup
    private lateinit var browserOpen: MaterialButton
    private lateinit var browserBlocked: MaterialButton
    private lateinit var browserLoaded: MaterialButton

    private lateinit var summaryCard: MaterialCardView
    private lateinit var summary: TextView
    private lateinit var conditions: TextView

    /** The last run. Lost on recreation, which is honest: it is a measurement of
     *  a moment, and showing a stale one after a configuration change would date
     *  a result the user would read as current. */
    private var report: SelfTestReport? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_selftest, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        runButton = view.findViewById(R.id.selftest_run)
        progress = view.findViewById(R.id.selftest_progress)
        progressLabel = view.findViewById(R.id.selftest_progress_label)

        domainCard = view.findViewById(R.id.selftest_domain_card)
        domainText = view.findViewById(R.id.selftest_domain)
        domainSource = view.findViewById(R.id.selftest_domain_source)

        lanesCard = view.findViewById(R.id.selftest_lanes_card)
        laneTitles = listOf(
            view.findViewById(R.id.lane1_title),
            view.findViewById(R.id.lane2_title),
            view.findViewById(R.id.lane3_title),
        )
        laneOutcomes = listOf(
            view.findViewById(R.id.lane1_outcome),
            view.findViewById(R.id.lane2_outcome),
            view.findViewById(R.id.lane3_outcome),
        )
        laneDetails = listOf(
            view.findViewById(R.id.lane1_detail),
            view.findViewById(R.id.lane2_detail),
            view.findViewById(R.id.lane3_detail),
        )

        browserActions = view.findViewById(R.id.selftest_browser_actions)
        browserOpen = view.findViewById(R.id.selftest_browser_open)
        browserBlocked = view.findViewById(R.id.selftest_browser_blocked)
        browserLoaded = view.findViewById(R.id.selftest_browser_loaded)

        summaryCard = view.findViewById(R.id.selftest_summary_card)
        summary = view.findViewById(R.id.selftest_summary)
        conditions = view.findViewById(R.id.selftest_context)

        runButton.setOnClickListener { start() }
        browserOpen.setOnClickListener { openInBrowser() }
        browserBlocked.setOnClickListener { recordBrowser(loaded = false) }
        browserLoaded.setOnClickListener { recordBrowser(loaded = true) }

        report?.let { render(it) }
    }

    private fun start() {
        runButton.isEnabled = false
        progress.visibility = View.VISIBLE
        progressLabel.visibility = View.VISIBLE
        BlockingSelfTest.run(requireContext()) { result ->
            if (!isAdded) return@run
            report = result
            progress.visibility = View.GONE
            progressLabel.visibility = View.GONE
            runButton.isEnabled = true
            runButton.setText(R.string.selftest_action_rerun)
            render(result)
        }
    }

    private fun render(r: SelfTestReport) {
        domainCard.visibility = View.VISIBLE
        if (!r.ran) {
            // Nothing was measured. Say that, and do not show lanes that would
            // read as three quiet passes.
            domainText.setText(R.string.selftest_domain_none)
            domainSource.text = r.unavailableReason.orEmpty()
            lanesCard.visibility = View.GONE
            summaryCard.visibility = View.VISIBLE
            summary.setText(R.string.selftest_summary_none)
            conditions.text = contextLines(r)
            return
        }

        domainText.text = r.domain
        domainSource.text = getString(R.string.selftest_domain_source, r.rule ?: "—")

        lanesCard.visibility = View.VISIBLE
        laneTitles[2].text = r.browserLabel
            ?.let { getString(R.string.selftest_lane_browser, it) }
            ?: getString(R.string.selftest_lane_browser_unknown)

        renderLane(0, r.lane(Lane.SYSTEM_RESOLVER))
        renderLane(1, r.lane(Lane.WEBVIEW))
        renderLane(2, r.lane(Lane.BROWSER))

        // The browser lane can be re-answered; the buttons stay.
        browserActions.visibility = View.VISIBLE

        summaryCard.visibility = View.VISIBLE
        summary.text = summaryFor(r)
        conditions.text = contextLines(r)
    }

    private fun renderLane(slot: Int, result: LaneResult?) {
        val outcomeView = laneOutcomes[slot]
        val detailView = laneDetails[slot]
        if (result == null) {
            outcomeView.text = ""
            detailView.text = ""
            return
        }
        outcomeView.setText(labelFor(result.outcome))
        outcomeView.setTextColor(colour(colourFor(result.outcome)))
        detailView.text = result.detail
    }

    private fun labelFor(outcome: Outcome): Int = when (outcome) {
        Outcome.BLOCKED -> R.string.selftest_outcome_blocked
        Outcome.LEAKED -> R.string.selftest_outcome_leaked
        Outcome.INCONCLUSIVE -> R.string.selftest_outcome_inconclusive
        Outcome.SKIPPED -> R.string.selftest_outcome_skipped
        Outcome.PENDING -> R.string.selftest_outcome_pending
    }

    /**
     * Amber for both "cannot determine" and "waiting", grey for "not tested".
     * Nothing that was not measured is ever green: the colour is the claim.
     */
    private fun colourFor(outcome: Outcome): Int = when (outcome) {
        Outcome.BLOCKED -> R.color.nr_status_ok
        Outcome.LEAKED -> R.color.nr_status_bad
        Outcome.INCONCLUSIVE, Outcome.PENDING -> R.color.nr_status_warn
        Outcome.SKIPPED -> R.color.nr_status_unknown
    }

    private fun summaryFor(r: SelfTestReport): String {
        val parts = ArrayList<String>(3)
        val leaks = r.leaked.size
        parts += when {
            r.measured.isEmpty() -> getString(R.string.selftest_summary_none)
            leaks == 0 -> getString(R.string.selftest_summary_all_blocked)
            else -> resources.getQuantityString(
                R.plurals.selftest_summary_leaks, leaks, leaks
            )
        }
        if (r.killSwitch || r.mode == ControlPage.MODE_PAUSED || r.mode == ControlPage.MODE_OFF) {
            parts += getString(R.string.selftest_summary_not_enforcing)
        }
        parts += if (r.deepModeRunning) {
            getString(R.string.selftest_summary_deep_on)
        } else {
            getString(R.string.selftest_summary_deep_off)
        }
        return parts.joinToString(" ")
    }

    private fun contextLines(r: SelfTestReport): String = listOf(
        getString(R.string.selftest_context_mode, BlockingSelfTest.modeName(requireContext(), r.mode)),
        getString(
            R.string.selftest_context_response,
            BlockingSelfTest.responseModeName(requireContext(), r.responseMode),
        ),
        getString(
            R.string.selftest_context_deep,
            getString(
                if (r.deepModeRunning) R.string.selftest_context_on
                else R.string.selftest_context_off
            ),
        ),
    ).joinToString("\n")

    private fun openInBrowser() {
        val domain = report?.domain ?: return
        try {
            startActivity(BlockingSelfTest.browserIntent(domain))
        } catch (_: ActivityNotFoundException) {
            laneDetails[2].setText(R.string.selftest_browser_no_app)
        }
    }

    private fun recordBrowser(loaded: Boolean) {
        val current = report ?: return
        val detail = getString(
            if (loaded) R.string.selftest_browser_reported_leaked
            else R.string.selftest_browser_reported_blocked
        )
        val updated = current.withBrowserObservation(loaded, detail)
        report = updated
        render(updated)
    }

    private fun colour(res: Int): Int = ContextCompat.getColor(requireContext(), res)
}
