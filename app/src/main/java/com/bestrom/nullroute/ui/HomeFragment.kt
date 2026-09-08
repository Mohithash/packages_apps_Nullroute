package com.bestrom.nullroute.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.job.HealthWatchdog
import com.google.android.material.button.MaterialButton

/**
 * Home: status, the dual probe, and pause/resume.
 *
 * **The status card is not allowed to lie.** Every word of it comes from
 * [Probes.Health.status], which is computed from the two `.invalid` probes and
 * the mode byte — never from `q_blocked`, never from "the index file exists",
 * never from "the app started successfully". Those are all things that stay true
 * while the filter is dead.
 *
 * The screen therefore has three honest states it can be in, and shows the
 * difference between them: measuring, measured, and unable to measure.
 */
class HomeFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var accent: View
    private lateinit var statusTitle: TextView
    private lateinit var statusDetail: TextView
    private lateinit var probeIdx: TextView
    private lateinit var probeHosts: TextView
    private lateinit var stateProp: TextView
    private lateinit var telemetry: TextView
    private lateinit var pauseButton: MaterialButton
    private lateinit var recheckButton: MaterialButton

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_home, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        accent = view.findViewById(R.id.status_accent)
        statusTitle = view.findViewById(R.id.status_title)
        statusDetail = view.findViewById(R.id.status_detail)
        probeIdx = view.findViewById(R.id.probe_idx_value)
        probeHosts = view.findViewById(R.id.probe_hosts_value)
        stateProp = view.findViewById(R.id.state_prop_value)
        telemetry = view.findViewById(R.id.telemetry_value)
        pauseButton = view.findViewById(R.id.button_pause)
        recheckButton = view.findViewById(R.id.button_recheck)

        pauseButton.setOnClickListener { togglePause() }
        recheckButton.setOnClickListener { refresh() }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        showMeasuring()
        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            val health = runCatching { HealthWatchdog.runCheck(app) }.getOrNull()
            main.post { if (isAdded) render(health) }
        }
    }

    private fun showMeasuring() {
        statusTitle.setText(R.string.status_checking)
        statusDetail.setText(R.string.status_checking_detail)
        accent.setBackgroundColor(colour(R.color.nr_status_unknown))
        probeIdx.setText(R.string.probe_pending)
        probeHosts.setText(R.string.probe_pending)
        recheckButton.isEnabled = false
    }

    private fun render(health: Probes.Health?) {
        recheckButton.isEnabled = true

        if (health == null) {
            // Measuring itself failed. Saying "Protected" here would be the exact
            // failure this screen exists to prevent.
            statusTitle.setText(R.string.status_unknown)
            statusDetail.setText(R.string.status_unknown_detail)
            accent.setBackgroundColor(colour(R.color.nr_status_unknown))
            return
        }

        val status = health.status()
        val (titleRes, detailRes, colourRes) = when (status) {
            Probes.FilterStatus.PROTECTED -> Triple(
                R.string.status_protected,
                R.string.status_protected_detail,
                R.color.nr_status_ok,
            )

            Probes.FilterStatus.PROTECTED_NO_L0 -> Triple(
                R.string.status_protected,
                R.string.status_protected_no_l0_detail,
                R.color.nr_status_ok,
            )

            Probes.FilterStatus.LIMITED_L0_ONLY -> Triple(
                R.string.status_limited,
                R.string.status_limited_detail,
                R.color.nr_status_warn,
            )

            Probes.FilterStatus.NOT_FILTERING -> Triple(
                R.string.status_not_filtering,
                R.string.status_not_filtering_detail,
                R.color.nr_status_bad,
            )

            // Pausing and switching off do NOT disable L0. The resolver only
            // skips the hosts scan while it is enforcing (hostsLayerSuperseded()
            // requires mode == ENFORCE), so a paused device is still blocking the
            // baked list. Which of each pair applies is decided by what probe B
            // actually answered, not by assumption.
            Probes.FilterStatus.PAUSED -> Triple(
                R.string.status_paused,
                if (health.hostsLayerLive) {
                    R.string.status_paused_detail_l0
                } else {
                    R.string.status_paused_detail
                },
                R.color.nr_status_warn,
            )

            Probes.FilterStatus.OFF -> Triple(
                R.string.status_off,
                if (health.hostsLayerLive) {
                    R.string.status_off_detail_l0
                } else {
                    R.string.status_off_detail
                },
                R.color.nr_status_warn,
            )

            Probes.FilterStatus.KILLED -> Triple(
                R.string.status_killed,
                if (health.hostsLayerLive) {
                    R.string.status_killed_detail_l0
                } else {
                    R.string.status_killed_detail
                },
                R.color.nr_status_warn,
            )

            Probes.FilterStatus.UNKNOWN -> Triple(
                R.string.status_unknown,
                R.string.status_unknown_detail,
                R.color.nr_status_unknown,
            )
        }

        statusTitle.setText(titleRes)
        statusDetail.setText(detailRes)
        accent.setBackgroundColor(colour(colourRes))

        // The probe rows are shown even when the headline is good, because they
        // are the evidence for it. A status card whose reasoning is hidden is a
        // status card the user has to take on faith.
        probeIdx.text = idxProbeText(health)
        probeHosts.text =
            if (health.hostsLayerLive) getString(R.string.probe_ok, Probes.HOSTS_EXPECT)
            else getString(R.string.probe_failed)
        stateProp.text = health.stateProp

        val t = ControlPage.telemetry()
        telemetry.text = if (!t.mapped) {
            getString(R.string.telemetry_unavailable)
        } else {
            getString(
                R.string.telemetry_counts,
                t.queriesBlocked,
                t.queriesTotal,
                t.mappedGeneration,
            )
        }

        pauseButton.setText(
            if (health.mode == ControlPage.MODE_ENFORCE) R.string.action_pause
            else R.string.action_resume
        )
        pauseButton.isEnabled = ControlPage.isMapped
    }

    /**
     * The probe-A row.
     *
     * A failure only means something when the filter was in a position to answer.
     * [Probes.sample] skips probe A entirely under the kill switch and under any
     * non-enforcing mode, because `nr_evaluate()` returns PASS before it reaches
     * the redirect table in both cases — so "no answer" there is arithmetic, not
     * evidence, and a red cross the user cannot act on would train them to ignore
     * the row that matters.
     */
    private fun idxProbeText(health: Probes.Health): String = when {
        health.resolverHookLive -> getString(R.string.probe_ok, Probes.IDX_EXPECT)
        health.killSwitch -> getString(R.string.probe_killed)
        health.mode == ControlPage.MODE_PAUSED -> getString(R.string.probe_paused)
        health.mode != ControlPage.MODE_ENFORCE -> getString(R.string.probe_off)
        else -> getString(R.string.probe_failed)
    }

    private fun colour(res: Int): Int = ContextCompat.getColor(requireContext(), res)

    private fun togglePause() {
        if (!ControlPage.open()) return
        val next = if (ControlPage.mode == ControlPage.MODE_ENFORCE) {
            ControlPage.MODE_PAUSED
        } else {
            ControlPage.MODE_ENFORCE
        }
        ControlPage.setMode(next)
        refresh()
    }
}
