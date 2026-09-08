package com.bestrom.nullroute.ui

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.SwitchCompat
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.job.UpdateJobService
import com.bestrom.nullroute.qs.TilePrefsActivity
import com.google.android.material.button.MaterialButton

/**
 * Settings: response semantics and the update schedule.
 *
 * ## Response mode is where a user can hurt themselves
 *
 * `EAI_NONAME` is the default because it is byte-identical to a real NXDOMAIN:
 * the app stops, spends no battery retrying, and nothing listens anywhere. The
 * sinkhole is the option that looks familiar (everyone has seen `0.0.0.0` in a
 * hosts file) and behaves nothing like it looks — Linux maps a `connect()` to
 * `0.0.0.0` onto `INADDR_LOOPBACK`, so the app connects **to itself** rather than
 * failing, and whatever it happens to be listening on answers. It is offered
 * because one broken app is a real reason to want it, and it asks for
 * confirmation because a user who picks it from a list of three will otherwise
 * never learn any of that.
 *
 * ## The schedule line reports the scheduler, not the checkbox
 *
 * [UpdateJobService.isScheduled] is asked every time this screen resumes.
 * A `setPersisted` job can be lost without the preference changing, and a user
 * reading "auto-update: on" while nothing ever runs has no way to discover it.
 */
class SettingsFragment : Fragment() {

    private lateinit var responseGroup: RadioGroup
    private lateinit var status: TextView
    private lateinit var autoUpdate: SwitchCompat
    private lateinit var unmetered: SwitchCompat
    private lateinit var scheduleState: TextView
    private lateinit var updateNow: MaterialButton
    private lateinit var privacy: MaterialButton
    private lateinit var tile: MaterialButton
    private lateinit var intro: MaterialButton

    /** Guards the listener while code, rather than the user, moves a control. */
    private var binding = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_settings, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        responseGroup = view.findViewById(R.id.sett_resp_group)
        status = view.findViewById(R.id.sett_status)
        autoUpdate = view.findViewById(R.id.sett_auto_update)
        unmetered = view.findViewById(R.id.sett_unmetered)
        scheduleState = view.findViewById(R.id.sett_schedule_state)
        updateNow = view.findViewById(R.id.sett_update_now)
        privacy = view.findViewById(R.id.sett_privacy)
        tile = view.findViewById(R.id.sett_tile)
        intro = view.findViewById(R.id.sett_intro)

        responseGroup.setOnCheckedChangeListener { _, checkedId ->
            if (binding) return@setOnCheckedChangeListener
            onResponseChosen(modeFor(checkedId))
        }

        autoUpdate.setOnCheckedChangeListener { _, isChecked ->
            if (binding) return@setOnCheckedChangeListener
            Settings.setAutoUpdate(requireContext(), isChecked)
            // schedule() cancels when the preference is off, so one call covers
            // both directions and there is only ever one place that decides.
            UpdateJobService.schedule(requireContext())
            renderSchedule()
        }

        unmetered.setOnCheckedChangeListener { _, isChecked ->
            if (binding) return@setOnCheckedChangeListener
            Settings.setUnmeteredOnly(requireContext(), isChecked)
            // The network constraint is baked into the JobInfo, so the existing
            // job has to be replaced for the change to mean anything.
            UpdateJobService.schedule(requireContext())
            renderSchedule()
        }

        updateNow.setOnClickListener {
            UpdateJobService.runNow(requireContext())
            showStatus(getString(R.string.sett_update_started))
        }

        privacy.setOnClickListener {
            parentFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, PrivacyFragment())
                .addToBackStack(null)
                .commit()
        }

        tile.setOnClickListener {
            startActivity(Intent(requireContext(), TilePrefsActivity::class.java))
        }

        intro.setOnClickListener {
            startActivity(OnboardingActivity.replayIntent(requireContext()))
        }
    }

    override fun onResume() {
        super.onResume()
        bind()
    }

    private fun bind() {
        val context = requireContext()
        binding = true
        responseGroup.check(buttonFor(Settings.responseMode(context)))
        autoUpdate.isChecked = Settings.autoUpdate(context)
        unmetered.isChecked = Settings.unmeteredOnly(context)
        binding = false
        renderSchedule()
    }

    private fun renderSchedule() {
        scheduleState.setText(
            if (UpdateJobService.isScheduled(requireContext())) R.string.sett_schedule_on
            else R.string.sett_schedule_off
        )
    }

    private fun onResponseChosen(mode: Int) {
        if (mode == ControlPage.RESP_SINKHOLE) {
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.sett_resp_sinkhole_confirm_title)
                .setMessage(R.string.sett_resp_sinkhole_confirm_body)
                // Cancelling has to put the radio back, or the screen would show
                // a mode the resolver is not using.
                .setNegativeButton(R.string.rec_cancel) { _, _ -> bind() }
                .setOnCancelListener { bind() }
                .setPositiveButton(R.string.rec_confirm) { _, _ -> apply(mode) }
                .show()
            return
        }
        apply(mode)
    }

    private fun apply(mode: Int) {
        val context = requireContext()
        // Settings.setResponseMode writes the preference and the control byte.
        // The preference is durable; the byte is what the resolver reads, and it
        // silently does nothing when the page is not mapped — so the mapping is
        // checked here and the half-success is reported as one.
        val mapped = ControlPage.open()
        Settings.setResponseMode(context, mode)
        if (mapped) {
            status.visibility = View.GONE
        } else {
            showStatus(getString(R.string.sett_control_unavailable))
        }
    }

    private fun showStatus(message: String) {
        status.text = message
        status.visibility = View.VISIBLE
    }

    private fun buttonFor(mode: Int): Int = when (mode) {
        ControlPage.RESP_NODATA -> R.id.sett_resp_nodata
        ControlPage.RESP_SINKHOLE -> R.id.sett_resp_sinkhole
        else -> R.id.sett_resp_noname
    }

    private fun modeFor(buttonId: Int): Int = when (buttonId) {
        R.id.sett_resp_nodata -> ControlPage.RESP_NODATA
        R.id.sett_resp_sinkhole -> ControlPage.RESP_SINKHOLE
        else -> ControlPage.RESP_NONAME
    }
}
