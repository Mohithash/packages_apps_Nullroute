package com.bestrom.nullroute.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.deep.DeepVpnService
import com.bestrom.nullroute.deep.DeepWatchdog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.switchmaterial.SwitchMaterial

/**
 * The Deep-mode switch.
 *
 * Deep mode is the only layer that reaches Chrome, WebView and every other app
 * that runs its own resolver, and it is the only feature in Nullroute that costs
 * the user something they may already be using: Android allows exactly one
 * `VpnService` at a time, so turning this on means their work VPN cannot
 * connect. That trade is stated on the screen itself
 * ([R.string.deepui_summary]) and again in the consent sheet before the system's
 * own VPN dialog, which does not mention it at all.
 *
 * **Three things on this screen are deliberately not optimistic:**
 *
 *  * "On" is only claimed once the tunnel has answered its own `.invalid` probe.
 *    An established tunnel that is not actually carrying DNS looks identical to a
 *    working one from every API Android exposes, and that is exactly the state
 *    [DeepWatchdog] exists to catch — so until the probe answers, this says
 *    "unverified" and shows amber.
 *  * The auto-disable history is shown whenever the watchdog has ever fired. A
 *    switch that moved by itself, with no explanation, is indistinguishable from
 *    a bug; leaving the reason on screen is what makes the automatic behaviour
 *    legible instead of alarming.
 *  * The scope card is on the screen, not behind a link, and the self-test button
 *    sits next to the switch. The honest answer to "does this actually block
 *    Chrome on my phone" is a measurement, not a paragraph.
 */
class DeepModeFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var switch: SwitchMaterial
    private lateinit var stateAccent: View
    private lateinit var stateText: TextView
    private lateinit var privateDns: TextView
    private lateinit var defaultReason: TextView
    private lateinit var historyCard: MaterialCardView
    private lateinit var historyBody: TextView
    private lateinit var historyRule: TextView
    private lateinit var testButton: MaterialButton
    private lateinit var recheckButton: MaterialButton

    /** Guards the listener against the programmatic writes in [render]. */
    private var updatingSwitch = false

    /**
     * A consistent view of Deep mode's state, assembled off the main thread.
     *
     * [Probes.sample] issues real DNS lookups and [DeepWatchdog.resolveDefault]
     * samples the probes on first run, so neither may be called from
     * `onResume()` directly.
     */
    private class Snapshot(
        val enabled: Boolean,
        val running: Boolean,
        val probeAnswered: Boolean,
        val onRom: Boolean,
        val privateDnsStrict: Boolean,
        val autoDisabledReason: String?,
        val lastError: String?,
        val failuresInWindow: Int,
        val mostRecentFailureMs: Long,
    )

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_deepmode, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        switch = view.findViewById(R.id.deep_switch)
        stateAccent = view.findViewById(R.id.deep_state_accent)
        stateText = view.findViewById(R.id.deep_state_text)
        privateDns = view.findViewById(R.id.deep_private_dns)
        defaultReason = view.findViewById(R.id.deep_default_reason)
        historyCard = view.findViewById(R.id.deep_history_card)
        historyBody = view.findViewById(R.id.deep_history_body)
        historyRule = view.findViewById(R.id.deep_history_rule)
        testButton = view.findViewById(R.id.deep_button_test)
        recheckButton = view.findViewById(R.id.deep_button_recheck)

        switch.setOnCheckedChangeListener { _, checked ->
            if (updatingSwitch) return@setOnCheckedChangeListener
            if (checked) askForConsent() else turnOff()
        }
        testButton.setOnClickListener { openSelfTest() }
        recheckButton.setOnClickListener { refresh() }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        recheckButton.isEnabled = false
        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            val snapshot = runCatching { sample(app) }.getOrNull()
            main.post { if (isAdded) render(snapshot) }
        }
    }

    private fun sample(context: Context): Snapshot {
        // resolveDefault() decides the first-run default ONCE and persists it, so
        // calling it here is idempotent after the first pass. It has to run
        // before isEnabled() is read or the very first render would show "off"
        // for a device where the default is on.
        val enabled = DeepWatchdog.resolveDefault(context)
        val health = Probes.sample()
        val failures = failureTimestamps(context)
        return Snapshot(
            enabled = enabled,
            running = DeepVpnService.isRunning,
            probeAnswered = health.deepModeLive,
            onRom = health.stateProp.isNotEmpty() && health.stateProp != "unknown",
            privateDnsStrict = DeepVpnService.privateDnsStrict(context),
            autoDisabledReason = DeepWatchdog.autoDisabledReason(context),
            lastError = DeepWatchdog.lastError(context),
            failuresInWindow = failures.size,
            mostRecentFailureMs = failures.maxOrNull() ?: 0L,
        )
    }

    private fun render(s: Snapshot?) {
        recheckButton.isEnabled = true

        if (s == null) {
            stateText.setText(R.string.deepui_unavailable)
            stateAccent.setBackgroundColor(colour(R.color.nr_status_unknown))
            return
        }

        updatingSwitch = true
        switch.isChecked = s.enabled
        updatingSwitch = false

        val (textRes, colourRes) = when {
            // The watchdog's decision outranks everything below it: the switch is
            // off, and the history card says who moved it.
            s.autoDisabledReason != null -> R.string.deepui_state_off to R.color.nr_status_warn

            !s.enabled && s.onRom -> R.string.deepui_state_off to R.color.nr_status_unknown
            !s.enabled -> R.string.deepui_state_off_norom to R.color.nr_status_warn

            // Enabled but no service: either it is still coming up, or Android
            // revoked it. Both are amber; neither is "on".
            !s.running -> R.string.deepui_state_enabled_not_running to R.color.nr_status_warn

            s.probeAnswered -> R.string.deepui_state_on to R.color.nr_status_ok
            else -> R.string.deepui_state_unverified to R.color.nr_status_warn
        }
        stateText.setText(textRes)
        stateAccent.setBackgroundColor(colour(colourRes))

        privateDns.visibility = if (s.privateDnsStrict) View.VISIBLE else View.GONE

        defaultReason.setText(
            if (s.onRom) R.string.deep_default_off_reason else R.string.deep_default_on_reason
        )

        renderHistory(s)
    }

    /**
     * The auto-disable history.
     *
     * Shown whenever there is anything to show — a standing auto-disable, or a
     * recorded failure from a session that recovered. `lastError` alone is worth
     * surfacing: it means a tunnel died at least once without reaching the
     * three-strike rule, which is the difference between "Deep mode is flaky
     * here" and "Deep mode has never had a problem on this device".
     */
    private fun renderHistory(s: Snapshot) {
        val reason = s.autoDisabledReason
        val lastError = s.lastError
        if (reason == null && lastError == null && s.failuresInWindow == 0) {
            historyCard.visibility = View.GONE
            return
        }
        historyCard.visibility = View.VISIBLE

        val lines = ArrayList<String>(4)
        if (reason != null) lines += getString(R.string.deepui_history_reason, reason)
        if (lastError != null && lastError != reason) {
            lines += getString(R.string.deepui_history_last_error, lastError)
        }
        if (s.failuresInWindow > 0 && s.mostRecentFailureMs > 0L) {
            lines += resources.getQuantityString(
                R.plurals.deepui_history_recent,
                s.failuresInWindow,
                s.failuresInWindow,
                DateUtils.getRelativeTimeSpanString(s.mostRecentFailureMs).toString(),
            )
        }
        if (reason != null) lines += getString(R.string.deepui_history_cleared)
        historyBody.text = lines.joinToString("\n\n")

        historyRule.text = getString(
            R.string.deepui_history_rule,
            DeepWatchdog.MAX_FAILURES,
            (DeepWatchdog.WINDOW_MS / 60_000L).toInt(),
        )
    }

    // ---- turning it on and off ---------------------------------------------

    /**
     * Our consent sheet, then the system's.
     *
     * [R.string.deep_consent_body] is shown first because Android's VPN dialog
     * says nothing about the VPN slot being exclusive, and nothing about what
     * Deep mode still cannot block. Answering the platform dialog without either
     * fact is not informed consent, whatever the platform thinks.
     */
    private fun askForConsent() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.deep_consent_title)
            .setMessage(R.string.deep_consent_body)
            .setPositiveButton(R.string.deep_consent_continue) { _, _ -> requestVpn() }
            .setNegativeButton(android.R.string.cancel) { _, _ -> revertSwitch() }
            .setOnCancelListener { revertSwitch() }
            .show()
    }

    @Suppress("DEPRECATION") // Fragment.startActivityForResult: VpnService.prepare()
    // returns an Intent that must be launched for result from an Activity, and
    // this is the API the deep/ integration contract specifies. The androidx
    // ActivityResult API would work equally well; it is not worth the churn.
    private fun requestVpn() {
        val consent = runCatching { DeepVpnService.prepareIntent(requireContext()) }.getOrNull()
        if (consent == null) {
            // Already the prepared VPN — no dialog to show, and no consent to
            // ask for that the user has not already given.
            enable()
        } else {
            startActivityForResult(consent, RC_VPN_CONSENT)
        }
    }

    // Paired with the startActivityForResult above; deprecated on Fragment, but
    // still the delivery path for the result of a call made through that API.
    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != RC_VPN_CONSENT) return
        if (resultCode == Activity.RESULT_OK) {
            enable()
        } else {
            // The user said no. Deep mode stays off and is NOT asked for again
            // unprompted; the switch is the only thing that may re-ask.
            revertSwitch()
            stateText.setText(R.string.deepui_consent_declined)
            stateAccent.setBackgroundColor(colour(R.color.nr_status_unknown))
        }
    }

    private fun enable() {
        val context = requireContext().applicationContext
        DeepWatchdog.setEnabled(context, true)
        DeepVpnService.start(context)
        // The tunnel needs a moment before its probe can answer, so the first
        // render after this legitimately says "unverified" rather than "on".
        refresh()
    }

    private fun turnOff() {
        val context = requireContext().applicationContext
        DeepWatchdog.setEnabled(context, false)
        DeepVpnService.stop(context)
        refresh()
    }

    private fun revertSwitch() {
        updatingSwitch = true
        switch.isChecked = false
        updatingSwitch = false
    }

    // ---- the self-test ------------------------------------------------------

    /**
     * Swaps in [SelfTestFragment] inside whatever container is hosting this
     * fragment, rather than naming `R.id.fragment_container` — this screen is
     * reachable from the bottom navigation and from the Settings entry activity,
     * and the two use different hosts.
     */
    private fun openSelfTest() {
        val containerId = (view?.parent as? View)?.id ?: View.NO_ID
        if (containerId == View.NO_ID) {
            testButton.isEnabled = false
            return
        }
        parentFragmentManager.beginTransaction()
            .replace(containerId, SelfTestFragment())
            .addToBackStack(null)
            .commit()
    }

    // ---- the watchdog's failure list ---------------------------------------

    /**
     * The failure timestamps still inside the watchdog's window.
     *
     * Read directly out of the Deep-mode preferences because [DeepWatchdog]
     * exposes the *reason* it disabled but not the *history* behind it, and this
     * screen is the one place that history means something. Read-only, and
     * tolerant of anything it finds: the same file is written by the tunnel
     * thread on a path where the process may be about to die, so a half-written
     * or absent value is a normal outcome and not an error to report.
     *
     * The file and key names are duplicated from `DeepWatchdog`'s private
     * constants. docs/needs-deep.md asks for a `failureHistory()` accessor there
     * so this duplication can be deleted; until it exists, a wrong name here
     * degrades to "no history", never to a wrong history.
     */
    private fun failureTimestamps(context: Context): List<Long> {
        val prefs = runCatching {
            Paths.de(context).getSharedPreferences(DEEP_PREFS, Context.MODE_PRIVATE)
        }.getOrNull() ?: return emptyList()

        val raw = runCatching { prefs.getString(DEEP_KEY_FAILURES, "") }.getOrNull().orEmpty()
        if (raw.isEmpty()) return emptyList()

        val now = System.currentTimeMillis()
        return raw.split(',').mapNotNull { it.trim().toLongOrNull() }
            .filter { it in (now - DeepWatchdog.WINDOW_MS)..now }
    }

    private fun colour(res: Int): Int = ContextCompat.getColor(requireContext(), res)

    companion object {
        private const val RC_VPN_CONSENT = 4001

        private const val DEEP_PREFS = "nullroute_deep"
        private const val DEEP_KEY_FAILURES = "failures"
    }
}
