package com.bestrom.nullroute.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.UserPolicy

/**
 * Advanced: the two settings that cost something.
 *
 * ## The switch reflects the control page, never the tap
 *
 * [ControlPage.setCnameUncloak] is the only authority for CNAME uncloaking —
 * there is deliberately no preference mirroring it, because a second copy is a
 * second thing that can disagree. So the switch is re-read from the page after
 * every write and after every resume. If the write failed (page not mapped,
 * SELinux denying `map`) the control springs back and says so, rather than
 * showing a state the resolver does not have.
 *
 * ## Why the cost is stated before the switch
 *
 * Uncloaking is the one feature here that can make DNS measurably more expensive:
 * it parses every answer and evaluates up to eight further names per lookup.
 * That is a genuinely good trade for someone who cares about CNAME
 * trackers and a bad one for someone who does not, which makes it a real choice
 * — and a real choice needs the cost above the control, not under it.
 *
 * ## The scope card is measured, not assumed
 *
 * Enumerating Android users needs `MANAGE_USERS`, which this app does not hold
 * and should not ask for to fill in a caption. [UserPolicy.scope] therefore
 * reports the users the resolver has actually attributed queries to, and says
 * plainly that an empty list is absence of evidence rather than evidence of
 * absence.
 */
class AdvancedFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var cnameSwitch: SwitchCompat
    private lateinit var cnameState: TextView
    private lateinit var scopeUser: TextView
    private lateinit var scopeManaged: TextView
    private lateinit var scopeReach: TextView

    /** Guards the listener while code, rather than the user, moves the switch. */
    private var binding = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_advanced, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        cnameSwitch = view.findViewById(R.id.adv_cname_switch)
        cnameState = view.findViewById(R.id.adv_cname_state)
        scopeUser = view.findViewById(R.id.adv_scope_user)
        scopeManaged = view.findViewById(R.id.adv_scope_managed)
        scopeReach = view.findViewById(R.id.adv_scope_reach)

        cnameSwitch.setOnCheckedChangeListener { _, checked ->
            if (binding) return@setOnCheckedChangeListener
            onCnameToggled(checked)
        }
    }

    override fun onResume() {
        super.onResume()
        renderCname(writeFailed = false)
        refreshScope()
    }

    private fun onCnameToggled(checked: Boolean) {
        // Mapping is checked first so a page that was never mapped produces the
        // "unavailable" message rather than a generic write failure — the two
        // have different fixes and the user is the one who has to tell them
        // apart.
        if (!ControlPage.isMapped) {
            renderCname(writeFailed = false)
            return
        }
        val ok = ControlPage.setCnameUncloak(checked)
        renderCname(writeFailed = !ok)
    }

    /**
     * Re-reads the byte and paints the control from it.
     *
     * `binding` is held across the `isChecked` assignment because setting it
     * re-enters the listener, which would write the page again — harmlessly the
     * first time and endlessly if a write ever failed.
     */
    private fun renderCname(writeFailed: Boolean) {
        val mapped = ControlPage.isMapped
        val on = mapped && ControlPage.cnameUncloak

        binding = true
        cnameSwitch.isChecked = on
        cnameSwitch.isEnabled = mapped
        binding = false

        cnameState.setText(
            when {
                !mapped -> R.string.adv_cname_unavailable
                writeFailed -> R.string.adv_cname_write_failed
                on -> R.string.adv_cname_on
                else -> R.string.adv_cname_off
            }
        )
    }

    private fun refreshScope() {
        scopeUser.setText(R.string.adv_scope_measuring)
        scopeReach.setText(R.string.adv_scope_measuring)
        scopeManaged.visibility = View.GONE

        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            // Opens SQLite; never on the main thread.
            val scope = runCatching { UserPolicy.scope(app) }.getOrNull()
            main.post { if (isAdded) renderScope(scope) }
        }
    }

    private fun renderScope(scope: UserPolicy.Scope?) {
        if (scope == null) {
            // The log could not be read. Say the one thing that is still true —
            // policy is shared — rather than guessing at a user list.
            scopeUser.setText(R.string.adv_scope_no_log)
            scopeReach.setText(R.string.adv_scope_no_log)
            return
        }

        scopeUser.text = getString(R.string.adv_scope_user, scope.userId)
        scopeManaged.visibility = if (scope.managedProfile) View.VISIBLE else View.GONE

        scopeReach.text = when (scope.reach) {
            UserPolicy.Reach.THIS_USER_ONLY ->
                getString(R.string.adv_scope_this_user_only)

            UserPolicy.Reach.EVERY_USER ->
                getString(
                    R.string.adv_scope_every_user,
                    scope.otherUserIds.joinToString(", "),
                )
        }
    }
}
