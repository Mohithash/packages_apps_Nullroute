package com.bestrom.nullroute.ui

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
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.data.AppPolicyStore
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputEditText

/**
 * Per-app filtering policy — one byte per appId in the shared control page.
 *
 * ## Every control here does something
 *
 * That is the constraint the screen is built around, and it removed a row.
 * `NR_POLICY_STRICT` exists in the ABI, but `nr_evaluate()` tests only for
 * `NR_POLICY_EXEMPT`, so a "Strict" switch would move, write a byte, and change
 * nothing about a single DNS answer. It is not offered, and the footer says why
 * — see [AppPolicyStore].
 *
 * The same rule decides two other details:
 *
 *  * When the control page is not mapped, every switch is **disabled** and a
 *    banner says so. A switch that animates and writes nothing is exactly the
 *    kind of quiet failure the rest of this app is arguing against.
 *  * Nullroute's own row is shown but not switchable, with the reason on the row.
 *    [ControlPage.setUidPolicy] refuses to exempt our own appId because the
 *    liveness probe resolves from this process — an exemption would make Home
 *    report "not filtering" on a healthy device. A refusal the user cannot see
 *    the reason for is indistinguishable from a bug.
 *
 * A uid no installed package claims is labelled "System (uid N)" rather than
 * given an invented name. It stays switchable because its byte is still live in
 * the control page, and switching it off is the only way to clear it.
 */
class AppPolicyFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var banner: TextView
    private lateinit var status: TextView
    private lateinit var search: TextInputEditText
    private lateinit var list: RecyclerView

    private val shown = ArrayList<AppPolicyStore.AppEntry>()
    private var all: List<AppPolicyStore.AppEntry> = emptyList()
    private lateinit var adapter: AppAdapter

    private var controlUsable = false

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_apppolicy, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        banner = view.findViewById(R.id.apps_banner)
        status = view.findViewById(R.id.apps_status)
        search = view.findViewById(R.id.apps_search)
        list = view.findViewById(R.id.apps_list)

        adapter = AppAdapter(shown, { entry, exempt -> setExempt(entry, exempt) }, { controlUsable })
        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter

        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) = applyFilter()
        })
    }

    override fun onResume() {
        super.onResume()
        controlUsable = ControlPage.isMapped || ControlPage.open()
        banner.visibility = if (controlUsable) View.GONE else View.VISIBLE
        load()
    }

    private fun load() {
        status.visibility = View.VISIBLE
        status.setText(R.string.apps_loading)
        val context = requireContext().applicationContext
        NullrouteApp.io.execute {
            // getInstalledApplications is a binder call returning a few hundred
            // records, each of which needs a label lookup of its own. Never on
            // the main thread, and never as part of onCreateView.
            val entries = AppPolicyStore.load(context)
            main.post {
                if (!isAdded) return@post
                all = entries
                status.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
                if (entries.isEmpty()) status.setText(R.string.apps_empty)
                applyFilter()
            }
        }
    }

    private fun applyFilter() {
        val needle = search.text?.toString()?.trim()?.lowercase().orEmpty()
        shown.clear()
        shown.addAll(
            if (needle.isEmpty()) all
            else all.filter { entry ->
                entry.label.lowercase().contains(needle) ||
                    entry.packages.any { it.contains(needle) }
            }
        )
        adapter.notifyDataSetChanged()
    }

    private fun setExempt(entry: AppPolicyStore.AppEntry, exempt: Boolean) {
        val context = requireContext().applicationContext
        when (val result = AppPolicyStore.setExempt(context, entry, exempt)) {
            is AppPolicyStore.Result.Ok -> {
                replace(entry.copy(exempt = exempt))
                toast(getString(R.string.apps_applies_now))
            }

            // Each failure is named, and the row is put back to what the control
            // page actually holds. A switch left in the position the user chose
            // while the byte says otherwise is the lie in miniature.
            is AppPolicyStore.Result.RefusedSelf -> {
                replace(entry)
                toast(getString(R.string.apps_self_reason))
            }

            is AppPolicyStore.Result.NoControlPage -> {
                replace(entry)
                toast(getString(R.string.apps_no_control))
            }

            is AppPolicyStore.Result.Failed -> {
                replace(entry)
                toast(getString(R.string.apps_failed, result.reason))
            }
        }
    }

    private fun replace(entry: AppPolicyStore.AppEntry) {
        all = all.map { if (it.appId == entry.appId) entry else it }
        applyFilter()
    }

    private fun toast(text: String) {
        Toast.makeText(requireContext(), text, Toast.LENGTH_LONG).show()
    }

    private class AppAdapter(
        private val items: List<AppPolicyStore.AppEntry>,
        private val onToggle: (AppPolicyStore.AppEntry, Boolean) -> Unit,
        private val controlUsable: () -> Boolean,
    ) : RecyclerView.Adapter<AppAdapter.Holder>() {

        class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val label: TextView = view.findViewById(R.id.app_label)
            val packageName: TextView = view.findViewById(R.id.app_package)
            val note: TextView = view.findViewById(R.id.app_note)
            val toggle: SwitchMaterial = view.findViewById(R.id.app_switch)
        }

        override fun getItemCount(): Int = items.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false))

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val entry = items[position]
            val context = holder.itemView.context

            holder.label.text = entry.label
            // The state is written out in words next to the package rather than
            // left to the switch position alone: "Exempt" and "Filtered" are the
            // two facts a screenshot in a bug report has to carry, and a switch
            // thumb does not survive being described over a phone call.
            val state = context.getString(
                if (entry.exempt) R.string.apps_exempt_state else R.string.apps_filtered
            )
            val pkg = entry.packages.firstOrNull()
            holder.packageName.text =
                if (pkg.isNullOrEmpty()) state else "$pkg  ·  $state"

            val note = when {
                entry.self -> context.getString(R.string.apps_self_reason)
                entry.unattributed -> context.getString(R.string.apps_unattributed_note)
                entry.shared ->
                    context.getString(R.string.apps_shared_uid, entry.packages.size - 1)
                else -> ""
            }
            holder.note.text = note
            holder.note.visibility = if (note.isEmpty()) View.GONE else View.VISIBLE

            // The listener is cleared before the state is set, or restoring a row
            // after a refused write re-enters onToggle and fights the user.
            holder.toggle.setOnCheckedChangeListener(null)
            holder.toggle.isChecked = entry.exempt
            holder.toggle.contentDescription = context.getString(R.string.apps_exempt)
            holder.toggle.isEnabled = controlUsable() && !entry.self
            holder.toggle.setOnCheckedChangeListener { _, checked ->
                onToggle(entry, checked)
            }
        }
    }
}
