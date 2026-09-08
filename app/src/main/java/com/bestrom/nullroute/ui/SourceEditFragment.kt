package com.bestrom.nullroute.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
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
import com.bestrom.nullroute.data.Profile
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.SourceCatalog
import com.bestrom.nullroute.data.SourceRef
import com.bestrom.nullroute.data.SourceRole
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

/**
 * The source list of the active profile, and the user's edits to it.
 *
 * ## Three files, and why the base one is read-only
 *
 * The shipped profile lives inside a verity-protected image and cannot be
 * written, which turns out to be the right design rather than a limitation: an
 * OTA can change what BALANCED means without discarding the user's edits, and a
 * source the user removed does not come back the next time upstream adds it.
 * Edits are therefore an overlay — `<id>_added.txt` and `<id>_removed.txt` — and
 * a tombstone matches on URL rather than position, so reordering the base file
 * resurrects nothing. All of that is [ProfileStore]'s; this screen is its face.
 *
 * ## Off is not gone
 *
 * The switch writes an `# OFF #` marker, not a deletion, so a source toggled off
 * and on again keeps its label and its place. Remove is the separate,
 * destructive action, and the two are not the same control wearing different
 * labels.
 *
 * ## Block or allow is a choice, not a property of the file
 *
 * The role toggle on the add form exists because no amount of parsing can tell
 * the two apart: HaGeZi publishes `blocklist-referral` and `whitelist-referral`
 * as the **same 1,604 domains** with opposite intent. Sniffing would get it
 * wrong half the time and invert every entry in the list when it did.
 *
 * ## What editing does, and when
 *
 * It changes what is fetched, not what is currently blocked. The footer says so;
 * the index is unchanged until the next update compiles one.
 */
class SourceEditFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var header: TextView
    private lateinit var urlLayout: TextInputLayout
    private lateinit var url: TextInputEditText
    private lateinit var role: MaterialButtonToggleGroup
    private lateinit var addButton: MaterialButton
    private lateinit var resetButton: MaterialButton
    private lateinit var list: RecyclerView

    private val sources = ArrayList<SourceRef>()
    private lateinit var adapter: SourceAdapter

    private var profile: Profile? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_sourceedit, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        header = view.findViewById(R.id.srcedit_header)
        urlLayout = view.findViewById(R.id.srcedit_url_layout)
        url = view.findViewById(R.id.srcedit_url)
        role = view.findViewById(R.id.srcedit_role)
        addButton = view.findViewById(R.id.srcedit_add)
        resetButton = view.findViewById(R.id.srcedit_reset)
        list = view.findViewById(R.id.srcedit_list)

        role.check(R.id.srcedit_role_block)

        adapter = SourceAdapter(
            sources,
            onToggle = { ref, enabled -> setEnabled(ref, enabled) },
            onRemove = { ref -> remove(ref) },
        )
        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter

        addButton.setOnClickListener { add() }
        resetButton.setOnClickListener { reset() }
    }

    override fun onResume() {
        super.onResume()
        reload()
    }

    private fun reload() {
        val context = requireContext().applicationContext
        NullrouteApp.io.execute {
            // Reads three files off /data/misc and, on a device with a shipped
            // profile directory, the image copy too. Off the main thread.
            val active = ProfileStore.activeProfile(context)
            val hasOverlay = ProfileStore.hasOverlay(active.id)
            main.post {
                if (!isAdded) return@post
                profile = active
                header.text = getString(R.string.srcedit_header, active.displayName)
                resetButton.isEnabled = hasOverlay
                sources.clear()
                sources.addAll(active.sources)
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun add() {
        val profileId = profile?.id ?: return
        val raw = url.text?.toString()?.trim().orEmpty()
        if (!raw.startsWith("https://") && !raw.startsWith("http://")) {
            urlLayout.error = getString(R.string.srcedit_bad_url)
            return
        }
        urlLayout.error = null

        val chosenRole =
            if (role.checkedButtonId == R.id.srcedit_role_allow) SourceRole.ALLOW
            else SourceRole.BLOCK

        // A URL the catalogue knows still goes into _added.txt: the catalogue
        // describes what we ship, and conflating that with "you asked for this"
        // would let a later OTA drop the user's choice along with the entry.
        val ref = SourceRef(
            url = raw,
            label = SourceCatalog.byUrl(raw)?.label ?: hostOf(raw),
            enabled = true,
            userAdded = true,
            role = chosenRole,
        )

        NullrouteApp.io.execute {
            val ok = ProfileStore.addSource(profileId, ref)
            val duplicate = !ok && sources.any { it.url == raw }
            main.post {
                if (!isAdded) return@post
                when {
                    ok -> {
                        url.setText("")
                        toast(getString(R.string.srcedit_added))
                    }
                    duplicate -> toast(getString(R.string.srcedit_duplicate))
                    else -> toast(getString(R.string.srcedit_write_failed))
                }
                reload()
            }
        }
    }

    private fun setEnabled(ref: SourceRef, enabled: Boolean) {
        val profileId = profile?.id ?: return
        val context = requireContext().applicationContext
        NullrouteApp.io.execute {
            val ok = ProfileStore.setSourceEnabled(context, profileId, ref.url, enabled)
            main.post {
                if (!isAdded) return@post
                if (!ok) toast(getString(R.string.srcedit_write_failed))
                reload()
            }
        }
    }

    private fun remove(ref: SourceRef) {
        val profileId = profile?.id ?: return
        NullrouteApp.io.execute {
            val ok = ProfileStore.removeSource(profileId, ref.url)
            main.post {
                if (!isAdded) return@post
                toast(getString(if (ok) R.string.srcedit_removed else R.string.srcedit_write_failed))
                reload()
            }
        }
    }

    private fun reset() {
        val profileId = profile?.id ?: return
        NullrouteApp.io.execute {
            val ok = ProfileStore.resetOverlay(profileId)
            main.post {
                if (!isAdded) return@post
                toast(getString(if (ok) R.string.srcedit_reset_done else R.string.srcedit_reset_none))
                reload()
            }
        }
    }

    private fun hostOf(value: String): String =
        runCatching { java.net.URI(value).host ?: value }.getOrDefault(value)

    private fun toast(text: String) {
        Toast.makeText(requireContext(), text, Toast.LENGTH_SHORT).show()
    }

    private class SourceAdapter(
        private val items: List<SourceRef>,
        private val onToggle: (SourceRef, Boolean) -> Unit,
        private val onRemove: (SourceRef) -> Unit,
    ) : RecyclerView.Adapter<SourceAdapter.Holder>() {

        class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val label: TextView = view.findViewById(R.id.source_label)
            val url: TextView = view.findViewById(R.id.source_url)
            val licence: TextView = view.findViewById(R.id.source_licence)
            val badges: TextView = view.findViewById(R.id.source_badges)
            val toggle: SwitchMaterial = view.findViewById(R.id.source_switch)
            val remove: MaterialButton = view.findViewById(R.id.source_remove)
        }

        override fun getItemCount(): Int = items.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_source, parent, false))

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val ref = items[position]
            val context = holder.itemView.context

            holder.label.text = ref.label
            holder.url.text = ref.url

            // Licence.summary() already says the operative thing — whether the
            // content may ship with the ROM or must be compiled here — so it is
            // printed rather than reduced to an SPDX id the user must look up.
            holder.licence.text = ref.licence.summary()

            val badges = ArrayList<String>(3)
            badges += if (ref.userAdded) {
                context.getString(R.string.srcedit_user_added)
            } else {
                context.getString(R.string.srcedit_shipped)
            }
            badges += context.getString(
                if (ref.role == SourceRole.ALLOW) R.string.srcedit_role_allow
                else R.string.srcedit_role_block
            )
            if (!ref.enabled) badges += context.getString(R.string.srcedit_disabled)

            val entry = ref.catalogEntry
            if (entry != null) {
                badges += context.getString(
                    R.string.srcedit_approx,
                    String.format("%,d", entry.approxDomains),
                )
            } else {
                badges += context.getString(R.string.srcedit_unknown_source)
            }
            holder.badges.text = badges.joinToString("  ·  ")

            holder.toggle.setOnCheckedChangeListener(null)
            holder.toggle.isChecked = ref.enabled
            holder.toggle.setOnCheckedChangeListener { _, checked -> onToggle(ref, checked) }
            holder.remove.setOnClickListener { onRemove(ref) }
        }
    }
}
