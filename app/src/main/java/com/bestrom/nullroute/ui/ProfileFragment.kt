package com.bestrom.nullroute.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.RadioButton
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.R
import com.bestrom.nullroute.data.Profile
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.Settings

/**
 * Profile picker.
 *
 * A profile here is a **strictness** choice. In Re-Malwack it was also implicitly
 * a performance choice, because the profile decided how many megabytes of text
 * got linearly rescanned on every cache-missing lookup; that is why it auto-picked
 * one from `MemTotal`. Here every profile compiles to the same table shape and
 * the same ~200 ns lookup, so the only question left for the user is how much
 * breakage they want to trade for how much blocking — which is a question they
 * can actually answer.
 *
 * Each row also names the licence of its sources, because that is what decides
 * whether a list ships with the ROM or is fetched and compiled here. Users of a
 * custom ROM are exactly the audience that cares.
 */
class ProfileFragment : Fragment() {

    private lateinit var list: RecyclerView
    private lateinit var adapter: ProfileAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_profile, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        list = view.findViewById(R.id.profile_list)
        list.layoutManager = LinearLayoutManager(requireContext())

        val profiles = ProfileStore.profiles(requireContext())
        adapter = ProfileAdapter(profiles, Settings.profileId(requireContext())) { chosen ->
            Settings.setProfileId(requireContext(), chosen.id)
            adapter.setSelected(chosen.id)
            view.findViewById<TextView>(R.id.profile_footer)
                .setText(R.string.profile_change_pending)
        }
        list.adapter = adapter
    }

    private class ProfileAdapter(
        private val profiles: List<Profile>,
        private var selectedId: String,
        private val onSelect: (Profile) -> Unit,
    ) : RecyclerView.Adapter<ProfileAdapter.Holder>() {

        class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val radio: RadioButton = view.findViewById(R.id.profile_radio)
            val title: TextView = view.findViewById(R.id.profile_title)
            val description: TextView = view.findViewById(R.id.profile_description)
            val detail: TextView = view.findViewById(R.id.profile_detail)
        }

        fun setSelected(id: String) {
            selectedId = id
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(
                LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_profile, parent, false)
            )

        override fun getItemCount(): Int = profiles.size

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val profile = profiles[position]
            val context = holder.itemView.context

            holder.title.text = profile.displayName
            holder.description.text = profile.description
            holder.radio.isChecked = profile.id == selectedId

            // Say plainly which lists are fetched rather than shipped, and why.
            val fetched = profile.enabledSources.count { !it.licence.bakeable }
            holder.detail.text = context.getString(
                R.string.profile_source_detail,
                profile.enabledSources.size,
                fetched,
            )

            val click = View.OnClickListener { onSelect(profile) }
            holder.itemView.setOnClickListener(click)
            holder.radio.setOnClickListener(click)
        }
    }
}
