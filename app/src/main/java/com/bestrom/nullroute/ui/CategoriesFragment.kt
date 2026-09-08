package com.bestrom.nullroute.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.R
import com.bestrom.nullroute.data.Categories
import com.google.android.material.switchmaterial.SwitchMaterial

/**
 * The add-on toggles, with the consequence on the row.
 *
 * ## Why the consequence is not behind a tap
 *
 * Two of these switches read **backwards** from every other toggle in Android.
 * `Anti-fraud fingerprinting` and `Attribution / deep links` are
 * [Categories.CategoryKind.ALLOW_CARVEOUT]s: those domains are allowed by
 * default — compiled in as allow rules that strip them back out of every
 * imported list — and turning the switch ON *stops* allowing them. A user who
 * reads "Anti-fraud fingerprinting" as a protective feature and flips it on has
 * just broken their banking app, and will not connect the two.
 *
 * So each row states, in one clause, what ON costs, and the three switches with a
 * named victim also carry a confirmation dialog naming it:
 *
 *  * DoH / VPN / proxy bypass breaks the user's **own** VPN and private DNS.
 *  * Anti-fraud breaks **banking** and payment apps.
 *  * Attribution breaks **delivery** and ride-hailing onboarding.
 *
 * §10.3.4 is where those come from, and the point of quoting them here is that
 * the symptoms — "the app spins forever", "onboarding loops" — are impossible for
 * a user to attribute to a DNS filter after the fact. The only place the warning
 * can land is the moment before the tap.
 *
 * ## What a change does, and when
 *
 * Nothing immediately. The set is compiled into the index at the next build, and
 * the footer says so rather than letting a switch imply an instant effect it does
 * not have.
 */
class CategoriesFragment : Fragment() {

    private lateinit var list: RecyclerView
    private lateinit var adapter: CategoryAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_categories, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        list = view.findViewById(R.id.cats_list)
        list.layoutManager = LinearLayoutManager(requireContext())

        // Categories.all() is a function rather than a table because the OEM row
        // depends on ro.product.brand; re-reading it here keeps that honest on a
        // build where the property is set late.
        val categories = Categories.all()
        val state = LinkedHashMap<String, Boolean>()
        categories.forEach { state[it.id] = Categories.isEnabled(requireContext(), it) }

        adapter = CategoryAdapter(categories, state) { category, wanted ->
            onToggle(category, wanted)
        }
        list.adapter = adapter
    }

    private fun onToggle(category: Categories.Category, wanted: Boolean) {
        // Confirmation is asked only on the way IN. Turning a breaking category
        // back off returns the device to a state that works, and putting a
        // dialog in front of that would train the user to dismiss dialogs.
        if (wanted && category.needsConfirmation) {
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.cats_confirm_title)
                .setMessage(confirmationFor(category))
                .setPositiveButton(R.string.cats_confirm_enable) { _, _ -> apply(category, true) }
                .setNegativeButton(R.string.cats_confirm_cancel) { _, _ ->
                    adapter.setEnabled(category.id, false)
                }
                .setOnCancelListener { adapter.setEnabled(category.id, false) }
                .show()
            return
        }
        apply(category, wanted)
    }

    private fun apply(category: Categories.Category, enabled: Boolean) {
        Categories.setEnabled(requireContext(), category.id, enabled)
        adapter.setEnabled(category.id, enabled)
    }

    /**
     * The specific victim, not a generic warning. [Categories.FpRisk] already
     * carries a short label and a detail string; this dialog spells out the
     * failure the user will otherwise experience as an unexplained hang.
     */
    private fun confirmationFor(category: Categories.Category): Int = when (category.risk) {
        Categories.FpRisk.BREAKS_OWN_VPN -> R.string.cats_confirm_vpn
        Categories.FpRisk.BREAKS_BANKING -> R.string.cats_confirm_banking
        Categories.FpRisk.BREAKS_DELIVERY -> R.string.cats_confirm_delivery
        else -> category.risk.detailRes
    }

    private class CategoryAdapter(
        private val categories: List<Categories.Category>,
        private val state: MutableMap<String, Boolean>,
        private val onToggle: (Categories.Category, Boolean) -> Unit,
    ) : RecyclerView.Adapter<CategoryAdapter.Holder>() {

        class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val title: TextView = view.findViewById(R.id.cat_title)
            val summary: TextView = view.findViewById(R.id.cat_summary)
            val consequence: TextView = view.findViewById(R.id.cat_consequence)
            val chip: TextView = view.findViewById(R.id.cat_risk_chip)
            val size: TextView = view.findViewById(R.id.cat_size)
            val riskDetail: TextView = view.findViewById(R.id.cat_risk_detail)
            val toggle: SwitchMaterial = view.findViewById(R.id.cat_switch)
        }

        fun setEnabled(id: String, enabled: Boolean) {
            state[id] = enabled
            val position = categories.indexOfFirst { it.id == id }
            if (position >= 0) notifyItemChanged(position)
        }

        override fun getItemCount(): Int = categories.size

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(
                LayoutInflater.from(parent.context)
                    .inflate(R.layout.item_category, parent, false)
            )

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val category = categories[position]
            val context = holder.itemView.context

            holder.title.setText(category.titleRes)
            holder.summary.setText(category.summaryRes)

            // Categories.onMeansRes() is the single source for this clause, so
            // the row and the data model cannot come to disagree about which way
            // a carve-out points.
            holder.consequence.setText(category.onMeansRes())

            holder.chip.setText(category.risk.labelRes)
            holder.chip.setTextColor(ContextCompat.getColor(context, chipColour(category.risk)))
            holder.riskDetail.setText(category.risk.detailRes)

            holder.size.text = context.getString(
                if (category.kind == Categories.CategoryKind.ALLOW_CARVEOUT) {
                    R.string.cats_carveout_domains
                } else {
                    R.string.cats_approx_domains
                },
                String.format("%,d", category.approxDomains),
            )

            holder.toggle.setOnCheckedChangeListener(null)
            holder.toggle.isChecked = state[category.id] ?: category.defaultOn
            holder.toggle.setOnCheckedChangeListener { _, checked ->
                onToggle(category, checked)
            }
        }

        /**
         * Amber for anything with a named victim, not red: these are legitimate
         * choices with a cost, not mistakes. Red is reserved for the Home screen,
         * where it means the filter is not running.
         */
        private fun chipColour(risk: Categories.FpRisk): Int = when (risk) {
            Categories.FpRisk.LOW -> R.color.nr_status_ok
            Categories.FpRisk.MEDIUM -> R.color.nr_status_warn
            else -> R.color.nr_status_bad
        }
    }
}
