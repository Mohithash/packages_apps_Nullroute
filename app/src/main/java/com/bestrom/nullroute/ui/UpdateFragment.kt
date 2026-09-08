package com.bestrom.nullroute.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ProgressBar
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.build.IndexBuilder
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.net.SourceSync
import com.google.android.material.button.MaterialButton

/**
 * "Update now": fetch, compile, check, promote — with the steps visible.
 *
 * The progress is reported from typed [IndexBuilder.BuildStep] events rather than
 * scraped from log output, and every per-source failure is listed by name. A
 * source that could not be downloaded is a fact the user is entitled to; folding
 * it into a generic "update failed", or worse into a silent success with fewer
 * rules, is how a blocklist quietly stops blocking.
 */
class UpdateFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var lastUpdate: TextView
    private lateinit var profileLine: TextView
    private lateinit var stepLine: TextView
    private lateinit var progress: ProgressBar
    private lateinit var button: MaterialButton
    private lateinit var list: RecyclerView

    private val rows = ArrayList<Row>()
    private val adapter = RowAdapter(rows)

    @Volatile
    private var running = false

    data class Row(val title: String, val detail: String)

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_update, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        lastUpdate = view.findViewById(R.id.update_last)
        profileLine = view.findViewById(R.id.update_profile)
        stepLine = view.findViewById(R.id.update_step)
        progress = view.findViewById(R.id.update_progress)
        button = view.findViewById(R.id.update_button)
        list = view.findViewById(R.id.update_rows)

        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter

        button.setOnClickListener { start() }
        renderIdle()
    }

    private fun renderIdle() {
        val context = requireContext()
        val record = Settings.lastUpdate(context)
        lastUpdate.text = if (!record.everRan) {
            getString(R.string.update_never)
        } else {
            val ago = DateUtils.getRelativeTimeSpanString(
                record.whenMs, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS,
            )
            getString(
                if (record.ok) R.string.update_last_ok else R.string.update_last_failed,
                ago, record.message,
            )
        }

        val profile = ProfileStore.activeProfile(context)
        profileLine.text = getString(
            R.string.update_profile_line,
            profile.displayName,
            profile.enabledSources.size,
        )

        val net = SourceSync.connectivity(context)
        stepLine.text = when {
            !net.connected -> getString(R.string.update_no_network)
            !net.unmetered -> getString(R.string.update_metered)
            else -> getString(R.string.update_ready)
        }

        progress.visibility = View.GONE
        button.isEnabled = !running
        button.setText(R.string.action_update_now)
    }

    private fun start() {
        if (running) return
        running = true
        rows.clear()
        adapter.notifyDataSetChanged()

        progress.visibility = View.VISIBLE
        progress.isIndeterminate = true
        button.isEnabled = false
        stepLine.setText(R.string.update_starting)

        val app = requireContext().applicationContext
        NullrouteApp.io.execute {
            IndexBuilder.run(
                app,
                IndexBuilder.Listener { step -> main.post { if (isAdded) onStep(step) } },
            )
            running = false
            main.post { if (isAdded) renderIdle() }
        }
    }

    private fun onStep(step: IndexBuilder.BuildStep) {
        when (step) {
            is IndexBuilder.BuildStep.Starting ->
                stepLine.setText(R.string.update_starting)

            is IndexBuilder.BuildStep.Fetching -> {
                progress.isIndeterminate = false
                progress.max = step.total
                progress.progress = step.index
                stepLine.text = getString(
                    R.string.update_fetching, step.index + 1, step.total, step.label,
                )
            }

            is IndexBuilder.BuildStep.Fetched -> {
                addRow(getString(R.string.update_row_sources), step.summary)
                step.failures.forEach { addRow(getString(R.string.update_row_unavailable), it) }
            }

            is IndexBuilder.BuildStep.Overlaying ->
                stepLine.setText(R.string.update_overlaying)

            is IndexBuilder.BuildStep.Compiling -> {
                progress.isIndeterminate = true
                stepLine.setText(R.string.update_compiling)
            }

            is IndexBuilder.BuildStep.Compiled -> {
                val s = step.stats
                addRow(
                    getString(R.string.update_row_compiled),
                    getString(
                        R.string.update_row_compiled_detail,
                        s.blockIn, s.blockCollapsed, s.bytes / 1024,
                    ),
                )
                s.sources.filter { it.error != null }.forEach {
                    addRow(it.name, it.error.orEmpty())
                }
            }

            is IndexBuilder.BuildStep.Checking ->
                stepLine.setText(R.string.update_checking)

            is IndexBuilder.BuildStep.Promoting ->
                stepLine.setText(R.string.update_promoting)

            is IndexBuilder.BuildStep.Done -> {
                val outcome = step.outcome
                stepLine.text = outcome.message()
                when (outcome) {
                    is IndexBuilder.Outcome.Success -> {
                        addRow(
                            getString(R.string.update_row_done),
                            getString(
                                R.string.update_row_done_detail,
                                outcome.generation, outcome.elapsedMs / 1000,
                            ),
                        )
                        outcome.warnings.forEach {
                            addRow(getString(R.string.update_row_advisory), it)
                        }
                    }

                    is IndexBuilder.Outcome.Failure ->
                        addRow(getString(R.string.update_row_rejected), outcome.reason)
                }
                progress.visibility = View.GONE
            }
        }
    }

    private fun addRow(title: String, detail: String) {
        rows += Row(title, detail)
        adapter.notifyItemInserted(rows.size - 1)
        list.scrollToPosition(rows.size - 1)
    }

    private class RowAdapter(private val rows: List<Row>) :
        RecyclerView.Adapter<RowAdapter.Holder>() {

        class Holder(view: View) : RecyclerView.ViewHolder(view) {
            val title: TextView = view.findViewById(R.id.row_title)
            val detail: TextView = view.findViewById(R.id.row_detail)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(LayoutInflater.from(parent.context).inflate(R.layout.item_row, parent, false))

        override fun getItemCount(): Int = rows.size

        override fun onBindViewHolder(holder: Holder, position: Int) {
            holder.title.text = rows[position].title
            holder.detail.text = rows[position].detail
        }
    }
}
