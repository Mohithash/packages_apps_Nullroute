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
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

/**
 * "What would this device do with this name?" — answered by the matcher itself.
 *
 * ## Why this screen exists
 *
 * The recurring support report for every DNS filter is "blocking is broken", and
 * it is almost always wrong. The user checks `doubleclick.net`, sees it resolve,
 * and concludes the filter is dead. It is not: the upstream lists deliberately
 * leave that apex — and `googleadservices.com`, and `graph.facebook.com` —
 * resolvable, and block their ad subdomains instead, because blocking the apex
 * takes out Google sign-in, Play billing and Facebook login inside third-party
 * apps. `google-analytics.com`, by contrast, *is* in the lists and *is* blocked.
 *
 * So this screen does two things a plain lookup cannot. It runs the same
 * `nr_evaluate()` netd runs, against the index the device is actually serving —
 * so the answer cannot differ from the device's behaviour — and when the answer
 * is PASS it says so **unambiguously** and explains the omission, rather than
 * leaving a blank space the user fills in with "it is broken".
 *
 * ## Three outcomes, not two
 *
 * `evaluated: false` is neither blocked nor a failure: it is a name the matcher
 * declines to look at at all (an address literal, a single label, `.local`), and
 * PASS is exactly what the resolver does with it. And an index that cannot be
 * read produces "no answer", which is deliberately *not* worded as "not blocked"
 * — those are different facts and collapsing them is how a broken filter comes to
 * look like a working one.
 *
 * This screen reads the index. It does **not** measure whether filtering is live;
 * that is [HomeFragment]'s job, via the probes, and the footer says so.
 */
class QueryFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var inputLayout: TextInputLayout
    private lateinit var input: TextInputEditText
    private lateinit var runButton: MaterialButton
    private lateinit var card: MaterialCardView
    private lateinit var accent: View
    private lateinit var verdict: TextView
    private lateinit var canonical: TextView
    private lateinit var detail: TextView
    private lateinit var ruleLine: TextView
    private lateinit var depthLine: TextView
    private lateinit var sourceLine: TextView
    private lateinit var omissionHeader: TextView
    private lateinit var omission: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_query, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        inputLayout = view.findViewById(R.id.query_input_layout)
        input = view.findViewById(R.id.query_input)
        runButton = view.findViewById(R.id.query_run)
        card = view.findViewById(R.id.query_card)
        accent = view.findViewById(R.id.query_accent)
        verdict = view.findViewById(R.id.query_verdict)
        canonical = view.findViewById(R.id.query_canonical)
        detail = view.findViewById(R.id.query_detail)
        ruleLine = view.findViewById(R.id.query_rule)
        depthLine = view.findViewById(R.id.query_depth)
        sourceLine = view.findViewById(R.id.query_source)
        omissionHeader = view.findViewById(R.id.query_omission_header)
        omission = view.findViewById(R.id.query_omission)

        runButton.setOnClickListener { runQuery() }
        // Named runQuery, not run: kotlin.run is in scope everywhere and a
        // zero-arg member called run() resolving over it is a coin toss for the
        // next reader.
        input.setOnEditorActionListener { _, _, _ ->
            runQuery()
            true
        }
    }

    private fun runQuery() {
        val host = input.text?.toString()?.trim()?.lowercase()?.removeSuffix(".").orEmpty()
        if (host.isEmpty()) {
            inputLayout.error = getString(R.string.query_input_required)
            return
        }
        inputLayout.error = null

        val index = Paths.currentIndex
        if (!index.isFile) {
            // There being no index at all is a different answer from "not
            // blocked", and saying so is the whole discipline of this screen.
            showUnknown(host, getString(R.string.query_index_missing))
            return
        }

        verdict.setText(R.string.query_checking)
        card.visibility = View.VISIBLE
        runButton.isEnabled = false

        NullrouteApp.io.execute {
            val result = Native.query(index.absolutePath, host)
            val labels = host.count { it == '.' } + 1
            main.post {
                if (!isAdded) return@post
                runButton.isEnabled = true
                render(host, labels, result)
            }
        }
    }

    private fun render(host: String, labels: Int, result: Native.QueryVerdict) {
        canonical.text = host
        ruleLine.visibility = View.GONE
        depthLine.visibility = View.GONE
        sourceLine.visibility = View.GONE
        omissionHeader.visibility = View.GONE
        omission.visibility = View.GONE

        if (!result.ok || result.kind == Native.VerdictKind.UNKNOWN) {
            showUnknown(host, getString(R.string.query_unknown_detail))
            return
        }

        when (result.kind) {
            Native.VerdictKind.BLOCK -> {
                verdict.setText(R.string.query_verdict_blocked)
                accent.setBackgroundColor(colour(R.color.nr_status_ok))
                detail.setText(R.string.query_blocked_detail)
                showEvidence(result, labels)
            }

            Native.VerdictKind.REDIRECT -> {
                verdict.setText(R.string.query_verdict_redirected)
                accent.setBackgroundColor(colour(R.color.nr_status_ok))
                detail.text = result.address
                    ?.let { getString(R.string.query_redirect_address, it) }
                    .orEmpty()
                showEvidence(result, labels)
            }

            else -> {
                verdict.setText(R.string.query_verdict_pass)
                accent.setBackgroundColor(colour(R.color.nr_status_unknown))
                detail.setText(
                    if (!result.evaluated) R.string.query_not_evaluated
                    else R.string.query_pass_detail
                )
                showOmissionNote(host)
            }
        }
    }

    private fun showEvidence(result: Native.QueryVerdict, labels: Int) {
        result.rule?.let {
            ruleLine.visibility = View.VISIBLE
            ruleLine.text = getString(R.string.query_matched_rule, it)
        }
        if (result.depth > 0) {
            depthLine.visibility = View.VISIBLE
            depthLine.text = getString(R.string.query_depth, result.depth, labels)
        }
        sourceLine.visibility = View.VISIBLE
        // An unnamed group is not hidden. The number is authoritative and the
        // name comes from manifest.<gen>.json, which a pruned generation may no
        // longer have — saying "group 3, the manifest is gone" is a fact the user
        // can act on, where a blank line is not.
        sourceLine.text = if (result.groupName.isNotEmpty()) {
            getString(R.string.query_source, result.groupName)
        } else {
            getString(R.string.query_source_unnamed, result.group)
        }
    }

    /**
     * The false-"blocking is broken" defence.
     *
     * When the name is one of the three the lists leave alone on purpose, the
     * note is specific to it; otherwise the general explanation is shown, because
     * a user who has just seen PASS on *any* ad-looking domain is the user this
     * text exists for.
     */
    private fun showOmissionNote(host: String) {
        omissionHeader.visibility = View.VISIBLE
        omission.visibility = View.VISIBLE
        val known = DELIBERATE_OMISSIONS.firstOrNull { host == it || host.endsWith(".$it") }
        omission.text = if (known != null) {
            getString(R.string.query_omission_specific, known)
        } else {
            getString(R.string.query_omission_note)
        }
    }

    private fun showUnknown(host: String, reason: String) {
        card.visibility = View.VISIBLE
        canonical.text = host
        verdict.setText(R.string.query_verdict_unknown)
        accent.setBackgroundColor(colour(R.color.nr_status_bad))
        detail.text = reason
        ruleLine.visibility = View.GONE
        depthLine.visibility = View.GONE
        sourceLine.visibility = View.GONE
        omissionHeader.visibility = View.GONE
        omission.visibility = View.GONE
    }

    private fun colour(res: Int): Int = ContextCompat.getColor(requireContext(), res)

    companion object {
        /**
         * Apexes the upstream lists leave resolvable on purpose. Not a
         * denylist-of-the-denylist: these are the three names users actually test
         * with, and each is omitted because blocking it breaks sign-in, billing
         * or app login rather than because it was missed.
         *
         * `google-analytics.com` is deliberately NOT here — it is in the lists
         * and it is blocked, which is what makes it the right thing to suggest
         * checking instead.
         */
        private val DELIBERATE_OMISSIONS = listOf(
            "doubleclick.net",
            "googleadservices.com",
            "graph.facebook.com",
        )
    }
}
