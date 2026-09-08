package com.bestrom.nullroute.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.bestrom.nullroute.R
import com.bestrom.nullroute.data.Settings
import com.google.android.material.button.MaterialButton

/**
 * First-run introduction: four pages, and the second one is the limits.
 *
 * ## Why the limits come before the benefits
 *
 * A DNS-name filter cannot block an ad served from the same domain as the
 * content around it, and it does not see traffic from an app that resolves names
 * itself — Chrome being the one every user has. Those are not bugs to be fixed
 * later; they are what "filter at the name layer" means. A user told this on day
 * one treats a served ad as expected behaviour. The same user, told nothing,
 * finds the ad on day three and concludes the app is broken or lying — and the
 * usual reaction is to install a second blocker on top, which makes the device
 * measurably worse.
 *
 * So page two is titled "What it cannot do" and page one is deliberately short.
 *
 * ## Why this is an Activity and not a fragment
 *
 * It runs before the tabs make sense, it must be launchable again from Settings
 * without disturbing the tab that is showing, and it has to be finishable from
 * the notification-free first-boot path. None of that fits the single-container
 * tab host in MainActivity.
 */
class OnboardingActivity : AppCompatActivity() {

    private lateinit var step: TextView
    private lateinit var title: TextView
    private lateinit var body: TextView
    private lateinit var skip: MaterialButton
    private lateinit var back: MaterialButton
    private lateinit var next: MaterialButton

    private var page = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        step = findViewById(R.id.onb_step)
        title = findViewById(R.id.onb_page_title)
        body = findViewById(R.id.onb_page_body)
        skip = findViewById(R.id.onb_skip)
        back = findViewById(R.id.onb_back)
        next = findViewById(R.id.onb_next)

        page = savedInstanceState?.getInt(KEY_PAGE) ?: 0

        skip.setOnClickListener { finishOnboarding() }
        back.setOnClickListener { if (page > 0) render(page - 1) }
        next.setOnClickListener {
            if (page < PAGES.lastIndex) render(page + 1) else finishOnboarding()
        }

        render(page)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(KEY_PAGE, page)
    }

    private fun render(index: Int) {
        page = index
        val (titleRes, bodyRes) = PAGES[index]
        step.text = getString(R.string.onb_step, index + 1, PAGES.size)
        title.setText(titleRes)
        body.setText(bodyRes)

        back.visibility = if (index == 0) View.INVISIBLE else View.VISIBLE
        // Skip disappears on the last page: there is nothing left to skip, and a
        // "Skip" next to "Get started" is two words for the same action.
        skip.visibility = if (index == PAGES.lastIndex) View.INVISIBLE else View.VISIBLE
        next.setText(if (index == PAGES.lastIndex) R.string.onb_done else R.string.onb_next)
    }

    /**
     * Marks first run done even when the user skipped.
     *
     * Skipping is a decision, and re-showing this on the next launch would
     * override it. Settings has "Show the introduction again" for the user who
     * changes their mind, which is the only place that decision should be
     * reversible.
     */
    private fun finishOnboarding() {
        Settings.setFirstRunDone(this)
        finish()
    }

    companion object {
        private const val KEY_PAGE = "page"

        private val PAGES = listOf(
            R.string.onb_1_title to R.string.onb_1_body,
            R.string.onb_2_title to R.string.onb_2_body,
            R.string.onb_3_title to R.string.onb_3_body,
            R.string.onb_4_title to R.string.onb_4_body,
        )

        /** Re-entry from Settings; identical flow, and finishing returns there. */
        fun replayIntent(context: Context): Intent =
            Intent(context, OnboardingActivity::class.java)

        /**
         * The first-run gate, for whoever owns the launch path.
         *
         * Deliberately a query rather than a "show it if needed" helper: the
         * decision belongs to the activity that would be interrupted, and
         * [Settings.firstRunDone] is DE-backed so this is answerable before first
         * unlock.
         */
        fun isNeeded(context: Context): Boolean = !Settings.firstRunDone(context)
    }
}
