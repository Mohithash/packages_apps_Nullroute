package com.bestrom.nullroute.notify

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.ui.MainActivity

/**
 * The SPEC §3.4 four-state table, in one place.
 *
 * | Probe A (index) | Probe B (hosts) | Status                                    |
 * |---|---|---|
 * | 127.0.0.7 | 127.0.0.8 | **Protected** |
 * | fails     | 127.0.0.8 | **Limited — running on the built-in list only.** *(Diagnostics)* |
 * | 127.0.0.7 | fails     | **Protected.** Built-in list missing — Diagnostics, non-urgent. |
 * | fails     | fails     | **Not filtering.** Persistent notice. |
 *
 * The mapping and the *interruption* are deliberately separated. [notice] is a
 * pure function of the sampled health and is what Diagnostics and the Home card
 * read; [update] is the only thing that touches the notification shade, and it
 * fires for exactly one of the states.
 *
 * ## Why only one state earns a notification
 *
 * Two of these are real degradations that the user cannot act on from a
 * notification. "Limited" still blocks ~2,000 domains from the baked hosts file;
 * "built-in list missing" is a build defect with no user-visible symptom at all.
 * Interrupting for either teaches the user that this channel is noise — and the
 * one state that matters, *nothing at all is being blocked*, arrives in a shade
 * they have already learned to swipe.
 *
 * Note what is **not** in the table: PAUSED, OFF and KILLED. In all three the L0
 * hosts layer keeps filtering — `NrFilter::hostsLayerSuperseded()` bails on the
 * kill switch and on any mode other than ENFORCE, so the resolver goes back to
 * consulting `/system/etc/hosts` exactly as stock AOSP would. Reporting "not
 * filtering" there would be as much of a lie as claiming protection we do not
 * have, and PAUSED/OFF are the user's own choice besides. KILLED is the odd one:
 * it is not chosen from the UI and only clears at boot, so it is surfaced in
 * Diagnostics with the instructions rather than as a notification the user
 * cannot act on.
 *
 * ## Ownership note
 *
 * The notification id and channel are the same ones
 * [com.bestrom.nullroute.job.HealthWatchdog] posts on, so the two can never both
 * be visible and can never disagree about the same state. HealthWatchdog's
 * private `updateNotification()` should be deleted in favour of calling
 * [update]; see `docs/integration-log.md`.
 */
object DegradedNotifier {

    private const val TAG = "Nullroute"

    /** Shared with HealthWatchdog by design — see the class comment. */
    private const val CHANNEL_ID = "nullroute_status"
    private const val NOTIFICATION_ID = 1

    /** How loudly a state should be told. */
    enum class Urgency {
        /** Nothing to say. */
        NONE,

        /** Worth a row in Diagnostics; never an interruption. */
        DIAGNOSTICS,

        /** A persistent notice the user has to acknowledge. */
        NOTIFICATION,
    }

    data class Notice(
        val status: Probes.FilterStatus,
        val titleRes: Int,
        val bodyRes: Int,
        val urgency: Urgency,
    )

    /**
     * What this health sample means, or `null` when there is nothing to report.
     *
     * Pure: no I/O, no side effects, no Context. That is what lets the same
     * mapping drive the Home card, the Diagnostics list and the shade without
     * three copies of the table drifting apart.
     */
    fun notice(health: Probes.Health): Notice? = when (health.status()) {
        Probes.FilterStatus.PROTECTED -> null

        Probes.FilterStatus.PROTECTED_NO_L0 -> Notice(
            Probes.FilterStatus.PROTECTED_NO_L0,
            R.string.degraded_no_l0_title,
            R.string.degraded_no_l0_body,
            Urgency.DIAGNOSTICS,
        )

        Probes.FilterStatus.LIMITED_L0_ONLY -> Notice(
            Probes.FilterStatus.LIMITED_L0_ONLY,
            R.string.status_limited,
            R.string.status_limited_detail,
            Urgency.DIAGNOSTICS,
        )

        Probes.FilterStatus.NOT_FILTERING -> Notice(
            Probes.FilterStatus.NOT_FILTERING,
            R.string.status_not_filtering,
            R.string.status_not_filtering_detail,
            Urgency.NOTIFICATION,
        )

        Probes.FilterStatus.KILLED -> Notice(
            Probes.FilterStatus.KILLED,
            R.string.status_killed,
            R.string.degraded_killed_body,
            Urgency.DIAGNOSTICS,
        )

        // The user's own choice, and L0 is still filtering in both.
        Probes.FilterStatus.PAUSED,
        Probes.FilterStatus.OFF,
        -> null

        // Never sampled. Saying nothing is right: this class must not invent a
        // verdict from the absence of one.
        Probes.FilterStatus.UNKNOWN -> null
    }

    /**
     * Posts or clears the persistent notice for [health].
     *
     * Idempotent and safe to call after every probe: a state that does not earn
     * an interruption cancels whatever was there, so recovery clears the notice
     * without anyone having to remember to.
     */
    fun update(context: Context, health: Probes.Health) {
        val nm = ensureChannel(context) ?: return
        val notice = notice(health)

        if (notice == null || notice.urgency != Urgency.NOTIFICATION) {
            runCatching { nm.cancel(NOTIFICATION_ID) }
            return
        }

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_TAB, MainActivity.TAB_DIAGNOSTICS)
        }
        val pending = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val body = context.getString(notice.bodyRes)
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nullroute)
            .setContentTitle(context.getString(notice.titleRes))
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText(body))
            .setContentIntent(pending)
            // Ongoing + autoCancel is exactly "non-dismissible until tapped": it
            // cannot be swiped away, and tapping both opens Diagnostics and
            // clears it. A user who has seen why is not nagged; a user who has
            // not cannot make it go away without looking.
            .setOngoing(true)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_ERROR)
            .build()

        runCatching { nm.notify(NOTIFICATION_ID, notification) }
            .onFailure { Log.w(TAG, "degraded notify failed: ${it.message}") }
    }

    private fun ensureChannel(context: Context): NotificationManager? {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return null
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.channel_status),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = context.getString(R.string.channel_status_desc)
            setShowBadge(true)
        }
        nm.createNotificationChannel(channel)
        return nm
    }
}
