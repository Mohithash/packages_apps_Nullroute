package com.bestrom.nullroute.notify

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.util.Log
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.ForegroundAppTracker
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.log.RingReader
import com.bestrom.nullroute.ui.MainActivity

/**
 * The breakage notifier: **five or more blocks within ten seconds from the app
 * the user is looking at** becomes
 *
 * > Nullroute blocked 6 requests from Bank.
 * > Tap to exempt this app.
 *
 * SPEC §10.3 calls this the highest-ROI feature in the app, and the reason is
 * not the notification — it is what happens without one. A blocklist update
 * breaks a banking app; the app shows a spinner and then a generic network
 * error; the user has no reason on earth to connect that to an ad blocker they
 * turned on three weeks ago. That is a support thread, a one-star review, or the
 * whole feature switched off. This turns it into a tap.
 *
 * ## Why the constraints are exactly these
 *
 * **Foreground only.** Background chatter — a sync adapter, an ad SDK
 * prefetching, a game phoning home while it is not on screen — is *the product
 * working*. Notifying about it would train the user to dismiss the one
 * notification that matters. So a burst is only interesting when it comes from
 * the app in front of the user, and [ForegroundAppTracker] answers "unknown"
 * rather than guessing, in which case nothing is sent.
 *
 * **Five in ten seconds.** A single block is an ad that did not load, which is
 * the feature. A *burst* is a retry loop, which is breakage. The window is
 * measured over the record timestamps the resolver wrote, not over wall-clock at
 * drain time, so a drain that runs a minute late still sees the burst that
 * happened a minute ago and does not manufacture one out of records spread over
 * an hour.
 *
 * **Once per app per day.** An app that is genuinely broken keeps producing
 * bursts for as long as the user keeps trying. Re-notifying every time would be
 * indistinguishable from spam, and the user would silence the channel — losing
 * every future breakage on every other app with it.
 *
 * ## What tapping does
 *
 * The tap opens the app on the log, with the offending appId attached, so the
 * exemption is one confirmed action away rather than a hunt through a settings
 * tree. Exempting is a **one-byte write** to `uid_policy[appId]` in the shared
 * control page and is live on the resolver's very next query — see
 * [ControlPage.setUidPolicy]. It is deliberately not performed by the
 * notification itself: "Nullroute has stopped filtering this app" is not
 * something that should be one accidental swipe-tap away, and the confirming
 * screen is also where "Force stop app" belongs (in-app DNS caches are not ours
 * to flush, SPEC §3.5).
 */
object BreakageNotifier {

    private const val TAG = "Nullroute"

    private const val CHANNEL_ID = "nullroute_breakage"

    /**
     * Notification ids are `NOTIFICATION_ID_BASE + appId`, so a second burst from
     * the same app replaces its own notification instead of stacking, and two
     * different apps never overwrite each other. Deliberately far away from
     * [DegradedNotifier]'s single id.
     */
    private const val NOTIFICATION_ID_BASE = 2_000_000

    /** The burst that counts as breakage. */
    const val BURST_COUNT = 5
    const val BURST_WINDOW_MS = 10_000L

    /** One notification per app per day, no matter how broken it stays. */
    private const val RATE_LIMIT_MS = 24L * 60L * 60L * 1000L

    private const val PREFS = "nullroute_log"
    private const val KEY_LAST_PREFIX = "breakage_last_"

    /**
     * Extras on the tap intent. [MainActivity] is owned elsewhere; until it reads
     * these, the tap still opens the app and the extras are inert — a tap that
     * lands one screen away is a degradation, a crash is not.
     */
    const val EXTRA_APP_ID = "com.bestrom.nullroute.extra.BREAKAGE_APP_ID"
    const val EXTRA_APP_LABEL = "com.bestrom.nullroute.extra.BREAKAGE_APP_LABEL"
    const val EXTRA_BLOCK_COUNT = "com.bestrom.nullroute.extra.BREAKAGE_COUNT"

    private const val AID_USER_OFFSET = 100_000

    /**
     * Inspects a freshly drained batch and notifies about at most one app.
     *
     * **Blocking** — it asks [ForegroundAppTracker], which reads from the
     * usage-stats service. Call it from the log-drain worker.
     *
     * At most one, on purpose: two apps cannot both be in front of the user, so a
     * second notification from the same batch would necessarily be about
     * background traffic.
     */
    fun observe(context: Context, records: List<RingReader.Record>) {
        if (records.isEmpty()) return

        val bursts = records
            .filter { it.blocked }
            .groupBy { it.uid }
            .filterValues { isBurst(it) }
        if (bursts.isEmpty()) return

        // Ask for the foreground app ONCE, after establishing that there is
        // something worth asking about: the query is the expensive part and the
        // common case is a batch with no burst in it at all.
        val foreground = ForegroundAppTracker.foregroundUid(context)
        if (foreground == ForegroundAppTracker.UNKNOWN_UID) {
            Log.d(TAG, "burst from ${bursts.keys} but the foreground app is unknown; not notifying")
            return
        }
        val hits = bursts[foreground] ?: return

        val appId = foreground % AID_USER_OFFSET
        // Already exempt? Then these blocks are stale records from before the
        // exemption landed, and telling the user to exempt an app they already
        // exempted is worse than silence.
        if (ControlPage.isMapped && ControlPage.getUidPolicy(appId) == ControlPage.POLICY_EXEMPT) {
            return
        }
        if (!rateLimitPasses(context, appId)) return

        val label = ForegroundAppTracker.label(context, foreground)
        if (label == null) {
            // A uid with no installed package: a platform component, or an app
            // uninstalled between the block and this drain. There is nothing
            // truthful to put in the title and nothing useful to exempt.
            Log.d(TAG, "burst from uid $foreground with no package; not notifying")
            return
        }

        notify(context, appId, label, hits.size)
        recordNotified(context, appId)
    }

    /**
     * True when some [BURST_COUNT] of these records fall inside a
     * [BURST_WINDOW_MS] window.
     *
     * A sliding window over the sorted timestamps, not "first to last", because
     * the batch can span the whole ring: six blocks spread evenly over an hour
     * are an ad-heavy app behaving normally, and only a genuine cluster is
     * evidence of a retry loop.
     */
    private fun isBurst(records: List<RingReader.Record>): Boolean {
        if (records.size < BURST_COUNT) return false
        val times = records.map { it.timestampMs }.sorted()
        for (i in 0..times.size - BURST_COUNT) {
            if (times[i + BURST_COUNT - 1] - times[i] <= BURST_WINDOW_MS) return true
        }
        return false
    }

    // ---- rate limit ----------------------------------------------------------

    private fun prefs(context: Context) =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun rateLimitPasses(context: Context, appId: Int): Boolean {
        val now = System.currentTimeMillis()
        val last = prefs(context).getLong(KEY_LAST_PREFIX + appId, 0L)
        // `last > now` is a backwards clock step, not a future notification; treat
        // it as due rather than locking the app out until the clock catches up.
        return last <= 0L || last > now || now - last >= RATE_LIMIT_MS
    }

    private fun recordNotified(context: Context, appId: Int) {
        prefs(context).edit()
            .putLong(KEY_LAST_PREFIX + appId, System.currentTimeMillis())
            .apply()
    }

    /** Lets the confirming screen re-arm the notifier once the user has acted. */
    fun clearRateLimit(context: Context, appId: Int) {
        prefs(context).edit().remove(KEY_LAST_PREFIX + appId).apply()
    }

    // ---- notification --------------------------------------------------------

    private fun ensureChannel(context: Context): NotificationManager? {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return null
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.channel_breakage),
            // DEFAULT, not HIGH: this is a helpful suggestion about an app the
            // user is already looking at, not an emergency. HIGH would heads-up
            // over the very app it is talking about.
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = context.getString(R.string.channel_breakage_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
        return nm
    }

    private fun notify(context: Context, appId: Int, label: String, count: Int) {
        val nm = ensureChannel(context) ?: return

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_OPEN_TAB, MainActivity.TAB_DIAGNOSTICS)
            putExtra(EXTRA_APP_ID, appId)
            putExtra(EXTRA_APP_LABEL, label)
            putExtra(EXTRA_BLOCK_COUNT, count)
        }
        val pending = PendingIntent.getActivity(
            context,
            appId, // distinct request code per app, or the extras of the first win
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val title = context.resources.getQuantityString(
            R.plurals.breakage_title, count, count, label,
        )
        val text = context.getString(R.string.breakage_body)

        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nullroute)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(context.getString(R.string.breakage_body_long, label)))
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_STATUS)
            // Same PendingIntent as the tap: the action is a shortcut to the same
            // confirming screen, not a second, quieter way to switch filtering
            // off for an app without seeing what it means.
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(context, R.drawable.ic_nullroute),
                    context.getString(R.string.breakage_action_exempt),
                    pending,
                ).build()
            )
            .build()

        runCatching { nm.notify(NOTIFICATION_ID_BASE + appId, notification) }
            .onFailure { Log.w(TAG, "breakage notify failed: ${it.message}") }
    }

    /** Withdraws an app's notification once its policy has been decided. */
    fun cancel(context: Context, appId: Int) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        runCatching { nm.cancel(NOTIFICATION_ID_BASE + appId) }
    }
}
