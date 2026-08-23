package com.bestrom.nullroute.job

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Log
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.core.SysProp
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.ui.MainActivity

/**
 * Health sampling, and the app's half of the boot-loop breaker.
 *
 * ## The boot-loop breaker (F7), and exactly what disarms it
 *
 * netd's init stanza carries `onrestart restart zygote`. A matcher fault is
 * therefore not a network outage — it is a **UI loop**, and a device that will
 * not finish booting cannot be fixed from an app. So the seeder counts bad boots
 * and gives up on the third:
 *
 * ```
 * nullroute_seed, every post-fs-data:
 *     prev_ok = getprop persist.sys.nullroute.boot_ok
 *     streak  = getprop persist.sys.nullroute.fail_streak
 *     if prev_ok != "1": streak += 1  else: streak = 0
 *     setprop fail_streak <streak>
 *     setprop boot_ok 0                      # armed for THIS boot
 *     if streak >= 3: quarantine current.nrdx; setprop kill 1
 * ```
 *
 * This class supplies the `boot_ok = 1` that the seeder looks for. Getting the
 * condition wrong in either direction is expensive:
 *
 *  * Never setting it — filtering dies on the third boot of a perfectly healthy
 *    device, permanently, with the kill switch latched.
 *  * Setting it too eagerly (say, at process start) — a device that boots far
 *    enough to start our app and then loops never advances the streak, and the
 *    breaker never fires.
 *
 * **The condition is 120 seconds of uptime, and nothing else.** Specifically it
 * is *not* "the probes passed": the breaker exists to detect a boot loop, not a
 * degraded filter. A device whose resolver hook is simply missing is stable and
 * unfiltered; making it accumulate a fail streak would quarantine a working index
 * and latch `kill=1`, which also switches off the L0 hosts layer via
 * `hostsLayerSuperseded()`. That would take a device from "partly protected" to
 * "not protected at all" as a *response to being partly protected*.
 */
object HealthWatchdog {

    private const val TAG = "Nullroute"

    /** Job ids are shared with [UpdateJobService], which dispatches on them. */
    const val JOB_ID_BOOT_HEALTH = 2001

    /**
     * Uptime after which this boot counts as healthy. Matches the seeder's
     * expectation; changing it in one place only re-introduces F7.
     */
    private const val BOOT_HEALTHY_AFTER_MS = 120_000L

    private const val CHANNEL_ID = "nullroute_status"
    private const val NOTIFICATION_ID = 1

    // ---- boot-loop breaker --------------------------------------------------

    /**
     * Schedules the disarm.
     *
     * Deliberately **not persisted**: a persisted job that survived a reboot
     * would mark the *next* boot healthy on behalf of the previous one, which is
     * the one thing this timer must never do. The deadline is generous because
     * being late is harmless — the streak only advances on a boot that never
     * reached 120 s at all.
     */
    fun scheduleBootHealthCheck(context: Context) {
        val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
        val job = JobInfo.Builder(
            JOB_ID_BOOT_HEALTH,
            ComponentName(context, UpdateJobService::class.java),
        )
            .setMinimumLatency(BOOT_HEALTHY_AFTER_MS)
            .setOverrideDeadline(BOOT_HEALTHY_AFTER_MS + 60_000L)
            .setPersisted(false)
            .build()
        runCatching { scheduler.schedule(job) }
            .onFailure { Log.w(TAG, "boot-health job not scheduled: ${it.message}") }
    }

    /**
     * Marks this boot healthy if it has lasted long enough.
     *
     * Called from the scheduled job and, as a belt-and-braces second path, from
     * app start — a user who opens the app three minutes after booting has
     * demonstrated the same thing the timer would have.
     *
     * `fail_streak` is cleared as well as `boot_ok` being set. The seeder derives
     * one from the other at the next `post-fs-data`, so this is redundant by
     * design: if the app can only manage one of the two writes, either one alone
     * still disarms the breaker.
     */
    fun markBootHealthyIfDue(context: Context): Boolean {
        val uptime = SystemClock.elapsedRealtime()
        if (uptime < BOOT_HEALTHY_AFTER_MS) return false
        if (SysProp.get(Probes.PROP_BOOT_OK) == "1") return true

        val setOk = SysProp.set(Probes.PROP_BOOT_OK, "1")
        val clearedStreak = SysProp.set(Probes.PROP_FAIL_STREAK, "0")
        Log.i(TAG, "boot marked healthy after ${uptime / 1000}s (ok=$setOk streak=$clearedStreak)")
        return setOk || clearedStreak
    }

    // ---- health sampling ----------------------------------------------------

    /**
     * Samples every signal and updates the persistent notification.
     * **Blocking** — the probes go out to the resolver. Background thread only.
     */
    fun runCheck(context: Context): Probes.Health {
        ControlPage.open()
        val health = Probes.sample()
        Settings.setLastStatus(context, health.status().name)
        updateNotification(context, health)
        return health
    }

    // ---- notification -------------------------------------------------------

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

    /**
     * Posts the "Not filtering" notification, or clears it.
     *
     * Only [Probes.FilterStatus.NOT_FILTERING] earns an interruption. "Limited"
     * is a real degradation but the device is still filtering the baked list, and
     * a notification the user cannot act on is a notification they learn to
     * ignore — including the one time it matters.
     *
     * Ongoing plus auto-cancel gives the behaviour the spec asks for: it cannot
     * be swiped away, and tapping it both opens Diagnostics and clears it.
     */
    private fun updateNotification(context: Context, health: Probes.Health) {
        val nm = ensureChannel(context) ?: return
        if (!health.needsNotification) {
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

        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nullroute)
            .setContentTitle(context.getString(R.string.status_not_filtering))
            .setContentText(context.getString(R.string.status_not_filtering_detail))
            .setStyle(
                Notification.BigTextStyle()
                    .bigText(context.getString(R.string.status_not_filtering_detail))
            )
            .setContentIntent(pending)
            .setOngoing(true)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_ERROR)
            .build()

        runCatching { nm.notify(NOTIFICATION_ID, notification) }
            .onFailure { Log.w(TAG, "notify failed: ${it.message}") }
    }
}
