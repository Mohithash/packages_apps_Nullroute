package com.bestrom.nullroute.core

import android.app.ActivityManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.util.Log

/**
 * Best-effort "which app is the user actually looking at right now".
 *
 * This exists for exactly one caller — [com.bestrom.nullroute.notify.BreakageNotifier] — and the
 * quality bar follows from what that caller does with the answer. The notifier
 * fires when a burst of blocks comes from the app in front of the user, on the
 * theory that a user staring at a spinning bank app is the one person who can
 * connect "this is broken" to "Nullroute did it". Attribute the burst to the
 * wrong app and we tell them to exempt something they were not using; attribute
 * it to nothing and the single highest-ROI recovery path in the product never
 * fires.
 *
 * So: **wrong is worse than unknown.** Every accessor here returns
 * [UNKNOWN_UID] / `null` rather than a guess, and [isForeground] answers `false`
 * when it cannot tell. A notification we did not send costs the user one support
 * search; a notification naming the wrong app costs them their trust in every
 * later one.
 *
 * ## Two sources, in order of how much they actually know
 *
 * 1. **`UsageStatsManager.queryEvents`** — the only API that reports which
 *    *activity* was resumed, which is what "foreground" means to a user. It
 *    needs `PACKAGE_USAGE_STATS`, a privileged permission we are allowlisted for
 *    (SPEC §8.8) but which must also be granted as an appop; when it is not, the
 *    query returns an empty cursor rather than throwing, so an empty result is
 *    indistinguishable from "the screen has been off for a minute". Both are
 *    correctly reported as unknown.
 *
 * 2. **`ActivityManager.getRunningAppProcesses`** — process importance, not
 *    activity state. For an unprivileged caller this returns only our own
 *    process; a privileged one holding `REAL_GET_TASKS` sees the rest. It is a
 *    coarser signal (a foreground *service* also counts) so it is only consulted
 *    when the first source said nothing.
 *
 * Nothing here is cached: a stale answer is exactly the wrong-app failure this
 * class exists to avoid, and it is consulted once per drain, not per record.
 */
object ForegroundAppTracker {

    private const val TAG = "Nullroute"

    const val UNKNOWN_UID = -1

    /**
     * How far back to look for a resume event. Long enough to survive a drain
     * that ran a few seconds after the burst, short enough that the app the user
     * left a minute ago is never named.
     */
    private const val LOOKBACK_MS = 30_000L

    /**
     * The uid of the app currently in front of the user, or [UNKNOWN_UID].
     *
     * **Blocking**: `queryEvents` reads from the usage-stats service. Call it
     * from the log-drain worker, never from the main thread.
     */
    fun foregroundUid(context: Context): Int {
        val pkg = foregroundPackage(context) ?: return UNKNOWN_UID
        return uidForPackage(context, pkg)
    }

    /**
     * Whether [uid] is the app in front of the user.
     *
     * A uid can be shared by several packages (`sharedUserId`), and per-app
     * policy in `control.bin` is keyed by appId, not by package — so comparing
     * uids rather than package names is not a shortcut, it is the same
     * granularity the exemption itself has.
     */
    fun isForeground(context: Context, uid: Int): Boolean {
        if (uid < 0) return false
        val fg = foregroundUid(context)
        return fg != UNKNOWN_UID && fg == uid
    }

    /**
     * A user-facing name for [uid]: the application label, falling back to the
     * package name, and `null` when the uid belongs to no installed package.
     *
     * `null` is a real outcome and callers must handle it — a uid can name a
     * platform component with no launcher presence, or an app uninstalled
     * between the block and the drain. Naming such a burst "1000" in a
     * notification would be worse than staying quiet.
     */
    fun label(context: Context, uid: Int): String? {
        if (uid < 0) return null
        val pm = context.packageManager
        val packages = runCatching { pm.getPackagesForUid(uid) }.getOrNull() ?: return null
        if (packages.isEmpty()) return null

        // A shared uid has several packages and no canonical one. Take the first
        // that has a label; the exemption applies to all of them either way, and
        // the alternative — listing them — does not fit in a notification title.
        for (name in packages) {
            val label = runCatching {
                pm.getApplicationInfo(name, 0).loadLabel(pm).toString()
            }.getOrNull()
            if (!label.isNullOrBlank()) return label
        }
        return packages[0]
    }

    // ---- sources -------------------------------------------------------------

    private fun foregroundPackage(context: Context): String? =
        fromUsageStats(context) ?: fromRunningProcesses(context)

    private fun fromUsageStats(context: Context): String? {
        val usage = runCatching {
            context.getSystemService(UsageStatsManager::class.java)
        }.getOrNull() ?: return null

        val now = System.currentTimeMillis()
        val events = runCatching { usage.queryEvents(now - LOOKBACK_MS, now) }.getOrElse {
            // A SecurityException here means the appop is not granted. Log it
            // once at warn rather than at error: the product works without this,
            // it just loses the breakage notifier's targeting.
            Log.w(TAG, "usage events unavailable: ${it.message}")
            return null
        } ?: return null

        // queryEvents is chronological, so the last resume wins. There is no
        // "give me the current one" API; walking to the end is the supported way.
        var latestPkg: String? = null
        var latestAt = 0L
        val event = UsageEvents.Event()
        while (events.hasNextEvent()) {
            if (!events.getNextEvent(event)) break
            when (event.eventType) {
                UsageEvents.Event.ACTIVITY_RESUMED -> {
                    if (event.timeStamp >= latestAt) {
                        latestAt = event.timeStamp
                        latestPkg = event.packageName
                    }
                }
                // A pause of the app we were about to name means nothing is in
                // front of the user any more — the screen went off, or they went
                // home. Clearing is what makes "unknown" reachable at all.
                UsageEvents.Event.ACTIVITY_PAUSED,
                UsageEvents.Event.ACTIVITY_STOPPED,
                -> if (event.packageName == latestPkg && event.timeStamp >= latestAt) {
                    latestAt = event.timeStamp
                    latestPkg = null
                }
            }
        }
        return latestPkg
    }

    private fun fromRunningProcesses(context: Context): String? {
        val am = runCatching {
            context.getSystemService(ActivityManager::class.java)
        }.getOrNull() ?: return null

        val running = runCatching { am.runningAppProcesses }.getOrNull() ?: return null
        for (proc in running) {
            if (proc.importance != ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
                continue
            }
            // Our own process is foreground whenever the user has the app open,
            // and "Nullroute blocked 6 requests from Nullroute" is never the
            // notification anyone wants.
            if (proc.uid == android.os.Process.myUid()) continue
            val pkgs = proc.pkgList ?: continue
            if (pkgs.isNotEmpty()) return pkgs[0]
        }
        return null
    }

    private fun uidForPackage(context: Context, pkg: String): Int = runCatching {
        context.packageManager.getApplicationInfo(pkg, 0).uid
    }.getOrElse {
        Log.w(TAG, "no uid for $pkg: ${it.message}")
        UNKNOWN_UID
    }
}
