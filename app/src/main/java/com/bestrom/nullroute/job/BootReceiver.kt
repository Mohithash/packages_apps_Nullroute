package com.bestrom.nullroute.job

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Paths

/**
 * Boot entry point.
 *
 * Registered for `LOCKED_BOOT_COMPLETED` as well as `BOOT_COMPLETED` and marked
 * `directBootAware`, because everything it does is DE-safe and all of it matters
 * before the user unlocks: the index and control page live in `/data/misc`
 * precisely so that filtering is live at that point, and the boot-loop breaker's
 * 120 s timer has to start from the boot, not from the unlock. A device left on
 * the lockscreen overnight would otherwise accumulate a fail streak and
 * quarantine a perfectly good index.
 *
 * `LOCKED_BOOT_COMPLETED` fires first and `BOOT_COMPLETED` follows on the same
 * boot, so every action here is idempotent.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_LOCKED_BOOT_COMPLETED && action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }

        val app = context.applicationContext
        Log.i(TAG, "boot: $action")

        // Arm the disarm. Cheap, synchronous, and the single most important thing
        // this receiver does — see HealthWatchdog.
        HealthWatchdog.scheduleBootHealthCheck(app)
        UpdateJobService.schedule(app)

        // Everything below touches the filesystem or the resolver, so it goes to
        // a worker: a BroadcastReceiver has ~10 seconds and a failing DNS probe
        // can spend most of that on its own.
        val pending = goAsync()
        NullrouteApp.io.execute {
            try {
                if (Paths.stateTreeReady() && ControlPage.open()) {
                    // Re-derive the live mode byte from the durable property. init
                    // does this too, via `on property:persist.sys.nullroute.mode=*`
                    // -> `nrctl syncprop`; doing it again here costs one byte and
                    // covers the case where that trigger did not fire, which would
                    // otherwise silently resume a filter the user had paused.
                    val mode = ControlPage.syncModeFromProperty()
                    Log.i(TAG, "control page mapped, mode=$mode")
                } else {
                    Log.w(TAG, "control page unavailable: ${ControlPage.lastError}")
                }
                HealthWatchdog.runCheck(app)
            } catch (t: Throwable) {
                Log.w(TAG, "boot work failed: ${t.message}")
            } finally {
                pending.finish()
            }
        }
    }

    private companion object {
        const val TAG = "Nullroute"
    }
}
