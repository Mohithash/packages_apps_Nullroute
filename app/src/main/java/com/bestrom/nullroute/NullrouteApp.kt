package com.bestrom.nullroute

import android.app.Application
import android.util.Log
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.job.DeviceConfigFixups
import com.bestrom.nullroute.job.HealthWatchdog
import com.bestrom.nullroute.job.UpdateJobService
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Process entry point.
 *
 * The application is `directBootAware`, so `onCreate` can run before the user has
 * ever unlocked. Everything here is therefore DE-safe: mapping `control.bin`
 * under `/data/misc`, reading DE-backed preferences, scheduling jobs. Nothing
 * touches CE storage, and nothing blocks on the network.
 */
class NullrouteApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // Mapping the control page is an open() plus an mmap() of 128 KiB: cheap
        // enough for the main thread, and worth doing eagerly so that the first
        // screen the user sees already knows whether the page is reachable. A
        // failure is recorded, not thrown — an app that cannot start is an app
        // that cannot tell anyone filtering is broken.
        if (Paths.stateTreeReady()) {
            if (!ControlPage.open()) {
                Log.w(TAG, "control page unavailable: ${ControlPage.lastError}")
            }
        } else {
            Log.w(TAG, "${Paths.misc} is not set up; nullroute_seed did not run")
        }

        io.execute {
            runCatching { Paths.ensureAppDirs() }
            // Second path to the boot-loop disarm. If the user opens the app
            // three minutes after booting, they have demonstrated exactly what
            // the scheduled job was going to check for, and relying on a single
            // mechanism for something that quarantines the index on its third
            // failure is not a good trade.
            runCatching { HealthWatchdog.markBootHealthyIfDue(this) }
            runCatching { DeviceConfigFixups.apply() }
            runCatching { UpdateJobService.schedule(this) }
        }
    }

    companion object {
        private const val TAG = "Nullroute"

        /**
         * The one background executor in the app.
         *
         * Two threads, not a pool sized to the CPU: the only genuinely long task
         * is a blocklist compile, and running two of those at once would double
         * peak RSS for no gain — the native builder is already an external merge
         * sort chosen specifically to keep memory bounded. Daemon threads so a
         * queued job never keeps the process alive on its own.
         */
        val io: ExecutorService = Executors.newFixedThreadPool(2) { r ->
            Thread(r, "nullroute-io").apply { isDaemon = true }
        }
    }
}
