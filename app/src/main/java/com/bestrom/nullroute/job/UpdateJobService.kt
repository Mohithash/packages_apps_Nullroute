package com.bestrom.nullroute.job

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.build.IndexBuilder
import com.bestrom.nullroute.data.Settings
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The app's only [JobService]. Two job ids run through it: the periodic
 * blocklist refresh and the one-shot boot-health disarm (see [HealthWatchdog]).
 *
 * Plain `JobScheduler`, not WorkManager. WorkManager would drag androidx.work and
 * Room into a Soong build to buy scheduling guarantees we already have: this app
 * is listed in `rom/sysconfig-nullroute.xml` as `allow-in-power-save` and
 * `allow-in-data-usage-save`, so it is not fighting Doze or the standby buckets
 * in the first place. Being in-tree is what makes that possible, and it is most
 * of the reason this is a ROM component rather than a Play app.
 */
class UpdateJobService : JobService() {

    private val cancelled = AtomicBoolean(false)

    override fun onStartJob(params: JobParameters): Boolean {
        cancelled.set(false)
        when (params.jobId) {
            JOB_ID_UPDATE -> {
                NullrouteApp.io.execute {
                    var reschedule = false
                    try {
                        val outcome = IndexBuilder.run(applicationContext, null)
                        // Only a recoverable failure earns a retry. Asking
                        // JobScheduler to back off exponentially on "the native
                        // compiler is missing" would burn wakeups forever on a
                        // condition no retry can change.
                        reschedule = (outcome as? IndexBuilder.Outcome.Failure)?.recoverable == true
                    } catch (t: Throwable) {
                        Log.e(TAG, "update job failed", t)
                        reschedule = true
                    } finally {
                        if (!cancelled.get()) jobFinished(params, reschedule)
                    }
                }
                return true
            }

            HealthWatchdog.JOB_ID_BOOT_HEALTH -> {
                NullrouteApp.io.execute {
                    try {
                        HealthWatchdog.markBootHealthyIfDue(applicationContext)
                        HealthWatchdog.runCheck(applicationContext)
                    } catch (t: Throwable) {
                        Log.w(TAG, "boot-health job: ${t.message}")
                    } finally {
                        if (!cancelled.get()) jobFinished(params, false)
                    }
                }
                return true
            }

            else -> return false
        }
    }

    /**
     * The system is taking the job away. Returning true asks for a retry; the
     * in-flight build is abandoned, which is safe by construction — nothing is
     * published until `promote()` renames, so a killed build leaves `current.nrdx`
     * untouched and the device exactly as protected as it was.
     */
    override fun onStopJob(params: JobParameters): Boolean {
        cancelled.set(true)
        return params.jobId == JOB_ID_UPDATE
    }

    companion object {
        private const val TAG = "Nullroute"

        const val JOB_ID_UPDATE = 2000

        private const val PERIOD_MS = 24L * 60 * 60 * 1000
        private const val FLEX_MS = 6L * 60 * 60 * 1000
        private const val BACKOFF_MS = 30L * 60 * 1000

        /**
         * (Re)schedules the periodic refresh.
         *
         * `setEstimatedNetworkBytes` is not decoration: it is how the scheduler
         * knows this is a several-megabyte job and defers it off a metered link
         * instead of discovering the cost halfway through.
         */
        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            if (!Settings.autoUpdate(context)) {
                runCatching { scheduler.cancel(JOB_ID_UPDATE) }
                return
            }

            val network = if (Settings.unmeteredOnly(context)) {
                JobInfo.NETWORK_TYPE_UNMETERED
            } else {
                JobInfo.NETWORK_TYPE_ANY
            }

            val job = JobInfo.Builder(JOB_ID_UPDATE, ComponentName(context, UpdateJobService::class.java))
                .setRequiredNetworkType(network)
                .setRequiresBatteryNotLow(true)
                .setPeriodic(PERIOD_MS, FLEX_MS)
                .setBackoffCriteria(BACKOFF_MS, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
                .setEstimatedNetworkBytes(2_000_000L, 4_096L)
                .setPersisted(true)
                .build()

            runCatching { scheduler.schedule(job) }
                .onFailure { Log.w(TAG, "update job not scheduled: ${it.message}") }
        }

        /** Runs an update now, outside the scheduler. Used by `nrctl update`. */
        fun runNow(context: Context) {
            NullrouteApp.io.execute {
                runCatching { IndexBuilder.run(context.applicationContext, null) }
                    .onFailure { Log.e(TAG, "immediate update failed", it) }
            }
        }
    }
}
