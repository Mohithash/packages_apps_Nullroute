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
 *
 * ## Being killed mid-update is a supported outcome, not an edge case
 *
 * A periodic job on an unmetered network with battery-not-low is exactly the job
 * the system reclaims first when conditions change, and a full compile takes
 * seconds to minutes. So the design is that stopping is free: the builder writes
 * only to `staging.<gen>.nrdx` and to scratch files under `priv/build`, and
 * `current.nrdx` is replaced by a single `rename()` after every gate has passed.
 * Kill the process at any earlier instant and the device keeps the index it had —
 * there is no partial state to recover, no journal to replay, and nothing for
 * [onStopJob] to clean up.
 *
 * That is why [onStopJob] simply asks for a retry and abandons the work, and why
 * it does not try to interrupt the worker thread: an interrupt in the middle of
 * a native compile would have to be handled correctly in the native builder to
 * buy anything, and abandoning it is already correct.
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
                        // compiler is missing" or "this index needs a newer
                        // resolver" would burn wakeups forever on a condition no
                        // retry can change.
                        reschedule = (outcome as? IndexBuilder.Outcome.Failure)?.recoverable == true
                    } catch (t: Throwable) {
                        Log.e(TAG, "update job failed", t)
                        reschedule = true
                    } finally {
                        // If the system already stopped us, jobFinished() would
                        // be reporting on a job we no longer own.
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
     * in-flight build is abandoned, which is safe by construction — see the class
     * KDoc.
     */
    override fun onStopJob(params: JobParameters): Boolean {
        cancelled.set(true)
        if (params.jobId == JOB_ID_UPDATE) {
            Log.i(TAG, "update job stopped; current.nrdx is untouched")
            return true
        }
        return false
    }

    companion object {
        private const val TAG = "Nullroute"

        const val JOB_ID_UPDATE = 2000

        private const val PERIOD_MS = 24L * 60 * 60 * 1000
        private const val FLEX_MS = 6L * 60 * 60 * 1000
        private const val BACKOFF_MS = 30L * 60 * 1000

        /**
         * What a full BALANCED refresh costs when every list changed. Reported to
         * the scheduler as an upper bound, with the download-only figure as the
         * typical case: the version probe means most runs transfer a few
         * kilobytes, and telling the scheduler otherwise would have it defer a
         * job that is cheaper than the one it is deferring for.
         */
        private const val ESTIMATED_DOWNLOAD_BYTES = 9L * 1024 * 1024
        private const val ESTIMATED_UPLOAD_BYTES = 8L * 1024

        /**
         * (Re)schedules the periodic refresh.
         *
         * `setEstimatedNetworkBytes` is not decoration: it is how the scheduler
         * knows this is a several-megabyte job and defers it off a metered link
         * instead of discovering the cost halfway through.
         *
         * `setRequiresBatteryNotLow` and an unmetered network are the two
         * conditions that make a daily job on a phone defensible at all; the app
         * being `allow-in-power-save` means Doze does not then postpone it
         * indefinitely, which is the failure Re-Malwack's `crond` + `sleep 86400`
         * loop has in the opposite direction — it never fires within 24 h of a
         * reboot, so a device that reboots daily never updates.
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
                .setEstimatedNetworkBytes(ESTIMATED_DOWNLOAD_BYTES, ESTIMATED_UPLOAD_BYTES)
                .setPersisted(true)
                .build()

            runCatching { scheduler.schedule(job) }
                .onFailure { Log.w(TAG, "update job not scheduled: ${it.message}") }
        }

        /**
         * True when the periodic job is currently registered. Diagnostics shows
         * this rather than "auto-update: on", because the setting and the
         * scheduler's actual state can disagree — a `setPersisted` job is lost on
         * a factory reset of the scheduler's own storage, and a user staring at
         * "on" while nothing runs has no way to find that out.
         */
        fun isScheduled(context: Context): Boolean {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return false
            return runCatching { scheduler.getPendingJob(JOB_ID_UPDATE) != null }
                .getOrDefault(false)
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
