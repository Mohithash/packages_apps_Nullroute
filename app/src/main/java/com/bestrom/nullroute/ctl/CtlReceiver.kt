package com.bestrom.nullroute.ctl

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Generation
import com.bestrom.nullroute.deep.DeepVpnService
import com.bestrom.nullroute.deep.DeepWatchdog
import com.bestrom.nullroute.export.SettingsArchive
import com.bestrom.nullroute.importer.HostsImporter
import com.bestrom.nullroute.job.HealthWatchdog
import com.bestrom.nullroute.job.UpdateJobService
import java.io.File

/**
 * The control channel for `nrctl`'s mutating verbs.
 *
 * Read-only verbs (`status`, `query`, `verify`) never come through here — they
 * read the mmapped files directly, since `shell` holds read access to
 * `nullroute_index_file`, `nullroute_ctl_file` and `nullroute_log_file`. Only
 * things that change state need an authenticated caller.
 *
 * ## The gate, and the trap it avoids (F2)
 *
 * The obvious implementation is `Binder.getCallingUid()` inside `onReceive()`.
 * **It does not work.** There is no ongoing binder transaction at that point, so
 * the call returns *this process's own* uid — a gate that unconditionally
 * approves. It looks correct in review, it looks correct in testing (the uid it
 * returns is on the allowlist), and it authenticates nothing.
 *
 * Three real gates instead:
 *
 *  1. `android:permission` on the receiver, checked by ActivityManager against
 *     the sender before we are ever invoked;
 *  2. [BroadcastReceiver.getSentFromUid], added in API 34, which is the only API
 *     that names the sender from inside `onReceive()`;
 *  3. the explicit `{0, 1000, 2000}` allowlist below.
 *
 * Below API 34 there is no way to authenticate the sender at all, so every
 * broadcast is refused. `min_sdk_version` is 33 and Android 17 is 37, so this is
 * a compile-time floor rather than a runtime one — but a gate that silently
 * degrades to "allow" on an older platform is not a gate.
 */
class CtlReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_CTL) return

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Log.w(TAG, "refusing CTL: sender cannot be authenticated below API 34")
            return
        }

        val from = senderUid()
        if (from !in ALLOWED_UIDS) {
            Log.w(TAG, "rejecting CTL from uid=$from pkg=${senderPackage()}")
            return
        }

        val verb = intent.getStringExtra(EXTRA_VERB).orEmpty()
        Log.i(TAG, "CTL $verb from uid=$from")
        dispatch(context.applicationContext, verb, intent)
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun senderUid(): Int = runCatching { sentFromUid }.getOrDefault(-1)

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun senderPackage(): String = runCatching { sentFromPackage }.getOrNull() ?: "?"

    /**
     * Executes a verb.
     *
     * Mode changes are a single byte in a mapped page and complete inline.
     * Anything longer is handed to the shared worker and this method returns
     * immediately: a receiver has about ten seconds of runtime and a full
     * recompile takes minutes, so `update` starts the work rather than
     * pretending to be synchronous. `nrctl` reports "started", not "done", for
     * the same reason.
     */
    private fun dispatch(context: Context, verb: String, intent: Intent) {
        when (verb) {
            VERB_PAUSE -> setMode(context, ControlPage.MODE_PAUSED)
            VERB_RESUME -> setMode(context, ControlPage.MODE_ENFORCE)
            VERB_OFF -> setMode(context, ControlPage.MODE_OFF)

            VERB_MODE -> {
                val value = intent.getIntExtra(EXTRA_VALUE, ControlPage.MODE_ENFORCE)
                if (value in ControlPage.MODE_ENFORCE..ControlPage.MODE_OFF) {
                    setMode(context, value)
                } else {
                    Log.w(TAG, "ignoring out-of-range mode $value")
                }
            }

            VERB_UPDATE -> UpdateJobService.runNow(context)

            VERB_CHECK -> NullrouteApp.io.execute {
                runCatching { HealthWatchdog.runCheck(context) }
            }

            // A path from a privileged caller, not from the file system: the
            // sender is already gated to {root, system, shell}, so the check that
            // matters is whether the APP can read it. /data/local/tmp cannot be
            // read by an app at all, which is why nrctl says so in its output.
            VERB_IMPORT -> {
                val path = intent.getStringExtra(EXTRA_PATH)
                if (path.isNullOrEmpty()) {
                    Log.w(TAG, "import with no $EXTRA_PATH extra")
                    return
                }
                NullrouteApp.io.execute {
                    runCatching {
                        val plan = HostsImporter.preview(context, Uri.fromFile(File(path)))
                        Log.i(TAG, "import $path -> ${plan.commit(context)}")
                    }.onFailure { Log.w(TAG, "import $path failed", it) }
                }
            }

            VERB_EXPORT -> {
                val path = intent.getStringExtra(EXTRA_PATH) ?: DEFAULT_EXPORT_PATH
                NullrouteApp.io.execute {
                    runCatching {
                        val file = File(path)
                        file.parentFile?.mkdirs()
                        Log.i(TAG, "export $path: ${SettingsArchive.export(context, Uri.fromFile(file)).bytes} bytes")
                    }.onFailure { Log.w(TAG, "export $path failed", it) }
                }
            }

            VERB_ROLLBACK -> NullrouteApp.io.execute {
                if (!Generation.canRollback()) {
                    Log.w(TAG, "rollback refused: no previous index")
                } else {
                    Log.i(TAG, "rollback: ${Generation.rollback(context).describe()}")
                }
            }

            VERB_DEEP -> {
                val enable = intent.getBooleanExtra(EXTRA_ENABLE, false)
                DeepWatchdog.setEnabled(context, enable)
                if (!enable) {
                    DeepVpnService.stop(context)
                } else if (DeepVpnService.prepareIntent(context) == null) {
                    DeepVpnService.start(context)
                } else {
                    // Consent has never been granted and a broadcast cannot grant
                    // it. Starting anyway would fail at establish() and spend one
                    // of the watchdog's three lives on something that is not a
                    // malfunction. The flag is still set, so the app asks the next
                    // time the screen opens.
                    Log.w(TAG, "deep on requested but VPN consent has not been granted")
                }
            }

            // Every switch at once. Deliberately touches no user DATA: panic is
            // for a device that cannot resolve anything, and a verb that also
            // deleted rules would be one nobody could safely try.
            VERB_PANIC -> {
                setMode(context, ControlPage.MODE_OFF)
                DeepWatchdog.setEnabled(context, false)
                DeepVpnService.stop(context)
                Log.w(TAG, "panic: mode=off, deep=off")
            }

            else -> Log.w(TAG, "unknown CTL verb \"$verb\"")
        }
    }

    private fun setMode(context: Context, mode: Int) {
        if (!ControlPage.open()) {
            Log.w(TAG, "cannot set mode: ${ControlPage.lastError}")
            return
        }
        ControlPage.setMode(mode)
        NullrouteApp.io.execute { runCatching { HealthWatchdog.runCheck(context) } }
    }

    companion object {
        private const val TAG = "Nullroute"

        const val ACTION_CTL = "com.bestrom.nullroute.action.CTL"
        const val EXTRA_VERB = "verb"
        const val EXTRA_VALUE = "value"

        const val VERB_PAUSE = "pause"
        const val VERB_RESUME = "resume"
        const val VERB_OFF = "off"
        const val VERB_MODE = "mode"
        const val VERB_UPDATE = "update"
        const val VERB_CHECK = "check"

        const val EXTRA_PATH = "path"
        const val EXTRA_ENABLE = "enable"

        const val VERB_IMPORT = "import"
        const val VERB_EXPORT = "export"
        const val VERB_ROLLBACK = "rollback"
        const val VERB_DEEP = "deep"
        const val VERB_PANIC = "panic"

        /** Where `nrctl export` writes when it is given no path. */
        const val DEFAULT_EXPORT_PATH = "/data/misc/nullroute/priv/nullroute-settings.zip"

        /**
         * root, system, shell. Note that uid 2000 is only reachable if the ROM
         * assigns `com.bestrom.nullroute.permission.CTL` to shell in
         * /system_ext/etc/permissions — uid 0 and 1000 bypass permission checks
         * inside ActivityManager, shell does not. See the manifest comment.
         */
        private val ALLOWED_UIDS = intArrayOf(0, 1000, 2000)
    }
}
