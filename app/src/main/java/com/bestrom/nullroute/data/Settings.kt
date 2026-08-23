package com.bestrom.nullroute.data

import android.content.Context
import android.content.SharedPreferences
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Paths

/**
 * App settings, on **Device Encrypted** storage.
 *
 * Two deliberate choices here, both of which look like the wrong answer until you
 * consider when this code runs.
 *
 * **SharedPreferences, not androidx.datastore.** DataStore has no prebuilt in the
 * tree, so a Soong build cannot link it — but the real reason is that the boot
 * receiver, the watchdog and the QS tile all read settings *before first unlock*,
 * and DataStore's coroutine-and-CE assumptions do not survive that. A DE-backed
 * SharedPreferences does.
 *
 * **Mode is not stored here.** `persist.sys.nullroute.mode` is the durable
 * authority for pause/resume and `ctl.mode` is the live derivation of it; adding
 * a third copy in preferences would create two authorities that can disagree
 * about a boolean, which is precisely the failure this design was built to avoid.
 * [ControlPage.setMode] is the only writer.
 */
object Settings {

    private const val PREFS = "nullroute"

    private const val KEY_PROFILE = "profile_id"
    private const val KEY_RESPONSE_MODE = "response_mode"
    private const val KEY_LOG_LEVEL = "log_level"
    private const val KEY_LAST_GENERATION = "last_generation"
    private const val KEY_LAST_PROMOTED = "last_promoted_generation"
    private const val KEY_LAST_UPDATE_MS = "last_update_ms"
    private const val KEY_LAST_UPDATE_OK = "last_update_ok"
    private const val KEY_LAST_UPDATE_MSG = "last_update_msg"
    private const val KEY_LAST_ENTRY_COUNT = "last_entry_count"
    private const val KEY_AUTO_UPDATE = "auto_update"
    private const val KEY_UNMETERED_ONLY = "unmetered_only"
    private const val KEY_LAST_STATUS = "last_status"
    private const val KEY_FIRST_RUN_DONE = "first_run_done"

    private fun prefs(context: Context): SharedPreferences =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // ---- profile ------------------------------------------------------------

    fun profileId(context: Context): String =
        prefs(context).getString(KEY_PROFILE, SourceCatalog.DEFAULT_PROFILE)
            ?: SourceCatalog.DEFAULT_PROFILE

    fun setProfileId(context: Context, id: String) {
        prefs(context).edit().putString(KEY_PROFILE, id).apply()
    }

    // ---- response semantics -------------------------------------------------

    /**
     * What a blocked lookup returns. Default `EAI_NONAME`: byte-identical to a
     * real NXDOMAIN, so the app makes zero connection attempts and spends zero
     * battery on them. It is not a "network unavailable" signal, which is why
     * this is a setting at all — some apps hard-fail on NXDOMAIN.
     */
    fun responseMode(context: Context): Int =
        prefs(context).getInt(KEY_RESPONSE_MODE, ControlPage.RESP_NONAME)

    fun setResponseMode(context: Context, value: Int) {
        prefs(context).edit().putInt(KEY_RESPONSE_MODE, value).apply()
        ControlPage.setResponseMode(value)
    }

    fun logLevel(context: Context): Int = prefs(context).getInt(KEY_LOG_LEVEL, 0)

    fun setLogLevel(context: Context, value: Int) {
        prefs(context).edit().putInt(KEY_LOG_LEVEL, value).apply()
        ControlPage.setLogLevel(value)
    }

    // ---- generations --------------------------------------------------------

    fun lastGeneration(context: Context): Long = prefs(context).getLong(KEY_LAST_GENERATION, 0L)

    fun setLastGeneration(context: Context, value: Long) {
        prefs(context).edit().putLong(KEY_LAST_GENERATION, value).apply()
    }

    fun lastPromotedGeneration(context: Context): Long =
        prefs(context).getLong(KEY_LAST_PROMOTED, 0L)

    fun setLastPromotedGeneration(context: Context, value: Long) {
        prefs(context).edit().putLong(KEY_LAST_PROMOTED, value).apply()
    }

    // ---- last update --------------------------------------------------------

    data class UpdateRecord(
        val whenMs: Long,
        val ok: Boolean,
        val message: String,
        val entryCount: Int,
    ) {
        val everRan: Boolean get() = whenMs > 0L
    }

    fun lastUpdate(context: Context): UpdateRecord = prefs(context).let {
        UpdateRecord(
            whenMs = it.getLong(KEY_LAST_UPDATE_MS, 0L),
            ok = it.getBoolean(KEY_LAST_UPDATE_OK, false),
            message = it.getString(KEY_LAST_UPDATE_MSG, "").orEmpty(),
            entryCount = it.getInt(KEY_LAST_ENTRY_COUNT, 0),
        )
    }

    fun recordUpdate(context: Context, ok: Boolean, message: String, entryCount: Int) {
        prefs(context).edit()
            .putLong(KEY_LAST_UPDATE_MS, System.currentTimeMillis())
            .putBoolean(KEY_LAST_UPDATE_OK, ok)
            .putString(KEY_LAST_UPDATE_MSG, message)
            .putInt(KEY_LAST_ENTRY_COUNT, entryCount)
            .apply()
    }

    // ---- scheduling ---------------------------------------------------------

    fun autoUpdate(context: Context): Boolean = prefs(context).getBoolean(KEY_AUTO_UPDATE, true)

    fun setAutoUpdate(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTO_UPDATE, value).apply()
    }

    fun unmeteredOnly(context: Context): Boolean =
        prefs(context).getBoolean(KEY_UNMETERED_ONLY, true)

    fun setUnmeteredOnly(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_UNMETERED_ONLY, value).apply()
    }

    // ---- cached status ------------------------------------------------------

    /**
     * The last probe verdict, cached only so the QS tile can render instantly.
     * Every other consumer re-probes: a cached "Protected" shown as if it were
     * live is exactly the lie the dual-probe design exists to prevent, so this
     * value is always presented as "last checked", never as "now".
     */
    fun lastStatus(context: Context): String =
        prefs(context).getString(KEY_LAST_STATUS, "UNKNOWN") ?: "UNKNOWN"

    fun setLastStatus(context: Context, status: String) {
        prefs(context).edit().putString(KEY_LAST_STATUS, status).apply()
    }

    fun firstRunDone(context: Context): Boolean =
        prefs(context).getBoolean(KEY_FIRST_RUN_DONE, false)

    fun setFirstRunDone(context: Context) {
        prefs(context).edit().putBoolean(KEY_FIRST_RUN_DONE, true).apply()
    }

    // TODO(Phase 2): category toggles and their FP-risk chips, the anti-fraud /
    // attribution carve-outs, and the update schedule editor.
    // TODO(Phase 3): log retention days and the redaction default.
}
