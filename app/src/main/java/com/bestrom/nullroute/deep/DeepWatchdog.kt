package com.bestrom.nullroute.deep

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes

/**
 * Counters for one Deep-mode session.
 *
 * Written only by the tunnel thread and read by the health tick and by
 * Diagnostics, so single-writer volatile longs are sufficient and a lock on the
 * packet path is not.
 */
class DeepStats {
    @Volatile var queries = 0L
    @Volatile var blocked = 0L
    @Volatile var redirected = 0L
    @Volatile var probes = 0L
    @Volatile var forwarded = 0L
    @Volatile var answered = 0L
    @Volatile var servfails = 0L
    @Volatile var dropped = 0L
    @Volatile var truncatedAnswers = 0L
    @Volatile var upstreamTimeouts = 0L
    @Volatile var upstreamErrors = 0L
    @Volatile var upstreamMismatch = 0L
    @Volatile var socketErrors = 0L
    @Volatile var writeDrops = 0L
    @Volatile var malformed = 0L
    @Volatile var stray = 0L
    @Volatile var evalErrors = 0L
    @Volatile var networkChanges = 0L

    @Volatile var tcpAccepted = 0L
    @Volatile var tcpRejected = 0L
    @Volatile var tcpQueries = 0L
    @Volatile var tcpRelayed = 0L
    @Volatile var tcpAnswered = 0L
    @Volatile var tcpTimeouts = 0L
    @Volatile var tcpErrors = 0L

    /** Every query we produced an answer for, from any source. */
    val served: Long get() = answered + blocked + redirected + probes + tcpAnswered

    override fun toString(): String =
        "q=$queries served=$served blocked=$blocked fwd=$forwarded ans=$answered " +
            "sf=$servfails drop=$dropped tc=$truncatedAnswers to=$upstreamTimeouts " +
            "err=$upstreamErrors tcp=$tcpAccepted/$tcpAnswered"
}

/**
 * The thing that stops Deep mode from bricking connectivity with no way out.
 *
 * ## The failure this exists for
 *
 * Deep mode takes the device's DNS and routes it through this process. If the
 * tunnel establishes and then does not work — a packet-path bug, an index that
 * will not map, an upstream we cannot reach — the user has a phone with no
 * name resolution. They cannot open the Play Store, they may not be able to
 * open a browser, and if the failure survives a reboot they cannot obviously
 * get back to a working state. "Open the app and switch it off" is not a
 * recovery path on a device where nothing loads.
 *
 * So the counter is **persisted before `establish()`, not after**. That
 * ordering is the whole design:
 *
 * ```
 *   beforeEstablish()   commit() a marker saying "an attempt is in flight"
 *   establish()         from here on the device's DNS is ours
 *   ...
 *   markHealthy()       the liveness probe answered — clear the marker
 * ```
 *
 * A tunnel that wedges the device, or takes the process down with it, leaves
 * the marker set. The next start sees it and counts a failure *for the attempt
 * that never reported success* — including the case where we never ran again at
 * all until the next boot. Three of those inside ten minutes and Deep mode
 * turns itself off and stays off until the user turns it back on.
 *
 * Anything an `apply()` would have written is at risk of being lost with the
 * process that wrote it, which is precisely the process this protects against.
 * Hence [SharedPreferences.Editor.commit] on the marker, and Device Encrypted
 * storage so the marker is readable before first unlock.
 */
object DeepWatchdog {

    private const val TAG = "NullrouteDeep"

    /**
     * A separate preferences file from `data/Settings.kt`. Deep mode's state has
     * to be legible and writable on the failure path — before unlock, from a
     * boot receiver, with the rest of the app possibly never having started —
     * and mixing it into the general settings would tie its durability to
     * theirs.
     */
    private const val PREFS = "nullroute_deep"

    private const val KEY_ENABLED = "enabled"
    private const val KEY_DEFAULT_RESOLVED = "default_resolved"
    private const val KEY_ATTEMPT_AT = "attempt_at"
    private const val KEY_FAILURES = "failures"
    private const val KEY_DISABLED_REASON = "disabled_reason"
    private const val KEY_LAST_ERROR = "last_error"

    /** Failures inside [WINDOW_MS] that switch Deep mode off. */
    const val MAX_FAILURES = 3
    const val WINDOW_MS = 10 * 60_000L

    /** Health-tick samples with traffic but no answers before we give up. */
    private const val BAD_SAMPLES_LIMIT = 6

    /** Queries per sample below which "no answers" proves nothing. */
    private const val MIN_SAMPLE_QUERIES = 3L

    private fun prefs(context: Context): SharedPreferences =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // ---- the user-visible switch -------------------------------------------

    fun isEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ENABLED, false)

    /**
     * Turns Deep mode on or off at the user's request. Clears any automatic
     * disable — the user has overruled it, and leaving the reason set would make
     * the UI keep explaining a decision that no longer holds.
     */
    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_ENABLED, enabled)
            .putBoolean(KEY_DEFAULT_RESOLVED, true)
            .remove(KEY_DISABLED_REASON)
            .remove(KEY_FAILURES)
            .remove(KEY_ATTEMPT_AT)
            .apply()
    }

    /**
     * Decides the first-run default, once, and remembers it.
     *
     * **Off on BestROM, on everywhere else.** Deep mode duplicates what the
     * resolver hook already does, at the cost of the user's only VPN slot, so on
     * a device where the hook is live it is an opt-in extra for Chromium
     * coverage. On a device with no hook it is the only thing that can filter at
     * all, and defaulting it off would ship an APK that does nothing.
     *
     * The discriminator is `sys.nullroute.filter`: it only exists on an image
     * carrying our resolver patch. A ROM whose filter is merely *paused* still
     * publishes the property, so pausing the filter does not silently hand the
     * VPN slot to Deep mode.
     *
     * **Blocking** — it samples the probes. Background thread only.
     */
    fun resolveDefault(context: Context): Boolean {
        val p = prefs(context)
        if (p.getBoolean(KEY_DEFAULT_RESOLVED, false)) return isEnabled(context)

        val health = Probes.sample()
        val onRom = health.stateProp.isNotEmpty() && health.stateProp != "unknown"
        val enabled = !onRom && !health.resolverHookLive

        p.edit()
            .putBoolean(KEY_ENABLED, enabled)
            .putBoolean(KEY_DEFAULT_RESOLVED, true)
            .apply()
        Log.i(TAG, "deep default=$enabled (onRom=$onRom hook=${health.resolverHookLive})")
        return enabled
    }

    /** Set when Deep mode switched itself off; null when it did not. */
    fun autoDisabledReason(context: Context): String? =
        prefs(context).getString(KEY_DISABLED_REASON, null)

    /** The last failure message, for Diagnostics. Not a status. */
    fun lastError(context: Context): String? = prefs(context).getString(KEY_LAST_ERROR, null)

    // ---- the attempt marker -------------------------------------------------

    /**
     * The first thing a start does. Returns false when Deep mode must not run.
     *
     * Settles the *previous* attempt on the way in: a marker still set means
     * that attempt established a tunnel and never got as far as [markHealthy],
     * so it is counted now — before we repeat it. This is the only place a
     * failure from a session that took the process down with it can be seen.
     */
    fun mayStart(context: Context): Boolean {
        val p = prefs(context)
        if (!p.getBoolean(KEY_ENABLED, false)) return false
        if (p.getString(KEY_DISABLED_REASON, null) != null) return false

        val stale = p.getLong(KEY_ATTEMPT_AT, 0L)
        if (stale != 0L) {
            Log.w(TAG, "previous Deep-mode attempt never reported healthy")
            if (recordFailure(context, "the tunnel stopped responding")) return false
        }
        return true
    }

    /**
     * Arms the marker. Call in the statement immediately before `establish()`,
     * and nowhere else.
     *
     * Everything up to this point — mapping the index, choosing aliases, reading
     * the network's resolvers — can fail without the device losing anything,
     * because no tunnel exists yet. Arming any earlier would count those as
     * failures and switch Deep mode off for a user who was merely in a lift.
     *
     * `commit()` rather than `apply()`: the process this protects against may
     * not survive long enough for an asynchronous write to land, and a marker
     * that was never written is a failure that is never counted.
     */
    fun armAttempt(context: Context) {
        val ok = prefs(context).edit()
            .putLong(KEY_ATTEMPT_AT, System.currentTimeMillis())
            .commit()
        if (!ok) Log.w(TAG, "attempt marker did not commit; auto-disable is degraded")
    }

    /**
     * The tunnel proved itself — the Deep-mode liveness probe resolved through
     * it. Clears the marker and the failure history.
     */
    fun markHealthy(context: Context) {
        prefs(context).edit()
            .remove(KEY_ATTEMPT_AT)
            .remove(KEY_FAILURES)
            .apply()
    }

    /**
     * A stop that is nobody's fault — the user switched it off, or another VPN
     * took the slot. Clears the marker without counting a failure: revocation is
     * not a malfunction, and counting it would auto-disable Deep mode for a user
     * who merely connected to their work VPN three times.
     */
    fun markCleanStop(context: Context) {
        prefs(context).edit().remove(KEY_ATTEMPT_AT).apply()
    }

    /**
     * Records a failed session. Returns true if that was the third inside the
     * window and Deep mode has switched itself off.
     */
    fun recordFailure(context: Context, reason: String): Boolean {
        val p = prefs(context)
        val now = System.currentTimeMillis()
        val kept = ArrayList<Long>(MAX_FAILURES + 1)
        for (part in (p.getString(KEY_FAILURES, "") ?: "").split(',')) {
            val at = part.trim().toLongOrNull() ?: continue
            // A clock step backwards would otherwise strand old entries in the
            // window for ever; treat anything in the future as now.
            if (at in (now - WINDOW_MS)..now) kept += at
        }
        kept += now

        val editor = p.edit()
            .putString(KEY_FAILURES, kept.joinToString(","))
            .putString(KEY_LAST_ERROR, reason)
            .remove(KEY_ATTEMPT_AT)

        val exhausted = kept.size >= MAX_FAILURES
        if (exhausted) {
            editor.putBoolean(KEY_ENABLED, false).putString(KEY_DISABLED_REASON, reason)
            Log.w(TAG, "Deep mode auto-disabled after ${kept.size} failures: $reason")
        } else {
            Log.w(TAG, "Deep-mode failure ${kept.size}/$MAX_FAILURES: $reason")
        }
        editor.commit()
        return exhausted
    }

    // ---- in-session liveness ------------------------------------------------

    /**
     * Watches a running tunnel for the "up but dead" state — routes in place,
     * queries arriving, nothing coming back.
     *
     * Deliberately says nothing about an *idle* tunnel. A phone in a pocket
     * sends no DNS for minutes at a time, and treating silence as failure would
     * tear down a perfectly good tunnel every time the screen went off. Only a
     * sustained run of samples that carried real traffic and produced no answers
     * counts, because that is the only shape that distinguishes "broken" from
     * "quiet".
     */
    class Liveness {
        private var lastQueries = 0L
        private var lastServed = 0L
        private var badSamples = 0

        /** False once the tunnel has been carrying traffic and answering none. */
        fun sample(stats: DeepStats): Boolean {
            val q = stats.queries
            val s = stats.served
            val dq = q - lastQueries
            val ds = s - lastServed
            lastQueries = q
            lastServed = s
            if (dq >= MIN_SAMPLE_QUERIES && ds == 0L) badSamples++ else badSamples = 0
            return badSamples < BAD_SAMPLES_LIMIT
        }

        fun reset() {
            badSamples = 0
        }
    }
}
