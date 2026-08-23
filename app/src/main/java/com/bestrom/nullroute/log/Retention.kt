package com.bestrom.nullroute.log

import android.content.Context
import android.util.Log
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.data.Settings

/**
 * What the query log keeps, and for how long.
 *
 * A DNS log is a browsing history. Every default here is the conservative one,
 * and each is a deliberate choice rather than a placeholder:
 *
 *  * **Blocked-only, on by default.** The passes are the user's actual browsing;
 *    the blocks are what the product did. Logging only the blocks answers every
 *    question the Log screen exists to answer — which app, which domain, which
 *    rule — while storing a small fraction of the history. "Everything" stays
 *    available for debugging, behind an explicit choice, because there is one
 *    question it alone answers: *why was this domain NOT blocked?*
 *  * **Seven days.** Long enough to explain an app that broke last weekend,
 *    short enough that a stolen phone is not a month of browsing.
 *  * **A row cap as well as an age cap.** Ten thousand blocks an hour is a real
 *    device with a real ad-heavy app on it, and an age-only policy would let the
 *    database reach hundreds of megabytes on CE storage before the first purge.
 *
 * ## The mode is not stored here
 *
 * `ControlPage.log_level` already decides whether netd writes a record into the
 * ring at all — 0 none, 1 blocked-only, 2 all — and it is the resolver's own
 * copy of this setting. A second "blocked only" flag in preferences would be a
 * second authority that can disagree with it, which is the failure this project
 * keeps designing away from (see [Settings] on why mode lives in a property).
 * So [mode] *derives* from `Settings.logLevel`, [setMode] writes through it, and
 * the storage filter below is a belt-and-braces second gate for records the ring
 * already contained when the level changed.
 */
object Retention {

    private const val TAG = "Nullroute"

    /** Shared with [RingReader]: the log subsystem's own DE-backed preferences. */
    private const val PREFS = "nullroute_log"

    private const val KEY_DAYS = "retention_days"
    private const val KEY_MAX_ROWS = "retention_max_rows"
    private const val KEY_LAST_PURGE_MS = "retention_last_purge_ms"

    const val DEFAULT_DAYS = 7
    const val DEFAULT_MAX_ROWS = 50_000

    /** Bounds on what the UI may offer. Zero days would mean "log, then throw it
     * away", which is strictly worse than logging nothing — use [LogMode.OFF]. */
    const val MIN_DAYS = 1
    const val MAX_DAYS = 90

    /** A purge is a range delete on an indexed column; hourly is far more often
     * than it needs to be and still costs nothing next to the drain it follows. */
    private const val PURGE_INTERVAL_MS = 60L * 60L * 1000L

    private const val DAY_MS = 24L * 60L * 60L * 1000L

    /**
     * The three values `NrControl::log_level` takes, named. The numbers are an
     * ABI with the resolver (`NrRingWriter.cpp` compares `lvl == 0` and
     * `lvl < 2`), not an internal enumeration to be renumbered.
     */
    enum class LogMode(val level: Int) {
        /** Nothing is written to the ring, so nothing can be stored. */
        OFF(0),

        /** Blocks and redirects only. The default. */
        BLOCKED(1),

        /** Everything, including passes. Debugging; the user is told what it costs. */
        ALL(2),
        ;

        companion object {
            fun of(level: Int): LogMode = values().firstOrNull { it.level == level } ?: OFF
        }
    }

    private fun prefs(context: Context) =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // ---- mode ---------------------------------------------------------------

    fun mode(context: Context): LogMode = LogMode.of(Settings.logLevel(context))

    /**
     * Changes what gets logged, at the source.
     *
     * [Settings.setLogLevel] writes both the preference and `ControlPage.log_level`,
     * so turning logging off stops netd writing records rather than merely
     * stopping us storing them. Switching to [LogMode.OFF] also drops what is
     * already stored: a user who turns off logging means "stop having this", not
     * "stop adding to this".
     */
    fun setMode(context: Context, newMode: LogMode) {
        Settings.setLogLevel(context, newMode.level)
        if (newMode == LogMode.OFF) clear(context)
    }

    /**
     * Whether a drained record is worth keeping.
     *
     * Takes the mode rather than a Context so a 4096-record batch reads the
     * setting once.
     */
    fun shouldStore(logMode: LogMode, record: RingReader.Record): Boolean = when (logMode) {
        LogMode.OFF -> false
        LogMode.BLOCKED -> record.verdict != RingReader.VERDICT_PASS
        LogMode.ALL -> true
    }

    // ---- window -------------------------------------------------------------

    fun days(context: Context): Int =
        prefs(context).getInt(KEY_DAYS, DEFAULT_DAYS).coerceIn(MIN_DAYS, MAX_DAYS)

    fun setDays(context: Context, value: Int) {
        prefs(context).edit().putInt(KEY_DAYS, value.coerceIn(MIN_DAYS, MAX_DAYS)).apply()
        // Shortening the window must take effect now, not at the next hourly
        // slot: the user just asked for less history to exist.
        purgeNow(context)
    }

    fun maxRows(context: Context): Int =
        prefs(context).getInt(KEY_MAX_ROWS, DEFAULT_MAX_ROWS).coerceAtLeast(1_000)

    fun setMaxRows(context: Context, value: Int) {
        prefs(context).edit().putInt(KEY_MAX_ROWS, value.coerceAtLeast(1_000)).apply()
        purgeNow(context)
    }

    // ---- purging ------------------------------------------------------------

    /** Runs a purge if one has not run in the last hour. Cheap to call often. */
    fun purgeIfDue(context: Context): Result? {
        val now = System.currentTimeMillis()
        val last = prefs(context).getLong(KEY_LAST_PURGE_MS, 0L)
        // `last > now` catches a backwards clock step: without it a device whose
        // clock jumped forward once would never purge again.
        if (last in 1..now && now - last < PURGE_INTERVAL_MS) return null
        return purgeNow(context)
    }

    data class Result(val byAge: Int, val byCount: Int) {
        val total: Int get() = byAge + byCount
    }

    /**
     * Deletes what the policy says should be gone. Returns `null` before first
     * unlock, when the database is legitimately unreachable.
     *
     * **Blocking; background thread only.**
     */
    fun purgeNow(context: Context): Result? {
        val db = QueryLogDb.get(context) ?: return null
        return try {
            val cutoff = System.currentTimeMillis() - days(context) * DAY_MS
            val byAge = db.deleteOlderThan(cutoff)
            val byCount = db.trimTo(maxRows(context))
            prefs(context).edit().putLong(KEY_LAST_PURGE_MS, System.currentTimeMillis()).apply()
            if (byAge + byCount > 0) {
                Log.i(TAG, "log purge: $byAge by age, $byCount by cap")
            }
            Result(byAge, byCount)
        } catch (t: Throwable) {
            Log.w(TAG, "log purge failed: ${t.message}")
            null
        }
    }

    /** Deletes everything the log holds. The UI's "Clear log". */
    fun clear(context: Context) {
        runCatching { QueryLogDb.get(context)?.clear() }
            .onFailure { Log.w(TAG, "clear log failed: ${it.message}") }
    }

    // ---- reporting ----------------------------------------------------------

    /**
     * What Diagnostics shows about the log. `available == false` before first
     * unlock is not a fault — see [QueryLogDb].
     */
    data class Stats(
        val available: Boolean,
        val rows: Int,
        val oldestMs: Long,
        val days: Int,
        val maxRows: Int,
        val mode: LogMode,
    )

    fun stats(context: Context): Stats {
        val db = QueryLogDb.get(context)
        if (db == null) {
            return Stats(false, 0, 0L, days(context), maxRows(context), mode(context))
        }
        return runCatching {
            Stats(true, db.rowCount(), db.oldestMs(), days(context), maxRows(context), mode(context))
        }.getOrElse {
            Stats(false, 0, 0L, days(context), maxRows(context), mode(context))
        }
    }
}
