package com.bestrom.nullroute.log

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log
import com.bestrom.nullroute.core.Paths

/**
 * The query log, on **Credential Encrypted** storage.
 *
 * ## The storage choice is the security control
 *
 * Everything else Nullroute owns lives in DE storage under `/data/misc/nullroute`
 * so that filtering is live at `post-fs-data`, before first unlock, with no
 * `ENOKEY` window. This database goes the other way on purpose: a DNS log is a
 * browsing history, and a seized-but-locked device must expose none of it. So it
 * sits at
 *
 * ```
 * /data/user/<u>/com.bestrom.nullroute/databases/querylog.db
 * ```
 *
 * which is unreadable until the user unlocks — including by us. Before first
 * unlock the ring accumulates and may wrap; losing some records is the correct
 * trade and [RingReader.Drain] reports it rather than hiding it. That is also why
 * the manifest sets `directBootAware` but deliberately **not**
 * `defaultToDeviceProtectedStorage`: the latter would drag this file into DE
 * along with everything else.
 *
 * SQLite is used here and nowhere else in the system. It cannot be anywhere near
 * the resolver — netd cannot open the app's database, and SQLite needs write
 * access to a journal even to read (SPEC §7.2). A log is the one place where its
 * cost is affordable and its indices are worth having.
 *
 * ## Why `seq` is the primary key
 *
 * The ring ticket is monotonic and unique for the life of the ring file, so it is
 * a natural key and — declared as `INTEGER PRIMARY KEY` — it *is* the rowid,
 * costing no extra index. `INSERT OR REPLACE` then makes re-ingestion idempotent:
 * a cursor lost to a killed process replays records that are already stored and
 * they land on themselves instead of doubling.
 *
 * The one case where the key repeats is a ring file recreated from scratch
 * (`nullroute_seed` reformatting it) without the CE database being wiped. REPLACE
 * is the right behaviour there too: the newest records win and the oldest are
 * overwritten, which is exactly what the retention policy would have done anyway.
 * The opposite choice — `INSERT OR IGNORE` — would silently discard *new* records
 * in favour of stale ones.
 */
class QueryLogDb private constructor(context: Context) :
    SQLiteOpenHelper(context, NAME, null, VERSION) {

    init {
        // One writer (the log pump) and readers on the UI thread. WAL keeps a
        // Log-screen query from blocking behind an insert transaction, which at
        // 4096 records a batch is the difference between a smooth list and a
        // visible stall.
        setWriteAheadLoggingEnabled(true)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE $TABLE (
                seq        INTEGER PRIMARY KEY,
                ts_ms      INTEGER NOT NULL,
                uid        INTEGER NOT NULL,
                name       TEXT    NOT NULL,
                verdict    INTEGER NOT NULL,
                depth      INTEGER NOT NULL,
                rule_group INTEGER NOT NULL,
                truncated  INTEGER NOT NULL DEFAULT 0
            )
            """.trimIndent()
        )
        // Every query the Log screen runs is "recent", "recent for this app" or
        // "which domains", in that order of frequency. Retention's purge is also
        // a range delete on ts_ms, so that index earns its keep twice.
        db.execSQL("CREATE INDEX idx_${TABLE}_ts ON $TABLE(ts_ms)")
        db.execSQL("CREATE INDEX idx_${TABLE}_uid_ts ON $TABLE(uid, ts_ms)")
        db.execSQL("CREATE INDEX idx_${TABLE}_name ON $TABLE(name)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // A query log is telemetry with a retention policy measured in days.
        // Migrating it across a schema change would be work spent preserving data
        // that is about to be deleted anyway, and a migration bug here would be a
        // crash on a screen the user opened *because* something was already
        // wrong. Dropping is both cheaper and safer; it is announced in the UI.
        db.execSQL("DROP TABLE IF EXISTS $TABLE")
        onCreate(db)
    }

    override fun onDowngrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        onUpgrade(db, oldVersion, newVersion)
    }

    // ---- writing -------------------------------------------------------------

    /**
     * Stores a batch in one transaction. Returns how many rows were written.
     *
     * A compiled statement bound in a loop, not `ContentValues` per row: a full
     * ring is 4096 records and `insert()` re-parses the SQL and allocates a map
     * for every one of them.
     */
    fun insert(records: List<RingReader.Record>): Int {
        if (records.isEmpty()) return 0
        val db = writableDatabase
        var written = 0
        db.beginTransaction()
        try {
            db.compileStatement(
                "INSERT OR REPLACE INTO $TABLE" +
                    " (seq, ts_ms, uid, name, verdict, depth, rule_group, truncated)" +
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ).use { stmt ->
                for (r in records) {
                    stmt.clearBindings()
                    stmt.bindLong(1, r.seq)
                    stmt.bindLong(2, r.timestampMs)
                    stmt.bindLong(3, r.uid.toLong())
                    stmt.bindString(4, r.name)
                    stmt.bindLong(5, r.verdict.toLong())
                    stmt.bindLong(6, r.depth.toLong())
                    stmt.bindLong(7, r.ruleGroup.toLong())
                    stmt.bindLong(8, if (r.truncated) 1L else 0L)
                    stmt.executeInsert()
                    written++
                }
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return written
    }

    // ---- reading -------------------------------------------------------------

    data class Entry(
        val seq: Long,
        val timestampMs: Long,
        val uid: Int,
        val name: String,
        val verdict: Int,
        val depth: Int,
        val ruleGroup: Int,
        val truncated: Boolean,
    )

    data class AppTotals(val uid: Int, val blocked: Int, val total: Int)

    data class DomainTotals(val name: String, val blocked: Int, val lastMs: Long, val ruleGroup: Int)

    /** Newest first. [uid] of `null` means every app. */
    fun recent(limit: Int, uid: Int? = null, blockedOnly: Boolean = false): List<Entry> {
        val where = StringBuilder()
        val args = ArrayList<String>(2)
        if (uid != null) {
            where.append("uid = ?")
            args.add(uid.toString())
        }
        if (blockedOnly) {
            if (where.isNotEmpty()) where.append(" AND ")
            where.append("verdict != ${RingReader.VERDICT_PASS}")
        }

        val sql = buildString {
            append("SELECT seq, ts_ms, uid, name, verdict, depth, rule_group, truncated FROM $TABLE")
            if (where.isNotEmpty()) append(" WHERE ").append(where)
            append(" ORDER BY ts_ms DESC, seq DESC LIMIT ?")
        }
        args.add(limit.toString())

        val out = ArrayList<Entry>(minOf(limit, 256))
        readableDatabase.rawQuery(sql, args.toTypedArray()).use { c ->
            while (c.moveToNext()) {
                out.add(
                    Entry(
                        seq = c.getLong(0),
                        timestampMs = c.getLong(1),
                        uid = c.getInt(2),
                        name = c.getString(3),
                        verdict = c.getInt(4),
                        depth = c.getInt(5),
                        ruleGroup = c.getInt(6),
                        truncated = c.getInt(7) != 0,
                    )
                )
            }
        }
        return out
    }

    /** Per-app totals since [sinceMs], busiest first. */
    fun topApps(sinceMs: Long, limit: Int): List<AppTotals> {
        val sql =
            "SELECT uid," +
                " SUM(CASE WHEN verdict != ${RingReader.VERDICT_PASS} THEN 1 ELSE 0 END)," +
                " COUNT(*)" +
                " FROM $TABLE WHERE ts_ms >= ? GROUP BY uid ORDER BY 2 DESC, 3 DESC LIMIT ?"
        val out = ArrayList<AppTotals>()
        readableDatabase.rawQuery(sql, arrayOf(sinceMs.toString(), limit.toString())).use { c ->
            while (c.moveToNext()) out.add(AppTotals(c.getInt(0), c.getInt(1), c.getInt(2)))
        }
        return out
    }

    /** Per-domain totals since [sinceMs], busiest first. */
    fun topDomains(sinceMs: Long, limit: Int): List<DomainTotals> {
        val sql =
            "SELECT name," +
                " SUM(CASE WHEN verdict != ${RingReader.VERDICT_PASS} THEN 1 ELSE 0 END)," +
                " MAX(ts_ms), MAX(rule_group)" +
                " FROM $TABLE WHERE ts_ms >= ? GROUP BY name ORDER BY 2 DESC, 3 DESC LIMIT ?"
        val out = ArrayList<DomainTotals>()
        readableDatabase.rawQuery(sql, arrayOf(sinceMs.toString(), limit.toString())).use { c ->
            while (c.moveToNext()) {
                out.add(DomainTotals(c.getString(0), c.getInt(1), c.getLong(2), c.getInt(3)))
            }
        }
        return out
    }

    fun blockedSince(sinceMs: Long): Int = scalar(
        "SELECT COUNT(*) FROM $TABLE WHERE ts_ms >= ? AND verdict != ${RingReader.VERDICT_PASS}",
        arrayOf(sinceMs.toString()),
    ).toInt()

    fun rowCount(): Int = scalar("SELECT COUNT(*) FROM $TABLE", emptyArray()).toInt()

    /** Timestamp of the oldest stored record, or 0 when the log is empty. */
    fun oldestMs(): Long = scalar("SELECT COALESCE(MIN(ts_ms), 0) FROM $TABLE", emptyArray())

    // ---- deleting ------------------------------------------------------------

    /** Rows strictly older than [cutoffMs]. Returns how many went. */
    fun deleteOlderThan(cutoffMs: Long): Int =
        writableDatabase.delete(TABLE, "ts_ms < ?", arrayOf(cutoffMs.toString()))

    /**
     * Trims to the newest [maxRows] rows.
     *
     * The floor is by *time*, not by rowid: `seq` restarts at 1 whenever the ring
     * file is recreated, so ordering by the primary key would delete the newest
     * records after a reformat rather than the oldest.
     */
    fun trimTo(maxRows: Int): Int {
        val total = rowCount()
        if (total <= maxRows) return 0
        return writableDatabase.delete(
            TABLE,
            "seq IN (SELECT seq FROM $TABLE ORDER BY ts_ms ASC, seq ASC LIMIT ?)",
            arrayOf((total - maxRows).toString()),
        )
    }

    /** Deletes everything and reclaims the pages — "Clear log" must actually
     * shrink the file, not merely mark rows free for reuse. */
    fun clear() {
        writableDatabase.delete(TABLE, null, null)
        runCatching { writableDatabase.execSQL("VACUUM") }
    }

    private fun scalar(sql: String, args: Array<String>): Long =
        readableDatabase.rawQuery(sql, args).use { c ->
            if (c.moveToFirst()) c.getLong(0) else 0L
        }

    companion object {

        private const val TAG = "Nullroute"

        private const val NAME = "querylog.db"
        private const val VERSION = 1
        private const val TABLE = "queries"

        @Volatile
        private var instance: QueryLogDb? = null

        /**
         * The shared helper, or `null` before first unlock.
         *
         * `null` is a normal, expected answer and every caller handles it. It is
         * not an error state and must never be reported as one: it means the user
         * has not unlocked the device yet, and the log is *supposed* to be
         * unreachable then.
         */
        fun get(context: Context): QueryLogDb? {
            if (!Paths.ceAvailable(context)) return null
            instance?.let { return it }
            return synchronized(this) {
                instance ?: runCatching {
                    // applicationContext, deliberately: the app is not
                    // defaultToDeviceProtectedStorage, so its default context IS
                    // the CE one. Routing this through Paths.de() would put the
                    // browsing history in DE storage and quietly undo the whole
                    // point of this file.
                    QueryLogDb(context.applicationContext).also { instance = it }
                }.getOrElse {
                    Log.w(TAG, "query log unavailable: ${it.message}")
                    null
                }
            }
        }

        /** Drops the open handle, e.g. after "Clear log and stop logging". */
        fun close() {
            synchronized(this) {
                runCatching { instance?.close() }
                instance = null
            }
        }
    }
}
