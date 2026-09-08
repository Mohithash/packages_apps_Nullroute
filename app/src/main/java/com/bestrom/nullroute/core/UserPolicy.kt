package com.bestrom.nullroute.core

import android.content.Context
import android.os.Process
import android.os.UserManager
import com.bestrom.nullroute.log.QueryLogDb

/**
 * What per-app policy means on a device that has more than one Android user.
 *
 * The control page stores policy as `uid_policy[appId]`, one byte per **appId**,
 * where `appId = uid % 100000` — the resolver computes it that way and
 * `NrControl.h` pins the array's shape by `static_assert`. The user half of a
 * uid is discarded before the lookup. That is not an oversight: netd serves every
 * user from one process and one mapping, and a per-(user, app) table would be
 * 100000 bytes times however many users exist, sized at build time, for a
 * distinction almost no rule needs.
 *
 * The consequence is the thing this file exists to make impossible to miss:
 *
 * > Work-profile Chrome (uid 1010123) and personal Chrome (uid 10123) share
 * > appId 123. **One policy byte governs both.** Exempting an app in one profile
 * > exempts it in every profile on the device, including the owner's.
 *
 * A per-app screen that did not say so would be lying by omission — the user
 * would believe they had scoped a change to their work profile. So every write
 * goes through [set], which returns the reach of what it just did, and every
 * caller is expected to show it.
 *
 * **No new permissions.** Enumerating other users needs `MANAGE_USERS` or
 * `INTERACT_ACROSS_USERS`, neither of which this app holds and neither of which
 * is worth requesting to populate a caption. So the other users are not asked
 * for — they are *observed*, from the uids the resolver actually attributed
 * queries to in the query log. That is evidence rather than assumption, which is
 * the same standard the status card is held to, and it degrades honestly: a user
 * who has generated no DNS traffic simply is not listed, and [Reach] says
 * "every user" rather than naming them.
 */
object UserPolicy {

    /** `AID_USER_OFFSET` from `android_filesystem_config.h`; also `NR_AID_USER_OFFSET`. */
    const val AID_USER_OFFSET = 100_000

    /** First appId Android hands to an installed app; below this is a system aid. */
    const val AID_APP_START = 10_000

    fun userIdOf(uid: Int): Int = uid / AID_USER_OFFSET

    fun appIdOf(uid: Int): Int = uid % AID_USER_OFFSET

    /** True for a normal installed app, false for the platform aids (root, radio, ...). */
    fun isAppUid(uid: Int): Boolean = appIdOf(uid) >= AID_APP_START

    /** The user this process runs as. Derived from our own uid, so no permission. */
    fun currentUserId(): Int = userIdOf(Process.myUid())

    /**
     * Whether this instance runs inside a managed (work) profile.
     *
     * `UserManager.isManagedProfile()` is public API and asks only about the
     * calling user, so it needs no permission — unlike the overload that takes a
     * user id.
     */
    fun isManagedProfile(context: Context): Boolean =
        runCatching {
            context.getSystemService(UserManager::class.java)?.isManagedProfile == true
        }.getOrDefault(false)

    /** How far a single policy write actually travels. */
    enum class Reach {
        /** Only user we have evidence of, and it is ours. */
        THIS_USER_ONLY,

        /** Other users exist; the byte governs the same app in all of them. */
        EVERY_USER,
    }

    /**
     * Where this app instance sits, and how far its writes reach.
     *
     * [otherUserIds] is what the query log has *seen*, never a claim of
     * completeness — [reach] is the authority. When traffic from exactly one
     * user has been logged we still cannot prove no other user exists; we can
     * only prove none has resolved anything yet, which is why the log is
     * consulted for the caption and not for the verdict.
     */
    data class Scope(
        val userId: Int,
        val managedProfile: Boolean,
        val otherUserIds: List<Int>,
        val reach: Reach,
    )

    /**
     * Reads the query log. **Call from a background thread** — it opens a
     * SQLite database.
     */
    fun scope(context: Context, sinceMs: Long = 0L): Scope {
        val me = currentUserId()
        val others = observedUserIds(context, sinceMs).filter { it != me }.sorted()
        return Scope(
            userId = me,
            managedProfile = isManagedProfile(context),
            otherUserIds = others,
            reach = if (others.isEmpty()) Reach.THIS_USER_ONLY else Reach.EVERY_USER,
        )
    }

    /**
     * Android users the resolver has attributed at least one query to.
     *
     * Uses [QueryLogDb.topApps] rather than a bespoke query so there is one place
     * that knows the log's schema. A null database (logging off, or the file
     * unopenable) yields an empty list, which reads as "no evidence" and never as
     * "no other users".
     */
    fun observedUserIds(context: Context, sinceMs: Long = 0L): List<Int> {
        val db = QueryLogDb.get(context) ?: return emptyList()
        return runCatching {
            db.topApps(sinceMs, TOP_APPS_SAMPLE)
                .map { userIdOf(it.uid) }
                .distinct()
        }.getOrDefault(emptyList())
    }

    /** What happened, and — when something happened — how far it went. */
    sealed class Result {
        data class Applied(val appId: Int, val reach: Reach) : Result()

        /** The control page is not mapped; nothing was written and nothing changed. */
        object NotMapped : Result()

        /**
         * Refused: exempting our own appId would make the liveness probe resolve
         * `idx-probe.nullroute.invalid` unfiltered, and the status card would
         * then report "not filtering" on a perfectly healthy device.
         * [ControlPage.setUidPolicy] enforces this; it is named here so a caller
         * can explain the refusal instead of showing a silent no-op.
         */
        object RefusedOwnApp : Result()

        object OutOfRange : Result()
    }

    /**
     * Sets policy for the app that owns [uid].
     *
     * Takes a **uid**, not an appId, because that is what callers actually hold —
     * the query log records uids — and converting here is the point at which the
     * user half is visibly discarded rather than accidentally.
     *
     * Reads the query log. **Call from a background thread.**
     */
    fun set(context: Context, uid: Int, policy: Byte, sinceMs: Long = 0L): Result {
        val appId = appIdOf(uid)
        if (appId < 0 || appId >= AID_USER_OFFSET) return Result.OutOfRange
        if (!ControlPage.isMapped) return Result.NotMapped
        if (policy == ControlPage.POLICY_EXEMPT && appId == ControlPage.ownAppId()) {
            return Result.RefusedOwnApp
        }
        if (!ControlPage.setUidPolicy(appId, policy)) return Result.NotMapped
        return Result.Applied(appId, scope(context, sinceMs).reach)
    }

    fun get(uid: Int): Byte = ControlPage.getUidPolicy(appIdOf(uid))

    /**
     * The stricter of two policies.
     *
     * The ordering is STRICT > ENFORCE > EXEMPT, and it is deliberately not the
     * numeric order of the constants (`ENFORCE 0, EXEMPT 1, STRICT 2`). Merging
     * two intents for the same appId — the same app in two profiles, or a rule
     * the user set twice — must never be able to turn two "block this" into one
     * "don't", so the merge is defined by strictness and the byte values stay
     * free to change.
     */
    fun strictest(a: Byte, b: Byte): Byte =
        if (rank(a) >= rank(b)) a else b

    private fun rank(policy: Byte): Int = when (policy) {
        ControlPage.POLICY_STRICT -> 2
        ControlPage.POLICY_EXEMPT -> 0
        else -> 1 // ENFORCE, and anything unrecognised, which must not read as exempt
    }

    /**
     * A label for [uid] good enough for a caption: the package name if this user
     * can see it, otherwise `uid <n>`.
     *
     * `getNameForUid` only resolves packages installed for the CALLING user, so a
     * uid belonging to another profile deliberately renders as its number rather
     * than as a guess.
     */
    fun label(context: Context, uid: Int): String =
        runCatching { context.packageManager.getNameForUid(uid) }.getOrNull()
            ?: "uid $uid"

    /**
     * How many rows of `topApps` are enough to notice a second user exists. The
     * log is grouped by uid, so this is a count of distinct apps, not of queries;
     * a profile that has resolved anything at all lands well inside it.
     */
    private const val TOP_APPS_SAMPLE = 200
}
