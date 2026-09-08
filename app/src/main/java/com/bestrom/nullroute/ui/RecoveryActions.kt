package com.bestrom.nullroute.ui

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.bestrom.nullroute.R
import com.bestrom.nullroute.build.IndexBuilder
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.ForegroundAppTracker
import com.bestrom.nullroute.data.RuleStore
import com.bestrom.nullroute.notify.BreakageNotifier

/**
 * The three recovery moves, and the truth about what each one actually does.
 *
 * A user reaches these from a broken app, so every one of them returns a message
 * that says what changed **and when it takes effect**, because the three differ:
 *
 * | action        | live when                          |
 * |---------------|------------------------------------|
 * | exempt app    | the resolver's next lookup         |
 * | allow domain  | after the index is recompiled      |
 * | force stop    | immediately, and destructively     |
 *
 * ## Why force stop is offered at all
 *
 * Un-blocking is genuinely instant at the resolver: a blocked answer is refused
 * before `res_cache` is ever consulted and is never inserted into it, so there is
 * no stale entry of *ours* anywhere in the system. What survives is the cache
 * **inside the app** — OkHttp's `Dns` results, Chromium's host cache, the JVM's
 * negative `InetAddress` cache — and those are not ours to flush. The one API
 * that would clear the system side, `IDnsResolver.flushNetworkCache`, is behind
 * `dnsresolver_service`, which sepolicy `neverallow`s any app from reaching; we
 * cannot call it even as a privileged app, and pretending otherwise would leave
 * the user tapping a button that does nothing.
 *
 * So the honest UI is: change the policy, say it is live, and offer the one lever
 * that does empty an app's own caches — restarting it.
 *
 * Every function here is **blocking** (file IO or a binder call) and belongs on a
 * background thread; the callers use `NullrouteApp.io` and post back.
 */
object RecoveryActions {

    private const val TAG = "Nullroute"

    /**
     * `android.permission.FORCE_STOP_PACKAGES` as a literal.
     *
     * The constant is `@hide`, and this module compiles against `system_current`.
     * The permission is in rom/privapp-permissions-com.bestrom.nullroute.xml; the
     * matching `<uses-permission>` is in docs/needs-ui3.md, and until it lands
     * [canForceStop] correctly reports false rather than throwing at the user.
     */
    private const val PERM_FORCE_STOP = "android.permission.FORCE_STOP_PACKAGES"

    /** `ActivityManager.forceStopPackage` is `@hide`; see [DeviceConfigFixups]. */
    private val forceStopMethod by lazy {
        runCatching {
            ActivityManager::class.java.getMethod("forceStopPackage", String::class.java)
        }.getOrElse {
            Log.w(TAG, "forceStopPackage not resolvable: ${it.message}")
            null
        }
    }

    /**
     * What happened, in words the screen can show unchanged.
     *
     * [pending] is the load-bearing field: an allow rule is written but *not* in
     * force, and a screen that reports "done" for both cases teaches the user
     * that our "done" means nothing.
     */
    data class Outcome(
        val ok: Boolean,
        val message: String,
        val pending: Boolean = false,
    )

    // ---- app exemption: live on the next lookup ------------------------------

    /**
     * appId from uid. `uid % AID_USER_OFFSET` is the same arithmetic
     * [ControlPage.setUidPolicy] indexes with — policy is per *app*, shared
     * across secondary users and work profiles, because the resolver has one
     * table and a single `uid_policy` byte per appId.
     */
    private fun appIdOf(uid: Int): Int = uid % 100_000

    fun isExempt(uid: Int): Boolean =
        ControlPage.isMapped &&
            ControlPage.getUidPolicy(appIdOf(uid)) == ControlPage.POLICY_EXEMPT

    fun setExempt(context: Context, uid: Int, exempt: Boolean): Outcome {
        val label = ForegroundAppTracker.label(context, uid)
            ?: return Outcome(false, context.getString(R.string.rec_exempt_unknown_app))

        if (!ControlPage.open()) {
            return Outcome(false, context.getString(R.string.rec_exempt_unavailable))
        }

        val appId = appIdOf(uid)
        if (exempt && appId == ControlPage.ownAppId()) {
            // ControlPage refuses this too. Refusing it here as well means the
            // user gets the reason instead of a silent no-op.
            return Outcome(false, context.getString(R.string.rec_exempt_self))
        }

        val policy = if (exempt) ControlPage.POLICY_EXEMPT else ControlPage.POLICY_ENFORCE
        if (!ControlPage.setUidPolicy(appId, policy)) {
            return Outcome(false, context.getString(R.string.rec_exempt_unavailable))
        }

        if (exempt) {
            // The breakage notification is now answered; leaving it in the shade
            // would invite a second exemption of an app already exempt.
            runCatching { BreakageNotifier.cancel(context, appId) }
            runCatching { BreakageNotifier.clearRateLimit(context, appId) }
        }

        val res = if (exempt) R.string.rec_exempt_done else R.string.rec_exempt_undone
        return Outcome(true, context.getString(res, label))
    }

    // ---- domain allow: live after a rebuild ----------------------------------

    /**
     * Adds `domain` to `allow.txt`.
     *
     * The rule is stored as a **pattern**, never as the expansion of one, so the
     * file stays the thing the user can read back and edit. It does not take
     * effect until the index is recompiled — [rebuild] — and the returned
     * [Outcome.pending] says so.
     */
    fun allowDomain(context: Context, domain: String): Outcome {
        val parsed = RuleStore.parseAllow(domain)
        val pattern = parsed.getOrElse {
            return Outcome(
                false,
                context.getString(R.string.rec_allow_bad, it.message ?: domain),
            )
        }

        if (RuleStore.readAllow().contains(pattern)) {
            return Outcome(true, context.getString(R.string.rec_allow_duplicate, pattern.domain))
        }

        if (!RuleStore.addAllow(pattern)) {
            return Outcome(false, context.getString(R.string.rec_allow_write_failed))
        }

        return Outcome(
            ok = true,
            message = context.getString(R.string.rec_allow_done, pattern.domain) + " " +
                context.getString(R.string.rec_allow_pending),
            pending = true,
        )
    }

    fun isAllowed(domain: String): Boolean = runCatching {
        val pattern = RuleStore.parseAllow(domain).getOrNull() ?: return false
        RuleStore.readAllow().contains(pattern)
    }.getOrDefault(false)

    /**
     * Recompiles the index so a freshly written allow rule takes effect.
     *
     * This is the ordinary update path, which is deliberate: one builder, one
     * promotion, one set of canaries. Sources already downloaded are reused, so
     * a device with no network still gets its rule applied.
     *
     * **Minutes-long. Background thread only.**
     */
    fun rebuild(context: Context): Outcome {
        val outcome = runCatching { IndexBuilder.run(context.applicationContext, null) }
            .getOrElse {
                Log.e(TAG, "rebuild after allow failed", it)
                return Outcome(false, it.message ?: it.javaClass.simpleName)
            }
        return Outcome(outcome.ok, outcome.message())
    }

    // ---- force stop: immediate and destructive -------------------------------

    /**
     * Whether this build can actually do it.
     *
     * Both halves are checked because they fail independently: the permission can
     * be missing from the manifest while the method exists, and a future platform
     * could rename the method while the permission is still granted. A button
     * that is present but inert is worse than one that is absent.
     */
    fun canForceStop(context: Context): Boolean =
        forceStopMethod != null &&
            context.checkSelfPermission(PERM_FORCE_STOP) == PackageManager.PERMISSION_GRANTED

    fun packagesFor(context: Context, uid: Int): List<String> = runCatching {
        context.packageManager.getPackagesForUid(uid)?.toList().orEmpty()
    }.getOrDefault(emptyList())

    /**
     * Force stops every package sharing [uid].
     *
     * A `sharedUserId` app is several packages behind one uid, and the exemption
     * that preceded this applies to all of them, so stopping one and leaving the
     * others running would restart the same cached failure from the sibling.
     */
    fun forceStop(context: Context, uid: Int): Outcome {
        val label = ForegroundAppTracker.label(context, uid) ?: uid.toString()

        if (appIdOf(uid) == ControlPage.ownAppId()) {
            return Outcome(false, context.getString(R.string.rec_force_stop_self))
        }
        if (!canForceStop(context)) {
            return Outcome(false, context.getString(R.string.rec_force_stop_unavailable))
        }

        val packages = packagesFor(context, uid)
        if (packages.isEmpty()) {
            return Outcome(false, context.getString(R.string.rec_exempt_unknown_app))
        }

        val am = context.getSystemService(ActivityManager::class.java)
            ?: return Outcome(false, context.getString(R.string.rec_force_stop_unavailable))
        val method = forceStopMethod
            ?: return Outcome(false, context.getString(R.string.rec_force_stop_unavailable))

        for (pkg in packages) {
            val failure = runCatching { method.invoke(am, pkg) }.exceptionOrNull() ?: continue
            // Report the first real failure rather than continuing quietly: a
            // half-stopped shared uid is not the state the message would claim.
            val reason = failure.cause?.message ?: failure.message ?: failure.javaClass.simpleName
            Log.w(TAG, "forceStopPackage($pkg) failed: $reason")
            return Outcome(false, context.getString(R.string.rec_force_stop_failed, label, reason))
        }

        return Outcome(true, context.getString(R.string.rec_force_stop_done, label))
    }
}
