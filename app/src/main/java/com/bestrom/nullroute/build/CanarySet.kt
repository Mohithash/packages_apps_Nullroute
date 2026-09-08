package com.bestrom.nullroute.build

import android.content.Context
import android.util.Log
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.data.Categories
import com.bestrom.nullroute.data.RuleStore

/**
 * The behavioural gate between a compiled index and a published one.
 *
 * Everything upstream of this asks whether the artefact is *well formed*:
 * `nativeVerify` checks the structure, the sha256 seal and the liveness probe,
 * and the sanity ratio in [com.bestrom.nullroute.core.Generation] asks whether it
 * is suspiciously empty. None of them can tell you that the index is **wrong** —
 * that some list shipped a rule which takes FCM push, the captive-portal check or
 * the user's bank off the air. That is this file's only job, and it is why
 * `Generation.promote` will not publish anything without it.
 *
 * ## Three questions, asked of the artefact itself
 *
 *  * **must PASS** — the never-block floor, the live captive-portal hosts, the
 *    compatibility carve-outs the user did not opt out of, and every rule the
 *    user typed into their own allow list. A failure here is the whole reason the
 *    gate exists: it is the class of breakage the user cannot diagnose and will
 *    never attribute to an ad blocker.
 *  * **must REDIRECT** — `idx-probe.nullroute.invalid`. Without it the Home
 *    screen can never observe the filter, so an index missing it is unpublishable
 *    however sound the rest of it is.
 *  * **must BLOCK** — a canonical ad/tracker set, checked as a **regression**
 *    against the index that is live right now (see [CANONICAL_BLOCKED]).
 *
 * It runs through [Native.query], which is the same `nr_evaluate()` netd links,
 * so the canary cannot approve behaviour the device will not reproduce.
 *
 * ## Why it cannot be derailed
 *
 * [Native.query] returns a verdict carrying an error rather than throwing, so one
 * bad name costs one probe. Errors are counted and reported; only the case where
 * *nothing* could be evaluated is treated as a failure, because a canary that
 * silently checked zero domains is a gate that is not there.
 *
 * Nothing in here throws: `Generation.promote` calls it between the ABI gate and
 * the publish, outside any try/catch, and an exception escaping would abandon a
 * promotion half-way rather than refuse it cleanly.
 */
object CanarySet {

    private const val TAG = "Nullroute"

    /**
     * Ceiling on how many of the user's own allow rules are probed.
     *
     * An import can leave tens of thousands of allow rules behind, and this runs
     * inside every promotion. The floor, the probes and the carve-outs are added
     * before the user's rules and are never trimmed, so a user with 40,000 rules
     * loses coverage of their own list's tail, not of the things that break the
     * phone.
     */
    private const val MAX_USER_ALLOW_PROBES = 200

    /** The same ceiling, for the shipped carve-out files. */
    private const val MAX_CARVE_OUT_PROBES = 200

    /**
     * The must-BLOCK set, checked **comparatively**.
     *
     * A blocklist is not an API: which of these a given profile actually carries
     * depends entirely on the lists the user chose, and the apexes people reach
     * for by instinct (`doubleclick.net`, `googleadservices.com`) are deliberately
     * absent from the curated lists so that first-party traffic keeps working —
     * `selftest/BlockingSelfTest` documents the same trap. Asserting them
     * absolutely would abort every promotion on a LITE profile, on a healthy
     * device, forever.
     *
     * So the assertion is the one SPEC §6.5 step 10 actually asks for: a
     * **regression**. A name the live index blocks and the new one does not is a
     * finding; a name neither of them blocks is not this gate's business, and the
     * sanity-ratio gate downstream is what catches an index that lost its content
     * wholesale.
     */
    private val CANONICAL_BLOCKED = listOf(
        "google-analytics.com",
        "www.google-analytics.com",
        "ssl.google-analytics.com",
        "app-measurement.com",
        "firebase-settings.crashlytics.com",
        "ads.pubmatic.com",
        "analytics.tiktok.com",
        "sb.scorecardresearch.com",
        "pagead2.googlesyndication.com",
        "stats.g.doubleclick.net",
        "ad.doubleclick.net",
        "static.criteo.net",
        "trc.taboola.com",
        "mv.outbrain.com",
        "z.moatads.com",
        "match.adsrvr.org",
        "sdkm.w.inmobi.com",
        "data.flurry.com",
        "api.amplitude.com",
        "api.mixpanel.com",
    )

    /** What a probe was asked to prove. */
    enum class Expect { PASS, BLOCK, REDIRECT }

    /**
     * One probe that did not come back the way it had to.
     *
     * Carries the domain verbatim because SPEC §6.5 step 10 requires the user to
     * be told the exact failing name — "safety check failed" on its own is a
     * message nobody can act on.
     */
    data class Failure(
        val domain: String,
        val expect: Expect,
        val observed: String,
        val rule: String?,
    ) {
        fun describe(): String {
            val expected = when (expect) {
                Expect.PASS -> "must not be blocked"
                Expect.BLOCK -> "was blocked by the current index"
                Expect.REDIRECT -> "must be redirected"
            }
            val because = rule?.let { " (rule \"$it\")" }.orEmpty()
            return "$domain $expected, but this build says $observed$because"
        }
    }

    /**
     * The verdict on a whole run. [firstFailure] is what the promotion reports;
     * the rest is for the log, where a second failing domain is often what names
     * the list that caused it.
     */
    data class Report(
        val ok: Boolean,
        val firstFailure: Failure?,
        val checked: Int,
        val skipped: Int,
        val failures: List<Failure>,
    )

    /**
     * Runs every check against the index at [indexPath] — the staging blob, not
     * the live one.
     *
     * Blocking: a few hundred JNI calls, each of which maps and validates the
     * index. Background thread only.
     */
    fun run(context: Context, indexPath: String): Report = try {
        evaluate(context, indexPath)
    } catch (t: Throwable) {
        // Nothing below is expected to throw. If something does, the honest
        // answer is that the index was not cleared, never that it passed.
        Log.e(TAG, "canary aborted", t)
        Report(
            ok = false,
            firstFailure = Failure("", Expect.PASS, t.message ?: t.javaClass.simpleName, null),
            checked = 0,
            skipped = 0,
            failures = emptyList(),
        )
    }

    private fun evaluate(context: Context, indexPath: String): Report {
        val failures = ArrayList<Failure>()
        var checked = 0
        var skipped = 0

        // The allow-side patterns the user or the ROM put in place. Used twice:
        // as must-PASS probes, and to explain away a must-BLOCK regression that
        // the user themselves asked for.
        val userAllow = RuleStore.readAllow()
        val carveOuts = carveOutPatterns(context)

        val mustPass = LinkedHashSet<String>()
        mustPass += NeverBlockFloor.domains(context)
        carveOuts.take(MAX_CARVE_OUT_PROBES).forEach { mustPass += it.canaryProbe() }
        userAllow.take(MAX_USER_ALLOW_PROBES).forEach { mustPass += it.canaryProbe() }

        // SPEC §6.5 step 10 also asks for "every domain resolved by apps the user
        // marked critical in the last 7 days". Neither half of that exists yet:
        // there is no "critical" app flag (data/AppPolicyStore.kt has only the
        // exemption) and the query log is Phase 3, in CE storage, unreadable
        // before first unlock — which is exactly when the update job runs. The
        // clause is deliberately not faked here.

        for (domain in mustPass) {
            val verdict = Native.query(indexPath, domain)
            if (verdict.error != null) {
                skipped++
                continue
            }
            checked++
            // `evaluated: false` is a name the matcher declines to look at, and
            // PASS is exactly what the resolver would do with it.
            if (!verdict.evaluated) continue
            if (verdict.kind != Native.VerdictKind.PASS) {
                failures += Failure(domain, Expect.PASS, describe(verdict), verdict.rule)
            }
        }

        // The liveness probe. Checked from the matcher's end; `nativeVerify` reads
        // the redirect table directly, and the two failing separately is a real
        // distinction — a present entry the matcher cannot reach is worse than an
        // absent one, because the Home screen would report "not filtering" on a
        // device whose index looks perfect.
        val probe = Native.query(indexPath, Probes.IDX)
        if (probe.error != null) {
            skipped++
        } else {
            checked++
            if (probe.kind != Native.VerdictKind.REDIRECT || probe.address != Probes.IDX_EXPECT) {
                failures += Failure(
                    Probes.IDX, Expect.REDIRECT,
                    probe.address ?: describe(probe), probe.rule,
                )
            }
        }

        // ---- must BLOCK, as a regression ------------------------------------

        val current = Paths.currentIndex
        if (current.isFile) {
            val allowDomains = (userAllow + carveOuts).map { it.domain }
            for (domain in CANONICAL_BLOCKED) {
                // A domain the user has allowed for themselves is not a
                // regression, it is the user's decision. Without this a single
                // allow rule would abort every future promotion.
                if (allowDomains.any { domain == it || domain.endsWith(".$it") }) continue

                val before = Native.query(current.absolutePath, domain)
                if (before.error != null || before.kind != Native.VerdictKind.BLOCK) continue

                val after = Native.query(indexPath, domain)
                if (after.error != null) {
                    skipped++
                    continue
                }
                checked++
                if (after.kind != Native.VerdictKind.BLOCK) {
                    failures += Failure(domain, Expect.BLOCK, describe(after), before.rule)
                }
            }
        }

        // A canary that evaluated nothing is not a canary. This is the one place
        // where "we could not measure" has to read as a failure: promoting an
        // index nobody could query is precisely the thing the gate exists to stop.
        if (checked == 0) {
            val why = if (Native.available) "no probe could be evaluated" else "libnrjni not loaded"
            Log.e(TAG, "canary could not run: $why")
            return Report(
                ok = false,
                firstFailure = Failure(indexPath, Expect.PASS, why, null),
                checked = 0,
                skipped = skipped,
                failures = emptyList(),
            )
        }

        if (failures.isEmpty()) {
            Log.i(TAG, "canary: $checked probes clear ($skipped unreadable)")
        } else {
            // Every failure, not only the first: the second name is often what
            // identifies the list that caused it.
            failures.forEach { Log.e(TAG, "canary: ${it.describe()}") }
        }

        return Report(
            ok = failures.isEmpty(),
            firstFailure = failures.firstOrNull(),
            checked = checked,
            skipped = skipped,
            failures = failures,
        )
    }

    /**
     * The carve-out domains that are compiled in as ALLOW rules — the anti-fraud
     * and attribution names the user did *not* opt into blocking.
     *
     * Parsed rather than used raw because the shipped files carry `*.x` as well as
     * bare names, and a `*.` rule says nothing about the apex: probing the apex
     * would fail correctly and abort a perfectly good build.
     */
    private fun carveOutPatterns(context: Context): List<RuleStore.Pattern> =
        Categories.allowCarveOutDomains(context).mapNotNull { RuleStore.parseAllow(it).getOrNull() }

    private fun describe(verdict: Native.QueryVerdict): String = when (verdict.kind) {
        Native.VerdictKind.PASS -> "not blocked"
        Native.VerdictKind.BLOCK -> "blocked"
        Native.VerdictKind.REDIRECT -> "redirected to ${verdict.address ?: "?"}"
        Native.VerdictKind.UNKNOWN -> verdict.error ?: "unknown"
    }
}
