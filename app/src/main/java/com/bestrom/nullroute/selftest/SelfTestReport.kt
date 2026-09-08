package com.bestrom.nullroute.selftest

/**
 * The result of one "Test my blocking" run.
 *
 * Deliberately has no Android dependencies and no opinion about presentation:
 * [BlockingSelfTest] fills it in, [com.bestrom.nullroute.ui.SelfTestFragment]
 * renders it, and neither can quietly upgrade an outcome on the way through.
 *
 * ## Why there are four outcomes and not two
 *
 * The interesting failure of a self-test is not "it said blocked when it was
 * leaking" — it is "it said blocked when it could not tell". Two of the three
 * lanes here have states that are genuinely unreadable:
 *
 *  * with `response_mode = sinkhole`, a browser that cannot connect looks exactly
 *    like a browser that resolved a real but unreachable address;
 *  * nothing on the device can observe what a *different* app's network stack
 *    did with a name — there is no API for it, privileged or otherwise.
 *
 * Both come back as [Outcome.INCONCLUSIVE] with the reason attached, because a
 * green tick the user cannot act on is worse than no tick at all: it converts an
 * unknown into a false belief.
 */
enum class Lane {
    /** In-process `InetAddress` — the layer the resolver hook actually covers. */
    SYSTEM_RESOLVER,

    /** An offscreen `WebView`: Chromium's own resolver, in our own process. */
    WEBVIEW,

    /** The user's default browser, which we can only ask them about. */
    BROWSER,
}

enum class Outcome {
    /** The lane refused the domain. */
    BLOCKED,

    /** The lane resolved a domain the compiled index says it blocks. */
    LEAKED,

    /** The lane ran and the result does not distinguish the two. */
    INCONCLUSIVE,

    /** Not run, because running it could not have meant anything. */
    SKIPPED,

    /** Waiting on the user to say what they saw. */
    PENDING,
}

data class LaneResult(
    val lane: Lane,
    val outcome: Outcome,
    val detail: String,
    /** True when the user reported this rather than the device measuring it. */
    val userReported: Boolean = false,
)

data class SelfTestReport(
    /** The domain tested, or null when none could be confirmed as blocked. */
    val domain: String?,

    /** The index rule that blocks [domain] — the evidence for testing it at all. */
    val rule: String?,

    /** `ControlPage.MODE_*`, or -1 when the control page could not be read. */
    val mode: Int,

    /** `ControlPage.RESP_*`, or -1 when unknown. Decides what a connect failure means. */
    val responseMode: Int,

    val killSwitch: Boolean,
    val deepModeRunning: Boolean,

    /** The default browser's label, or null when no app claims web links. */
    val browserLabel: String?,

    val lanes: List<LaneResult>,
    val ranAtMs: Long,

    /** Set when the test could not run at all; every lane is then SKIPPED. */
    val unavailableReason: String? = null,
) {

    fun lane(lane: Lane): LaneResult? = lanes.firstOrNull { it.lane == lane }

    /** Lanes that resolved a domain the index blocks. */
    val leaked: List<LaneResult> get() = lanes.filter { it.outcome == Outcome.LEAKED }

    /** Lanes that produced an answer either way. */
    val measured: List<LaneResult>
        get() = lanes.filter { it.outcome == Outcome.BLOCKED || it.outcome == Outcome.LEAKED }

    val ran: Boolean get() = unavailableReason == null && domain != null

    /**
     * Records what the user saw in their own browser.
     *
     * Kept separate from the measured lanes by [LaneResult.userReported] so the
     * UI can label it as a report rather than a measurement. A site can fail to
     * load for a dozen reasons that have nothing to do with DNS, and this result
     * is exactly as trustworthy as the person who pressed the button.
     */
    fun withBrowserObservation(loaded: Boolean, detail: String): SelfTestReport {
        val replacement = LaneResult(
            lane = Lane.BROWSER,
            outcome = if (loaded) Outcome.LEAKED else Outcome.BLOCKED,
            detail = detail,
            userReported = true,
        )
        return copy(lanes = lanes.map { if (it.lane == Lane.BROWSER) replacement else it })
    }

    companion object {
        fun unavailable(reason: String, ranAtMs: Long) = SelfTestReport(
            domain = null,
            rule = null,
            mode = -1,
            responseMode = -1,
            killSwitch = false,
            deepModeRunning = false,
            browserLabel = null,
            lanes = emptyList(),
            ranAtMs = ranAtMs,
            unavailableReason = reason,
        )
    }
}
