package com.bestrom.nullroute.selftest

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.deep.DeepVpnService
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * "Test my blocking" — the same domain, asked for three different ways.
 *
 * ## What this is for
 *
 * Chromium — and therefore Chrome, WebView and Cronet — runs its own DNS client
 * and does not go through Android's system resolver, so the resolver hook cannot
 * see it (SPEC §10.4). That fact is currently a sentence on the Home screen, and
 * a sentence is something a user has to take on trust. This runs the experiment
 * instead: one domain the compiled index says it blocks, asked for by
 * [Lane.SYSTEM_RESOLVER], by [Lane.WEBVIEW] and by the user's own browser, with
 * the answer reported per lane. A caveat the product can demonstrate on the
 * user's own device is worth more than a caveat it merely admits to.
 *
 * ## The four things that stop this from lying
 *
 *  1. **The domain is chosen by asking the index, not by assumption.** A test
 *     domain that turns out not to be on the list would report a leak in every
 *     lane on a perfectly healthy device. Each candidate goes through
 *     [Native.query] first and is only used if the compiled index — the same one
 *     the resolver maps — says it blocks it, and the rule is shown.
 *  2. **There is a control lookup.** A phone in flight mode fails every lookup,
 *     which looks exactly like blocking everywhere. A name the index does *not*
 *     block is resolved first; if that fails too, the run is inconclusive and
 *     says why, rather than reporting a clean sweep.
 *  3. **`response_mode` decides what a connection failure means.** Under
 *     NXDOMAIN/NODATA, a browser that resolved and then failed to connect has
 *     leaked — the leak is the resolution. Under `sinkhole`, the same signal is
 *     unreadable, because a sinkholed address and an unreachable server both
 *     produce a connect error. That case reports "cannot determine" and explains
 *     itself.
 *  4. **The browser lane is never guessed.** No app on Android can observe
 *     another app's name resolution. The device opens the URL and the user says
 *     what they saw; it is recorded as a report, not a measurement.
 *
 * None of the above makes a clean run a guarantee. Deep mode cannot touch an app
 * that speaks DoH to an address compiled into it — there is no lookup to answer —
 * and this test has no way to detect one. See `selftest_caveat`.
 */
object BlockingSelfTest {

    private const val TAG = "Nullroute"

    /** How long the WebView lane waits before calling the answer unreadable. */
    private const val WEBVIEW_TIMEOUT_MS = 12_000L
    private const val WEBVIEW_TIMEOUT_S = 12

    /**
     * Candidates for the blocked lane, in preference order. Every one of these
     * is checked against the compiled index before it is used, because which of
     * them is present depends entirely on the chosen profile and sources.
     *
     * The apexes people reach for by instinct — `doubleclick.net`,
     * `googleadservices.com`, `graph.facebook.com` — are deliberately absent from
     * the curated lists so that logins and first-party traffic keep working, so
     * hardcoding one of those would produce a self-test that fails on a healthy
     * device. `google-analytics.com` is the one `nrctl help` names as reliably
     * present, and it leads the list for that reason.
     */
    private val BLOCKED_CANDIDATES = listOf(
        "google-analytics.com",
        "www.google-analytics.com",
        "app-measurement.com",
        "ads.pubmatic.com",
        "analytics.tiktok.com",
        "sb.scorecardresearch.com",
    )

    /**
     * The control. A name the index must NOT block, used to tell "everything is
     * blocked" apart from "this device cannot resolve anything at all".
     */
    private val CONTROL_CANDIDATES = listOf(
        "example.com",
        "connectivitycheck.gstatic.com",
        "one.one.one.one",
    )

    private val main = Handler(Looper.getMainLooper())

    /**
     * Runs the test.
     *
     * Must be called from the main thread with an **Activity** context: the
     * WebView lane instantiates a `WebView`, which the application context can
     * refuse. Lookups run on [NullrouteApp.io]; [onDone] is delivered on the
     * main thread, and exactly once.
     */
    fun run(context: Context, onDone: (SelfTestReport) -> Unit) {
        val appContext = context.applicationContext
        NullrouteApp.io.execute {
            val prepared = runCatching { prepare(appContext) }.getOrElse { t ->
                Log.w(TAG, "self-test could not start", t)
                SelfTestReport.unavailable(
                    appContext.getString(R.string.selftest_domain_unavailable),
                    System.currentTimeMillis(),
                )
            }
            main.post {
                if (!prepared.ran) {
                    onDone(prepared)
                    return@post
                }
                // The WebView lane is the only part that must run on the main
                // thread, and the only part that is asynchronous.
                runWebViewLane(context, prepared) { withWebView -> onDone(withWebView) }
            }
        }
    }

    // ---- lanes 1 and the setup ---------------------------------------------

    private fun prepare(context: Context): SelfTestReport {
        val now = System.currentTimeMillis()
        val indexPath = Paths.currentIndex.absolutePath

        val blocked = pickBlocked(indexPath)
            ?: return SelfTestReport.unavailable(
                context.getString(R.string.selftest_domain_unavailable), now
            )

        val health = runCatching { Probes.sample() }.getOrNull()
        val mode = if (ControlPage.isMapped) ControlPage.mode else -1
        val responseMode = if (ControlPage.isMapped) ControlPage.responseMode else -1

        val control = pickControl(indexPath)
        val controlResolves = control != null && resolvesAtAll(control)

        val systemLane = systemResolverLane(context, blocked.first, responseMode, mode, health,
            controlResolves = controlResolves, control = control)

        return SelfTestReport(
            domain = blocked.first,
            rule = blocked.second,
            mode = mode,
            responseMode = responseMode,
            killSwitch = health?.killSwitch ?: false,
            deepModeRunning = DeepVpnService.isRunning,
            browserLabel = defaultBrowserLabel(context, blocked.first),
            lanes = listOf(
                systemLane,
                // Filled in on the main thread; a placeholder here keeps the lane
                // order fixed so the UI never reorders itself mid-run.
                LaneResult(Lane.WEBVIEW, Outcome.PENDING, ""),
                LaneResult(
                    Lane.BROWSER, Outcome.PENDING,
                    context.getString(R.string.selftest_browser_prompt),
                ),
            ),
            ranAtMs = now,
        )
    }

    /** The first candidate the compiled index actually blocks, with its rule. */
    private fun pickBlocked(indexPath: String): Pair<String, String?>? {
        for (host in BLOCKED_CANDIDATES) {
            val v = runCatching { Native.query(indexPath, host) }.getOrNull() ?: continue
            if (v.ok && v.kind == Native.VerdictKind.BLOCK) return host to v.rule
        }
        return null
    }

    /** The first candidate the index leaves alone. Null if even that is unclear. */
    private fun pickControl(indexPath: String): String? {
        for (host in CONTROL_CANDIDATES) {
            val v = runCatching { Native.query(indexPath, host) }.getOrNull() ?: continue
            if (v.ok && v.kind == Native.VerdictKind.PASS) return host
        }
        return null
    }

    private fun resolvesAtAll(host: String): Boolean = try {
        InetAddress.getAllByName(host).isNotEmpty()
    } catch (_: UnknownHostException) {
        false
    } catch (t: Throwable) {
        Log.w(TAG, "control lookup failed", t)
        false
    }

    /**
     * Lane 1: the layer the resolver hook is responsible for.
     *
     * Android's `InetAddress` cache holds an answer for about two seconds, which
     * is short enough that a repeated run measures the resolver again rather than
     * replaying the first result.
     */
    private fun systemResolverLane(
        context: Context,
        domain: String,
        responseMode: Int,
        mode: Int,
        health: Probes.Health?,
        controlResolves: Boolean,
        control: String?,
    ): LaneResult {
        // A leak while the filter is deliberately not filtering is not a finding,
        // and reporting it as one would teach the user to distrust the test.
        if (health?.killSwitch == true) {
            return LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.SKIPPED,
                context.getString(
                    R.string.selftest_detail_system_skipped,
                    context.getString(R.string.selftest_mode_killed),
                ),
            )
        }
        if (mode == ControlPage.MODE_PAUSED || mode == ControlPage.MODE_OFF) {
            return LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.SKIPPED,
                context.getString(R.string.selftest_detail_system_skipped, modeName(context, mode)),
            )
        }
        // An exempted app is a supported state — the breakage notifier offers it —
        // and this process being the exempted one would make the lane meaningless.
        if (ControlPage.isMapped &&
            ControlPage.getUidPolicy(ControlPage.ownAppId()) == ControlPage.POLICY_EXEMPT
        ) {
            return LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.SKIPPED,
                context.getString(R.string.selftest_detail_system_exempt),
            )
        }

        val addresses = try {
            InetAddress.getAllByName(domain).toList()
        } catch (_: UnknownHostException) {
            // Exactly what NXDOMAIN and NODATA both look like from here — but only
            // if this device can resolve anything at all.
            return if (controlResolves || control == null) {
                LaneResult(
                    Lane.SYSTEM_RESOLVER, Outcome.BLOCKED,
                    context.getString(R.string.selftest_detail_system_nxdomain),
                )
            } else {
                LaneResult(
                    Lane.SYSTEM_RESOLVER, Outcome.INCONCLUSIVE,
                    context.getString(R.string.selftest_detail_no_dns, control),
                )
            }
        } catch (t: Throwable) {
            return LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.INCONCLUSIVE,
                context.getString(
                    R.string.selftest_detail_system_error,
                    t.message ?: t.javaClass.simpleName,
                ),
            )
        }

        val first = addresses.firstOrNull()
        return when {
            first == null -> LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.BLOCKED,
                context.getString(R.string.selftest_detail_system_nxdomain),
            )

            // The sinkhole answer. `isAnyLocalAddress` covers 0.0.0.0 and ::,
            // `isLoopbackAddress` covers 127.0.0.0/8 and ::1 — the whole set the
            // synthesiser can produce.
            addresses.all { it.isAnyLocalAddress || it.isLoopbackAddress } -> LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.BLOCKED,
                context.getString(
                    R.string.selftest_detail_system_sinkhole, first.hostAddress ?: "?"
                ),
            )

            else -> LaneResult(
                Lane.SYSTEM_RESOLVER, Outcome.LEAKED,
                context.getString(
                    R.string.selftest_detail_system_leak,
                    first.hostAddress ?: "?",
                    if (responseMode == ControlPage.RESP_SINKHOLE) {
                        context.getString(R.string.selftest_detail_expected_sinkhole)
                    } else {
                        context.getString(R.string.selftest_detail_expected_nxdomain)
                    },
                ),
            )
        }
    }

    // ---- lane 2: WebView ----------------------------------------------------

    /**
     * Lane 2: Chromium's own resolver, running inside this process.
     *
     * The WebView is never attached to the view hierarchy — it is a network
     * client here, not a renderer — and it is destroyed as soon as the lane
     * settles or times out.
     *
     * **This lane cannot say which layer answered.** WebView is inside the Deep
     * mode tunnel like every other app, and Chromium falls back to the system
     * resolver in some configurations, so a block here is a block by *something*.
     * That is still the useful answer: the question the user has is whether their
     * browser leaks, not which of our layers caught it.
     */
    private fun runWebViewLane(
        context: Context,
        report: SelfTestReport,
        onDone: (SelfTestReport) -> Unit,
    ) {
        val domain = report.domain
        if (domain == null) {
            onDone(report)
            return
        }

        val web = try {
            WebView(context)
        } catch (t: Throwable) {
            onDone(
                report.replace(
                    LaneResult(
                        Lane.WEBVIEW, Outcome.INCONCLUSIVE,
                        context.getString(
                            R.string.selftest_detail_webview_unavailable,
                            t.message ?: t.javaClass.simpleName,
                        ),
                    )
                )
            )
            return
        }

        var settled = false
        val finish = { result: LaneResult ->
            if (!settled) {
                settled = true
                runCatching {
                    web.stopLoading()
                    web.destroy()
                }
                onDone(report.replace(result))
            }
        }

        val timeout = Runnable {
            finish(
                LaneResult(
                    Lane.WEBVIEW, Outcome.INCONCLUSIVE,
                    context.getString(
                        R.string.selftest_detail_webview_timeout, WEBVIEW_TIMEOUT_S
                    ),
                )
            )
        }

        web.settings.apply {
            javaScriptEnabled = false
            domStorageEnabled = false
            blockNetworkImage = true
            cacheMode = WebSettings.LOAD_NO_CACHE
        }
        web.webViewClient = object : WebViewClient() {

            override fun onReceivedError(
                view: WebView,
                request: WebResourceRequest,
                error: WebResourceError,
            ) {
                if (!request.isForMainFrame) return
                main.removeCallbacks(timeout)
                finish(classifyWebViewError(context, error.errorCode, report.responseMode))
            }

            override fun onReceivedHttpError(
                view: WebView,
                request: WebResourceRequest,
                errorResponse: WebResourceResponse,
            ) {
                if (!request.isForMainFrame) return
                // A status code means a server answered, which means the name
                // resolved. The status itself is irrelevant.
                main.removeCallbacks(timeout)
                finish(
                    LaneResult(
                        Lane.WEBVIEW, Outcome.LEAKED,
                        context.getString(R.string.selftest_detail_webview_loaded),
                    )
                )
            }

            override fun onPageFinished(view: WebView, url: String) {
                main.removeCallbacks(timeout)
                finish(
                    LaneResult(
                        Lane.WEBVIEW, Outcome.LEAKED,
                        context.getString(R.string.selftest_detail_webview_loaded),
                    )
                )
            }
        }

        main.postDelayed(timeout, WEBVIEW_TIMEOUT_MS)
        // A unique path so that nothing in the stack can answer from a cache, and
        // https rather than http so a captive portal cannot transparently answer
        // for a name that never resolved.
        web.loadUrl("https://$domain/nullroute-selftest?t=${System.currentTimeMillis()}")
    }

    private fun classifyWebViewError(
        context: Context,
        code: Int,
        responseMode: Int,
    ): LaneResult = when (code) {
        WebViewClient.ERROR_HOST_LOOKUP -> LaneResult(
            Lane.WEBVIEW, Outcome.BLOCKED,
            context.getString(R.string.selftest_detail_webview_hostlookup),
        )

        // This set, and only this set, implies the name produced an address and
        // the failure happened afterwards. Under NXDOMAIN/NODATA that is the leak
        // itself; under a sinkhole answer the two are indistinguishable.
        //
        // ERROR_UNKNOWN, ERROR_BAD_URL, ERROR_UNSUPPORTED_SCHEME and
        // ERROR_PROXY_AUTHENTICATION are deliberately NOT here: the first three
        // can fail before any lookup happens, and the fourth means an HTTP proxy
        // is configured, in which case Chromium hands the *hostname* to the proxy
        // and never resolves it locally at all. Counting any of them as a leak
        // would manufacture findings on a device that is behaving.
        WebViewClient.ERROR_CONNECT,
        WebViewClient.ERROR_TIMEOUT,
        WebViewClient.ERROR_IO,
        WebViewClient.ERROR_FAILED_SSL_HANDSHAKE,
        WebViewClient.ERROR_REDIRECT_LOOP,
        -> if (responseMode == ControlPage.RESP_SINKHOLE) {
            LaneResult(
                Lane.WEBVIEW, Outcome.INCONCLUSIVE,
                context.getString(R.string.selftest_detail_webview_connect_sinkhole, code),
            )
        } else {
            LaneResult(
                Lane.WEBVIEW, Outcome.LEAKED,
                context.getString(R.string.selftest_detail_webview_connect, code),
            )
        }

        else -> LaneResult(
            Lane.WEBVIEW, Outcome.INCONCLUSIVE,
            context.getString(R.string.selftest_detail_webview_other, code),
        )
    }

    // ---- lane 3: the user's browser ----------------------------------------

    /**
     * The label of whatever app would open a web link, or null.
     *
     * Package visibility filtering can hide the answer from us even though the
     * user can see it perfectly well, so a null here means "we could not look it
     * up", never "there is no browser".
     */
    fun defaultBrowserLabel(context: Context, domain: String): String? = runCatching {
        val pm = context.packageManager
        val info = pm.resolveActivity(
            browserIntent(domain),
            PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()),
        ) ?: return null
        val label = info.loadLabel(pm).toString().trim()
        // The disambiguation activity is not a browser name; naming it would be
        // worse than saying nothing.
        if (label.isEmpty() || info.activityInfo?.packageName == "android") null else label
    }.getOrNull()

    fun browserIntent(domain: String): Intent =
        Intent(Intent.ACTION_VIEW, Uri.parse("https://$domain/nullroute-selftest"))
            .addCategory(Intent.CATEGORY_BROWSABLE)

    // ---- helpers ------------------------------------------------------------

    private fun SelfTestReport.replace(result: LaneResult): SelfTestReport =
        copy(lanes = lanes.map { if (it.lane == result.lane) result else it })

    fun modeName(context: Context, mode: Int): String = context.getString(
        when (mode) {
            ControlPage.MODE_ENFORCE -> R.string.selftest_mode_enforce
            ControlPage.MODE_PAUSED -> R.string.selftest_mode_paused
            ControlPage.MODE_OFF -> R.string.selftest_mode_off
            else -> R.string.selftest_mode_unknown
        }
    )

    fun responseModeName(context: Context, responseMode: Int): String = context.getString(
        when (responseMode) {
            ControlPage.RESP_NONAME -> R.string.selftest_resp_noname
            ControlPage.RESP_NODATA -> R.string.selftest_resp_nodata
            ControlPage.RESP_SINKHOLE -> R.string.selftest_resp_sinkhole
            else -> R.string.selftest_resp_unknown
        }
    )
}
