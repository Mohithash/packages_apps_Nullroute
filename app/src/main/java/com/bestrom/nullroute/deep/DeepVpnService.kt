package com.bestrom.nullroute.deep

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.ui.MainActivity
import java.io.File
import java.io.FileDescriptor
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Decoding for the packed verdict [DeepEvaluator.evaluate] returns.
 *
 * One `long` rather than an object because this is called once per DNS query
 * from a loop that must not allocate; the redirect address, which does not fit,
 * is written into a caller-owned scratch array instead.
 *
 * ```
 *  bits  0..7   kind        0 pass, 1 block, 2 redirect
 *  bits  8..15  depth       label depth the winning rule matched at
 *  bits 16..31  group       source list id
 *  bits 32..39  family      AF_INET / AF_INET6, redirect only
 *  bits 40..47  response    NR_RESP_*, from the control page
 *  bits 48..55  mode        NR_MODE_*, from the control page
 *  bit  56      control page was mapped (otherwise defaults were used)
 * ```
 */
object DeepVerdict {
    const val PASS = 0
    const val BLOCK = 1
    const val REDIRECT = 2

    fun kind(packed: Long) = (packed and 0xFF).toInt()
    fun depth(packed: Long) = ((packed ushr 8) and 0xFF).toInt()
    fun group(packed: Long) = ((packed ushr 16) and 0xFFFF).toInt()
    fun family(packed: Long) = ((packed ushr 32) and 0xFF).toInt()
    fun responseMode(packed: Long) = ((packed ushr 40) and 0xFF).toInt()
    fun mode(packed: Long) = ((packed ushr 48) and 0xFF).toInt()
    fun controlMapped(packed: Long) = (packed and (1L shl 56)) != 0L
}

/**
 * The tunnel's view of the index — the *same* mmap and the *same* `nr_evaluate`
 * the resolver hook runs, reached through `native/jni_deep.cpp`.
 *
 * There is deliberately no second matcher for Deep mode. A tunnel that answered
 * differently from the resolver would make "why was this blocked?" unanswerable
 * and the Query screen a liar, which is the failure this whole project is built
 * to avoid (SPEC §6.1).
 */
class DeepEvaluator private constructor(private var handle: Long) {

    companion object {
        private const val TAG = "NullrouteDeep"

        /** Anything negative means "no verdict"; the caller relays the query. */
        const val NO_VERDICT = -1L

        /**
         * Maps [indexPath], and [controlPath] when it exists. Returns null if the
         * index cannot be mapped — Deep mode does not establish a tunnel it
         * cannot filter with, because that would take the VPN slot and give
         * nothing back.
         */
        fun open(indexPath: String, controlPath: String?): DeepEvaluator? {
            if (!Native.available) {
                Log.w(TAG, "libnrjni unavailable; Deep mode cannot evaluate")
                return null
            }
            val h = try {
                Native.deepOpen(indexPath, controlPath)
            } catch (t: Throwable) {
                Log.e(TAG, "deepOpen failed: ${t.message}")
                0L
            }
            return if (h != 0L) DeepEvaluator(h) else null
        }
    }

    /**
     * The verdict for one hostname. [name] holds `len` raw lowercase bytes;
     * [outAddr] receives the redirect address when the verdict is REDIRECT.
     *
     * Returns [NO_VERDICT] once closed, so a query racing a shutdown relays
     * rather than crashing.
     */
    fun evaluate(name: ByteArray, len: Int, uid: Int, outAddr: ByteArray): Long {
        val h = handle
        if (h == 0L) return NO_VERDICT
        return try {
            Native.deepEvaluate(h, name, len, uid, outAddr)
        } catch (t: Throwable) {
            NO_VERDICT
        }
    }

    /** Re-maps if the app has published a newer generation. Slow path only. */
    fun refresh(): Boolean {
        val h = handle
        if (h == 0L) return false
        return try {
            Native.deepRefresh(h) == 1
        } catch (t: Throwable) {
            false
        }
    }

    /** JSON for Diagnostics. Cold path. */
    fun status(): String {
        val h = handle
        if (h == 0L) return "{\"ok\":false,\"error\":\"closed\"}"
        return try {
            Native.deepStatus(h)
        } catch (t: Throwable) {
            "{\"ok\":false,\"error\":\"${t.javaClass.simpleName}\"}"
        }
    }

    @Synchronized
    fun close() {
        val h = handle
        handle = 0L
        if (h != 0L) runCatching { Native.deepClose(h) }
    }
}

/**
 * Deep mode: the optional, DNS-only `VpnService`.
 *
 * ## What it buys, stated plainly
 *
 * Chromium — and therefore Chrome, WebView and every Cronet/`HttpEngine` client
 * — runs its own resolver and does not use `getaddrinfo`, so the resolver hook
 * never sees those lookups (SPEC §10.4). Routing DNS through a tunnel puts them
 * back in scope, and on a device with no resolver hook at all it is the only
 * thing that filters anything.
 *
 * ## What it still cannot do — none of this is a bug to be fixed later
 *
 * * **In-app DoH/DoT to hardcoded IPs.** An app that ships its own encrypted
 *   resolver and its own bootstrap addresses never asks us anything. It never
 *   asks the resolver hook either; this is a property of the DNS layer, not of
 *   our implementation.
 * * **First-party ads.** YouTube, Instagram and Spotify serve advertising from
 *   the same names as the content. There is no name to block.
 * * **Hardcoded IP literals and domain fronting.** No name, again.
 * * **Anything at all while a third-party VPN holds the slot.** Android allows
 *   exactly one VpnService. If the user connects their work VPN, Deep mode is
 *   revoked and stops — see [onRevoke]. It does not fight for the slot and it
 *   does not silently reconnect.
 * * **Private DNS in strict mode.** With a DoT hostname configured, the system
 *   resolves that hostname and connects to *its* address, which is not routed
 *   into this tunnel — so Deep mode sees nothing. We will not "fix" that by
 *   writing `Settings.Global.PRIVATE_DNS_MODE`: silently switching off the
 *   user's encrypted DNS to make our feature work is a privacy regression sold
 *   as a convenience (SPEC §1). [privateDnsStrict] exists so the UI can say so
 *   instead.
 *
 * ## The VPN slot
 *
 * Deep mode occupies the device's only VPN slot for as long as it runs. That is
 * a real cost and the UI must say so in those words before the user turns it on
 * — see `deep_notification_text` in `res/values/strings_deep.xml`.
 */
class DeepVpnService : VpnService(), DeepHost {

    companion object {
        private const val TAG = "NullrouteDeep"

        const val ACTION_START = "com.bestrom.nullroute.action.DEEP_START"
        const val ACTION_STOP = "com.bestrom.nullroute.action.DEEP_STOP"

        private const val CHANNEL_ID = "nullroute_deep"
        private const val NOTIFICATION_ID = 2
        private const val NOTIFICATION_ID_ALERT = 3

        /** Delay before the first liveness probe, so the tunnel is settled. */
        private const val PROBE_DELAY_MS = 1_500L
        private const val PROBE_RETRIES = 3
        private const val PROBE_INTERVAL_MS = 3_000L

        /** How often to check for a newly published index generation. */
        private const val REFRESH_INTERVAL_MS = 60_000L

        private const val JOIN_TIMEOUT_MS = 1_000L

        @Volatile
        var isRunning = false
            private set

        /**
         * The consent Intent, or null when this app is already the prepared VPN.
         *
         * Must be launched from an Activity with `startActivityForResult`; the
         * user's answer is the only thing that can authorise taking the slot,
         * and there is no privileged shortcut we are willing to use for it.
         */
        fun prepareIntent(context: Context): Intent? = VpnService.prepare(context)

        fun start(context: Context) {
            val intent = Intent(context, DeepVpnService::class.java).setAction(ACTION_START)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, DeepVpnService::class.java).setAction(ACTION_STOP)
            runCatching { context.startService(intent) }
        }

        /**
         * True when Private DNS is pinned to a hostname. Read-only, always —
         * see the class comment.
         *
         * The key is `Settings.Global.PRIVATE_DNS_MODE`, which is `@hide`, so the
         * literal is used rather than taking a hidden-API dependency for a
         * string constant.
         */
        fun privateDnsStrict(context: Context): Boolean = runCatching {
            Settings.Global.getString(context.contentResolver, "private_dns_mode") == "hostname"
        }.getOrDefault(false)
    }

    private class Session(
        val tun: ParcelFileDescriptor,
        val loop: TunLoop,
        val thread: Thread,
        val evaluator: DeepEvaluator,
        val stats: DeepStats,
    )

    private val main = Handler(Looper.getMainLooper())
    private val pool = AliasPool()
    private val liveness = DeepWatchdog.Liveness()

    @Volatile
    private var session: Session? = null

    @Volatile
    private var underlying: Network? = null

    @Volatile
    private var stopping = false

    private var lastRefreshMs = 0L
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // ---- lifecycle ----------------------------------------------------------

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            teardown(clean = true, reason = null)
            stopSelf()
            return START_NOT_STICKY
        }

        // Foreground first and synchronously: the platform gives a service a few
        // seconds to post its notification and kills it otherwise, and every
        // step after this one can block.
        startForegroundCompat(buildNotification(starting = true))

        if (session != null) return START_STICKY

        // A sticky restart arrives with a null intent. Treating that as "start
        // if still enabled" is what makes the watchdog's counter meaningful: the
        // attempt marker left by the session that died is settled on the way in.
        Thread({ bringUp() }, "nullroute-deep-setup").start()
        return START_STICKY
    }

    /**
     * The user revoked our VPN consent, or another app took the slot.
     *
     * Not counted as a failure, and deliberately not followed by a reconnect.
     * Two VPN apps racing for the slot is a worse outcome for the user than Deep
     * mode staying off until they ask for it again.
     */
    override fun onRevoke() {
        Log.i(TAG, "VPN consent revoked; another app has the slot")
        teardown(clean = true, reason = null)
        notifyAlert(
            getString(R.string.deep_revoked_title),
            getString(R.string.deep_revoked_text),
        )
        stopSelf()
    }

    override fun onDestroy() {
        teardown(clean = true, reason = null)
        super.onDestroy()
    }

    // ---- bring-up -----------------------------------------------------------

    private fun bringUp() {
        try {
            if (!DeepWatchdog.mayStart(this)) {
                val reason = DeepWatchdog.autoDisabledReason(this)
                if (reason != null) {
                    notifyAlert(
                        getString(R.string.deep_disabled_title),
                        getString(R.string.deep_disabled_text, reason),
                    )
                }
                main.post { stopSelf() }
                return
            }

            // Everything from here to armAttempt() can fail freely: no tunnel
            // exists, so nothing on the device is worse off than it was, and
            // these are aborts rather than failures. Counting a lift with no
            // signal towards the auto-disable would switch Deep mode off for a
            // user whose only mistake was going underground three times.
            val indexPath = resolveIndexPath()
            if (indexPath == null) {
                abort("Nullroute has not built a blocklist yet, so there is nothing to filter with")
                return
            }
            val evaluator = DeepEvaluator.open(
                indexPath,
                Paths.controlBin.takeIf { it.canRead() }?.absolutePath,
            )
            if (evaluator == null) {
                abort("the blocklist could not be read")
                return
            }

            if (!pool.reset()) {
                evaluator.close()
                abort("no usable private address range for the tunnel")
                return
            }
            pool.remap(currentDnsServers())
            if (!pool.hasUpstreams) {
                // Establishing anyway would take the VPN slot and blackhole every
                // lookup on the device. Refusing is the fail-open answer.
                evaluator.close()
                abort("this network has not given the device a DNS server")
                return
            }

            // The point of no return: from the next statement the device's DNS
            // is ours, so the marker goes down first.
            DeepWatchdog.armAttempt(this)
            val tunnel = TunnelBuilder.build(this, pool, configureIntent())
            val stats = DeepStats()
            val loop = TunLoop(this, tunnel.fd.fileDescriptor, pool, evaluator, stats, tunnel.mtu)
            val thread = Thread(loop, "nullroute-deep")
            thread.priority = Thread.NORM_PRIORITY + 1
            session = Session(tunnel.fd, loop, thread, evaluator, stats)
            isRunning = true
            liveness.reset()
            lastRefreshMs = System.currentTimeMillis()
            thread.start()

            registerNetworkCallback()
            main.post { startForegroundCompat(buildNotification(starting = false)) }

            if (privateDnsStrict(this)) {
                // Not an error and not something we will "fix" for the user.
                Log.i(TAG, "Private DNS is in strict mode; system lookups bypass this tunnel")
            }

            runLivenessProbe()
        } catch (t: Throwable) {
            Log.e(TAG, "Deep mode failed to start", t)
            fail(t.message ?: t.javaClass.simpleName)
        }
    }

    /**
     * Proves the tunnel end to end before declaring it healthy.
     *
     * `vpn-probe.nullroute.invalid` is answered by [TunLoop] and by nothing else
     * on the device, so resolving it to 127.0.0.9 through the *system* resolver
     * proves the routes are in place, the descriptor is being read, and answers
     * are getting back — none of which a counter inside this process could
     * establish (SPEC §3.4).
     */
    private fun runLivenessProbe() {
        Thread({
            var ok = false
            for (attempt in 0 until PROBE_RETRIES) {
                Thread.sleep(if (attempt == 0) PROBE_DELAY_MS else PROBE_INTERVAL_MS)
                if (session == null) return@Thread
                ok = runCatching {
                    InetAddress.getAllByName(Probes.DEEP).any { it.hostAddress == Probes.DEEP_EXPECT }
                }.getOrDefault(false)
                if (ok) break
            }
            if (session == null) return@Thread
            if (ok) {
                Log.i(TAG, "Deep-mode liveness probe answered")
                DeepWatchdog.markHealthy(this)
            } else {
                fail("the tunnel established but did not answer its own liveness probe")
            }
        }, "nullroute-deep-probe").start()
    }

    /**
     * The index to filter against.
     *
     * `/data/misc/nullroute` on BestROM, where the seeder and the compiler put
     * it. The app-private copy is the stock-Android variant's location, where
     * `/data/misc` is not ours to write.
     */
    private fun resolveIndexPath(): String? {
        val shared = Paths.currentIndex
        if (shared.canRead()) return shared.absolutePath
        val private = File(File(Paths.de(this).filesDir, "index"), "current.nrdx")
        return if (private.canRead()) private.absolutePath else null
    }

    // ---- teardown -----------------------------------------------------------

    /**
     * Stops everything. [clean] distinguishes a stop nobody is at fault for —
     * the user, or another VPN — from one that counts towards the auto-disable.
     */
    @Synchronized
    private fun teardown(clean: Boolean, reason: String?) {
        if (stopping) return
        stopping = true
        isRunning = false

        unregisterNetworkCallback()

        val s = session
        session = null
        if (s != null) {
            s.loop.stop()
            // stop() writes the wake pipe, so the loop normally exits within
            // microseconds. The bound is short because onDestroy() reaches here
            // on the main thread and a wedged loop must not become an ANR.
            runCatching { s.thread.join(JOIN_TIMEOUT_MS) }
            runCatching { s.tun.close() }
            s.evaluator.close()
            Log.i(TAG, "Deep mode stopped: ${s.stats}")
        }

        if (clean) {
            DeepWatchdog.markCleanStop(this)
        } else if (reason != null && DeepWatchdog.recordFailure(this, reason)) {
            notifyAlert(
                getString(R.string.deep_disabled_title),
                getString(R.string.deep_disabled_text, reason),
            )
        }
        stopping = false
    }

    /** Records a failure, tears the tunnel down and stops the service. */
    private fun fail(reason: String) {
        Log.w(TAG, "Deep mode failing: $reason")
        teardown(clean = false, reason = reason)
        main.post { stopSelf() }
    }

    /**
     * Gives up before the tunnel ever existed. Tells the user why and stops,
     * without counting anything towards the auto-disable — see [bringUp].
     */
    private fun abort(reason: String) {
        Log.i(TAG, "Deep mode not started: $reason")
        teardown(clean = true, reason = null)
        notifyAlert(
            getString(R.string.deep_failed_title),
            getString(R.string.deep_failed_text, reason),
        )
        main.post { stopSelf() }
    }

    // ---- DeepHost -----------------------------------------------------------

    /**
     * Exempts a socket from our own tunnel.
     *
     * `VpnService.protect()` wants a raw descriptor number and `Os.socket()`
     * hands back a `FileDescriptor`; `ParcelFileDescriptor.dup()` bridges the two
     * with public API only. Protecting the dup protects the *socket* — both
     * descriptors name the same open file description — so the temporary can be
     * closed immediately.
     */
    override fun protectSocket(fd: FileDescriptor): Boolean = try {
        ParcelFileDescriptor.dup(fd).use { protect(it.fd) }
    } catch (t: Throwable) {
        Log.w(TAG, "protect() failed: ${t.message}")
        false
    }

    /**
     * Pins a socket to the network we are relaying through.
     *
     * Belt and braces over [protectSocket]: `protect()` exempts a socket from the
     * VPN and lets routing pick the default network, while binding names the
     * network explicitly, so a handover mid-query cannot send an upstream query
     * out of an interface whose resolver we never asked.
     */
    override fun bindToUnderlying(fd: FileDescriptor) {
        val network = underlying ?: return
        runCatching { network.bindSocket(fd) }
    }

    override fun connectionOwnerUid(
        protocol: Int, local: InetSocketAddress, remote: InetSocketAddress,
    ): Int = try {
        getSystemService(ConnectivityManager::class.java)
            ?.getConnectionOwnerUid(protocol, local, remote) ?: UID_UNKNOWN
    } catch (t: Throwable) {
        UID_UNKNOWN
    }

    override fun onHealthTick(uptimeMs: Long) {
        val s = session ?: return
        if (!liveness.sample(s.stats)) {
            // Routed through onTunnelFailed rather than calling fail() directly:
            // this runs ON the tunnel thread, and teardown() joins that thread.
            onTunnelFailed("the tunnel carried queries but answered none")
            return
        }
        val now = System.currentTimeMillis()
        if (now - lastRefreshMs >= REFRESH_INTERVAL_MS) {
            lastRefreshMs = now
            // Cheap when nothing changed: the native side compares the control
            // page's want_generation (or the file's identity on stock) before
            // touching the filesystem.
            if (s.evaluator.refresh()) Log.i(TAG, "Deep mode re-mapped a new index generation")
        }
    }

    /**
     * Called from the tunnel thread. Teardown runs on a thread of its own —
     * neither the caller (which teardown joins) nor the main thread (which would
     * be blocked for the length of that join) can safely do it.
     */
    override fun onTunnelFailed(reason: String) {
        Thread({ fail(reason) }, "nullroute-deep-teardown").start()
    }

    // ---- connectivity -------------------------------------------------------

    private fun currentDnsServers(): List<InetAddress> {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        // Read before establish(): afterwards the active network is our own VPN
        // and its DNS servers are the aliases we are about to advertise.
        val network = underlying ?: cm.activeNetwork ?: return emptyList()
        return cm.getLinkProperties(network)?.dnsServers.orEmpty()
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            // NOT_VPN keeps this from tracking our own tunnel, whose DNS servers
            // are the aliases — a loop that would map the aliases onto
            // themselves and spin a core.
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                underlying = network
                cm.getLinkProperties(network)?.let { apply(it) }
            }

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                underlying = network
                apply(lp)
            }

            override fun onLost(network: Network) {
                if (underlying == network) underlying = null
            }

            private fun apply(lp: LinkProperties) {
                pool.remap(lp.dnsServers)
                session?.loop?.onNetworkChanged()
            }
        }
        networkCallback = callback
        runCatching {
            // Tracks the single best matching network rather than every one, so
            // "the network we relay to" is never ambiguous.
            cm.registerBestMatchingNetworkCallback(request, callback, main)
        }.onFailure {
            Log.w(TAG, "network callback not registered: ${it.message}")
            networkCallback = null
        }
    }

    private fun unregisterNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
    }

    // ---- notifications ------------------------------------------------------

    private fun configureIntent(): PendingIntent? = runCatching {
        PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }.getOrNull()

    private fun ensureChannel(): NotificationManager? {
        val nm = getSystemService(NotificationManager::class.java) ?: return null
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.deep_channel),
            // LOW: the tunnel's own notification is a permanent status line, not
            // an event. The alerts that interrupt use the same channel and set
            // their own priority.
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = getString(R.string.deep_channel_desc) }
        nm.createNotificationChannel(channel)
        return nm
    }

    private fun buildNotification(starting: Boolean): Notification {
        ensureChannel()
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, DeepVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val text = getString(
            if (starting) R.string.deep_notification_starting else R.string.deep_notification_text
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nullroute)
            .setContentTitle(getString(R.string.deep_notification_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(configureIntent())
            .addAction(
                Notification.Action.Builder(
                    null, getString(R.string.deep_action_stop), stopIntent,
                ).build()
            )
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
    }

    private fun startForegroundCompat(notification: Notification) {
        runCatching {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(
                    NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        }.onFailure { Log.e(TAG, "startForeground failed: ${it.message}") }
    }

    private fun notifyAlert(title: String, text: String) {
        val nm = ensureChannel() ?: return
        val n = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nullroute)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(configureIntent())
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_ERROR)
            .build()
        runCatching { nm.notify(NOTIFICATION_ID_ALERT, n) }
    }
}
