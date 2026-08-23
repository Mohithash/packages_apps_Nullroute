package com.bestrom.nullroute.core

import android.util.Log
import java.net.InetAddress

/**
 * The dual `.invalid` liveness probe — the only thing on this device that is
 * allowed to decide whether the status card says "Protected".
 *
 * **Why not a counter.** `control.bin` carries `q_total` / `q_blocked` /
 * `map_errors`, and every one of them lives inside the page whose mapping is the
 * single most likely thing to fail. A counter cannot report its own death (F8).
 * So health is measured end-to-end instead: we ask the system resolver to
 * resolve a name that *only* our machinery can answer, and believe the answer.
 *
 * **Why a redirect and not a block.** Our default block response is
 * `EAI_NONAME`, which is byte-identical to what a genuinely unresolvable
 * `.invalid` name returns. "The lookup failed" would therefore prove nothing at
 * all. A *redirect* to a fixed loopback address is unforgeable by absence: only
 * a live index with a parsed redirect table can produce 127.0.0.7, and only an
 * intact `/system/etc/hosts` can produce 127.0.0.8.
 *
 * `.invalid` is deliberately absent from `nr_has_skip_suffix()` for exactly this
 * reason — see `native/NrCanon.cpp`.
 */
object Probes {

    private const val TAG = "Nullroute"

    const val IDX = "idx-probe.nullroute.invalid"
    const val HOSTS = "hosts-probe.nullroute.invalid"

    /** Phase 4. Synthesized by the Deep-mode tunnel; never resolvable in Phase 1. */
    const val DEEP = "vpn-probe.nullroute.invalid"

    const val IDX_EXPECT = "127.0.0.7"
    const val HOSTS_EXPECT = "127.0.0.8"
    const val DEEP_EXPECT = "127.0.0.9"

    /** Set by netd at every state change: `ok:<gen>`, `nomap:<errno>`, `killed`… */
    const val PROP_FILTER_STATE = "sys.nullroute.filter"

    const val PROP_KILL = "persist.sys.nullroute.kill"
    const val PROP_FAIL_STREAK = "persist.sys.nullroute.fail_streak"
    const val PROP_BOOT_OK = "persist.sys.nullroute.boot_ok"
    const val PROP_SEED = "sys.nullroute.seed"

    /**
     * What the Home screen may say. Derived only from [Health.status]; no other
     * code is allowed to invent a status string.
     */
    enum class FilterStatus {
        /** Both layers answered. */
        PROTECTED,

        /** L1 live, L0 hosts file missing its probe line. Non-urgent. */
        PROTECTED_NO_L0,

        /** L1 dead, L0 intact: the built-in ~2,000-entry list and nothing more. */
        LIMITED_L0_ONLY,

        /** Neither layer answered. */
        NOT_FILTERING,

        /**
         * `mode = PAUSED`. L1 is inert (`nr_evaluate()` gates on mode) but L0 is
         * not — see [OFF]. Probe A cannot be interpreted in this state.
         */
        PAUSED,

        /**
         * `mode = OFF`.
         *
         * This does **not** switch off the built-in list. `hostsLayerSuperseded()`
         * (NrFilter.cpp) returns false unless `ctl.mode == NR_MODE_ENFORCE`, so
         * the moment the user pauses or switches off, H4 stops skipping the L0
         * scan and `/system/etc/hosts` is consulted again exactly as stock AOSP
         * would. The baked ~2,000-entry floor keeps blocking.
         *
         * Getting this backwards in the copy would tell a user they have no
         * protection when they measurably do, which is the same class of lie as
         * claiming protection they do not have.
         */
        OFF,

        /**
         * `persist.sys.nullroute.kill = 1`. A different state from [OFF] only in
         * how it got there and how it is cleared: `hostsLayerSuperseded()` bails
         * on `kill` as well as on a non-ENFORCE mode, so here too the baked hosts
         * file is doing the filtering. The kill switch is persistent and only
         * takes effect at boot, so the UI must not offer a toggle for it.
         */
        KILLED,

        /** Not sampled yet. */
        UNKNOWN,
    }

    data class Health(
        val resolverHookLive: Boolean,
        val hostsLayerLive: Boolean,
        val deepModeLive: Boolean,
        val stateProp: String,
        val killSwitch: Boolean,
        val mode: Int,
        val heartbeat: ControlPage.Heartbeat?,
        val sampledAtMs: Long,
    ) {
        /**
         * The four-state table from SPEC §3.4, plus the two states the table does
         * not cover.
         *
         * The pause case is the subtle one. `nr_evaluate()` gates on
         * `ctl.mode != NR_MODE_ENFORCE` *before* it consults the redirect table,
         * so a paused filter fails probe A exactly like a dead one. Reporting
         * "Limited" to a user who just tapped Pause would be a lie; so would
         * reporting "Protected". The honest answer is that while paused we cannot
         * observe the hook at all, and the UI says so.
         */
        fun status(): FilterStatus = when {
            killSwitch -> FilterStatus.KILLED
            mode == ControlPage.MODE_OFF -> FilterStatus.OFF
            mode == ControlPage.MODE_PAUSED -> FilterStatus.PAUSED
            resolverHookLive && hostsLayerLive -> FilterStatus.PROTECTED
            resolverHookLive && !hostsLayerLive -> FilterStatus.PROTECTED_NO_L0
            !resolverHookLive && hostsLayerLive -> FilterStatus.LIMITED_L0_ONLY
            else -> FilterStatus.NOT_FILTERING
        }

        /** True when the user should be interrupted rather than merely informed. */
        val needsNotification: Boolean get() = status() == FilterStatus.NOT_FILTERING
    }

    /**
     * Resolves one probe and checks it against its expected address.
     *
     * Uses `getAllByName`, not `getByName`: a resolver that returns several
     * records must still count as healthy if ours is among them. Blocked and
     * redirected answers never enter `res_cache` (the hook short-circuits before
     * `dns_getaddrinfo`), so every call here is a live measurement rather than a
     * replay of the last one.
     */
    private fun resolves(name: String, expect: String): Boolean = try {
        InetAddress.getAllByName(name).any { it.hostAddress == expect }
    } catch (t: Throwable) {
        false
    }

    /**
     * Samples every health signal. **Blocking** — a failing probe walks all the
     * way out to the network before it gives up, so this must never be called on
     * the main thread.
     */
    fun sample(): Health {
        val kill = SysProp.getBoolean(PROP_KILL)
        val mode = if (ControlPage.isMapped) ControlPage.mode else ControlPage.MODE_ENFORCE
        // Probe A is skipped whenever it is provably going to fail: the kill
        // switch short-circuits nr_filter_hook, and a non-ENFORCE mode makes
        // nr_evaluate() return PASS before it ever reaches the redirect table.
        // Issuing it anyway costs a full failing lookup for a .invalid name —
        // resolver timeout and all, on every Home refresh — to learn a value we
        // already know, and its result would be indistinguishable from a real
        // fault. Probe B still runs: L0 is live in both of those states.
        val idxLive =
            if (kill || mode != ControlPage.MODE_ENFORCE) false else resolves(IDX, IDX_EXPECT)
        val hostsLive = resolves(HOSTS, HOSTS_EXPECT)
        val health = Health(
            resolverHookLive = idxLive,
            hostsLayerLive = hostsLive,
            deepModeLive = false, // TODO(Phase 4): probe DEEP when the tunnel exists.
            stateProp = SysProp.get(PROP_FILTER_STATE, "unknown"),
            killSwitch = kill,
            mode = mode,
            heartbeat = ControlPage.readHeartbeatOrNull(),
            sampledAtMs = System.currentTimeMillis(),
        )
        Log.i(
            TAG,
            "probe idx=$idxLive hosts=$hostsLive prop=${health.stateProp} " +
                "mode=${health.mode} kill=$kill -> ${health.status()}",
        )
        return health
    }
}

/**
 * Reflective access to `android.os.SystemProperties`.
 *
 * The class is `@SystemApi(client = MODULE_LIBRARIES)`, so it is not on the
 * `system_current` surface this app compiles against, and it is not on the
 * public SDK the Gradle parity build compiles against either. Reflection is what
 * keeps one set of sources buildable by both; the
 * `<hidden-api-whitelisted-app package="com.bestrom.nullroute"/>` entry in
 * rom/sysconfig-nullroute.xml is what makes the call legal at runtime.
 *
 * Every accessor swallows failure and returns a neutral value. A property we
 * cannot read is reported as unknown, never as healthy.
 */
internal object SysProp {

    private const val TAG = "Nullroute"

    private val getMethod by lazy {
        runCatching {
            Class.forName("android.os.SystemProperties")
                .getMethod("get", String::class.java, String::class.java)
        }.getOrNull()
    }

    private val setMethod by lazy {
        runCatching {
            Class.forName("android.os.SystemProperties")
                .getMethod("set", String::class.java, String::class.java)
        }.getOrNull()
    }

    fun get(key: String, def: String = ""): String =
        runCatching { getMethod?.invoke(null, key, def) as? String }.getOrNull() ?: def

    fun getBoolean(key: String): Boolean = when (get(key).trim()) {
        "1", "true", "y", "yes", "on" -> true
        else -> false
    }

    fun getInt(key: String, def: Int): Int = get(key).trim().toIntOrNull() ?: def

    /**
     * Writes a persistent property. Requires an SELinux `set_prop` grant for the
     * app domain on `nullroute_prop`; without it init silently refuses and the
     * value does not change, which is why callers that care re-read.
     */
    fun set(key: String, value: String): Boolean = runCatching {
        setMethod?.invoke(null, key, value)
        true
    }.getOrElse {
        Log.w(TAG, "setprop $key failed: ${it.message}")
        false
    }
}
