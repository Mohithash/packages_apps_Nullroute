package com.bestrom.nullroute.job

import android.util.Log

/**
 * Platform flags Nullroute needs pinned, applied through `DeviceConfig`.
 *
 * ## `tethering / close_quic_connection`
 *
 * The Connectivity mainline module can be told to tear down QUIC connections on
 * certain network events. Left at its default, an app whose QUIC session is
 * closed underneath it falls back to its own resolver path, which is exactly the
 * traffic a name-layer filter is trying to see. Pinning it to `-1` disables the
 * payload registration and keeps app DNS on the system resolver, where our hook
 * is.
 *
 * This ships in Phase 0 as part of the baked floor, and is re-asserted here
 * because `DeviceConfig` values are server-pushable: a flag we set at flash time
 * is a flag that can be changed out from under us later.
 *
 * ## Why reflection
 *
 * `android.provider.DeviceConfig` is `@SystemApi`. The shipping build compiles
 * against `system_current` and could link it directly, but the Gradle parity
 * build compiles against the public SDK and cannot — and keeping one set of
 * sources buildable by both is worth more than a direct call here. The
 * `WRITE_DEVICE_CONFIG` / `READ_DEVICE_CONFIG` permissions in the manifest are
 * pure `signature`, so they need no privapp allowlist entry, and the
 * `hidden-api-whitelisted-app` entry in rom/sysconfig-nullroute.xml is what makes
 * the reflective call legal at runtime.
 */
object DeviceConfigFixups {

    private const val TAG = "Nullroute"

    private const val NAMESPACE_TETHERING = "tethering"
    private const val KEY_CLOSE_QUIC = "close_quic_connection"
    private const val VALUE_DISABLED = "-1"

    private val deviceConfigClass by lazy {
        runCatching { Class.forName("android.provider.DeviceConfig") }.getOrNull()
    }

    /**
     * Applies every fixup. Safe to call repeatedly; a value already at the target
     * is left alone so we do not churn the flag's staged/committed state.
     *
     * Returns false when nothing could be applied — a missing grant, a renamed
     * flag, a stubbed-out DeviceConfig. That is reported in Diagnostics rather
     * than retried: a flag we cannot write is a fact about the build, not a
     * transient error.
     */
    fun apply(): Boolean {
        val current = getProperty(NAMESPACE_TETHERING, KEY_CLOSE_QUIC)
        if (current == VALUE_DISABLED) return true
        val ok = setProperty(NAMESPACE_TETHERING, KEY_CLOSE_QUIC, VALUE_DISABLED)
        Log.i(TAG, "close_quic_connection: was=$current set=$ok")
        return ok
    }

    /** Current value, or null if it is unset or unreadable. */
    fun getProperty(namespace: String, name: String): String? = runCatching {
        val method = deviceConfigClass
            ?.getMethod("getProperty", String::class.java, String::class.java)
        method?.invoke(null, namespace, name) as? String
    }.getOrNull()

    private fun setProperty(namespace: String, name: String, value: String): Boolean = runCatching {
        val method = deviceConfigClass?.getMethod(
            "setProperty",
            String::class.java, String::class.java, String::class.java, Boolean::class.javaPrimitiveType,
        )
        // makeDefault = false: this is a runtime override, not a new platform
        // default. Claiming to be the default would survive a settings reset and
        // make the change much harder for anyone else to diagnose.
        method?.invoke(null, namespace, name, value, false) as? Boolean ?: false
    }.getOrElse {
        Log.w(TAG, "DeviceConfig.setProperty($namespace/$name) failed: ${it.message}")
        false
    }
}
