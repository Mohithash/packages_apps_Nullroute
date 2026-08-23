# Integration — Phase 4, Deep mode (`deep`)

Every change below lands in a file this feature does **not** own. Each snippet is
copy-pasteable and self-contained; nothing here is a description of a change you
have to derive.

Files this feature *does* own, already written:

```
app/src/main/java/com/bestrom/nullroute/deep/
    DeepVpnService.kt      lifecycle, onRevoke, foreground service, notifications
                           (also DeepVerdict + DeepEvaluator — the native handle)
    TunnelBuilder.kt       RFC 5737/3849 aliases, /32 + /128 routes, no allowBypass
    AliasPool.kt           alias <-> real upstream remap across network changes
    TunLoop.kt             poll() over tun + wake pipe + N upstream sockets
                           (also DeepTransport / DeepDnsPolicy / DeepHost)
    PacketCodec.kt         IPv4/IPv6 + UDP + TCP parse and emit, checksums
    DnsMessage.kt          DNS wire reader (QNAME, EDNS0), bounded, loop-safe
    ResponseSynthesizer.kt NXDOMAIN + SOA MINIMUM=60, NODATA, sinkhole, TC, SERVFAIL
    Tcp53Server.kt         a minimal userspace TCP endpoint for port 53
    DeepWatchdog.kt        the auto-disable, and DeepStats
app/src/main/res/values/strings_deep.xml
native/jni_deep.cpp
```

Already applied by this feature, listed so nobody re-applies it:

* `tools/verify_source.sh` line 86 — the JNI-header case now reads
  `jni_bridge.cpp|jni_deep.cpp)`. Without it the gate compiles `jni_deep.cpp`
  with no `jni.h` on the include path and goes red.

---

## 1. `app/src/main/AndroidManifest.xml`

### 1a. Permissions — add beside the existing `<uses-permission>` block

Both are `normal` protection level, so **neither needs a privapp-permissions
entry** and neither affects `ro.control_privapp_permissions=enforce`.

```xml
    <!--
        Deep mode (Phase 4). Both are normal-level, so no privapp entry and no
        runtime grant. FOREGROUND_SERVICE_SPECIAL_USE is API 34+; declaring it
        on a lower API is inert.
    -->
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
```

Nothing else is needed. `ConnectivityManager.getConnectionOwnerUid()` is
unrestricted for the app that owns the active VPN, and Deep mode only ever
*reads* `Settings.Global.private_dns_mode`.

### 1b. The service — add inside `<application>`

```xml
        <!--
            Deep mode: the DNS-only VpnService.

            exported + BIND_VPN_SERVICE + the android.net.VpnService action are
            all mandatory — the framework binds this, and without the permission
            any app could.

            foregroundServiceType: Android 14 requires a type on every foreground
            service and has no VPN-specific one, so "specialUse" with the subtype
            property is the documented fallback. On a privileged BestROM build
            "systemExempted" is also available; if you switch, keep the property
            (it is inert for other types) and check logcat for
            "startForeground failed" — DeepVpnService catches that failure rather
            than crashing, so a wrong type degrades quietly and must be looked for.
        -->
        <service
            android:name=".deep.DeepVpnService"
            android:exported="true"
            android:foregroundServiceType="specialUse"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="Filters DNS for every app on the device; the tunnel must stay established while the screen is off, or name resolution stops." />
        </service>
```

`android:directBootAware` is deliberately **absent**. Deep mode reads its own
state from DE storage and could technically start before unlock, but
`VpnService.prepare()` consent is a user decision and the tunnel takes the
device's only VPN slot — neither belongs in the pre-unlock window.

---

## 2. `Android.bp`

One line, in the existing `libnrjni` module.

```soong
cc_library_shared {
    name: "libnrjni",
    srcs: [
        "native/jni_bridge.cpp",
        // Phase 4. Same library on purpose: Deep mode must reach the same
        // nr_evaluate() the resolver hook reaches, from the same libnrcore, or
        // the tunnel and the hook can disagree about a domain.
        "native/jni_deep.cpp",
    ],
    static_libs: ["libnrcore"],
    header_libs: ["jni_headers"],
    shared_libs: [
        "liblog",
        "libz",
    ],
    cflags: [
        "-Wall",
        "-Wextra",
        "-Werror",
    ],
}
```

`jni_deep.cpp` was compiled clean at `-Wall -Wextra` against real bionic headers
(NDK 28 `aarch64-linux-android35-clang++`) and links against
`NrCanon/NrQuery/NrCtlCore/NrBuilder/NrMap` with no undefined symbols.

---

## 3. `app/src/main/java/com/bestrom/nullroute/core/Native.kt`

Append inside `object Native`, after `nativeVerify`. This exact text has been
compiled against `android.jar` (API 36) together with the whole `deep` package.

```kotlin
    // ---- Deep mode (Phase 4) — native/jni_deep.cpp --------------------------
    //
    // A different shape from the three calls above, on purpose. Those answer
    // cold questions and return JSON so that `nrctl --json` and the app cannot
    // drift. These answer ONE question per DNS query on the Deep-mode packet
    // path, so the verdict comes back as a packed Long (decoded by
    // deep/DeepVerdict) with the redirect address written into a caller-owned
    // array, and only the diagnostics call emits JSON.
    //
    // The session handle names a slot in a fixed native pool plus the generation
    // that occupied it, so a call racing a close finds valid memory and a
    // generation that no longer matches rather than a freed pointer.

    /**
     * Maps [indexPath] read-only for the Deep-mode tunnel, plus [controlPath]
     * when the device has a control page. Returns 0 if the index could not be
     * mapped — Deep mode must not establish a tunnel it cannot filter with.
     * Never throws.
     */
    fun deepOpen(indexPath: String, controlPath: String?): Long {
        if (!available) return 0L
        return nativeDeepOpen(indexPath, controlPath)
    }

    /** Releases a session. Idempotent; safe with a stale handle. */
    fun deepClose(handle: Long) {
        if (available) nativeDeepClose(handle)
    }

    /**
     * The verdict for one hostname, as raw canonical bytes. Returns a negative
     * value for "no verdict", on which the caller relays the query untouched.
     *
     * [uid] must be a real application uid or a negative value; a negative uid
     * skips the per-app policy gate rather than indexing it with a wrapped
     * `uid_t`. See the uid note in native/jni_deep.cpp.
     */
    fun deepEvaluate(
        handle: Long, name: ByteArray, len: Int, uid: Int, outAddr: ByteArray,
    ): Long = nativeDeepEvaluate(handle, name, len, uid, outAddr)

    /** 1 if a newer index generation was mapped, 0 if unchanged, -1 on failure. */
    fun deepRefresh(handle: Long): Int = if (available) nativeDeepRefresh(handle) else -1

    /** JSON session state for Diagnostics. Cold path. */
    fun deepStatus(handle: Long): String = nativeDeepStatus(handle)

    private external fun nativeDeepOpen(indexPath: String, controlPath: String?): Long

    private external fun nativeDeepClose(handle: Long)

    private external fun nativeDeepEvaluate(
        handle: Long, name: ByteArray, len: Int, uid: Int, outAddr: ByteArray,
    ): Long

    private external fun nativeDeepRefresh(handle: Long): Int

    private external fun nativeDeepStatus(handle: Long): String
```

The five `external fun` declarations must stay inside `object Native` and keep
these names: `jni_deep.cpp` exports
`Java_com_bestrom_nullroute_core_Native_nativeDeep{Open,Close,Evaluate,Refresh,Status}`
with a `jobject` receiver, which is what a Kotlin `object` member compiles to.
Moving them to a `@JvmStatic` companion changes the second parameter to `jclass`
— harmless — but moving them to a different class breaks the symbol name and the
failure is `UnsatisfiedLinkError` at the first blocked query, not at load.

---

## 4. `app/src/main/java/com/bestrom/nullroute/core/Probes.kt`

`sample()` carries `deepModeLive = false, // TODO(Phase 4)`. Replace that line:

```kotlin
            // The Deep-mode probe is only meaningful while the tunnel is up, and
            // a failing .invalid lookup costs a full resolver timeout, so it is
            // skipped rather than issued-and-ignored — the same reasoning as
            // probe A under pause.
            deepModeLive = com.bestrom.nullroute.deep.DeepVpnService.isRunning &&
                resolves(DEEP, DEEP_EXPECT),
```

This is a `core` -> `deep` reference, which inverts the usual layering. It is one
`@Volatile Boolean` on a companion and no more; if that is unacceptable, pass the
flag into `sample()` instead of reaching for it.

`Probes.FilterStatus` deliberately gains **no** Deep-mode state. Deep mode is a
second layer, not a different value of the resolver-hook status, and folding it
into `status()` would let a live tunnel report "Protected" on a device whose
resolver filter is dead.

---

## 5. `app/src/main/java/com/bestrom/nullroute/job/BootReceiver.kt`

Deep mode does not restart itself. Add to the `LOCKED_BOOT_COMPLETED` /
`BOOT_COMPLETED` handling — under `BOOT_COMPLETED` only, because
`VpnService.establish()` before first unlock is not something to attempt:

```kotlin
        if (intent.action == Intent.ACTION_BOOT_COMPLETED &&
            DeepWatchdog.isEnabled(context)
        ) {
            // mayStart() settles the marker left by a session that died with the
            // device, so a tunnel that bricked DNS three times gets switched off
            // here rather than tried a fourth time.
            DeepVpnService.start(context)
        }
```

`DeepVpnService.start()` is safe to call when Deep mode is disabled or
auto-disabled: the service posts its notification, finds `mayStart()` false and
stops itself.

---

## 6. The Deep-mode UI (`ui/DeepModeFragment.kt`, whoever owns it)

Everything the screen needs is already public. The order matters.

```kotlin
// 1. First run, on a background thread. Decides the default ONCE: off on a ROM
//    that publishes sys.nullroute.filter, on where nothing else can filter.
DeepWatchdog.resolveDefault(context)

// 2. Turning it on. Show R.string.deep_consent_body FIRST — the system's own VPN
//    dialog does not say that this takes the device's only VPN slot, and the
//    user must have been told before they answer it.
val consent = DeepVpnService.prepareIntent(activity)
if (consent != null) {
    startActivityForResult(consent, RC_VPN_CONSENT)
} else {
    DeepWatchdog.setEnabled(context, true)
    DeepVpnService.start(context)
}

// 3. onActivityResult(RC_VPN_CONSENT, RESULT_OK) -> the two lines from the else.
//    Any other result means the user said no: leave DeepWatchdog disabled and
//    do not ask again unprompted.

// 4. Turning it off.
DeepWatchdog.setEnabled(context, false)
DeepVpnService.stop(context)

// 5. State for the switch row.
DeepVpnService.isRunning                  // R.string.deep_state_on / _starting / _off
DeepWatchdog.autoDisabledReason(context)  // non-null => show it, the switch is off
DeepWatchdog.lastError(context)           // Diagnostics only, never a status
DeepVpnService.privateDnsStrict(context)  // => show R.string.deep_private_dns_strict
```

`R.string.deep_scope` must be visible next to the switch, not behind a link. It
is the list of what Deep mode still cannot block, and the Home screen already
sets that precedent (SPEC §3.6).

---

## 7. Diagnostics

`DeepEvaluator.status()` returns JSON for the running session:

```json
{ "ok": true, "path": "…/current.nrdx", "generation": 42,
  "n_block": 226398, "n_allow": 1712, "n_redirect": 2,
  "control_mapped": true, "mode": 0, "response_mode": 0,
  "opened_at_ms": 1756…, "evaluations": 18422, "remaps": 1 }
```

`DeepStats.toString()` gives the one-line session counters that
`DeepVpnService` already logs at teardown.

---

## 8. Verification, for whoever runs Phase 4's gate

Source-level checks already performed:

* `native/jni_deep.cpp` compiles at `-Wall -Wextra` against real bionic headers
  and links against the native core with no undefined symbols; `llvm-nm` confirms
  all five `Java_…_nativeDeep*` symbols are exported.
* The whole `deep` package plus the `Native.kt` snippet above compiles against
  `android.jar` API 36.
* A 74-assertion harness over `PacketCodec` / `DnsMessage` /
  `ResponseSynthesizer` passes: IPv4, IPv6 and TCP checksums verified by an
  independent RFC 1071 implementation, odd-length payload tails, QNAME case
  folding, compression-pointer rejection, over-253 names, over-long labels,
  fragment rejection, `total_length` overrun rejection, the full NXDOMAIN+SOA
  layout down to `MINIMUM = 60`, the sinkhole/NODATA family split, TC and
  SERVFAIL, and the TCP MSS option. **It is not in the tree** — Phase 4 was
  scoped to the files listed at the top. It is worth adopting as
  `app/src/test/java/com/bestrom/nullroute/deep/DeepWireTest.kt`; the three
  classes it exercises have no Android dependencies, so it runs as a plain JVM
  unit test.

On-device checks that source verification cannot substitute for (SPEC §4,
Phase 4, and §10.6 spike 7):

```
chrome://net-internals/#dns with a known-blocked domain, Deep off then on
adb shell dumpsys connectivity | grep -A5 VPN            # /32 routes only, no default
adb shell getent hosts vpn-probe.nullroute.invalid       # 127.0.0.9
dig @<alias> +tcp <blocked domain>                       # the TCP/53 path
an IPv6-only / 464XLAT carrier                           # spike 7
a captive portal, and a work profile
```
