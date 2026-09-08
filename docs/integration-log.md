# Integration — Phase 3 logging spine (`log`)

Everything this feature needs that lives in a **shared file I must not edit**.
Each block is exact and copy-pasteable, with the target file named. Nothing below
is optional: without it the code compiles and runs, but the log never gets
drained, the breakage notifier can never identify an app, and the new fuzz gate
never runs under `atest`.

Files delivered by this task (no action needed on them):

```
resolver-patch/nullroute/nr_wire.h          DNS wire codec, header-only, fuzzed alone
resolver-patch/nullroute/NrResSend.cpp      H3 policy glue
resolver-patch/apply.sh                     H3 located, applied, checked, reverted
native/fuzz/nr_wire_fuzzer.cpp              MERGE GATE
tools/verify_source.sh                      runs the new gate; reports H3 applied/skipped
app/.../log/RingReader.kt                   ring consumer + the pump
app/.../log/QueryLogDb.kt                   CE-storage SQLite
app/.../log/Retention.kt                    retention policy + purge
app/.../notify/BreakageNotifier.kt          burst -> "Tap to exempt"
app/.../notify/DegradedNotifier.kt          SPEC §3.4 table
app/.../core/ForegroundAppTracker.kt        best-effort attribution
app/src/main/res/values/strings_log.xml     its own strings file
app/src/main/res/drawable/ic_log.xml        nav icon for the Log tab
```

---

## 1. `Android.bp` — the third fuzz target

`nr_wire_fuzzer` is a **merge gate** and matters more than the other two: it is
the only place the project parses network-shaped bytes, and it does it inside
netd. Add next to the existing `cc_fuzz` blocks:

```soong
cc_fuzz {
    name: "nr_wire_fuzzer",
    srcs: ["native/fuzz/nr_wire_fuzzer.cpp"],
    // Deliberately links NOTHING — not libnrfilter, not libnrformat_headers.
    // nr_wire.h is header-only and depends on nothing else in the project, so a
    // crash in this target is unambiguously a parser bug rather than a fixture
    // bug. That property is the reason the header is written the way it is.
    local_include_dirs: ["resolver-patch/nullroute"],
    host_supported: true,
    cflags: [
        "-Wall",
        "-Wextra",
        "-Werror",
    ],
}
```

`SPEC.md` §8.10 lists the merge-gate command as
`atest nr_hostname_fuzzer nr_index_fuzzer`; it should become

```
atest nr_hostname_fuzzer nr_index_fuzzer nr_wire_fuzzer
```

---

## 2. `app/src/main/AndroidManifest.xml` — two permissions

`ForegroundAppTracker` is what lets the breakage notifier name the right app, and
without these it always answers "unknown" — which is safe (nothing is sent) but
switches off the highest-ROI recovery path in the product (SPEC §10.3).

```xml
    <!--
        core/ForegroundAppTracker.kt — which app is in front of the user, so the
        breakage notifier can attribute a block burst to it. Both are
        signature|privileged and BOTH ARE ALREADY IN the frozen privapp allowlist
        from SPEC §8.8, so adding them here is an APK-only change and cannot
        break boot under ro.control_privapp_permissions=enforce.

        PACKAGE_USAGE_STATS  UsageStatsManager.queryEvents — activity resume
                             events, the only API that reports what the user is
                             actually looking at. Also needs the AppOp; without
                             it queryEvents returns an empty cursor rather than
                             throwing, which the tracker reports as unknown.
        REAL_GET_TASKS       ActivityManager.getRunningAppProcesses returning
                             more than our own process — the coarser fallback.
    -->
    <uses-permission android:name="android.permission.PACKAGE_USAGE_STATS" />
    <uses-permission android:name="android.permission.REAL_GET_TASKS" />
```

`rom/privapp-permissions-com.bestrom.nullroute.xml` needs **no change** — both
names are already in the frozen set. Worth re-checking rather than assuming, and
worth also granting the AppOp so the first source works:

```xml
<!-- rom/default-permissions-nullroute.xml, if the AppOp is not pre-granted -->
<!-- appop android:name="android:get_usage_stats" is granted via
     AppOpsManager.setMode(OPSTR_GET_USAGE_STATS, uid, pkg, MODE_ALLOWED);
     on a platform-signed privapp the privapp grant alone is usually enough —
     verify on device with `adb shell appops get com.bestrom.nullroute GET_USAGE_STATS`. -->
```

---

## 3. `ui/MainActivity.kt` — a Log tab, and the breakage deep-link

The notifier's tap intent already carries the extras. Until MainActivity reads
them the tap still opens the app (it falls back to `TAB_DIAGNOSTICS`), so this is
a degradation and never a crash — but the promise on the notification is *"Tap to
exempt"*, and it is only true once this lands.

```kotlin
    companion object {
        const val EXTRA_OPEN_TAB = "com.bestrom.nullroute.extra.OPEN_TAB"

        const val TAB_HOME = 0
        const val TAB_PROFILE = 1
        const val TAB_UPDATE = 2
        const val TAB_DIAGNOSTICS = 3
        const val TAB_LOG = 4              // <-- add
    }
```

```kotlin
    private fun select(tab: Int, fromUser: Boolean) {
        val fragment: Fragment = when (tab) {
            TAB_PROFILE -> ProfileFragment()
            TAB_UPDATE -> UpdateFragment()
            TAB_DIAGNOSTICS -> DiagnosticsFragment()
            TAB_LOG -> LogFragment()       // <-- add
            else -> HomeFragment()
        }
        // …
    }

    private fun tabForMenuId(id: Int): Int = when (id) {
        R.id.nav_profile -> TAB_PROFILE
        R.id.nav_update -> TAB_UPDATE
        R.id.nav_log -> TAB_LOG            // <-- add
        R.id.nav_diagnostics -> TAB_DIAGNOSTICS
        else -> TAB_HOME
    }

    private fun menuIdForTab(tab: Int): Int = when (tab) {
        TAB_PROFILE -> R.id.nav_profile
        TAB_UPDATE -> R.id.nav_update
        TAB_LOG -> R.id.nav_log            // <-- add
        TAB_DIAGNOSTICS -> R.id.nav_diagnostics
        else -> R.id.nav_home
    }

    private fun titleForTab(tab: Int): Int = when (tab) {
        TAB_PROFILE -> R.string.tab_profile
        TAB_UPDATE -> R.string.tab_update
        TAB_LOG -> R.string.log_title      // <-- add
        TAB_DIAGNOSTICS -> R.string.tab_diagnostics
        else -> R.string.app_name
    }
```

And route the breakage deep-link. `BreakageNotifier` sets `EXTRA_OPEN_TAB` to
`TAB_DIAGNOSTICS` today only because `TAB_LOG` does not exist yet; once it does,
change that line in `BreakageNotifier.notify()` to `TAB_LOG` and have the Log
screen open its exempt confirmation:

```kotlin
    private fun select(tab: Int, fromUser: Boolean) {
        // …
        if (tab == TAB_LOG) {
            val appId = intent.getIntExtra(BreakageNotifier.EXTRA_APP_ID, -1)
            if (appId >= 0) {
                // The confirmation belongs on a screen, not on the notification:
                // "Nullroute has stopped filtering this app" must not be one
                // accidental swipe-tap away, and this is also where "Force stop
                // app" belongs — in-app DNS caches are not ours to flush.
                (fragment as LogFragment).arguments = Bundle().apply {
                    putInt(BreakageNotifier.EXTRA_APP_ID, appId)
                    putString(
                        BreakageNotifier.EXTRA_APP_LABEL,
                        intent.getStringExtra(BreakageNotifier.EXTRA_APP_LABEL),
                    )
                    putInt(BreakageNotifier.EXTRA_BLOCK_COUNT,
                        intent.getIntExtra(BreakageNotifier.EXTRA_BLOCK_COUNT, 0))
                }
            }
        }
    }
```

After the user decides, call both of these so the notifier does not re-fire on a
decision already taken:

```kotlin
    BreakageNotifier.cancel(context, appId)
    BreakageNotifier.clearRateLimit(context, appId)   // only if they chose NOT to exempt
```

---

## 4. `res/menu/nav_main.xml` — the Log item

Between Update and Diagnostics. The icon (`ic_log.xml`) and the title
(`log_title`) both ship with this task.

```xml
    <item
        android:id="@+id/nav_log"
        android:icon="@drawable/ic_log"
        android:title="@string/log_title" />
```

---

## 5. `job/HealthWatchdog.kt` — hand the notification to `DegradedNotifier`

Not a file I own, and not one the consolidation agent merges, so this is a
request rather than a snippet drop.

`DegradedNotifier` deliberately uses the **same** channel id (`nullroute_status`)
and the **same** notification id (`1`) as `HealthWatchdog.updateNotification()`,
and posts for exactly the same single state (`NOT_FILTERING`). So the two can
never both be visible and cannot disagree — but there are two code paths writing
one notification, which is one too many. Please:

1. delete the private `ensureChannel()` / `updateNotification()` pair from
   `HealthWatchdog`, and
2. replace the call in `runCheck()`:

```kotlin
    fun runCheck(context: Context): Probes.Health {
        ControlPage.open()
        val health = Probes.sample()
        Settings.setLastStatus(context, health.status().name)
        DegradedNotifier.update(context, health)     // <-- was updateNotification(context, health)
        return health
    }
```

`DegradedNotifier.notice(health)` is a pure function of the sampled health and
returns the title/body/urgency for **all** of SPEC §3.4's states, including the
two that must never interrupt. `DiagnosticsFragment` and `HomeFragment` should
read it rather than re-deriving the mapping — that is what stops the shade, the
status card and the Diagnostics list describing the same state three ways.

---

## 6. Somebody has to call `RingReader.pump()`

Nothing drains the ring on its own. The ring is 4096 records and overwrites the
oldest, so a device that never pumps loses everything between drains and
`Drain.dropped` climbs. Three call sites, in order of importance:

**a. The periodic job** — `job/UpdateJobService.kt`, in the
`JOB_ID_BOOT_HEALTH` arm (it already runs on the DE-safe background worker):

```kotlin
            HealthWatchdog.JOB_ID_BOOT_HEALTH -> {
                NullrouteApp.io.execute {
                    try {
                        HealthWatchdog.markBootHealthyIfDue(applicationContext)
                        HealthWatchdog.runCheck(applicationContext)
                        RingReader.pump(applicationContext)      // <-- add
                    } // …
                }
                return true
            }
```

**b. A dedicated periodic job.** The boot-health job runs once. A ring that is
only drained at boot is a ring that is always lapped. A third job id — say
`JOB_ID_LOG_DRAIN = 2002`, `setPeriodic(15 min)`, `setRequiresBatteryNotLow(false)`,
no network constraint, `setPersisted(true)` — is the real answer. It is cheap:
the drain is an mmap read and one SQLite transaction, and it does nothing at all
when `log_level == 0` (the default until the user turns logging on).

**c. `LogFragment.onResume()`**, so the screen the user just opened is current.

Guard (b) on `Retention.mode(context) != Retention.LogMode.OFF` — scheduling a
periodic job to drain a ring nothing is writing to is a wakeup for nothing.

---

## 7. `data/Settings.kt` — the Phase 3 TODO is discharged

The file's closing comment reads:

```kotlin
    // TODO(Phase 3): log retention days and the redaction default.
```

Retention days and the row cap now live in `log/Retention.kt`, in their own
DE-backed prefs file (`nullroute_log`), **not** in `Settings`. That is
deliberate: `Settings.logLevel` already writes through to
`ControlPage.log_level`, which is the resolver's own copy of "what should be
logged", and the retention window is a different question (how long to keep what
was logged) with a different owner. `Retention.mode()` *derives* from
`Settings.logLevel` rather than duplicating it, so there is still exactly one
authority for the switch. The TODO can be struck.

Redaction is not implemented here — it belongs to `export/SettingsArchive.kt` and
the Diagnostics bundle, which are separate Phase 3 deliverables.

---

## 8. Note for whoever reviews the H3 hook site

SPEC §3.2 and §8.3 item 12 both place H3 "in `DnsProxyListener.cpp`, the
`ResNSendCommand` handler, ~40 lines". The delivered hook is on
**`resolv_res_nsend()`** — the external entry point that the ResNSendCommand
handler calls, located automatically by `apply.sh` in whichever file defines it
(`res_send.cpp` in current AOSP).

It is the same hook one seam lower, and the seam is worth the deviation:

* At the handler we would have to base64-decode the command argument ourselves
  and then reimplement the dnsproxyd reply framing (`sendBE32` +
  `sendLenAndData`) in order to short-circuit it — attacker-influenced decoding
  plus a private wire protocol, both things a permanent fork should not own.
* At `resolv_res_nsend()` the contract is already exactly what H3 needs: bytes
  in, bytes out, an rcode out-parameter, and a return value that is a length. The
  hunk is eight lines and names four identifiers, all of which `apply.sh`
  asserts.
* It is emphatically **not** `res_nsend()`, the internal function. That one is
  also reached by `res_nsearch()`/`res_nquery()` and therefore by every
  `getaddrinfo()` lookup, so hooking it would re-evaluate ~99% of the device's
  traffic several frames after H1 already decided it, double-count every block in
  the ring and in `ctl.q_blocked`, and reach a second verdict on a question H1
  had acted on.

`apply.sh` also handles both known parameter shapes (`std::span` and the older
pointer+length pair) and both spellings of the context parameter, and reports H3
as **skipped** — never failed — on a tree with no `ResNSendCommand`, so
H1/H2/H4 are never held hostage to it. `tools/verify_source.sh` prints which way
it went.
