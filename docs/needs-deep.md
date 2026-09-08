# Integration — Deep-mode UI, the blocking self-test, and the second wave of `nrctl` verbs

Every change below lands in a file this feature does **not** own. Each snippet is
copy-pasteable; nothing here is a description you have to derive.

Files this feature owns, already written:

```
app/src/main/java/com/bestrom/nullroute/
    ui/DeepModeFragment.kt          the switch, the state card, the auto-disable history
    ui/SelfTestFragment.kt          "Test my blocking"
    selftest/BlockingSelfTest.kt    the three lanes, the control lookup, the domain picker
    selftest/SelfTestReport.kt      the result model (no Android dependencies)
app/src/main/res/layout/fragment_deepmode.xml
app/src/main/res/layout/fragment_selftest.xml
app/src/main/res/values/strings_selftest.xml     (deepui_* and selftest_*)
app/src/main/res/drawable/ic_deep.xml · ic_selftest.xml
native/nrctl.cpp                    verbs apps/import/export/rollback/deep/panic (ADDED ONLY)
```

Deep-mode screen copy lives under a `deepui_` prefix in `strings_selftest.xml`
rather than in `strings_deep.xml`: `res/values` is merged, a name may be defined
once across all files, and `strings_deep.xml` belongs to the `deep/` service
feature. Nothing here redefines any name from it — `deep_consent_*`,
`deep_scope`, `deep_private_dns_strict` and `deep_default_*_reason` are used as
they are.

---

## 1. `ctl/CtlReceiver.kt` — **REQUIRED, or five CLI verbs are silent no-ops**

`nrctl` now marshals `import`, `export`, `rollback`, `deep` and `panic`. The
receiver has no arm for any of them, so today each one is delivered, logged as
`unknown CTL verb`, and does nothing — the exact defect the CLI's header comment
is written around. `nrctl selftest` asserts that the intents carry these exact
keys; it cannot assert that the receiver reads them.

### 1a. Companion additions

```kotlin
        const val EXTRA_PATH = "path"
        const val EXTRA_ENABLE = "enable"

        const val VERB_IMPORT = "import"
        const val VERB_EXPORT = "export"
        const val VERB_ROLLBACK = "rollback"
        const val VERB_DEEP = "deep"
        const val VERB_PANIC = "panic"

        /** Where `nrctl export` writes when it is given no path. */
        const val DEFAULT_EXPORT_PATH = "/data/misc/nullroute/priv/nullroute-settings.zip"
```

The keys are bare `path` and `enable`, **not** namespaced. `nrctl` sends
`--es path …` and `--ez enable …`; a receiver reading `nr.path` would get null
and import nothing, with no error anywhere.

### 1b. `dispatch()` arms

```kotlin
            // A path from a privileged caller, not from the file system: the
            // sender is already gated to {root, system, shell}, so the check that
            // matters is that the APP can read it. /data/local/tmp cannot be read
            // by an app at all, which is why nrctl says so in its own output.
            VERB_IMPORT -> {
                val path = intent.getStringExtra(EXTRA_PATH)
                if (path.isNullOrEmpty()) {
                    Log.w(TAG, "import with no $EXTRA_PATH extra")
                    return
                }
                NullrouteApp.io.execute {
                    runCatching {
                        val plan = HostsImporter.preview(context, Uri.fromFile(File(path)))
                        val result = plan.commit(context)
                        Log.i(TAG, "import $path -> $result")
                    }.onFailure { Log.w(TAG, "import $path failed", it) }
                }
            }

            VERB_EXPORT -> {
                val path = intent.getStringExtra(EXTRA_PATH) ?: DEFAULT_EXPORT_PATH
                NullrouteApp.io.execute {
                    runCatching {
                        val file = File(path)
                        file.parentFile?.mkdirs()
                        val out = SettingsArchive.export(context, Uri.fromFile(file))
                        Log.i(TAG, "export $path: ${out.bytes} bytes")
                    }.onFailure { Log.w(TAG, "export $path failed", it) }
                }
            }

            VERB_ROLLBACK -> NullrouteApp.io.execute {
                if (!Generation.canRollback()) {
                    Log.w(TAG, "rollback refused: no previous index")
                } else {
                    Log.i(TAG, "rollback: ${Generation.rollback(context).describe()}")
                }
            }

            VERB_DEEP -> {
                val enable = intent.getBooleanExtra(EXTRA_ENABLE, false)
                DeepWatchdog.setEnabled(context, enable)
                if (!enable) {
                    DeepVpnService.stop(context)
                } else if (DeepVpnService.prepareIntent(context) == null) {
                    DeepVpnService.start(context)
                } else {
                    // VpnService consent has never been granted, and a broadcast
                    // cannot grant it. Starting the service anyway would fail at
                    // establish() and spend one of the watchdog's three lives on
                    // a situation that is not a malfunction. The enabled flag is
                    // still set, so the app asks the next time the screen opens.
                    Log.w(TAG, "deep on requested but VPN consent has not been granted")
                }
            }

            // Every switch at once. Deliberately touches no user DATA — panic is
            // for a device that cannot resolve anything, and a verb that also
            // deleted rules would be one the user could never safely try.
            VERB_PANIC -> {
                setMode(context, ControlPage.MODE_OFF)
                DeepWatchdog.setEnabled(context, false)
                DeepVpnService.stop(context)
                Log.w(TAG, "panic: mode=off, deep=off")
            }
```

Imports to add: `android.net.Uri`, `java.io.File`,
`com.bestrom.nullroute.core.Generation`,
`com.bestrom.nullroute.deep.DeepVpnService`,
`com.bestrom.nullroute.deep.DeepWatchdog`,
`com.bestrom.nullroute.export.SettingsArchive`,
`com.bestrom.nullroute.importer.HostsImporter`.

**One thing to check before shipping this**: `SettingsArchive.export()` and
`HostsImporter.preview()` both go through `ContentResolver`. A `file://` Uri
works for a file the app itself owns, which is the case for anything under
`priv/`. If either turns out to reject `file://` on this platform version, give
them a `FileInputStream`/`FileOutputStream` overload rather than teaching `nrctl`
to hand over a content Uri — a shell has no way to mint one.

---

## 2. `res/menu/nav_main.xml` and `ui/MainActivity.kt` — one new tab

**`BottomNavigationView` takes at most five items.** There are four today, so
exactly one of the two new screens can become a tab, and it must be Deep mode:
the self-test is reachable from the Deep-mode screen already
(`DeepModeFragment.openSelfTest()` swaps it into whatever container is hosting
it) and should also be reachable from Home, per SPEC §3.6. Adding both as tabs
throws `IllegalArgumentException` at inflate time.

### 2a. `res/menu/nav_main.xml` — add before `nav_diagnostics`

```xml
    <item
        android:id="@+id/nav_deep"
        android:icon="@drawable/ic_deep"
        android:title="@string/tab_deep" />
```

### 2b. `ui/MainActivity.kt` — four one-line additions

```kotlin
        // select()
            TAB_DEEP -> DeepModeFragment()

        // tabForMenuId()
        R.id.nav_deep -> TAB_DEEP

        // menuIdForTab()
        TAB_DEEP -> R.id.nav_deep

        // titleForTab()
        TAB_DEEP -> R.string.deepui_title

        // companion object
        const val TAB_DEEP = 4
```

`TAB_DEEP = 4` rather than inserting it at 3: `EXTRA_OPEN_TAB` is a public
constant that the tile and the notifications already send, and renumbering the
existing tabs would silently redirect an intent built by an older component.

---

## 3. `ui/HomeFragment.kt` + `res/layout/fragment_home.xml` — the self-test entry

SPEC §3.6 and F12 both put "Test my blocking" on the **Home** screen, next to the
scope sentence. That is where a user who has just read "does not filter Chrome"
is standing.

In `fragment_home.xml`, inside the scope card:

```xml
                <com.google.android.material.button.MaterialButton
                    android:id="@+id/button_selftest"
                    style="@style/Widget.Material3.Button.TonalButton"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_marginTop="12dp"
                    android:text="@string/deepui_action_test" />
```

In `HomeFragment.onViewCreated`:

```kotlin
        view.findViewById<MaterialButton>(R.id.button_selftest).setOnClickListener {
            // The container rather than R.id.fragment_container: Home is hosted
            // by MainActivity and by SettingsEntryActivity, which use different
            // hosts for the same fragment.
            val containerId = (requireView().parent as? View)?.id ?: return@setOnClickListener
            parentFragmentManager.beginTransaction()
                .replace(containerId, SelfTestFragment())
                .addToBackStack(null)
                .commit()
        }
```

---

## 4. `app/src/main/AndroidManifest.xml` — optional, one `<queries>` block

The self-test names the user's default browser in lane 3
(`selftest_lane_browser`). Package-visibility filtering hides that from a
non-`QUERY_ALL_PACKAGES` app, and the lane then falls back to the unnamed
`selftest_lane_browser_unknown` string — functional, less useful. To name it:

```xml
    <!--
        Read-only visibility of whatever handles web links, so "Test my blocking"
        can name the browser in its third lane. This grants no ability to talk to
        it; the URL is launched with a plain ACTION_VIEW either way.
    -->
    <queries>
        <intent>
            <action android:name="android.intent.action.VIEW" />
            <data android:scheme="https" />
        </intent>
    </queries>
```

Nothing else is needed. Both new screens are fragments of the existing activity,
`WebView` needs no permission, and the self-test uses `INTERNET`, which the app
already holds.

---

## 5. `deep/DeepWatchdog.kt` — optional, deletes a duplicated constant

`DeepModeFragment` shows the auto-disable history, and the *history* (as opposed
to the standing reason) is only in the private `failures` key. The fragment reads
it out of the preferences file directly, duplicating `PREFS` and `KEY_FAILURES`
as literals. A wrong literal there degrades to "no history", never to a wrong
history — but the duplication is still worth removing:

```kotlin
    /**
     * The failure timestamps still inside [WINDOW_MS], oldest first. For the
     * Deep-mode screen, which has to explain a switch that moved by itself.
     */
    fun failureHistory(context: Context): List<Long> {
        val now = System.currentTimeMillis()
        return (prefs(context).getString(KEY_FAILURES, "") ?: "")
            .split(',')
            .mapNotNull { it.trim().toLongOrNull() }
            .filter { it in (now - WINDOW_MS)..now }
            .sorted()
    }
```

Then `DeepModeFragment.failureTimestamps()` becomes a call to it and the two
`DEEP_PREFS` / `DEEP_KEY_FAILURES` constants at the bottom of that file go away.

---

## 6. `native/include/NrCtl.h` — optional, one probe constant pair

`nrctl deep` resolves Deep mode's liveness probe and compares the answer. The
name and address are currently defined locally in `nrctl.cpp` and mirror
`core/Probes.kt`; the other two probes are in the header. Beside
`NR_PROBE_HOSTS_NAME`:

```c
#define NR_PROBE_DEEP_NAME "vpn-probe.nullroute.invalid"
#define NR_PROBE_DEEP_ADDR "127.0.0.9"
```

Then delete the two `#define`s under "Deep mode's liveness probe" in `nrctl.cpp`.

---

## 7. What was verified, and what was not

Verified:

* `native/nrctl.cpp` compiles clean at `-std=c++17 -O2 -Wall -Wextra` (clang 18,
  x86-64 Linux) — **zero warnings**, and links against `NrCanon`/`NrQuery`/
  `NrBuilder`/`NrParse`/`NrCollapse`/`NrStrings`/`NrMap`/`NrCtlCore`/
  `NrRingReader` with no undefined symbols.
* `nrctl selftest` passes end to end on that binary, including the new
  assertions: `import`/`export`/`rollback`/`deep`/`panic` each marshal a
  broadcast carrying the component, the action and the literal
  `--es path …` / `--ez enable …` / `--es verb …` the receiver will read, and
  `apps` reports a missing control page as *unavailable* rather than as an empty
  table.
* `nrctl help`, `nrctl deep`, `nrctl --json deep`, `nrctl apps` and
  `nrctl import <missing>` produce the intended output and exit codes (0 / 3).

Not verified, and not verifiable from source:

* Nothing in section 1 exists yet, so **every mutating verb in the second wave is
  a no-op on a device until the receiver arms land**. `nrctl` reports honestly in
  each case (`rollback` and `panic` prove themselves from `control.bin`,
  `export` from the file, `import` and `deep` say they cannot), so the failure is
  loud rather than silent — but it is still a failure.
* The Kotlin in this feature has not been through `kotlinc`; it is written
  against the same API surface `HomeFragment`/`ProfileFragment` use, plus
  `SwitchMaterial`, `MaterialAlertDialogBuilder` and `WebView`. `SwitchMaterial`
  is used rather than `MaterialSwitch` because it exists in every Material
  version this tree might pin.
* The three self-test lanes need a device: what Chromium's resolver actually does
  in WebView on this image is spike 5 (SPEC §10.6), and the whole point of the
  screen is that the answer is measured per device rather than assumed.
* `nrctl deep`'s probe from a shell depends on whether root/shell DNS traverses
  the VPN on this ROM. The verb reports the probe as *evidence* and says outright
  that a silent probe with a tun present is undetermined, so a "no" from that
  path is not a bug — but it is worth knowing which way it goes before anyone
  writes a script around it.
