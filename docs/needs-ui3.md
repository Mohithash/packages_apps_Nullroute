# Integration — Phase 3 UI (`ui3`)

Everything the log / settings / onboarding screens need that lives in a **shared
file I must not edit**. Each block is exact and copy-pasteable, with the target
file named. Without §1 and §2 the code compiles but the screens are unreachable;
without §3 the force-stop button is permanently disabled (it degrades honestly —
it reports `rec_force_stop_unavailable` rather than throwing).

Files delivered by this task (no action needed on them):

```
app/.../ui/LogFragment.kt            per-app / per-domain / recent, drop banner
app/.../ui/LogDetailFragment.kt      one domain or app + the three recovery moves
app/.../ui/RecoveryActions.kt        allow / exempt / force stop, and what each costs
app/.../ui/SettingsFragment.kt       response mode, update schedule
app/.../ui/PrivacyFragment.kt        log level, retention, purge, CE-storage statement
app/.../ui/OnboardingActivity.kt     four pages; page two is the limits
app/.../qs/TilePrefsActivity.kt      tile tap behaviour + TilePrefs (DE-backed)
app/src/main/res/layout/fragment_{log,logdetail,settings,privacy}.xml
app/src/main/res/layout/{activity_onboarding,activity_tileprefs,item_log}.xml
app/src/main/res/values/strings_ui3.xml
app/src/main/res/drawable/ic_{settings,privacy}.xml
```

---

## 1. `res/menu/nav_main.xml` — the Log tab

Five items is the maximum a `BottomNavigationView` renders as icons + labels, and
this takes it to exactly five. Insert **after** `nav_home`:

```xml
    <item
        android:id="@+id/nav_log"
        android:icon="@drawable/ic_log"
        android:title="@string/logui_tab" />
```

`ic_log.xml` already ships (delivered by the log backend task).

Settings does **not** get a sixth tab — it goes in the toolbar overflow, §2.3.

---

## 2. `ui/MainActivity.kt`

### 2.1 The tab constant and the four `when`s

```kotlin
        const val TAB_DIAGNOSTICS = 3
        const val TAB_LOG = 4          // add
```

```kotlin
    private fun select(tab: Int, fromUser: Boolean) {
        val fragment: Fragment = when (tab) {
            TAB_PROFILE -> ProfileFragment()
            TAB_UPDATE -> UpdateFragment()
            TAB_DIAGNOSTICS -> DiagnosticsFragment()
            TAB_LOG -> LogFragment()                        // add
            else -> HomeFragment()
        }
```

```kotlin
    private fun tabForMenuId(id: Int): Int = when (id) {
        R.id.nav_profile -> TAB_PROFILE
        R.id.nav_update -> TAB_UPDATE
        R.id.nav_diagnostics -> TAB_DIAGNOSTICS
        R.id.nav_log -> TAB_LOG                             // add
        else -> TAB_HOME
    }

    private fun menuIdForTab(tab: Int): Int = when (tab) {
        TAB_PROFILE -> R.id.nav_profile
        TAB_UPDATE -> R.id.nav_update
        TAB_DIAGNOSTICS -> R.id.nav_diagnostics
        TAB_LOG -> R.id.nav_log                             // add
        else -> R.id.nav_home
    }

    private fun titleForTab(tab: Int): Int = when (tab) {
        TAB_PROFILE -> R.string.tab_profile
        TAB_UPDATE -> R.string.tab_update
        TAB_DIAGNOSTICS -> R.string.tab_diagnostics
        TAB_LOG -> R.string.logui_tab                       // add
        else -> R.string.app_name
    }
```

`select()` uses `replace()` with no back-stack entry, which is right for tabs.
`LogFragment` pushes its detail screen onto the same container **with**
`addToBackStack(null)`, so system back returns to the list and then to the tab —
nothing else in MainActivity has to change for that to work.

### 2.2 First run

`OnboardingActivity` is self-contained: it marks first-run done itself, including
when the user skips. MainActivity only has to decide when to show it, in
`onCreate`, after `setContentView` and inside the `savedInstanceState == null`
branch so a rotation does not re-launch it:

```kotlin
        if (savedInstanceState == null) {
            if (OnboardingActivity.isNeeded(this)) {
                startActivity(OnboardingActivity.replayIntent(this))
            }
            select(intent.getIntExtra(EXTRA_OPEN_TAB, TAB_HOME), fromUser = false)
        }
```

`isNeeded` reads `Settings.firstRunDone`, which is DE-backed, so this is safe
before first unlock.

### 2.3 Settings in the toolbar overflow

New file — **not one of mine**, so it is written out here in full:
`app/src/main/res/menu/menu_toolbar.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<menu xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto">
    <item
        android:id="@+id/menu_settings"
        android:icon="@drawable/ic_settings"
        android:title="@string/sett_tab"
        app:showAsAction="never" />
</menu>
```

In `MainActivity.onCreate`, after `toolbar = findViewById(R.id.toolbar)`:

```kotlin
        toolbar.inflateMenu(R.menu.menu_toolbar)
        toolbar.setOnMenuItemClickListener { item ->
            if (item.itemId == R.id.menu_settings) {
                supportFragmentManager.beginTransaction()
                    .replace(R.id.fragment_container, SettingsFragment())
                    .addToBackStack(null)
                    .commit()
                true
            } else {
                false
            }
        }
```

`SettingsFragment` reaches `PrivacyFragment`, `TilePrefsActivity` and the
onboarding replay on its own, so this one entry point is enough for all of them.

---

## 3. `app/src/main/AndroidManifest.xml`

### 3.1 The force-stop permission

`android.permission.FORCE_STOP_PACKAGES` is **already** in
`rom/privapp-permissions-com.bestrom.nullroute.xml` (line 61) — the allowlist
entry alone grants nothing; the manifest has to request it. Add next to the other
privileged requests:

```xml
    <!-- "Allow + retry" offers Force stop because neither an allow rule nor a
         uid exemption can flush the app's OWN DNS cache: IDnsResolver's
         flushNetworkCache sits behind dnsresolver_service, which sepolicy
         neverallows any app from binding. Restarting the app is the only lever
         that empties OkHttp/Chromium/JVM negative caches. -->
    <uses-permission android:name="android.permission.FORCE_STOP_PACKAGES" />
```

Until this lands `RecoveryActions.canForceStop()` returns false, the button is
disabled and the screen says why — so this is a feature gap, not a crash.

### 3.2 The two new activities

```xml
        <activity
            android:name=".ui.OnboardingActivity"
            android:exported="false"
            android:label="@string/app_name"
            android:theme="@style/Theme.Nullroute" />

        <!--
            exported=true is required: SystemUI starts this from the tile's own
            "settings" affordance in the shade, and an unexported activity would
            simply do nothing there. It takes no extras and reads no caller data.
        -->
        <activity
            android:name=".qs.TilePrefsActivity"
            android:exported="true"
            android:label="@string/qsp_title"
            android:theme="@style/Theme.Nullroute">
            <intent-filter>
                <action android:name="android.service.quicksettings.action.QS_TILE_PREFERENCES" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
```

---

## 4. `qs/NullrouteTileService.kt` — honour the tile preferences

`TilePrefsActivity.TilePrefs` is the single reader of the DE-backed store; the
tile just asks it one question. Replace the body of `onClick()`:

```kotlin
    override fun onClick() {
        super.onClick()
        if (!ControlPage.open()) {
            render()
            return
        }

        val pausing = ControlPage.mode == ControlPage.MODE_ENFORCE
        // Opening the app is one tap further from switching protection off by
        // accident, and the shade is reachable on most lock screens.
        if (pausing && !TilePrefsActivity.TilePrefs.tapMayPauseSilently(applicationContext)) {
            val intent = android.content.Intent(this, com.bestrom.nullroute.ui.MainActivity::class.java)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            val pending = android.app.PendingIntent.getActivity(
                this, 0, intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pending)
            return
        }

        val next = if (pausing) ControlPage.MODE_PAUSED else ControlPage.MODE_ENFORCE
        ControlPage.setMode(next)
        render()
        NullrouteApp.io.execute {
            runCatching { HealthWatchdog.runCheck(applicationContext) }
            main.post { runCatching { render() } }
        }
    }
```

Note the asymmetry, which is deliberate: **resuming is never gated.** Confirmation
protects against accidentally becoming less protected; asking before restoring
protection would be friction with no upside.

`startActivityAndCollapse(PendingIntent)` is the API 34+ signature; this module's
`min_sdk_version` is 36, so the deprecated `Intent` overload must not be used.

---

## 5. Optional but recommended — point the breakage notification at the app

`notify/BreakageNotifier.kt` currently deep-links to `TAB_DIAGNOSTICS` carrying
`EXTRA_APP_ID`. The screen that can act on it now exists. In `BreakageNotifier`:

```kotlin
            putExtra(MainActivity.EXTRA_OPEN_TAB, MainActivity.TAB_LOG)
```

and in `MainActivity.select()`, when the tab is `TAB_LOG` and the intent carries
`BreakageNotifier.EXTRA_APP_ID`, hand the uid straight to the detail screen:

```kotlin
            TAB_LOG -> {
                val appId = intent.getIntExtra(BreakageNotifier.EXTRA_APP_ID, -1)
                if (appId >= 0) LogDetailFragment.forApp(appId) else LogFragment()
            }
```

`LogDetailFragment.forApp` takes an appId-or-uid interchangeably — every policy
read and write in `RecoveryActions` reduces it with `uid % 100_000` before it
touches `uid_policy`, which is exactly what the resolver indexes with.

---

## 6. Nothing else is needed

No new `static_libs`: the screens use `androidx.appcompat` (`SwitchCompat`,
`AlertDialog`), `androidx.recyclerview` and `com.google.android.material`
(`MaterialButton`, `MaterialButtonToggleGroup`), all already in `Android.bp`.
No `sdk_version` change: `ActivityManager.forceStopPackage` is reached by
reflection, the same way `DeviceConfigFixups` reaches `@SystemApi` DeviceConfig,
and `rom/sysconfig-nullroute.xml`'s `hidden-api-whitelisted-app` entry is what
makes that legal at runtime.
