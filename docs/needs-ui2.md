# needs-ui2 — what the Phase 2 screens need from files this feature does not own

Five fragments, one data store and two JNI entry points landed under
`ui2`. Everything below is a change to a file on the do-not-edit list, written
out verbatim so the integrator can paste rather than reconstruct.

Nothing here is optional in the sense of "nice to have": without (1) the screens
are unreachable, and without (3) the Apps screen shows one row.

---

## 1. `res/menu/nav_main.xml` + `ui/MainActivity.kt` — reaching the screens

`BottomNavigationView` renders at most **five** items before it starts eliding
labels, and Phase 1 already spends four. Phase 2 adds five more, and the log /
deep / port features add their own, so the bottom bar cannot absorb them all.

**Recommended:** leave `nav_main.xml` at Home / Rules / Query / Update /
Diagnostics, and put Apps, Categories, Sources and Profile behind the toolbar
overflow. Rules and Query earn a bottom-bar seat because they are the two
screens a user opens *while* something is wrong.

### `res/menu/nav_main.xml` — replace the `nav_profile` item

```xml
    <item
        android:id="@+id/nav_rules"
        android:icon="@drawable/ic_rules"
        android:title="@string/tab_rules" />
    <item
        android:id="@+id/nav_query"
        android:icon="@drawable/ic_query"
        android:title="@string/tab_query" />
```

### `res/menu/menu_overflow.xml` — new file (not owned by ui2; create it)

```xml
<?xml version="1.0" encoding="utf-8"?>
<menu xmlns:android="http://schemas.android.com/apk/res/android">
    <item android:id="@+id/menu_profile" android:title="@string/tab_profile" />
    <item android:id="@+id/menu_apps" android:title="@string/tab_apps" />
    <item android:id="@+id/menu_categories" android:title="@string/tab_categories" />
    <item android:id="@+id/menu_sources" android:title="@string/tab_sources" />
</menu>
```

### `ui/MainActivity.kt`

Add to the `companion object` — **renumber if another feature has already taken
these values**; the constants are positional only within this file:

```kotlin
        const val TAB_RULES = 4
        const val TAB_QUERY = 5
        const val TAB_APPS = 6
        const val TAB_CATEGORIES = 7
        const val TAB_SOURCES = 8
```

Add to `select()`:

```kotlin
            TAB_RULES -> RulesFragment()
            TAB_QUERY -> QueryFragment()
            TAB_APPS -> AppPolicyFragment()
            TAB_CATEGORIES -> CategoriesFragment()
            TAB_SOURCES -> SourceEditFragment()
```

Add to `tabForMenuId()`:

```kotlin
        R.id.nav_rules -> TAB_RULES
        R.id.nav_query -> TAB_QUERY
```

Add to `menuIdForTab()`:

```kotlin
        TAB_RULES -> R.id.nav_rules
        TAB_QUERY -> R.id.nav_query
```

Add to `titleForTab()`:

```kotlin
        TAB_RULES -> R.string.tab_rules
        TAB_QUERY -> R.string.tab_query
        TAB_APPS -> R.string.tab_apps
        TAB_CATEGORIES -> R.string.tab_categories
        TAB_SOURCES -> R.string.tab_sources
```

And the overflow, in `onCreate` after `setSupportActionBar` / `toolbar` is bound:

```kotlin
        toolbar.inflateMenu(R.menu.menu_overflow)
        toolbar.setOnMenuItemClickListener { item ->
            val tab = when (item.itemId) {
                R.id.menu_profile -> TAB_PROFILE
                R.id.menu_apps -> TAB_APPS
                R.id.menu_categories -> TAB_CATEGORIES
                R.id.menu_sources -> TAB_SOURCES
                else -> return@setOnMenuItemClickListener false
            }
            select(tab, fromUser = false)
            true
        }
```

`menuIdForTab()` has no entry for the overflow tabs, so `select(fromUser =
false)` calls `nav.menu.findItem(...)` with an id that is not in the bottom bar.
`findItem` returns null there and the `?.` already handles it — the bottom bar
simply keeps its previous selection, which is the correct behaviour for a screen
that has no bar item.

Note that `nav_rules` and `nav_query` are **@+id** declarations in a menu file,
so they exist for `MainActivity` only once the menu XML above is in place; adding
the Kotlin first is a compile error, not a runtime one.

---

## 2. `AndroidManifest.xml` — package visibility for the Apps screen

`AppPolicyStore.load()` calls `getInstalledApplications()`. From API 30 that
returns only packages this app can already see, so without the permission below
the Apps screen lists Nullroute and roughly nothing else — a screen that appears
to work and is silently empty.

```xml
    <!-- The Apps screen maps every installed appId to a name so the per-app
         policy rows can be labelled. Filtering is per-uid at the resolver, so
         the alternative to enumerating packages is showing bare uid numbers. -->
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
```

`QUERY_ALL_PACKAGES` is `protectionLevel="normal"`, so it needs **no** entry in
`rom/privapp-permissions-com.bestrom.nullroute.xml`. Do not add one — an
unmatched line there aborts boot before adbd comes up.

---

## 3. `job/BootReceiver.kt` — re-apply per-app exemptions

`nullroute_seed` re-creates `control.bin` when it is missing or the wrong size,
which zeroes `uid_policy`. Without this call the user's exemptions vanish on the
first boot after a flash and the only symptom is an app that quietly stopped
working again.

Inside the existing `NullrouteApp.io.execute { … }` block, in the branch where
`ControlPage.open()` succeeded, after `syncModeFromProperty()`:

```kotlin
                    val reapplied = AppPolicyStore.reapplyAll(app)
                    if (reapplied > 0) Log.i(TAG, "re-applied $reapplied app exemptions")
```

plus the import:

```kotlin
import com.bestrom.nullroute.data.AppPolicyStore
```

This is DE-safe and runs at `ACTION_LOCKED_BOOT_COMPLETED`.

---

## 4. `export/DiagnosticsBundle.kt` — one line each (optional but cheap)

```kotlin
        AppPolicyStore.describe(context).forEach { out.appendLine("uid_policy: $it") }
```

`AppPolicyStore.describe()` emits `com.example.app=exempt` per exempted package
and nothing else, so the bundle gains the per-app state without gaining a list of
everything installed.

---

## 5. `Android.bp` — nothing to do

`native/NrStrings.cpp` is already in `libnrcore`, and `libnrjni` already links
`libnrcore`, so `nativeStringsPreview` / `nativeStringsList` build with no module
change. `jni_bridge.cpp` gained `#include "NrStrings.h"` only.

---

## 6. Follow-ups this feature deliberately did not do

* **`NR_POLICY_STRICT` has no implementation.** `nr_evaluate()` in
  `native/NrQuery.cpp` tests `uid_policy[app_id] == NR_POLICY_EXEMPT` and nothing
  else, so a third policy value is inert. The Apps screen therefore offers two
  states, and says so on the screen. If the resolver grows a meaning for STRICT
  (the obvious one: ignore the never-block floor and the carve-out allows for
  this app), `AppPolicyStore` is where the third state goes.

* **`RuleStore` exposes unparsable lines for `allow.txt` only.**
  `unparsableAllowLines()` has no `deny` / `redirect` sibling, so the Rules screen
  can only surface dropped lines on the Allow tab. The other two tabs silently
  drop unreadable lines today. A `unparsableDenyLines()` /
  `unparsableRedirectLines()` pair would close that, and the Rules screen already
  has the section to render them in.

* **The preview reads the sidecar for the index on disk, not the one netd
  mapped.** They are the same file in every normal state; they differ in the
  window between a promotion and netd noticing it. Reading the on-disk generation
  is the right choice — it is what the *next* query will use — but a mismatch is
  not currently surfaced anywhere.
