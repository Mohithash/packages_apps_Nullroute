# Integration — import / export (`port`)

Everything the import/export feature needs from files it does not own. Each block
below names its target file and is copy-pasteable as written.

**Files this feature owns** (no action needed):

```
app/src/main/java/com/bestrom/nullroute/importer/ImportModel.kt
app/src/main/java/com/bestrom/nullroute/importer/AdAwayImporter.kt
app/src/main/java/com/bestrom/nullroute/importer/BindhostsImporter.kt
app/src/main/java/com/bestrom/nullroute/importer/HostsImporter.kt
app/src/main/java/com/bestrom/nullroute/export/SettingsArchive.kt      (also holds `internal object TarGz`)
app/src/main/java/com/bestrom/nullroute/export/DiagnosticsBundle.kt
app/src/main/res/values/strings_port.xml
```

`Android.bp` needs **no** change: `android_app` already globs
`app/src/main/java/**/*.kt` and `resource_dirs: ["app/src/main/res"]`.

---

## 1. `AndroidManifest.xml` — nothing is required

This is the whole integration note for the manifest, and it is deliberately
empty. Every picker used here is a `startActivityForResult` /
`ActivityResultContracts` flow against the system's `DocumentsUI`:

| action | contract | manifest entry |
|---|---|---|
| pick a backup / hosts file / AdAway JSON | `ActivityResultContracts.OpenDocument` | none |
| pick a bindhosts folder | `ActivityResultContracts.OpenDocumentTree` | none |
| create a settings backup / diagnostics bundle | `ActivityResultContracts.CreateDocument` | none |

No `READ_EXTERNAL_STORAGE`, no `WRITE_EXTERNAL_STORAGE`, no
`MANAGE_EXTERNAL_STORAGE`, and no `<queries>` block — nothing here resolves an
intent by package or asks what else is installed.

**No `FileProvider` either.** A provider would only be needed to hand a bundle
straight to a mail client with `ACTION_SEND`, and that is not how this ships: the
user creates the document wherever they like and attaches it themselves. Adding a
`FileProvider` would mean adding an exported component and a `file_paths.xml`
rooted somewhere under `/data`, which is a larger attack surface than the feature
is worth. If a later phase does want a one-tap "send to maintainer", raise it
then — do not add it pre-emptively.

### Optional, and currently unnecessary

`SettingsArchive` does **not** read `uid_policy` out of `control.bin`, so it does
not need `QUERY_ALL_PACKAGES` to turn app ids into package names. See §5.

---

## 2. `core/Native.kt` — nothing is required

No new JNI entry points. The importers use `RuleStore` for domain admissibility
and their own line sniffing for file *shape*; `DiagnosticsBundle` uses only the
existing `Native.verify()`.

### One thing worth knowing for later

`native/NrParse.cpp` (`nr_parse_line`) and `importer/HostsImporter.parseLine`
both decide what `||example.com^` means. They agree today and are covered by the
semantics table in `ImportModel`'s KDoc, but they are two implementations of one
decision.

If a future phase adds a JNI entry point that parses a line and returns
`{kind, domain, role}`, `HostsImporter.parseLine` / `parseAbp` / `parseDnsmasq`
should be deleted in favour of it. **Do not add that entry point just for this
feature** — the preview needs per-line skip *reasons* that the native parser does
not currently produce, so today it would be a step sideways.

---

## 3. `ui/MainActivity.kt` and `res/menu/nav_main.xml` — no new tab

Import and export are settings actions, not a fifth destination. They belong on
whatever settings surface the Phase 2/3 UI agent builds, under two headings that
already exist as strings:

```xml
<!-- res/values/strings_port.xml, already present -->
@string/port_section_import      "Import rules"
@string/port_section_backup      "Backup and diagnostics"
```

If a Rules screen lands, "Import rules" belongs in its overflow menu instead.
Either is fine; a nav tab is not.

---

## 4. Calling the API

All six entry points **block** — file IO, gzip, and in the diagnostics case real
DNS lookups. Use `NullrouteApp.io`.

```kotlin
// ---- import: preview, confirm, then commit --------------------------------
val plan = when (source) {
    ADAWAY    -> AdAwayImporter.preview(context, uri, options)
    BINDHOSTS -> BindhostsImporter.previewTree(context, treeUri, options)   // or previewFile(...)
    FILE      -> HostsImporter.preview(context, uri, options)
}
// plan.summary(), plan.conflicts, plan.skipped, plan.notes -> the confirm sheet.
// Nothing has been written at this point.
val result = plan.commit(context)
if (result.needsRebuild) { /* offer @string/port_import_done_action */ }

// ---- export --------------------------------------------------------------
SettingsArchive.export(context, uri)                       // uri from CreateDocument
val info = SettingsArchive.inspect(context, uri)           // preview a restore
SettingsArchive.restore(context, uri)                      // replaces, does not merge

// ---- diagnostics ---------------------------------------------------------
DiagnosticsBundle.write(context, uri, redactDomains = true)
DiagnosticsBundle.collect(context).render()                // the same text, for the clipboard
```

`CreateDocument` wants a MIME type and a name:

```kotlin
registerForActivityResult(ActivityResultContracts.CreateDocument(SettingsArchive.MIME_TYPE)) { uri -> … }
    .launch(SettingsArchive.suggestedFileName())           // "nullroute-settings-20260823-2051.tar.gz"

registerForActivityResult(ActivityResultContracts.CreateDocument(DiagnosticsBundle.MIME_TYPE)) { uri -> … }
    .launch(DiagnosticsBundle.suggestedFileName())
```

`OpenDocument` should be launched with `arrayOf("*/*")`: providers disagree about
whether a `.txt` blocklist is `text/plain`, `application/octet-stream` or
`application/x-unknown`, and a narrower filter greys out the file the user came
to pick.

### Two things the UI must say out loud

1. **An import does not change what is blocked.** Rules enter the index at the
   next compile. `@string/port_import_done` says so; do not replace it with a
   bare "Imported".
2. **A restore replaces, it does not merge.** `@string/port_restore_replaces`.
   Merging is what the importers are for.

---

## 5. A contract for whoever writes per-app policy (`data/AppPolicyStore.kt`)

`SettingsArchive` backs up **everything under `/data/misc/nullroute/priv/`** except
`cache/` and `build/`, rather than a named list of files. So:

> **Persist per-app policy to a file under `priv/`** — for example
> `priv/apppolicy.txt`, as `packageName=policy` lines — and it is backed up,
> restored and diagnosed for free, with no change to this feature.

Two reasons this is the right place anyway, beyond the backup:

* `control.bin` is pre-created by `nullroute_seed` each boot and `uid_policy` has
  to be re-applied from somewhere durable regardless.
* **Never persist a bare `appId`.** App ids are assigned at install time and are
  not stable across a reinstall, let alone across devices. Restoring
  `uid_policy[10234] = EXEMPT` from another phone's backup exempts whatever app
  happens to hold 10234 here, which is an arbitrary app silently excused from
  filtering. Store the package name and resolve it at apply time; skip and report
  the ones that do not resolve.

If policy lands somewhere other than `priv/`, tell this feature — the export needs
one line, but it needs to know.

---

## 6. Optional follow-up: fold `DiagnosticsFragment` onto `DiagnosticsBundle`

`ui/DiagnosticsFragment.gather()` and `DiagnosticsBundle.collect()` sample an
overlapping set of signals. `collect()` returns
`List<Section>` where `Section` is `(title, rows: List<Pair<String,String>>, json)`,
which is exactly the shape the fragment's `Item.Header` / `Item.Row` adapter
already renders:

```kotlin
val report = DiagnosticsBundle.collect(context)
report.sections.forEach { section ->
    items += Item.Header(section.title)
    section.rows.forEach { (k, v) -> items += Item.Row(k, v) }
}
```

That would leave one collector instead of two drifting ones, and the copy button
could become `report.render()`. Not done here because `DiagnosticsFragment.kt` is
owned by the consolidation pass — flagged rather than performed.

The bundle collects strictly more than the fragment does today (the ring file's
state, the per-source download manifest with its ETag/Last-Modified validators,
staging leftovers, free space, the build fingerprint), so the fold only adds rows.

---

## 7. Verification already done

Compiled with Kotlin 2.0.21 against `android.jar` (API 36): **0 errors,
0 warnings** across `importer/`, `export/` and their dependencies.

Two throwaway JVM harnesses exercised the parts most likely to be subtly wrong:

* **`TarGz` round trip** at sizes 0 / 1 / 511 / 512 / 513 / 5000 bytes, and the
  archive verified externally with **GNU tar 1.35** (`tar -tzvf`, `tar -xzf`,
  `gzip -t`) — headers, checksums, modes and sizes all accepted with no warnings.
  This caught one real bug: a zero-length member read as a truncated archive, and
  an untouched `allow.txt` is exactly a zero-length member.
* **Path traversal and archive bounds**: `../../../system/etc/hosts`,
  `priv/../../../data/system/packages.xml`, absolute paths, backslash traversal,
  `priv/cache/*` and over-deep paths are all refused; member-count, member-size
  and total-decompressed-size ceilings all fire; truncated and non-gzip inputs
  are rejected.
* **The line engine**, over hosts / domains / ABP / dnsmasq / Nullroute syntax:
  exact-vs-suffix semantics, sinkhole-is-a-block, `$modifier` and cosmetic rules
  skipped with reasons, `.local` and the probe zone refused, the `broaden` option,
  and the allow-list widening asymmetry.
* **The AdAway walker**, over five plausible backup schemas including a numeric
  `type` field (ignored on purpose), a disabled entry, a source object carrying a
  `name`, and a document with nothing recognisable in it (imports nothing rather
  than guessing).

Not covered without a device: SAF `Uri` plumbing, `DocumentsContract` tree
listing, and `Os.rename` on `/data/misc/nullroute/priv`.
