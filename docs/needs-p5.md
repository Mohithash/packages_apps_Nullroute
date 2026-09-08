# Phase 5 — CNAME uncloaking, per-user policy, Advanced screen

What Phase 5 built, what it needs from files it does not own, and what it
deliberately did not do.

## Files added / changed by Phase 5

| file | status |
|---|---|
| `resolver-patch/nullroute/NrCname.h` | new — header-only answer-section parser + the `nr::cnameBlocked()` hook surface |
| `resolver-patch/nullroute/NrCname.cpp` | new — the policy side (gate + `nr::hook()` per link) |
| `native/fuzz/nr_cname_fuzzer.cpp` | new — merge gate for the answer parser |
| `app/.../core/UserPolicy.kt` | new — what per-app policy means on a multi-user device |
| `app/.../ui/AdvancedFragment.kt` | new |
| `app/src/main/res/layout/fragment_advanced.xml` | new |
| `app/src/main/res/values/strings_phase5.xml` | new |
| `resolver-patch/apply.sh` | H5 hunk added behind its own marker; `SRC_FILES` and the `srcs` array gained `NrCname.*`; H1/H2/H3/H4 untouched |
| `app/.../core/ControlPage.kt` | **one additive edit** — see below |

### The one edit outside the owned set: `ControlPage.kt`

`OFF_CNAME_UNCLOAK = 11` was already declared and unused. Phase 5 added exactly
two members next to `logLevel`, in the existing style:

```kotlin
val cnameUncloak: Boolean get() = readByte(OFF_CNAME_UNCLOAK) != 0

fun setCnameUncloak(enabled: Boolean): Boolean {
    val ok = writeByte(OFF_CNAME_UNCLOAK, if (enabled) 1 else 0)
    bumpEpoch()
    return ok
}
```

Nothing else in the file changed. If another phase has touched `ControlPage.kt`
in parallel, this is the whole of the merge.

**There is deliberately no `Settings.kt` preference mirroring this byte.** `mode`
has a `persist.` property because *init* must re-derive it without the app
running; nothing re-derives `cname_uncloak`, so a preference would only be a
second authority that can disagree with the page — the exact failure the
mode/property split exists to prevent. The page lives on `/data` and keeps its
value across a reboot.

---

## 1. Wire the Advanced screen into Settings (required)

`AdvancedFragment` is a push destination, not a tab, so `res/menu/nav_main.xml`
and `MainActivity.kt` need **no** change. Two edits are needed in files Phase 5
does not own.

**`app/src/main/res/layout/fragment_settings.xml`** — add next to the existing
`sett_privacy` button:

```xml
<com.google.android.material.button.MaterialButton
    android:id="@+id/sett_advanced"
    style="@style/Widget.Material3.Button.TextButton"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="@string/adv_title" />
```

**`app/src/main/java/com/bestrom/nullroute/ui/SettingsFragment.kt`** — a field,
a `findViewById`, and a listener that matches the existing `privacy` one exactly:

```kotlin
private lateinit var advanced: MaterialButton
```

```kotlin
advanced = view.findViewById(R.id.sett_advanced)
```

```kotlin
advanced.setOnClickListener {
    parentFragmentManager.beginTransaction()
        .replace(R.id.fragment_container, AdvancedFragment())
        .addToBackStack(null)
        .commit()
}
```

`adv_title` lives in `strings_phase5.xml`, so no shared string file is touched.

---

## 2. Add the CNAME fuzzer to the merge gate (required)

`tools/verify_source.sh` already compiles every `resolver-patch/nullroute/*.cpp`
by glob, so `NrCname.cpp` is covered with no change. The fuzzer list is hardcoded
and is not. Add this stanza after the `nr_wire_fuzzer` block — same shape,
`CORE_SRC` deliberately absent for the same reason (`NrCname.h` is header-only
and depends on nothing but `nr_wire.h`, so a crash is unambiguously a parser bug):

```bash
# The ANSWER side. nr_wire_fuzzer covers bytes an app on the device chooses;
# this covers bytes the NETWORK chooses, walked record by record inside netd.
if "$CXX" -fsanitize=fuzzer,address -std=c++17 -O1 -g "${INC[@]}" \
    "$ROOT/native/fuzz/nr_cname_fuzzer.cpp" -o "$WORK/fz_cname" 2> "$WORK/err.txt"; then
    if "$WORK/fz_cname" -runs=100000 -max_len=900 > "$WORK/f4.log" 2>&1; then
        ok "nr_cname_fuzzer: 100k runs clean"
    else
        bad "nr_cname_fuzzer crashed"; tail -20 "$WORK/f4.log" | sed 's/^/        /'
    fi
else
    bad "nr_cname_fuzzer failed to build"; head -12 "$WORK/err.txt" | sed 's/^/        /'
fi
```

---

## 3. Optional: back the setting up (`export/SettingsArchive.kt`)

`SettingsArchive` round-trips `response_mode` and `log_level`. It does not know
about `cname_uncloak`, so a restore silently leaves uncloaking off. If that
matters:

```kotlin
// write side, next to .put("response_mode", ...)
.put("cname_uncloak", ControlPage.cnameUncloak)
```

```kotlin
// read side, next to the response_mode branch
json.optBoolean("cname_uncloak", false).let { ControlPage.setCnameUncloak(it) }
```

Left out of Phase 5 on purpose: an archive that restores a *performance* setting
onto a different device is a decision the export owner should make, not this one.

---

## 4. Nothing needed from `Android.bp`, the manifest, sepolicy or privapp-permissions

- **App `Android.bp`** — no new dependency. `AdvancedFragment` uses
  `androidx.appcompat.widget.SwitchCompat` (already used by `SettingsFragment`)
  and `MaterialCardView`; `UserPolicy` uses `android.os.UserManager` from
  `android.jar`.
- **`AndroidManifest.xml` / `privapp-permissions-*.xml`** — no new permission.
  `UserManager.isManagedProfile()` asks about the calling user only. Enumerating
  other users would need `MANAGE_USERS`; Phase 5 refuses to request it and
  observes uids in the query log instead.
- **`rom/sepolicy`** — `NrCname.cpp` maps `control.bin` a second time inside
  netd, and `nullroute.te` already grants
  `allow netd nullroute_ctl_file:file { open read write getattr map lock };`.
  No new rule.
- **Resolver `Android.bp`** — handled by `apply.sh`, which now adds
  `"nullroute/NrCname.cpp"` to `libnetd_resolv`'s `srcs`.

---

## 5. Known gaps, stated rather than hidden

1. **No liveness probe for H5.** The app writes `cname_uncloak`; a resolver built
   from a tree where H5 was reported SKIPPED will read the byte and ignore it,
   and nothing on the device can currently tell the difference. The Advanced
   screen says so in as many words. The honest fix is a third `.invalid` probe —
   a name that only resolves differently when an answer is inspected — which
   belongs with `Probes.kt`, not here.
2. **Telemetry becomes evaluations, not lookups.** With uncloaking on, one lookup
   can add up to `NR_CNAME_MAX_LINKS + 1` to `q_total` and write that many ring
   records, because each link goes through the same `nr::hook()` H1 uses. That is
   what buys correct per-app policy on this path; the alternative was a second
   copy of the policy logic. Diagnostics may want to caption the counters when
   the byte is set.
3. **Unprintable names disable uncloaking for that answer.** `nr_wire_read_name()`
   declines a label byte with no presentation form, and the record walk cannot
   step over a name it could not read, so such an answer falls open. A server can
   use that to dodge uncloaking. The alternative — a second, length-only name
   walker beside the audited one — is a worse trade inside netd.
4. **`gethnamaddr.cpp`'s `getanswer()` is not hooked.** The legacy
   `gethostbyname` path gets no CNAME uncloaking. H2 still covers it at the
   question.
5. **`V_REDIRECT` on a CNAME target denies rather than sinkholes.** The redirect
   address belongs to the tracker's name, not to the first-party name the caller
   asked about, and rewriting an `addrinfo` list from a six-line hook site is not
   something that seam can do correctly.

---

## 6. Verification actually run (build host, `serverhive`)

Tree: `/serverhive1/sal/bestrom-a17/packages/modules/DnsResolver`
(note: **`/serverhive1`**, not `/serverhive`). Corpus: Hagezi `pro-onlydomains`,
224,039 lines, fetched to `/tmp/blprobe/pro.txt`.

```
##### 1. verify_source.sh (merge gate) #####
  OK    NrCname.cpp                      (compiles -Wall -Wextra -DNULLROUTE_ENABLED)
  OK    nrtest built
  OK    ALL OK  (31 passed, 0 failed)
  OK    nr_hostname_fuzzer: 40k runs clean
  OK    nr_index_fuzzer: 40k runs clean
  OK    nr_wire_fuzzer: 100k runs clean
  OK    applied
  OK    idempotent on re-run
  OK    --check detects applied state
  OK    H3 applied to res_send.cpp
  OK    getaddrinfo.cpp braces balanced
  OK    gethnamaddr.cpp braces balanced
  OK    res_send.cpp braces balanced
  OK    revert clean
  OK    revert restored every patched file byte-for-byte
VERIFY OK

##### 2. nr_cname_fuzzer #####
#2000000  DONE   cov: 181 ft: 632 corp: 233/6085b exec/s: 90909
Done 2000000 runs in 22 second(s)          (clean, -fsanitize=fuzzer,address)

##### 3. positive-path test #####
status=0 count=2 truncated=0
  link[0] = example.eulerian.net
  link[1] = edge.eulerian.net
long: status=0 count=8 truncated=1
short: status=2 count=0
query: status=4
POSITIVE TESTS OK

##### 4. apply.sh on a scratch DnsResolver #####
   H5 answer hook anchors on the getanswer(query.answer, ...) call in getaddrinfo.cpp
OK — patch is applied (H1 H2 H3 H4).
     H5 (CNAME uncloaking) applied.
```

The hunk as it lands in the real tree:

```cpp
        if (netcontext != nullptr &&
            nr::cnameBlocked(query.answer.data(),
                             (query.n > 0 &&
                              (size_t)query.n <= query.answer.size())
                                     ? (size_t)query.n
                                     : (size_t)0,
                             netcontext->uid)) {
            he = HOST_NOT_FOUND;
            continue;
        }
        addrinfo* ai = getanswer(query.answer, query.n, query.name, query.qtype, pai, &he);
```

The length is clamped to `answer.size()`, not merely to zero: the one thing the
parser cannot defend itself against is a length longer than the allocation it was
pointed at, and the hook site is where that can be settled for a compare.

`apply.sh` also now asserts that `getaddrinfo.cpp` and `gethnamaddr.cpp` carry no
**nested** `NULLROUTE-BEGIN/END` pair. `--revert` strips markers with a single
boolean, so a nested fence would leave a stray marker and revert would stop being
byte-exact — that was a real hazard once getaddrinfo.cpp started carrying two
fenced includes, and it is now a staged-verification failure rather than a
silent one.
