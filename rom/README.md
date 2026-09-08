# Nullroute — ROM integration checklist

Everything in `rom/` is *configuration that lives outside this repository once
integrated*. The Soong modules in `../Android.bp` install most of it
automatically; the SELinux fragments and the two `vendor/` edits are the parts a
human has to place by hand, because they append to files the ROM already owns.

Follow this in order. Every path is relative to the tree root
(`/serverhive/sal/bestrom-a17`). **NEW** = create, **MOD** = modify, **APPEND** =
add to the end of an existing file.

> The riskiest thing in this project is that a broken integration and a working
> one look identical from userspace. Step 9 and step 10 are not optional
> paperwork — they are the only two places where that distinction becomes
> visible.

---

## 0. Prerequisites inside this repository

`../Android.bp` declares modules for the whole repo, so `mka Nullroute` needs
these to exist. They are owned by other parts of the project, not by `rom/`:

| Path | Produced by |
|---|---|
| `native/NrMap.cpp` | resolver-side mmap / validate / RCU publish |
| `native/NrRingReader.cpp` `native/NrCtlCore.cpp` | app-side native |
| `native/nrctl.cpp` `native/nullroute_seed.cpp` | CLI + seeder |
| `native/jni_bridge.cpp` | JNI |
| `native/fuzz/nr_hostname_fuzzer.cpp` `nr_index_fuzzer.cpp` | merge gate (F7) |
| `app/src/main/AndroidManifest.xml`, `app/src/main/res/**`, `app/src/main/java/**` | the app |
| `prebuilt/hosts` | `tools/gen_l0_hosts.py` |
| `prebuilt/baseline.domains.xz` + `.sha256` | `tools/gen_baseline.py` — generated; regenerate together |
| `prebuilt/neverblock.txt` `antifraud.txt` `attribution.txt` | curated |
| `prebuilt/profiles/{lite,balanced,aggressive}.txt` | curated |
| `resolver-patch/**` | the four hooks + `NrFilter` |

Soong resolves `src:`/`srcs:` at analysis time, so a single missing file in that
table fails **every** `mka` in this repo, not just the module that names it.

`baseline.domains.xz` and `baseline.domains.xz.sha256` are one artefact in two
files and both are installed to `/system_ext/etc/nullroute/`. `nullroute_seed`
verifies the baseline **only if the sidecar is present** — ship the `.xz` alone
and the integrity check does not fail, it does not happen, and nothing says so.

`native/NrCtlCore.cpp`, not `NrCtl.cpp`: `native/NrCtl.cpp` and `native/nrctl.cpp`
differ only in case and cannot coexist in a checkout on a case-insensitive
filesystem. The header is still `NrCtl.h` — nothing collides with that.

`native/NrStrings.cpp` (SPEC §5, the `NR_SEC_STR` front-coded rule-text blob) is
deliberately **absent** from `libnrcore`'s `srcs` until the file exists. Nothing
in `native/include` declares anything from it today.

`native/include/*.h`, `native/NrCanon.cpp`, `native/NrQuery.cpp`,
`native/NrBuilder.cpp` and `native/nrtest.cpp` already exist and are the proven
core — 31/31 semantic tests against the real 224k corpus. Do not modify them.

---

## 1. Re-verify the ground truth before touching anything

The design depends on facts about *this* tree. Re-run these after every sync;
they take a minute and each one can invalidate a decision.

```bash
# The resolver ships inside com.android.tethering here, NOT com.android.resolv.
grep -n 'apex_available' -A3 packages/modules/DnsResolver/Android.bp

# No prebuilt mainline APEX anywhere.
grep -rn 'resolv\|tethering' --include='*.mk' vendor/ device/ | grep -i apex
find prebuilts -name '*resolv*.apex' -o -name '*tethering*.apex' -o \
                -name '*resolv*.capex' -o -name '*tethering*.capex'

# The hook sites. H1 is the definition that carries the BODY, not the thin
# forwarding overload — hook whichever one that is in this tree.
grep -n '^int resolv_getaddrinfo'  packages/modules/DnsResolver/getaddrinfo.cpp
grep -n 'files_getaddrinfo'        packages/modules/DnsResolver/getaddrinfo.cpp
grep -n 'resolv_gethostbyname'     packages/modules/DnsResolver/gethnamaddr.cpp
grep -n 'uid'                      packages/modules/DnsResolver/include/netd_resolv/resolv.h

# The hosts path is a single hardcoded define.
sed -n '73p' bionic/libc/include/netdb.h
```

**Add the `com.android.tethering` payload and APK-v3 signing keys to the BestROM
release-key checklist today**, next to the platform key. Getting them wrong
bootloops `apexd` with *"public key doesn't match the pre-installed one"*. That
is a device-won't-boot problem, not a debugging problem, and this project has
prior art for exactly that failure class.

---

## 2. Drop the repository into the tree

```
packages/apps/Nullroute/          <- this repository, verbatim
```

Nothing else moves. `rom/` and `tools/` ride along inside it; the steps below
copy or append from there.

---

## 3. Phase 0 — the baked floor (ships alone, before any of the rest)

This is the layer that still works when the hook is dead, the index is corrupt,
the app is uninstalled, or the device is in safe mode.

1. **NEW** generate the baked data. Both scripts default to writing into
   `packages/apps/Nullroute/prebuilt/`, so they can be run from anywhere in the
   tree:
   ```bash
   python3 packages/apps/Nullroute/tools/gen_l0_hosts.py   # -> prebuilt/hosts
   python3 packages/apps/Nullroute/tools/gen_baseline.py   # -> prebuilt/baseline.domains.xz
   ```
   `gen_l0_hosts.py` emits the `127.0.0.8 hosts-probe.nullroute.invalid` line
   that health signal #1 and `ci_verify_image.sh` both key on. Only MIT /
   CC BY 3.0 / Unlicense material goes into either file — the GPL-3.0 and
   MPL-2.0 lists are fetched and compiled on device at first sync.
2. `nullroute_etc_hosts` in `packages/apps/Nullroute/Android.bp` already declares
   `overrides: ["etc_hosts"]` against `system/core/rootdir/Android.bp:175`.
3. **NEW** copy `packages/apps/Nullroute/rom/nullroute.mk` to
   `vendor/bestrom/config/nullroute.mk`.
4. **MOD** `vendor/lineage/config/common.mk` — add exactly one line:
   ```make
   include vendor/bestrom/config/nullroute.mk
   ```
   One line means one merge conflict per Lineage rebase instead of N.
5. **MOD** `vendor/lineage/prebuilt/common/bin/50-lineage.sh` — delete the
   `etc/hosts` entry from the addon.d survival list:
   ```bash
   git -C vendor/lineage am < packages/apps/Nullroute/rom/50-lineage.sh.patch
   ```
   Otherwise the first OTA restores the pre-OTA hosts file over the freshly
   built one — and it does so for the *next* build, so everything you check
   today passes. It is also invisible afterwards: the old file still answers
   `hosts-probe.nullroute.invalid`, so even the L0 liveness probe reports
   healthy while the floor quietly stops improving.
6. **Prove the override wins across the partition boundary** (Spike 6):
   ```bash
   mka nullroute_etc_hosts && wc -l out/target/product/peridot/system/etc/hosts
   ```
   Stock is 2 lines; ours is ~2,000. If you still see 2, use the
   `PRODUCT_COPY_FILES` fallback written out in `rom/nullroute.mk` and drop
   `nullroute_etc_hosts` from `PRODUCT_PACKAGES` so the two cannot fight.

`system/core/rootdir/etc/hosts` is **never edited in place**. We override the
module, so a Lineage rebase never conflicts there.

---

## 4. Shared headers and the matcher

Nothing to place — `packages/apps/Nullroute/Android.bp` declares
`libnrformat_headers` and `libnrfilter`, both `apex_available` to
`com.android.tethering` and `min_sdk_version: "30"`.

```bash
mka libnrformat_headers libnrfilter     # seconds
```

There is deliberately **no copy** of `NrIndex.h` under
`packages/modules/DnsResolver/`. Two "byte-identical" headers drift the first
time one repo is rebased and not the other, and the failure mode is a silently
mis-parsed index inside netd (F10).

---

## 5. Resolver fork — `packages/modules/DnsResolver/`

7. **NEW** `packages/modules/DnsResolver/nullroute/` ← copy
   `NrFilter.{h,cpp}`, `nr_hook.h`, `NrRingWriter.cpp` from
   `packages/apps/Nullroute/resolver-patch/nullroute/`.
8. **MOD** `packages/modules/DnsResolver/Android.bp`:
   ```soong
   srcs: [ /* existing */, "nullroute/NrFilter.cpp", "nullroute/NrRingWriter.cpp" ],
   header_libs: ["libnrformat_headers"],
   whole_static_libs: ["libnrfilter"],
   cflags: [ /* existing */, "-DNULLROUTE_ENABLED" ],
   ```
9. **MOD** `getaddrinfo.cpp` — **H1**, first statement of the
   `resolv_getaddrinfo()` definition that carries the body.
10. **MOD** `gethnamaddr.cpp` — **H2**, the `_hf_gethtbyname2` / `dns_gethtbyname`
    path (~line 437). /e/OS forgot this one; legacy `gethostbyname()` callers
    reach it.
11. **MOD** `getaddrinfo.cpp` — **H4**, first statement of `files_getaddrinfo()`:
    ```cpp
    if (nr::hostsLayerSuperseded()) return false;
    ```
    Two lines. This is what makes L0's linear `fgets` scan cost nothing on a
    healthy device while remaining a real floor on a broken one.
12. **MOD** `DnsProxyListener.cpp` — **H3**, Phase 3, the `ResNSendCommand`
    handler (not `res_nsend()` — hooking the external entry point avoids
    double-evaluating the resolver's own internal queries).
13. Keep all of this as a topic branch with `git rerere` enabled. Budget ~1 day
    per Android major.

---

## 6. SELinux — `device/lineage/sepolicy/common/private/`

That directory is appended to `SYSTEM_EXT_{PUBLIC,PRIVATE}_SEPOLICY_DIRS` by
`device/lineage/sepolicy/common/sepolicy.mk`, which `build/make/core/config.mk`
includes automatically. A system app domain is a `coredomain` and **must** go
here — putting it in `BOARD_VENDOR_SEPOLICY_DIRS` produces a policy that builds
and then denies everything at runtime.

**Write the policy before the code.**

14. **NEW** copy, unchanged:
    ```
    packages/apps/Nullroute/rom/sepolicy/nullroute.te
    packages/apps/Nullroute/rom/sepolicy/nullroute_app.te
    packages/apps/Nullroute/rom/sepolicy/nullroute_seed.te
    packages/apps/Nullroute/rom/sepolicy/nrctl.te
        -> device/lineage/sepolicy/common/private/
    ```
15. **APPEND** `rom/sepolicy/file_contexts.frag`
    → `device/lineage/sepolicy/common/private/file_contexts`
16. **APPEND** `rom/sepolicy/property_contexts.frag`
    → `device/lineage/sepolicy/common/private/property_contexts`
17. **APPEND** `rom/sepolicy/property.frag`
    → `device/lineage/sepolicy/common/private/property.te`
18. **INSERT** `rom/sepolicy/seapp_contexts.frag`
    → `device/lineage/sepolicy/common/private/seapp_contexts`,
    **BEFORE any broader `isPrivApp=true` catch-all.** If a catch-all is
    evaluated first the app lands in `priv_app`, every `nullroute_*` grant
    applies to a domain the app is never in, and netd blocks nothing with no
    denial to explain why. `tools/ci_verify_image.sh` asserts the ordering.
19. ```bash
    mka selinux_policy
    ```
    **must pass before you compile a line of app code.**

### What is in there, and what must never be

Four types, because one was defect **F1**:

| Type | Path | app | netd |
|---|---|---|---|
| `nullroute_index_file` | `/data/misc/nullroute/index` | rw | ro + **map** |
| `nullroute_ctl_file` | `/data/misc/nullroute/ctl` | rw + **map** | rw + **map** |
| `nullroute_log_file` | `/data/misc/nullroute/log` | ro + **map** | rw + **map** |
| `nullroute_data_file` | `/data/misc/nullroute/priv` | rw | **nothing** |

`map` is spelled out on every file rule even where the `r_`/`w_` macros already
include it. F1 was that permission going missing on the control page: `open()`
succeeded, `mmap(PROT_WRITE)` returned `EACCES`, and pause plus every per-app
policy write was discarded in silence.

Two rules that must never appear anywhere in this policy:

* **`mounton` on `system_file_type`** — `system/sepolicy/private/domain.te`
  neverallows every domain except `init`, and `sepolicy_tests.py::TestSystemTypeViolations`
  forbids relabelling the target to escape it. It is also pointless: L0 is a
  build-time prebuilt and L1 lives in `/data`.
* **`dnsresolver_service:service_manager find`** — neverallow-guarded, and
  `setResolverConfiguration()` is behind `NETWORK_STACK`/`MAINLINE_NETWORK_STACK`
  anyway. The consequence we accept is that we cannot call `flushNetworkCache()`
  after an un-block, which is why every "Allow" in the UI also offers
  "Force stop app".

Both prohibitions are commented in `rom/sepolicy/nullroute.te` at the point
where a future maintainer would be tempted.

---

## 7. init

20. `init.nullroute.rc` installs itself to `/system_ext/etc/init/` via
    `prebuilt_etc`. init parses that directory unconditionally, so **no
    device-tree change and no `vendor_init` edit is needed.**

It creates the four state dirs `0770 system misc` at `post-fs-data`, runs
`restorecon_recursive` (an OTA that first introduces these types finds the dirs
already present and would otherwise not relabel them), and starts
`nullroute_seed`.

Two details that are load-bearing:

* `group misc system` — **misc first**. init makes the first group the primary
  gid, and the primary gid is what the kernel stamps on files the process
  creates. With `system misc` the seeder would create `control.bin` as
  `system:system` and the app could never write it.
* `start`, not `exec_start`. Boot is never gated on the seeder. It costs
  200–400 ms only on the first boot after a flash or OTA, and the resolver
  tolerates a missing index with a lazy-open backoff and a fail-**open** verdict.
  `class core` runs before `class main` (netd), so in practice the index is live
  before the first query.

`control.bin` and `ring.bin` are pre-created by the seeder at the right size,
mode and ownership. **netd only ever opens files that already exist** — it runs
as root and would otherwise create root-owned files the app could never write.

---

## 8. App packaging and the DAC problem

21. Nothing to place. `packages/apps/Nullroute/Android.bp` builds the app as
    `sdk_version: "system_current"`, `certificate: "platform"`,
    `privileged: true`, `system_ext_specific: true`, `optimize: { enabled: false }`,
    matching the sibling `packages/apps/Freezer`.

    Set the baked-in `versionCode` to **10000** so out-of-band `/data/app`
    updates signed with the same platform key have headroom.

    **Do not add `android:sharedUserId="android.uid.system"`.** It is deprecated
    and permanently un-migratable, it collapses the app into the system UID's
    sandbox — so a bug in the blocklist parser, which chews on hundreds of
    thousands of lines of internet-sourced text, becomes a system-UID compromise
    — and it interferes with the `/data/app` sideload-update path.

22. **The DAC problem, solved without `sharedUserId`.** `/data/misc` is
    `01771 system:misc`; nothing outside uid system, uid root or gid `misc`
    (AID 9998) can traverse it. `rom/nullroute-gid.xml` maps
    `com.bestrom.nullroute.permission.STATE` → gid `misc` through the same
    `SystemConfig` mechanism that maps `INTERNET` → `inet`.

    Read the mode carefully: `/data/misc` at `01771` gives **other** execute, so
    the parent is traversable by anything. The gate is the `0770` on the four
    leaf dirs. `rom/nullroute-gid.xml` is what gets past it.

    The app must **also** declare that permission itself with
    `android:protectionLevel="signature"` and `<uses-permission>` it, so the
    permission exists regardless.

    That same file carries
    `<assign-permission name="com.bestrom.nullroute.permission.CTL" uid="shell"/>`.
    Without it `nrctl pause|resume|update` from a non-root `adb shell` is
    silently dropped: uid 0 and uid 1000 short-circuit
    `checkComponentPermission()`, uid 2000 does not, and `am` still reports
    `result=0`.

    Verify (Spike 2):
    ```bash
    adb shell cat /proc/$(adb shell pidof com.bestrom.nullroute)/status | grep Groups
    ```
    must list `9998`. If it does not, the documented fallback is to relax the
    four state dirs to `0775` in `init.nullroute.rc` and rely on SELinux alone —
    safe here specifically because `/data/misc` is already unreachable by
    `untrusted_app` and MAC is enforcing on user builds.

23. ⚠ **`rom/privapp-permissions-com.bestrom.nullroute.xml` is frozen at image
    build time.** Under `ro.control_privapp_permissions=enforce` (every user
    build) a `signature|privileged` permission present in the manifest but
    missing from that file **aborts boot**. Over-listing is inert; under-listing
    bricks; and it cannot be shipped out of band. Enumerate everything the app
    will ever need *now* — the file is annotated by phase for exactly that
    reason.

---

## 9. Product wiring

24. Already done in step 3 (`vendor/bestrom/config/nullroute.mk` +
    the one `include` line). Re-read the guards in that file:

    * **Guard 1 (F11)** errors out if any prebuilt resolv **or tethering** APEX
      appears in `PRODUCT_PACKAGES` or `PRODUCT_COPY_FILES`. In this tree the
      resolver ships inside `com.android.tethering`, so a prebuilt *tethering*
      APEX is just as fatal as a prebuilt resolv one — and the failure is
      invisible: everything else keeps working and the device blocks nothing.
      The guard only sees what is declared by the time it is included, which is
      why step 10 re-asserts it against the finished image.
    * **Guard 2** ships
      `persist.device_config.tethering.close_quic_connection=-1` regardless of
      which blocking layer is enabled. Not our bug; Google marked it Won't Fix.

---

## 10. Build and verify the image

```bash
mka libnrformat_headers libnrfilter          # header + matcher, seconds
mka Nullroute nrctl nullroute_seed -j8       # Soong / aapt2 / manifest errors, ~2 min
mka selinux_policy                           # neverallow violations
atest nr_hostname_fuzzer nr_index_fuzzer     # merge gate
mka bacon
packages/apps/Nullroute/tools/ci_verify_image.sh
```

`ci_verify_image.sh` is the thing that makes an invisible failure loud. It
asserts, against the built image:

* the shipping `com.android.tethering` APEX actually contains the Nullroute
  markers — by scanning the `.apex` itself where possible, since `apex_payload.img`
  is *stored* rather than deflated inside the zip;
* no `com.google.android.*` resolv/tethering APEX landed;
* the L0 hosts override won, and carries ~2,000 lines rather than a stub;
* the APK, all five XMLs, `init.nullroute.rc`, both binaries and all the baked
  list data are installed at the right paths;
* all four SELinux types, both property types and the `seapp_contexts` entry are
  in the built policy — **and that the `seapp_contexts` entry precedes any
  `isPrivApp=true` catch-all**;
* `50-lineage.sh` no longer restores `etc/hosts`.

It exits non-zero on any failure and prints every problem, not just the first.

> Note: `strings … | grep NRDX` alone is **not** a sufficient probe. `NR_MAGIC`
> is a numeric constant, so on arm64 it is materialised as a `movz`/`movk`
> immediate pair and the four bytes may not be a contiguous printable run in a
> correctly patched binary. The script keys on the string literals the patch
> introduces (`/data/misc/nullroute/…`, `sys.nullroute.filter`) and reports
> `NRDX` only as a bonus.

---

## 11. Verify on the device

A green `ci_verify_image.sh` proves the artefacts are on the image. It does
**not** prove the hook fires. Only these do:

```bash
# Spike 1 — is our patched resolver the one that is running?
adb shell grep libnetd_resolv /proc/$(adb shell pidof netd)/maps
adb shell pm list packages --apex-only | grep tethering

# Spike 3 — did the SELinux map grant land, or is the filter failing open?
adb shell getprop sys.nullroute.filter       # ok:<gen>   NOT nomap:13
adb shell getprop sys.nullroute.seed
adb shell dmesg | grep 'avc.*nullroute'      # must be empty

# The dual .invalid liveness probe (health signal #1 of three)
adb shell getent hosts idx-probe.nullroute.invalid    # 127.0.0.7  => L1 live
adb shell getent hosts hosts-probe.nullroute.invalid  # 127.0.0.8  => L0 intact

# Spike 2 — did the gid mapping take?
adb shell cat /proc/$(adb shell pidof com.bestrom.nullroute)/status | grep Groups
```

Bring the first device up with `setenforce 0` once, to separate policy problems
from code problems, then put it back and re-run. `nomap:13` is `EACCES` and
means the `map` permission did not land.

**Retire this on day one, before any app code exists.** Build a throwaway image
containing only the four hooks, `libnrfilter`, the sepolicy, `init.nullroute.rc`,
`nullroute_seed`, and a hand-written index with one rule plus the `idx-probe`
redirect. If those four commands come back clean, the entire architecture is
de-risked and everything after it is ordinary application work.

---

## 12. Turning it off

In increasing order of severity, none of which needs a rebuild:

| Lever | Effect |
|---|---|
| `setprop persist.sys.nullroute.mode 1` | pause — one byte in the control page |
| `setprop persist.sys.nullroute.kill 1` | resolver returns PASS for everything, H4 stops skipping the L0 scan; honoured with no app process involved |
| `setprop ro.nullroute.enabled false` *(build.prop)* | whole feature off at the next boot |
| drop `-DNULLROUTE_ENABLED` from the resolver's `cflags` | hooks compiled out entirely — use this when bisecting a netd crash rather than a filtering bug |
| remove `include vendor/bestrom/config/nullroute.mk` | nothing ships |

The boot-loop breaker is automatic: `nullroute_seed` arms
`persist.sys.nullroute.fail_streak` at every `post-fs-data` and the app clears it
after 120 s of healthy uptime. At 3 the seeder quarantines `current.nrdx` and
sets `kill=1`, so the third consecutive bad boot comes up clean. This matters
because netd's init stanza carries `onrestart restart zygote` — a matcher crash
is a UI loop, not a network outage (F7).

---

## 13. Every file in `rom/`, and where it goes

| Repository path | Destination | Placed by |
|---|---|---|
| `rom/privapp-permissions-com.bestrom.nullroute.xml` | `/system_ext/etc/permissions/` | `prebuilt_etc` |
| `rom/nullroute-gid.xml` | `/system_ext/etc/permissions/` | `prebuilt_etc` |
| `rom/preinstalled-packages-platform-nullroute.xml` | `/system_ext/etc/sysconfig/` | `prebuilt_etc` |
| `rom/sysconfig-nullroute.xml` | `/system_ext/etc/sysconfig/` | `prebuilt_etc` |
| `rom/default-permissions-nullroute.xml` | `/system_ext/etc/default-permissions/` | `prebuilt_etc` |
| `rom/init.nullroute.rc` | `/system_ext/etc/init/` | `prebuilt_etc` |
| `rom/sepolicy/nullroute.te` | `device/lineage/sepolicy/common/private/` | **by hand** |
| `rom/sepolicy/nullroute_app.te` | `device/lineage/sepolicy/common/private/` | **by hand** |
| `rom/sepolicy/nullroute_seed.te` | `device/lineage/sepolicy/common/private/` | **by hand** |
| `rom/sepolicy/nrctl.te` | `device/lineage/sepolicy/common/private/` | **by hand** |
| `rom/sepolicy/file_contexts.frag` | append to `…/private/file_contexts` | **by hand** |
| `rom/sepolicy/seapp_contexts.frag` | insert into `…/private/seapp_contexts`, **before any catch-all** | **by hand** |
| `rom/sepolicy/property_contexts.frag` | append to `…/private/property_contexts` | **by hand** |
| `rom/sepolicy/property.frag` | append to `…/private/property.te` | **by hand** |
| `rom/nullroute.mk` | `vendor/bestrom/config/nullroute.mk` | **by hand** |
| `rom/50-lineage.sh.patch` | `git -C vendor/lineage am` | **by hand** |
| — | one `include` line in `vendor/lineage/config/common.mk` | **by hand** |

Nothing in `rom/` is read at runtime from this repository — every path above is
either installed by Soong or copied into the ROM's own trees. The rows marked
**by hand** are the ones a fresh `repo sync` of `device/lineage` or
`vendor/lineage` silently reverts, so re-check them after every sync; the
`prebuilt_etc` rows look after themselves.
