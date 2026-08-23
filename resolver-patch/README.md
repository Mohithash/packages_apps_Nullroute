# Nullroute resolver patch

Everything that goes into `packages/modules/DnsResolver` to make L1 — the
resolver-native filter — real. Four small hunks plus one self-contained
directory, and nothing in it depends on resolver internals beyond
`android_net_context->uid` and `explore_numeric()`.

```
nullroute/NrFilter.h        process-wide singleton, no lock on the hot path
nullroute/NrFilter.cpp      generation watch, kill-switch cache, health property, self-disable
nullroute/nr_hook.h         SIGNATURE-AGNOSTIC entry points — the whole rebase strategy
nullroute/NrRingWriter.cpp  MPSC query-log producer
apply.sh                    idempotent, all-or-nothing patcher
```

The matcher itself is **not** here. `nr_evaluate()` lives in
`native/NrQuery.cpp` and is linked in through `libnrfilter`, so the live filter,
`nrctl query`, the Rules-screen preview and the build canary are byte-for-byte
the same code. There is deliberately no copied header either: the on-disk format
comes from `libnrformat_headers`, because two "identical" copies drift the first
time one repo is rebased and the other is not, and the failure mode is a
silently mis-parsed index inside netd.

---

## 1. Applying

```bash
cd $ANDROID_BUILD_TOP
packages/apps/Nullroute/resolver-patch/apply.sh          # apply (idempotent)
packages/apps/Nullroute/resolver-patch/apply.sh --check  # is it applied?
packages/apps/Nullroute/resolver-patch/apply.sh --revert # remove it cleanly
```

`apply.sh` locates each hook site by parsing the tree rather than by matching
diff context, because `resolv_getaddrinfo()` exists more than once in
`getaddrinfo.cpp` — a declaration, a thin forwarding overload, and the
definition that carries the body. A context patch that lands in the forwarder
produces a resolver that builds, boots and filters nothing. The script
identifies the body-carrying definition, asserts that every parameter the hunk
references (`hostname`, `servname`, `hints`, `netcontext`, `res`) is really in
that signature, and refuses to guess when it cannot. It stages every edit in a
temp directory and verifies the result there; the tree is not touched unless all
four hunks are known good.

### What it changes

| File | Change |
|---|---|
| `Android.bp` | `libnetd_resolv`: `srcs` += the two .cpp, `header_libs` += `libnrformat_headers`, `whole_static_libs` += `libnrfilter`, `cflags` += `-DNULLROUTE_ENABLED` |
| `getaddrinfo.cpp` | **H1** at the top of `resolv_getaddrinfo()`'s real body; **H4** as the first statement of `files_getaddrinfo()` |
| `gethnamaddr.cpp` | **H2** at the top of `resolv_gethostbyname()` |

Every insertion is fenced with `// NULLROUTE-BEGIN` / `// NULLROUTE-END`, which
is what makes re-running a no-op and `--revert` exact. Keep the whole thing as a
topic branch with `git rerere` on; budget about a day per Android major.

`-DNULLROUTE_ENABLED` is the bisect switch. Drop it and all four hunks fold to
constants, `libnrfilter` is never called, and the resolver is stock.

---

## 2. Verification — this is the riskiest step in the project

Landing the patch such that it ships inside the **activated** APEX, and stays
there, is the one thing that can fail while looking completely healthy. If the
APEX is rebuilt without `libnrfilter`, or the device activates a stale or
prebuilt copy, then the app, the UI, the index, the sepolicy and the canary all
work flawlessly and **block nothing**. Success and failure are
indistinguishable from userspace unless you go and look.

Run every command below. Not the ones that look interesting — all of them.

### 2.1 Build time, before you flash

```bash
OUT=out/target/product/peridot
SO=$(find "$OUT" -path '*com.android.tethering*' -name libnetd_resolv.so | head -1)
echo "$SO"                          # must be non-empty
strings "$SO" | grep -c NRDX        # must be >= 1
strings "$SO" | grep nullroute       # NrFilter's log strings and the three paths
```

`grep -c NRDX` is the load-bearing check: `NR_MAGIC` is compiled into
`nr_index_validate()`, so its absence means the filter is not in this .so no
matter what the build log said. This is Guard 1 in `tools/ci_verify_image.sh` —
keep it a CI gate, not a habit.

### 2.2 On device — does the patched resolver actually run?

```bash
adb root                                     # userdebug; otherwise use su -c
adb shell 'pm list packages --apex-only' | grep -E 'tethering|resolv'
adb shell 'ls -l /apex/com.android.tethering/lib64/libnetd_resolv.so'
adb shell 'grep libnetd_resolv /proc/$(pidof netd)/maps'
adb shell 'strings /apex/com.android.tethering/lib64/libnetd_resolv.so | grep -c NRDX'
```

The `maps` line proves netd mapped that exact file; the `strings` count proves
that file contains the filter. Either alone can lie — a device can activate a
different APEX than the one you built.

### 2.3 On device — is the filter healthy?

```bash
adb shell getprop sys.nullroute.filter
adb logcat -d -s NullrouteFilter
```

| Value | Meaning | What to do |
|---|---|---|
| `ok:<gen>` | Index generation `<gen>` mapped and validated. | Nothing. This is the good state. |
| `nomap:13` | `EACCES`. Almost always the missing SELinux **`map`** permission: `open()` succeeded and `mmap()` failed. | §4 below. |
| `nomap:2` | `ENOENT`. `nullroute_seed` has not published yet, or `/data/misc/nullroute` was never created. | `adb shell ls -lZ /data/misc/nullroute/index` |
| `badhdr:<field>` | The index mapped and was rejected. Field is one of `short magic fmtver labels section cap seclen load notreg size`. | The builder wrote a bad artefact; check the app's promotion path. |
| `off` | `NrControl::mode` is PAUSED or OFF. Not a fault. | The user paused it, or the QS tile is off. |
| `killed` | `persist.sys.nullroute.kill` is set. | `setprop persist.sys.nullroute.kill 0` |
| `disabled` | Three hard faults; the filter switched itself off for this boot. | Read the `NullrouteFilter` logcat lines for the first fault — that one is the real cause. |
| *(empty)* | Either **no hooked resolver ever ran a query**, or the `set_prop` was refused. | Read logcat FIRST. A refused set logs `could not publish sys.nullroute.filter=…` and means the filter is running fine and only the policy is missing (§4). Silence there means the hook never ran — go back to §2.2. |

`sys.nullroute.filter` deliberately does **not** travel through `control.bin`.
A counter living inside the page whose mapping is the single most likely thing
to fail cannot report its own death, which is why the health signal is a
property and a logcat tag and not a field in the shared page.

### 2.4 On device — the dual liveness probe

This is the only check that proves the hook fired **and** the index mapped
**and** the redirect table parsed, end to end, through the real code path.

```bash
adb shell getent hosts idx-probe.nullroute.invalid      # expect 127.0.0.7
adb shell getent hosts hosts-probe.nullroute.invalid    # expect 127.0.0.8
```

They are *redirects*, not blocks, precisely because the default block response
is `EAI_NONAME` — which is indistinguishable from a genuinely unresolvable
`.invalid` name, and would therefore "pass" on a device where nothing works.

| Probe A (index) | Probe B (hosts) | Reading |
|---|---|---|
| `127.0.0.7` | `127.0.0.8` | **Protected.** Both layers live. |
| fails | `127.0.0.8` | **L1 is not running.** Everything in §2.2 and §2.3 applies. |
| `127.0.0.7` | fails | L1 fine, the built-in hosts override did not win the build. Non-urgent. |
| fails | fails | Nothing is filtering. |

Both of those commands, and `ping`, reach the resolver through `getaddrinfo` on
current toybox — that is **H1**. There is no dependable shell-only trigger for
**H2**, the legacy `gethostbyname()` path (the one /e/OS forgot), so verify that
hunk two other ways: `apply.sh --check` proves it is in the source, and the
app's Diagnostics screen calls `gethostbyname()` directly and reports what came
back. Do not assume a passing probe covers both hunks — a patch that landed in
only one of the two files still passes everything above.

```bash
adb shell ping -c1 idx-probe.nullroute.invalid   # H1 again, a different caller
```

`.invalid` is deliberately absent from the matcher's skip-suffix list so these
names can reach the index at all, and `hostsLayerSuperseded()` deliberately
returns `false` for anything under `.nullroute.invalid` so probe B keeps
reaching the L0 hosts file after L1 supersedes it.

Check loopback too — it goes through the same file, and H4 is what could break
it:

```bash
adb shell getent hosts localhost        # expect 127.0.0.1
adb shell getent hosts ip6-localhost    # expect ::1
```

Both are single-label names, which `hostsLayerSuperseded()` never supersedes.
If either of these fails, H4 is over-reaching and nothing else in this file
matters until it is fixed — half the apps on the device use `localhost`.

### 2.5 On device — is it actually blocking?

```bash
adb shell getent hosts google-analytics.com   # expect: no output (EAI_NONAME)
adb shell getent hosts github.com             # expect: a real address
adb shell 'cat /proc/$(pidof netd)/maps | grep nullroute'   # index + ctl + ring mappings
```

Pick the blocked name from the list you actually compiled. HaGeZi Pro
intentionally does **not** contain `doubleclick.net`, `googleadservices.com` or
`graph.facebook.com` as apexes — testing with those and concluding the filter is
broken is the single most common false bug report this project will get.

### 2.6 SELinux denials

```bash
adb shell 'dmesg | grep -i "avc.*nullroute"'
adb shell 'logcat -d -b events | grep -i avc'
```

Bring the device up once with `setenforce 0` when you are triaging, to separate
a policy problem from a code problem. A filter that fails open under enforcing
and works under permissive is a missing rule, every time.

---

## 3. What the resolver side guarantees, and what it does not

**Fail-open is absolute.** There is no path through `NrFilter` that can make a
DNS lookup fail because Nullroute has a problem. A missing index, a corrupt
index, a denied `mmap`, a control page that will not map, a ring that will not
map, a mapping pool momentarily exhausted — every one of them returns `V_PASS`
and lets the query proceed. netd's init stanza carries
`onrestart restart zygote`, so a crash or a hang here is a UI/boot loop, not
merely a network outage; that asymmetry decides every trade-off in this
directory.

**The hot path** takes no lock, makes no syscall, allocates nothing and has no
unbounded loop. The kill switch is a cached `__system_property_serial()` — one
relaxed load in a mapping netd already has — never a property *read* per query.
(That is the correction to the `GetIntProperty`-per-call shape.) The generation
watch is one acquire-load of a cache line that also carries `config_epoch`, so a
promotion and a mode toggle both cost the same single compare.

**Publishing is RCU-style.** The publisher swaps a pointer and retires the old
mapping; the old mapping is only unmapped on the *next* slow path, once its
refcount has drained. `NrMapping` control blocks come from a fixed static pool
and are recycled rather than freed, so a reader that loses the publish race
touches valid memory, sees it is no longer current, and drops it. No query in
flight ever loses its mapping.

**Self-disable.** Three *hard* faults and the filter switches itself off for the
rest of the boot and records why. `ENOENT` is not a hard fault — at first boot
netd (`class main`) can beat `nullroute_seed` (`class core`) to the first query,
and spending the three strikes on that race would permanently disable the filter
on a healthy device. Soft failures back off 1 s → 60 s instead.

### Details other components need to agree with

- **State property values**, exhaustively: `ok:<gen>`, `nomap:<errno>`,
  `badhdr:<field>`, `killed`, `off`, `disabled`. `off` covers both PAUSED and
  OFF — the app wrote the mode, so it does not need the resolver to tell it
  which.
- **Counters.** `q_total` counts every evaluated query; `q_passed` counts
  `V_PASS`; `q_blocked` counts `V_BLOCK`. `V_REDIRECT` is in neither, so the
  periodic liveness probe does not inflate "blocked today".
- **`ring_drops`** counts every record that could not be written at all — ring
  not mapped, open backing off, another thread mid-open, logging permanently
  disabled. It does **not** count overwrite-oldest loss; the consumer detects
  that from jumps in `head`. Treat any non-zero value as "this log is
  incomplete" and say so in the UI, because after a permanent disable the
  counter climbs once per query that would have been logged.
- **Ring header**: magic `0x4752524E` ("NRRG"), version 1, records start at
  `sizeof(NrRingHeader)` = 4096. netd stamps the header itself when it finds the
  file zero-filled, and permanently disables logging if the header is somebody
  else's.
- **Record name truncation keeps the TAIL**, advanced to the next label
  boundary, with `flags` bit0 set. The matched rule is always a *suffix* of the
  queried name, so the tail is the part that explains the verdict. Consumers
  should render a leading ellipsis.
- **Sinkhole is IPv4-only.** `NR_RESP_SINKHOLE` is rewritten into a redirect to
  `0.0.0.0` inside `evaluate()`, so hook sites only ever handle `V_BLOCK` and
  `V_REDIRECT`. On an IPv6-only query the numeric explore finds no matching
  family and the lookup degrades to the default block. It stays a documented
  compat trap and never a default: Linux treats `connect()` to `0.0.0.0` as
  `INADDR_LOOPBACK`, so the app connects to itself rather than failing.
- **The resolver attempts each `want_generation` exactly once.** If the file at
  `current.nrdx` carries a different generation than `want_generation`
  advertises, the resolver maps what is actually there, records the *requested*
  generation as its remap target, and does **not** retry — otherwise it would
  re-open the index on every query forever. The publisher's rename-then-store
  ordering makes that mismatch impossible in normal operation, but it means the
  APP is what detects a stuck promotion: compare `NrControl::mapped_generation`
  against the `want_generation` you wrote. `sys.nullroute.filter` will read
  `ok:<old-gen>` and look perfectly healthy. Bumping `config_epoch` alone does
  not force a retry; publish a new generation.
- **Per-app response-mode override is not expressible in `NrControl` v1.**
  `uid_policy[]` carries ENFORCE/EXEMPT/STRICT only; `response_mode` is global.
  Adding a per-app response needs a new control-page field and an ABI bump.
- **H2 redirects** are synthesized into the caller's `hostent` + scratch buffer
  by `nr::fillHostent()`. When that cannot be done — the caller asked for the
  other address family, or the scratch buffer is too small — the hunk returns
  `blockErrno()` rather than continuing to the normal lookup. Same on H1 if
  `inet_ntop()` fails. Fail-open covers Nullroute being *broken*; it does not
  cover Nullroute having already reached a verdict, and resolving a name we
  decided to intercept is a silent filtering failure.
- **H4 exempts single-label names**, always, whatever the filter's state.
  `/system/etc/hosts` is not only the L0 blocklist: it is the only thing on
  Android that resolves `localhost` and `ip6-localhost`, because the mainline
  resolver has no built-in loopback case. Skipping the scan for a name with no
  dot would send `localhost` to a DNS server. It also exempts
  `*.nullroute.invalid` so probe B keeps working, and returns false outright if
  the hook site could not pass it the name — H4 is a ~79 us optimisation and is
  allowed to be inert, never wrong.
- **H4 also bypasses the per-netId customized hosts table** (the tail of
  `files_getaddrinfo()`, fed by `ResolverOptionsParcel.hosts`). AOSP documents
  that table as local-testing-only and nothing on a normal device populates it,
  but a tree that starts using it must drop the H4 hunk.
- **Both `netcontext` and the out-pointer are null-checked** in H1 and H2. The
  hunks run *before* each function's own argument validation — that is the point
  of them — so they cannot borrow it. A null deref in netd restarts zygote.

---

## 4. What this code needs from the rest of the ROM

Write these **before** the code, not after. Without the `map` permission,
`open()` succeeds, `mmap()` fails with `EACCES`, and the filter fails open on a
device that looks completely healthy — the second-riskiest step in the project
and the cheapest one to prevent.

```te
# netd reads the index and both shared pages
allow netd nullroute_index_file:file { getattr open read map };
allow netd nullroute_ctl_file:file   { getattr open read write map };
allow netd nullroute_log_file:file   { getattr open read write map };
allow netd nullroute_data_file:dir     search;
allow netd nullroute_index_file:dir    search;
allow netd nullroute_ctl_file:dir      search;
allow netd nullroute_log_file:dir      search;

# the health signal and the kill switch
set_prop(netd, nullroute_prop)          # sys.nullroute.filter
get_prop(netd, nullroute_prop)          # persist.sys.nullroute.kill
```

`map` is a separate permission from `read` and is the one that gets forgotten.
Note also that **nothing here bind-mounts over `/system/etc/hosts`** — the
`neverallow` in `system/sepolicy/private/domain.te` forbids `mounton` on
`system_file_type` for every domain except init, and this design never needs it.

The filter also expects `nullroute_seed` to have pre-created `control.bin`
(≥ 128 KiB) and `ring.bin` (≥ 260 KiB) with the right owner, mode and label at
`post-fs-data`. netd never creates either file: it runs as root and would leave
a root-owned file the app could never write again.

---

## 5. Recovery

```bash
adb shell setprop persist.sys.nullroute.kill 1     # takes effect on the next query
adb reboot
```

The kill switch is honoured on the query path within one property-serial change,
without a restart, and also makes `hostsLayerSuperseded()` return false so the
L0 hosts layer resumes. It is checked *before* anything else in `evaluate()`.

Without adb, delete `/data/misc/nullroute/index/current.nrdx` from recovery, or
let the boot-loop breaker do it: three boots without 120 s of healthy app uptime
quarantines the index and sets the kill property by itself.

Publish the two lines above in the BestROM release notes, not only inside the
app. A user whose device is looping cannot open the app.
