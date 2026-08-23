# Nullroute

A **resolver-native** ad / tracker / malware blocker for Android 17 (AOSP / lineage-24.0), built to be
baked into a custom ROM rather than installed as a root module.

Inspired by [Re-Malwack](https://github.com/ZG089/Re-Malwack), but it is not a port: Re-Malwack is a
Magisk/KernelSU module that systemlessly bind-mounts a generated `/system/etc/hosts`. Nullroute runs
*inside* the system, so it needs no root — and it deliberately does not use a hosts file as its primary
mechanism, for reasons that turned out to be measurable rather than aesthetic.

---

## Why not just ship a big hosts file

That was the obvious design, and it lost on two verified facts about this tree:

1. **The hosts file is linearly rescanned on every cache-missing lookup.** In
   `packages/modules/DnsResolver/getaddrinfo.cpp`, `files_getaddrinfo()` calls `_gethtent()`, which does
   `fopen(_PATH_HOSTS)` and then `fgets()` line by line with a `strcasecmp` per hostname token. There is
   no index.

   Reimplementing that exact scan and timing it against real hosts files:

   | hosts file | entries | size | CPU per cache-missing lookup |
   |---|---:|---:|---:|
   | Nullroute L0 floor | 2,000 | 61 KB | **79 µs** |
   | — | 20,000 | 600 KB | 931 µs |
   | StevenBlack unified | 93,516 | 2.6 MB | 4.0 ms |
   | Re-Malwack-scale | 224,553 | 6.1 MB | **9.3 ms** |

   That cost is paid inside netd, on the critical path of every app's first connection to a host. The
   NRDX index answers the same question in **231 ns** — about four orders of magnitude apart. This is
   also why L0 is capped at ~2,000 entries: as a fallback floor 79 µs is fine, as a primary mechanism it
   is not.

2. **A ROM cannot rewrite `/system/etc/hosts` at runtime anyway.** `_PATH_HOSTS` is hardcoded to
   `/system/etc/hosts` in `bionic/libc/include/netdb.h:73`, `/system` is read-only under AVB, and
   `system/sepolicy/private/domain.te` carries
   `neverallow { domain -init -otapreopt_chroot } { system_file_type ... }:dir_file_class_set mounton;`
   — so only `init` may bind-mount over it, and relabelling the target to escape that is itself blocked
   by `sepolicy_tests.py`.

So the block decision goes where lookups actually resolve: inside `libnetd_resolv`, against an mmap'd
index. That also buys three things a hosts file structurally cannot provide — wildcards, an allowlist
that wins by specificity, and **per-app rules**, because `netcontext->uid` at that hook is the real
calling app's uid (netd reads it from `SO_PEERCRED` on the dnsproxyd socket).

---

## Architecture: three layers

```
L0  BAKED HOSTS      ~2,000 curated permissive-licensed entries in /system/etc/hosts.
                     Zero code, always on. Survives a dead hook, a dead index, a dead
                     app, and safe mode. This is the floor, not the product.

L1  RESOLVER HOOK    PRIMARY. libnrfilter inside libnetd_resolv, reading an mmap'd NRDX
                     index. Wildcards, allowlist-wins, per-app policy, instant pause,
                     UID-attributed logging. Sits upstream of the hosts file, res_cache
                     and every transport — so Private DNS (DoT) does not defeat it.
                     ~230-270 ns/query, zero heap, zero syscalls, zero wakeups.

L2  DEEP MODE        OPTIONAL, user-chosen, off by default. DNS-only VpnService reusing
                     the SAME index via JNI. Adds Chromium plaintext coverage and makes
                     the APK useful on non-BestROM devices. Takes the VPN slot; says so.
```

L1 supersedes L0 when healthy, so the L0 scan costs nothing on a working device and is a real fallback
on a broken one.

## What it cannot block

Stated up front, because a blocker that hides its limits gets reported as broken:

- Ads served from the same domain as the content (YouTube, Instagram, Spotify).
- Chrome and other apps that run their own DNS — **Deep mode** covers the plaintext subset.
- Apps shipping their own DoH/DoT/DoQ, or connecting to hardcoded IPs.
- `ANDROID_DNS_MODE=local` processes, which bypass netd entirely.

It is a **name-layer** filter. Per-UID *network* policy (Datura/RethinkDNS-class firewalling) is a
complementary component, not this one.

---

## The index format (NRDX)

A sorted, open-addressed table of 46-bit fingerprints with a blocked-Bloom front end — no domain text is
stored or dereferenced at query time.

Lookup is a **suffix walk**: canonicalize the name, then hash right-to-left recording one hash at every
label boundary, so `ads.doubleclick.net` yields hashes for `net`, `doubleclick.net` and
`ads.doubleclick.net` in a single pass. The allow table is walked in full first (most-specific first),
then the block table — two passes rather than one interleaved walk, because an interleaved walk
short-circuits on the first block and could never see a shallower force-allow.

**Precedence** (normative, and asserted by the test suite):

1. `!domain` — absolute allow at any depth (the never-block floor and captive-portal set).
2. A redirect on the exact FQDN.
3. Otherwise more specific wins: `block example.com` + `allow cdn.example.com` → `cdn.` passes, `ads.` blocks.
4. Ties go to allow.

### Measured, not estimated

| corpus | parsed | after collapse | index | lookup |
|---|---:|---:|---:|---:|
| Hagezi Pro | 224,541 | 224,541 | 4.37 MB | 231 ns |
| Hagezi Pro++ + StevenBlack + 1Hosts Lite + blocklistproject | 781,735 | **353,524** | 8.55 MB | 268 ns |

Zero hash collisions across 224k domains, zero false positives on known-good hosts, and suffix collapse
removes 55% of entries when real lists are merged. Compare Re-Malwack BALANCED: ~28 MB of text,
linearly scanned per query.

```bash
clang++ -std=c++17 -O2 -Wall -Wextra -I native/include \
  native/NrCanon.cpp native/NrQuery.cpp native/NrBuilder.cpp native/nrtest.cpp -o nrtest && \
  ./nrtest <blocklist.txt>
```

---

## A note on expectations

Hagezi's lists deliberately do **not** contain the apex domains people test with. `doubleclick.net`,
`googleadservices.com`, `graph.facebook.com` and `adservice.google.com` are all absent — the lists block
specific ad subdomains (`ad.ae.doubleclick.net`, `afs.googleadservices.com`) to avoid collateral damage.
`google-analytics.com` *is* present.

So `ping doubleclick.net` resolving is **not** evidence that blocking is broken. `nrctl query` explains
which rule matched, at what depth, and from which source — precisely so this does not become a support
thread.

## Licensing posture

Only **MIT / CC BY 3.0 / Unlicense** material is baked into the signed image. HaGeZi, OISD, AdGuard and
r-a-y are GPL-3.0 and 1Hosts is MPL-2.0; a merged compiled blob derived from them is arguably a
derivative work, and GPLv3 §6 anti-tivoization is aimed squarely at copyleft material inside a
verity-protected signed image. Those lists are therefore **fetched and compiled on-device at first
sync** — the derivative work is created by the user, not distributed by the ROM. Profile files ship
URLs; they never ship the lists. *(IANAL — flagged for review.)*

## Status

The on-disk format, builder and matcher are implemented and verified against real corpora. Phase 0
(baked hosts floor) and Phase 1 (resolver hook + index + a four-screen app) are the current build
target. See `SPEC.md` for the full specification, `rom/README.md` for the ROM integration checklist and
`resolver-patch/README.md` for how to apply and — more importantly — how to *verify* the resolver patch
actually shipped, which is the one failure in this design that is invisible from userspace.
