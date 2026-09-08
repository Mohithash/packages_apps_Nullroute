# Ground truth — verified against the REAL tree at /serverhive/sal/bestrom-a17 (Android 17 / lineage-24.0)

These facts were read directly from source on the build host. They OVERRIDE any web research.

## 1. Hosts file
- `bionic/libc/include/netdb.h:73` → `#define _PATH_HOSTS "/system/etc/hosts"` (hardcoded, single define)
- Shipped file `system/core/rootdir/etc/hosts` is 2 lines (localhost + ip6-localhost)
- Installed by module `etc_hosts` in `system/core/rootdir/Android.bp:175`
- Both bionic's legacy resolver (`bionic/libc/dns/net/getaddrinfo.c:2034`) and the mainline
  DnsResolver (`packages/modules/DnsResolver/getaddrinfo.cpp:1472,1495`, `sethostent.cpp:51`) use it.

## 2. CRITICAL PERF FACT — hosts file is linearly rescanned per lookup
`packages/modules/DnsResolver/getaddrinfo.cpp` `files_getaddrinfo()` → `_sethtent()`/`_gethtent()`:
`fopen(_PATH_HOSTS)` then `fgets()` line-by-line with `strcasecmp` per hostname token, per cache-missing query.
There is NO index. A 200k-line hosts file = multi-MB linear scan per cold DNS query.
=> The Re-Malwack style "giant hosts file" approach is architecturally slow on this platform.

## 3. Resolver has an EXISTING custom hosts table (but AOSP says don't use it for blocking)
- `ResolverParamsParcel.resolverOptions` → `ResolverOptionsParcel.hosts` → `ResolverHostsParcel[] {ipAddr, hostName}`
  (`packages/modules/DnsResolver/binder/android/net/ResolverOptionsParcel.aidl`)
- Stored as `HostMapping customizedTable` = an **unordered_multimap<string,string>** in `NetConfig::setOptions()`
  (`res_cache.cpp:1018-1021`), queried by `getCustomizedTableByName()` (`res_cache.cpp:1623`), consulted from
  `files_getaddrinfo()` (`getaddrinfo.cpp:1540`) AFTER the hosts-file scan.
- Properties: exact-match only (NO wildcard/subdomain), per-netId, **cleared on every setResolverConfiguration()**.
- AOSP's own doc comment on this field says verbatim: it is "intended for local testing", "Future versions of the
  DnsResolver module may break your assumptions", and "It is also not an effective domain blocking mechanism,
  because apps can easily hardcode IPs or bypass the system DNS resolver."
- Memory cost: std::string multimap; ~200k entries ≈ tens of MB in the resolver process. Does NOT scale to a
  full blocklist.

## 4. Permission to set resolver config
`DnsResolverService.cpp` — `setResolverConfiguration()` is guarded by `ENFORCE_NETWORK_STACK_PERMISSIONS()`
= PERM_NETWORK_STACK or PERM_MAINLINE_NETWORK_STACK. Normally only system_server/ConnectivityService calls it
(via `packages/modules/Connectivity/.../DnsManager.java`). A plain privileged app cannot call it directly.

## 5. Resolver ships inside the com.android.tethering APEX (NOT com.android.resolv)
`packages/modules/DnsResolver/Android.bp` → `cc_library { name: "libnetd_resolv", ... apex_available: ["com.android.tethering"], min_sdk_version: "apex_inherit" }`
=> Patching the resolver means rebuilding the Connectivity/Tethering mainline APEX.
=> The AIDL `dnsresolver_aidl_interface` has FROZEN snapshots (`aidl_api/.../8,9,16,17/`) marked
   "THIS FILE IS IMMUTABLE" — adding fields means editing `current/` and bumping, which is a mainline-compat hazard.

## 6. Tree facts
- `packages/modules/DnsResolver` — PRESENT (source)
- `system/netd` — PRESENT (source)
- `packages/modules/Connectivity` — PRESENT (source)
- `packages/apps/` — standard Lineage set (Aperture, Jelly, LineageParts, Settings, Seedvault, ...)
- The user's `Freezer` app is NOT in this tree (it lives on the `packages-apps-freezer` branch, unsynced here)

## 7. Private DNS / DoT interaction
DoT is implemented INSIDE libnetd_resolv (DnsTlsDispatcher/DnsTlsTransport/PrivateDnsConfiguration.cpp).
The hosts + customizedTable check in `files_getaddrinfo()` runs BEFORE any network query is issued,
so a resolver-level block short-circuits Private DNS/DoT too. It does NOT stop an app that ships its own
DoH client (e.g. Chrome once bootstrapped) or that connects to a hardcoded IP.

## 8. Blocklist sizes — MEASURED 2026-08-23 (not estimated)
| list | bytes | uniq domains |
|---|---|---|
| Hagezi light (wildcard/light-onlydomains.txt) | 814 KB | 42,349 |
| Hagezi pro | 4.07 MB | 224,512 |
| Hagezi pro.plus | 4.79 MB | 248,663 |
| Hagezi ultimate | 5.19 MB | 271,154 |
| StevenBlack unified | 2.78 MB | 93,513 |
| 1Hosts Lite | 5.05 MB | 205,412 |
| OISD small | 1.13 MB | 58,272 |
| Hagezi referral allowlist | 30 KB | 1,604 |
Broken URLs at time of test (need correcting): Hagezi `whitelist-onlydomains.txt`, `1Hosts/Pro/domains.txt`,
AdGuard `filter_1.txt` (AdGuard-syntax, not plain domains — needs a different parser).

## 9. Index format — PROTOTYPED AND VERIFIED
Sorted array of little-endian u64 domain hashes (blake2b-64 truncation used in the prototype), mmap'd, binary search.
- 224,541 domains -> **1,796,328 bytes (1.71 MB) = exactly 8 bytes/domain**, vs 4.07 MB raw text
- **0 hash collisions** across 224,541 domains (64-bit space; expected collisions ~n^2/2^65 ~ 3e-9)
- Build time 0.25 s in Python
- Lookup = suffix walk: for a.b.c.example.com test hashes of the full name then each parent suffix,
  binary-search each. Verified: exact entries hit; `a.b.<entry>` hits via parent; google.com / github.com /
  www.bbc.co.uk / wikipedia.org / api.whatsapp.com all correctly ALLOW.
- 9.8 us/lookup in pure Python => roughly 0.2-0.5 us in C++/Kotlin. Safe to run in the DNS hot path.
- Entry shape in Hagezi pro: 151,135 are 2-label apex, 58,441 3-label, 12,077 4-label.

## 10. Expectation-setting gotcha (document this in the app)
Hagezi Pro intentionally does NOT contain the apex domains users test with:
`doubleclick.net`, `googleadservices.com`, `graph.facebook.com`, `adservice.google.com` are all ABSENT
(it blocks specific ad subdomains such as `ad.ae.doubleclick.net`, `afs.googleadservices.com` instead,
to avoid collateral breakage). `google-analytics.com` IS present.
=> The "query domain" feature must explain WHY a domain is allowed, or users will report false bugs.

## 11. Resolver patch points — EXACT (verified by reading the tree)
Two choke points, both already receive everything a policy engine needs:

(a) `packages/modules/DnsResolver/getaddrinfo.cpp` in `resolv_getaddrinfo()` (~line 493):
```cpp
if (!files_getaddrinfo(netcontext->dns_netid, hostname, pai, &result)) {
    error = dns_getaddrinfo(hostname, pai, netcontext, app_socket, &result, event);
}
```
(b) `packages/modules/DnsResolver/gethnamaddr.cpp` (~line 437) in the gethostbyname path:
```cpp
if (_hf_gethtbyname2(name, af, &info)) {
    int error = dns_gethtbyname(&res, name, af, &info);
```

A block check inserted immediately before each of these short-circuits BOTH the hosts-file scan and the
network query (plaintext, DoT and DoH alike, since all of those live downstream in dns_getaddrinfo).

**KEY CAPABILITY: `netcontext` carries `uid`** (`android_net_context.uid`, also `dns_netid`, `app_mark`).
=> per-app / per-UID allow+deny policy is available natively at this layer, plus per-network (netid) policy.
A hosts file cannot do this at all; a VpnService can only approximate it via addAllowedApplication/addDisallowedApplication.

Block response options at this point: return `EAI_NODATA`/`HOST_NOT_FOUND` (behaves as NXDOMAIN — apps fail fast,
best for battery) or synthesize `0.0.0.0`/`::` via `getaddrinfo_numeric()` (matches hosts-file semantics, some
apps handle it better). Should be a user-visible setting.

## 12. MEASURED: cost of AOSP's hosts-file linear scan
Reimplemented `_sethtent`/`_gethtent` verbatim from getaddrinfo.cpp (fopen + fgets + strcasecmp per
name token) and timed one cache-missing lookup against real files:

| hosts file | entries | size | us per miss |
|---|---:|---:|---:|
| L0 floor | 2,000 | 61 KB | 79 |
| — | 20,000 | 600 KB | 931 |
| StevenBlack unified | 93,516 | 2.6 MB | 3,996 |
| Re-Malwack-scale | 224,553 | 6.1 MB | 9,310 |

vs the NRDX index at 231 ns/lookup (BALANCED) / 268 ns (AGGRESSIVE) => ~40,000x.
Measured on the build host with a warm page cache, so a phone is no better than this.
This is the decisive quantitative argument for the resolver-index design over a hosts file,
AND the justification for capping the baked L0 floor at ~2,000 entries.
