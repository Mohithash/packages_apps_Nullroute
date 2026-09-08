# `prebuilt/` — what gets baked into the image, and under what licence

Everything in this directory ends up inside a **verity-protected,
platform-signed** BestROM system image that the user cannot replace. That single
fact drives every decision recorded here: what may be baked, how big the hosts
file is allowed to be, and why the interesting blocklists are shipped as URLs
rather than as bytes.

| File | Ships to | Consumed by | Generated? |
|---|---|---|---|
| `hosts` | `/system/etc/hosts` (`nullroute_etc_hosts`, `overrides: ["etc_hosts"]`) | bionic + `files_getaddrinfo()` → `_gethtent()` | **yes** — `tools/gen_l0_hosts.py` |
| `baseline.domains.xz` + `.sha256` | `/system_ext/etc/nullroute/` | `nullroute_seed` at first boot | **yes** — `tools/gen_baseline.py` |
| `neverblock.txt` | `/system_ext/etc/nullroute/` | compile pipeline, overlay 7(f) | hand-maintained |
| `antifraud.txt` | `/system_ext/etc/nullroute/` | compile pipeline, overlay 7(e) | hand-maintained |
| `attribution.txt` | `/system_ext/etc/nullroute/` | compile pipeline, overlay 7(e) | hand-maintained |
| `profiles/{lite,balanced,aggressive}.txt` | `/system_ext/etc/nullroute/profiles/` | `data/ProfileStore.kt`, `net/SourceSync.kt` | hand-maintained |

Soong wiring is in `Android.bp` (SPEC §8.1, §8.6). Nothing here is read at
runtime by the resolver — netd only ever maps the compiled NRDX index.

`hosts` and `baseline.domains.xz` (plus its `.sha256` sidecar) are committed
generated artefacts — `Android.bp` names both as `prebuilt_etc` sources, so a
missing one is a Soong error, not a degraded build.

---

## 1. Licence posture — the bake/fetch split

**Only material *declared* MIT, CC BY 3.0 or Unlicence is baked** — with one
qualification, in §1.0, that has to be read before release. HaGeZi, AdGuard (and
the r-a-y mirrors of it) and OISD are **GPL-3.0**; 1Hosts is **MPL-2.0**. A merged,
compiled blob derived from those lists is arguably a derivative work of them, and
GPLv3 §6 (Installation Information / anti-tivoization) is aimed squarely at
"GPLv3 material inside a verity-protected signed image".

So the copyleft lists reach the device as **URLs** — `profiles/*.txt` — and are
fetched and compiled **on the device, by the user's device, on first sync**. The
derivative work is created by the user, not distributed by us, and staleness is
fixed in the same move. See SPEC §7.6 (licensing-posture paragraph) and §10.5.

This is not a convention anyone has to remember. `tools/gen_l0_hosts.py`
`assert_permissive()` runs before a byte is fetched and fails the build on three
independent checks — the declared licence, known-copyleft markers in the URL
itself, and a missing `licence_caveat` on anything listed in `AGGREGATORS` — and
`tools/gen_baseline.py` imports the same catalogue and the same guard. Adding a
GPL source to either generator does not produce a bad artefact; it produces a
build failure.

### 1.0 ⚠️ The one thing that is NOT clean: StevenBlack is an aggregation

"StevenBlack unified is MIT" is true of Steven Black's own list and his merge
scripts, and **not** true of everything the unified file contains. From that
repo's own source table, read 2026-08-23:

| Upstream inside the unified file | Licence |
|---|---|
| MVPS hosts | **CC BY-NC-SA 4.0** |
| Dan Pollock / someonewhocares.org | **non-commercial, with attribution** |
| KADhosts | **CC BY-SA 4.0** |
| pgl.yoyo.org | **none stated** |
| AdAway | CC BY 3.0 |
| the other ten (StevenBlack ad-hoc, FadeMind ×4, Badd Boyz, hostsVN, minecraft-hosts, tiuxo, UncheckyAds, URLHaus) | MIT / CC0 / CC BY 4.0 |

Both baked artefacts therefore carry non-commercial and share-alike encumbered
fragments, and one fragment with no licence at all. A free ROM is plausibly
non-commercial and the images are plausibly not a "commercial" distribution —
but plausibly is not a clearance, share-alike arguably reaches the compiled
index, and aggregating an unlicensed list does not relicense it. This directly
qualifies the sentence above and is the single item on this page that needs a
lawyer rather than an engineer.

It is recorded where it cannot be lost: `Source.licence_caveat` in
`tools/gen_l0_hosts.py` (a build failure if an `AGGREGATORS` entry lacks one),
printed to stderr on every generator run, and reproduced verbatim in the
`hosts` header and in the `baseline.domains.xz` header line.

**If review says no**, the mechanical exit is to delete the `stevenblack` entry
from `SOURCES` and regenerate: L0 loses 23 of its 2,000 entries (the rest are
AdAway), and the offline baseline drops from ~93.9k domains to AdAway + NextDNS
alone — roughly 7k. Nothing else in the tree changes.

*IANAL. This is engineering caution, not legal advice — flag for legal review
before release.*

### 1.1 Sources that ARE baked

| Source | URL | Licence | Licence text | Used by |
|---|---|---|---|---|
| AdAway default blocklist | `https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt` | CC BY 3.0 | <http://creativecommons.org/licenses/by/3.0/> | `hosts`, `baseline.domains.xz` |
| StevenBlack unified hosts | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | MIT | <https://github.com/StevenBlack/hosts/blob/master/license.txt> | `hosts`, `baseline.domains.xz` |
| NextDNS CNAME cloaking blocklist | `https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains` | MIT | <https://github.com/nextdns/cname-cloaking-blocklist/blob/master/LICENSE> | `baseline.domains.xz` only |
| NextDNS click-tracking domains | `https://raw.githubusercontent.com/nextdns/click-tracking-domains/main/domains` | MIT | <https://github.com/nextdns/click-tracking-domains/blob/main/LICENSE> | `baseline.domains.xz` only |

CC BY 3.0 requires attribution. AdAway is credited in the generated `hosts`
header, in the `baseline.domains.xz` header, and in this table.

Two of the four are deliberately **not** eligible for `hosts`, and the reasons
are recorded in `SOURCES` in the generator:

* **CNAME cloaking** entries are CNAME *targets*, never the name an app asks
  for. `_gethtent()` only ever compares the queried name, so every byte spent on
  them in a hosts file blocks nothing. They need the response-path uncloaking of
  SPEC Phase 5.
* **Click-tracking** entries are affiliate/referral redirectors. Blocking them
  breaks shopping, cashback and invite links, and "the link does nothing" is not
  something a user can trace. In L1 that is one tap to allow; baked into a signed
  image it is an OTA. This mirrors SPEC §7.6's decision to ship HaGeZi's
  `whitelist-referral` rather than its `blocklist-referral` twin.

### 1.2 Sources that are NEVER baked (fetched on-device only)

| Source | Licence | Profile |
|---|---|---|
| HaGeZi `wildcard/light-onlydomains.txt` | GPL-3.0 | LITE |
| HaGeZi `wildcard/multi-onlydomains.txt` | GPL-3.0 | BALANCED |
| HaGeZi `wildcard/pro.plus-onlydomains.txt` | GPL-3.0 | AGGRESSIVE |
| HaGeZi `wildcard/whitelist-referral-onlydomains.txt`, `share/*` allowlists | GPL-3.0 | all (allow seeds) |
| r-a-y `AdguardMobileAds` / `AdguardMobileSpyware` / `AdguardDNS` | GPL-3.0 | LITE, BALANCED / AGGRESSIVE |
| badmojr 1Hosts `Lite/wildcards.txt` | MPL-2.0 | AGGRESSIVE |
| The Blocklist Project `alt-version/ads-nl.txt` | Unlicense | AGGRESSIVE |

The Blocklist Project is permissive and *could* be baked; it is not, because
SPEC §7.6 confines it to AGGRESSIVE on quality grounds and there is no reason to
carry 234k domains in the image for a non-default profile.

**Never used at all**, per SPEC §7.6: `hosts.rem01gaming.dev` (no licence, stale,
dedupes to nothing) and `pgl.yoyo.org` (no stated licence — its entries reach us
anyway inside StevenBlack's MIT aggregation).

---

## 2. `hosts` — the L0 baked floor

Regenerate:

```bash
python3 tools/gen_l0_hosts.py                      # writes prebuilt/hosts
python3 tools/gen_l0_hosts.py --stats              # + ranking diagnostics
python3 tools/gen_l0_hosts.py --cache-dir /tmp/nr  # cache downloads for reruns
python3 tools/gen_l0_hosts.py --cache-dir /tmp/nr --offline
```

**As generated 2026-08-23:** 53,199 bytes (52.0 KB), 2,054 lines, **2,000**
blocked entries, `sha256 09886f23b4d1edb26009e64ae937f7309d8660c1cf2d02ff658a94a3913c60df`.
1,977 of the 2,000 come from AdAway; the other 23 are curated-core endpoints that
only StevenBlack carries. From 93,534 eligible candidates, 448 were dropped by a
HARD exclusion, 1,240 by a SOFT one, 291 for length, and 1,400 by the per-apex
cap.

Set `SOURCE_DATE_EPOCH` to pin the generated-on stamp; with it set, a rerun over
the same upstream bytes is byte-identical (verified). Without it the stamp is the
real generation time and is the only byte that differs between runs.

⚠️ **Line endings.** Everything here is LF-only and must stay that way:
`_gethtent()` splits on `'\n'`, so a CRLF checkout would leave `\r` on the end of
every hostname token and silently break all 2,000 entries at once — while
leaving a file that still looks perfectly plausible. This repo is developed on
Windows with `core.autocrlf=true`, so the repo-root `.gitattributes` pins
`* text=auto eol=lf` (and `prebuilt/baseline.domains.xz binary`). Do not remove
it, and do not regenerate from a checkout that predates it without re-checking
`file prebuilt/hosts` first.

### Why ~56 KB and not 5 MB

`packages/modules/DnsResolver/getaddrinfo.cpp` `files_getaddrinfo()` calls
`_sethtent()`/`_gethtent()`, which `fopen()`s the file and walks it with
`fgets()` + `strcasecmp` per hostname token. There is no index and no cached
parse. That scan runs on **every cache-missing query**, and a query for a name
that is *not* in the file reads the file to its last byte — which is the common
case. The cost of this file is its **length**, paid by every app on the device.

56 KB / ~2,000 entries is the measured point where that is still cheap. If you
want more domains blocked, that is what the NRDX index (L1) is for: a ~200 ns
hash probe over 226k domains, versus a linear scan. **Do not lengthen this file.**
`--max-bytes` exists for experiments, not for shipping.

### Curation rules

L0 has no escape hatch. Phase 0 ships it **alone** — no resolver hook, no
`persist.sys.nullroute.kill`, no app, no allowlist — so until H4 lands the only
way to correct a wrong line is an OTA. The generator therefore applies:

* **HARD exclusions** (nothing bypasses them, curated core included): every
  domain in `neverblock.txt`, `antifraud.txt` and `attribution.txt` *read from
  those files*, plus rewarded-ad SDKs and third-party push providers. Reading the
  real files rather than duplicating them makes it structurally impossible for L0
  to contradict the ALLOW_FORCE floor or to pre-empt an opt-in carve-out.
* **SOFT exclusions** (the curated core bypasses these): multi-tenant platforms
  where a hostname belongs to whoever rented it this quarter (`*.amazonaws.com`,
  `*.pages.dev`, `*.akamaized.net`, …), first-party service apexes, and OEM
  telemetry apexes — the last because SPEC §7.6 makes OEM telemetry an *opt-in*
  category selected from `ro.product.brand`, which is the user's decision to make.
* A **per-apex cap** of 4 for non-core entries. StevenBlack's union has 1,726
  hostnames under `2o7.net` alone (per-customer Adobe/Omniture shards); uncapped,
  one dead tracker would eat a third of the budget.
* A **provenance gate on the curated core**: a recognisable domain name is not a
  licence. Core names carried by no permissive source are reported and dropped,
  never baked.

Ranking is deterministic — score desc, then shorter name, then lexicographic — so
two runs over the same upstream bytes produce byte-identical output and a
regeneration diff shows only real upstream churn. Output is written
alphabetically: scan cost is length, not position, so ordering buys nothing at
runtime and buys reviewable diffs at regeneration time.

`verify_output()` re-reads the finished file before it is written and re-asserts
every invariant (stock lines intact, exactly one probe, no duplicates, nothing
from an exclusion list, every name canonicalizable by `NrCanon.cpp`).

### Known limitations, stated rather than hidden

* **IPv4 only.** Entries sinkhole to `0.0.0.0`; an AAAA-only lookup misses the
  file and reaches DNS. Matching `::` lines would double the length and therefore
  the per-query scan cost for every app, to close a gap L1 closes anyway (L1
  matches on the *name* and is address-family agnostic).
* **The loopback trap.** Linux `connect()` to `0.0.0.0` is treated as
  `INADDR_LOOPBACK`, so a blocked app connects to itself instead of failing fast
  (SPEC §3.5). The hosts format cannot express "no such name"; L1 returns
  `EAI_NONAME`.
* **Exact match only.** No wildcards, no per-app rules, no pause.

The `127.0.0.8 hosts-probe.nullroute.invalid` line is the L0 half of the dual
liveness probe (SPEC §6.7). Its twin, `idx-probe.nullroute.invalid → 127.0.0.7`,
is served by the **index** and must never appear in this file: the two probes
being able to disagree is exactly what tells Diagnostics which layer died.

---

## 3. `baseline.domains.xz` — the offline seed, format `#NRBASE1 frontrev`

Regenerate:

```bash
python3 tools/gen_baseline.py                 # writes .xz AND .xz.sha256
python3 tools/gen_baseline.py --no-collapse   # keep suffix-redundant entries
```

**Measured 2026-08-23:** union 93,938 domains → **51,895** after suffix collapse
(−42,043); front-coded stream 572,521 B → **265,228 B (259.0 KB)** xz,
`sha256 a434b06346585891cc8b2798521781514fe16528622851b36edd8c00e52e315d`.
`SOURCE_DATE_EPOCH` applies here too; with it set and the same upstream bytes,
a rerun is byte-identical (verified with `cmp`).

> The union is smaller than SPEC §7.6's "~97,000" estimate because AdAway is
> almost entirely a subset of StevenBlack — 6,522 of its 6,540 entries are
> already there, so it contributes curation rather than volume. Collapse is far
> more effective than the −17.5% measured on BALANCED (−44.8% here) because
> StevenBlack lists many operator apexes *and* their subdomains, and every
> subdomain of a present apex is redundant under K_SUFFIX semantics.

### Format contract

**The consumer defines this format, not the generator.** `read_header()` and
`expand_frontrev()` in `native/nullroute_seed.cpp` are the specification;
`tools/gen_baseline.py` is written against them and carries a line-for-line
Python port of `expand_frontrev()` that every build runs over its own output.

The stream inside the xz container is:

```
line 1     "#NRBASE1 frontrev <free-form provenance, same line>"
then       front-coded records, and NOTHING else
```

A record is **one byte holding `0x20 + shared`**, the literal remainder of the
key, then `'\n'`. `shared` is how many leading bytes the key shares with the
previous key, capped at **94** so the length byte stays printable and a split on
`'\n'` is never ambiguous. Each key is the domain with its labels reversed and
rejoined: `ads.example.com` → `com.example.ads`; records are sorted by key and
`NrCompileInput::reversed_labels` flips them back after `nr_parse_line()`.

Two things that look like harmless additions and are not:

* **No comment lines inside the record region.** `expand_frontrev()` does not
  skip `'#'` — it reads `0x23` as a length byte (shared = 3), emits one garbage
  record *and poisons `prev` for every record after it*. `read_header()` erases
  exactly the first line, so all provenance lives on that line. It does, in
  full, including the CC BY 3.0 attribution: `xz -dc … | head -1`.
* **No record count line.** There is nowhere to put one that is not the record
  region.

Integrity is the sidecar `baseline.domains.xz.sha256` (sha256sum format), which
`load_baseline()` checks against the file **as it sits on disk**, before
decompressing. On a mismatch it compiles nothing rather than compile something
unknown. It is optional to the seeder but must be installed alongside the blob.

Also note `xz_decode()`'s `lzma_stream_decoder(&strm, 64 MiB, …)` memlimit: the
dictionary is sized from the payload (1 MiB here) rather than taken from
`preset=9`, whose 64 MiB dictionary the **decoder** must allocate. That would
both blow the memlimit — `LZMA_MEMLIMIT_ERROR`, no baseline at all — and cost
64 MiB of RSS at `post-fs-data` to gain nothing on a ~570 KB input.

Every entry is `K_SUFFIX`. The never-block floor and the two carve-outs are
**not** pre-applied; they are overlay stages 7(e)/7(f) of the compile pipeline,
and baking them in would make the opt-in categories impossible to opt into.

Reversed-label order is not cosmetic. It gives front coding the shared prefixes
domains actually have (TLD + registrable name), it puts every parent immediately
before its children so suffix collapse is one linear pass, and it is the same
order `NrSort.cpp` uses so the seeder's merge is a straight scan.

`gen_baseline.py` round-trips its own output through that reference decoder
before writing, including a check that suffix collapse orphaned nothing.

---

## 4. `profiles/*.txt` — format contract

Parsed by `data/ProfileStore.kt`; the URLs are the input to `net/SourceSync.kt`.

```
# Nullroute profile — BALANCED
# DESC: <one line, shown verbatim in the profile picker>
# ... free-form comments; per-source licence, format and measured counts ...

<url> # <Name>                block source
@<url> # <Name>               allowlist seed — parsed as ALLOW whatever the
                              list's own syntax says
# OFF # <url> # <Name>        shipped but disabled by default
```

* `# DESC:` must be present exactly once, and is the picker's subtitle.
* The `@` prefix reuses the §7.5 allow marker, so the file reads the same way as
  a rule file: `@` means "this is an allow" (`NR_ROLE_ALLOW` on the compile
  input, i.e. every parsed entry lands in the allow set whatever the list's own
  syntax says).
* User edits never rewrite these files. The overlay lives beside them as
  `profiles/<name>_added.txt` and `profiles/<name>_removed.txt` (tombstones), per
  `data/Profile.kt`.
* Category add-on URLs (OEM telemetry, TIF, pop-up, NSFW, gambling, URL
  shorteners, DoH bypass) are deliberately **not** here. They are independent of
  the tier and live in `data/SourceCatalog.kt`; duplicating them would create two
  sources of truth for the same URL.

> ⚠️ **`@` IS NOT IMPLEMENTED YET.** `ProfileStore.parseLine()` tests
> `url.startsWith("https://")` *after* the `# OFF #` strip and returns `null` for
> anything else, so an `@…` line is discarded with no log line and no UI trace.
> The allow seeds still reach the build — `SourceCatalog.alwaysAllowSources` is
> merged by `SourceSync` on every compile — so today the `@` lines here are
> documentation of what that constant must contain, **and the two lists are kept
> byte-identical for exactly that reason**. Until `SourceRef` carries a role and
> `parseLine()` strips a leading `@`, this file cannot change the allow seeds via
> an OTA the way it can change the block sources.

Current contents — LITE 3 block sources + 2 allow seeds, BALANCED 4 + 2,
AGGRESSIVE 5 + 2. All 10 distinct URLs were re-verified live (HTTP 200) on
2026-08-23. Note SPEC §7.6 correction 1: HaGeZi's repo **no longer has `hosts/`
or `domains/` directories** and any URL still pointing at them 404s — always use
the `wildcard/<name>-onlydomains.txt` form, which is also 5.2× smaller and
preserves the wildcard semantics the matcher uses.

**A file under hagezi's `share/` is not automatically an allowlist**, and
getting that wrong is silent: an allow seed that is really a blocklist fragment
strips its own domains back out of every profile and nothing anywhere reports
it. Three of the five seeds originally listed here were measured against
`wildcard/pro.plus-onlydomains.txt` and dropped:

| File | Entries | Also blocked by Pro++ | Verdict |
|---|---:|---:|---|
| `share/whitelist-referral-onlydomains.txt` | 1,604 | — | allowlist upstream, **kept** |
| `share/ultimate-known-issues.txt` | 178 | 8 (4%) | allowlist upstream, **kept** |
| `share/ad-shield-subdomains.txt` | 1,814 | 1,552 (**86%**) | blocklist fragment — dropped |
| `share/apple-private-relay.txt` | 22 | 0, but 5 are in `doh-vpn-proxy-bypass` | would nullify that add-on for an iOS-only feature — dropped |
| `share/microsoft.txt` | 74 | 15 (20%) | upstream calls it "which domains to unblock for which feature" — a menu, not a blanket allow; belongs behind a category toggle — dropped |

---

## 5. `neverblock.txt`, `antifraud.txt`, `attribution.txt`

| File | Rules | Overlay stage | Default effect |
|---|---:|---|---|
| `neverblock.txt` | 43 | 7(f) | `K_FORCE` — beats any block at any depth, not user-removable |
| `antifraud.txt` | 36 | 7(e) | ALLOW unless the user opts the category IN |
| `attribution.txt` | 28 | 7(e) | ALLOW unless the user opts the category IN |

`neverblock.txt` uses the `!domain` form (`K_FORCE`, suffix semantics). The
carve-outs use bare domains (`K_SUFFIX`) so that the apex is covered as well as
the subdomains — several attribution apexes *are* the click domain (`app.link`,
`adj.st`, `sng.link`, `page.link`).

Each file documents, group by group, **why** an entry is there — what breaks and
what the user sees when it breaks. Read those comments before editing: the whole
point of the floor is that its failures do not look like an ad blocker
misbehaving, they look like a broken phone.

Two things are deliberately absent from `neverblock.txt` and are supplied
**live** by the compile pipeline instead, because a static copy would go stale:
`Settings.Global.CAPTIVE_PORTAL_HTTP_URL` / `CAPTIVE_PORTAL_HTTPS_URL`, and the
device's configured Private DNS hostname. Hardcoding the public DoH providers
here would silently nullify the `doh-vpn-proxy-bypass` add-on, which exists
precisely to block them.

**Before the first BestROM release that carries Nullroute:** append BestROM's own
OTA host to the OS-update group in `neverblock.txt` and re-run the canary. It is
marked with a ⚠️ in the file.
