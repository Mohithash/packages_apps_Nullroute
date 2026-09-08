#!/usr/bin/env python3
"""
Nullroute — generate prebuilt/hosts, the L0 baked floor (SPEC §4 Phase 0, §7.1).

L0 is the layer that survives everything: a dead hook, a dead index, a dead app,
recovery, and safe mode. It is also the layer with no escape hatch. Phase 0 ships
this file ALONE — no resolver patch, no `persist.sys.nullroute.kill`, no app, no
allowlist. Until H4 lands there is exactly one way to correct a wrong line here,
and it is an OTA. Everything below is shaped by that asymmetry: a missing entry
costs one unblocked ad, a wrong entry costs a broken phone and a full release
cycle to fix.

    python3 tools/gen_l0_hosts.py --out prebuilt/hosts

LICENCE POSTURE (SPEC §7.6, §10.5). This file is baked into a verity-protected,
platform-signed system image. Only MIT / CC BY 3.0 / Unlicence material may go in
it. HaGeZi, AdGuard, r-a-y and OISD are GPL-3.0 and 1Hosts is MPL-2.0; a merged
blob derived from those, shipped inside a signed image the user cannot replace,
is precisely the situation GPLv3 §6 (Installation Information) is aimed at. Those
lists reach the device by URL, are fetched by the user's own device and compiled
into the user's own index — see prebuilt/profiles/*.txt. assert_permissive()
below enforces that split mechanically, because "we'll remember" is not a
licensing control.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Size budget
# ---------------------------------------------------------------------------
#
# READ THIS BEFORE ADDING ENTRIES.
#
# packages/modules/DnsResolver/getaddrinfo.cpp `files_getaddrinfo()` calls
# _sethtent()/_gethtent(), which fopen()s /system/etc/hosts and walks it with
# fgets() + strcasecmp per hostname token. There is no index and no cache of the
# parse. That scan runs on EVERY cache-missing query, and — this is the part that
# catches people out — a query for a domain that is NOT in the file scans the
# whole file to the last byte before giving up. Misses are the overwhelmingly
# common case, so the cost of this file is its LENGTH, paid by every app on the
# device, on every cold lookup, forever.
#
# 56 KB / ~2,000 entries is the measured point where that scan is still cheap.
# The Re-Malwack style "just concatenate a 200k-line hosts file" approach costs
# multi-megabyte linear scans per cold query and is what L1 exists to replace:
# the NRDX index is a ~200 ns hash probe over 226k domains. If you want more
# domains blocked, the answer is a bigger index, never a bigger hosts file.
DEFAULT_MAX_BYTES = 56 * 1024
DEFAULT_MAX_ENTRIES = 2000

# No single operator may eat the budget. StevenBlack's union contains 1,726
# hostnames under 2o7.net alone (per-customer Adobe/Omniture shards of the form
# <company>.112.2o7.net) and 752 under intellitxt.com. Each individual shard has
# a near-zero chance of ever being queried on this device, so an uncapped ranking
# would spend a third of the file on one dead tracker. Curated-core entries are
# exempt: doubleclick.net legitimately has half a dozen distinct high-traffic
# endpoints.
DEFAULT_PER_APEX_CAP = 4

# Longer than this and the value-per-byte stops making sense: names this long are
# almost always per-tenant or per-region CDN shards, i.e. exactly the sprawl the
# apex cap exists to contain.
MAX_NAME_BYTES = 48

SINK_IP = "0.0.0.0"

# The two stock lines from system/core/rootdir/etc/hosts, reproduced byte-exactly
# (module `etc_hosts`, system/core/rootdir/Android.bp:175). Our prebuilt_etc
# `overrides:` that module, so if these are dropped the device loses its own
# loopback names.
STOCK_LINES = (
    "127.0.0.1       localhost",
    "::1             ip6-localhost",
)

# The L0 half of the dual liveness probe (SPEC §6.7). Its twin,
# idx-probe.nullroute.invalid -> 127.0.0.7, is served by the INDEX and must never
# appear here: the whole point of two probes is that they can disagree, which is
# how Diagnostics distinguishes "the hosts layer is live but the hook is dead"
# from "both are dead". Putting the index probe in this file would make the two
# signals indistinguishable and blind the health screen.
PROBE_LINE = "127.0.0.8 hosts-probe.nullroute.invalid"


# ---------------------------------------------------------------------------
# Source catalogue
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    key: str
    name: str
    url: str
    fmt: str          # "hosts" | "domains"
    licence: str
    licence_url: str
    weight: int       # L0 ranking weight; see score()
    l0_eligible: bool
    note: str = ""
    # Non-empty when the source is an AGGREGATION and its own licence does not
    # cover everything it ships. Mandatory for anything in AGGREGATORS, printed
    # on every run, and reproduced verbatim in both generated artefacts — a
    # licence caveat that only lives in a code comment is a caveat nobody reads.
    licence_caveat: str = ""


# Every source Nullroute is allowed to BAKE. gen_baseline.py imports this list,
# so the licence guard below covers both baked artefacts.
SOURCES: tuple[Source, ...] = (
    Source(
        key="adaway",
        name="AdAway default blocklist",
        url="https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
        fmt="hosts",
        licence="CC BY 3.0",
        licence_url="http://creativecommons.org/licenses/by/3.0/",
        weight=100,
        l0_eligible=True,
        note="Mobile-first and hand-curated: 'blocking mobile ad providers and some "
             "analytics providers'. The best available proxy for 'a phone will "
             "actually query this name', which is the only thing an exact-match "
             "hosts file can act on.",
    ),
    Source(
        key="stevenblack",
        name="StevenBlack unified hosts",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        fmt="hosts",
        licence="MIT",
        licence_url="https://github.com/StevenBlack/hosts/blob/master/license.txt",
        weight=30,
        l0_eligible=True,
        note="93.5k domains aggregated from reputable upstreams. Used here for "
             "corroboration and for the operator-size signal; ~99.7% of AdAway is "
             "already inside it, so it is breadth rather than an independent vote.",
        licence_caveat=(
            "MIT covers Steven Black's own list and his merge scripts, NOT every "
            "upstream the unified file aggregates. Per that repo's own source "
            "table (read 2026-08-23): MVPS hosts is CC BY-NC-SA 4.0; "
            "someonewhocares.org is 'non-commercial with attribution'; KADhosts "
            "is CC BY-SA 4.0; pgl.yoyo.org states no licence at all. So the baked "
            "artefacts carry non-commercial and share-alike encumbered fragments "
            "and one unlicensed one. A free ROM is plausibly non-commercial, but "
            "plausibly is not a clearance, and aggregation does not relicense an "
            "unlicensed source. LEGAL REVIEW BEFORE RELEASE. The mechanical exit "
            "if review says no is to drop this source from SOURCES: L0 loses 23 "
            "of 2,000 entries, and the offline baseline drops from ~93.9k domains "
            "to AdAway+NextDNS alone."),
    ),
    Source(
        key="nextdns-cname",
        name="NextDNS CNAME cloaking blocklist",
        url="https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
        fmt="domains",
        licence="MIT",
        licence_url="https://github.com/nextdns/cname-cloaking-blocklist/blob/master/LICENSE",
        weight=0,
        l0_eligible=False,
        note="NOT L0-eligible: these are CNAME *targets*, never the name an app "
             "asks for. _gethtent only ever compares the queried name, so every "
             "byte spent on them in this file blocks nothing. They need the "
             "response-path CNAME uncloaking of Phase 5. Kept here because "
             "gen_baseline.py does use them.",
    ),
    Source(
        key="nextdns-click",
        name="NextDNS click-tracking domains",
        url="https://raw.githubusercontent.com/nextdns/click-tracking-domains/main/domains",
        fmt="domains",
        licence="MIT",
        licence_url="https://github.com/nextdns/click-tracking-domains/blob/main/LICENSE",
        weight=0,
        l0_eligible=False,
        note="NOT L0-eligible: affiliate and referral click redirectors. Blocking "
             "them breaks shopping, cashback and invite links, and the symptom "
             "('the link does nothing') is untraceable by the user. In L1 that is "
             "one tap to allow; baked into a signed image it is an OTA. This is "
             "the same judgement SPEC §7.6 makes when it ships HaGeZi's "
             "whitelist-referral rather than its blocklist-referral twin.",
    ),
)

PERMISSIVE_LICENCES = frozenset({"MIT", "CC BY 3.0", "Unlicense", "CC0-1.0", "BSD-3-Clause"})

# Sources that are unions of other people's lists. Their own licence file says
# nothing about what the union contains, so `licence` alone is not evidence and
# a missing caveat is a build failure rather than a shrug.
AGGREGATORS = frozenset({"stevenblack"})

# Belt and braces. A future edit could add a copyleft source with the licence
# field filled in wrongly — by mistake or by copy-paste — and the licence check
# above would wave it through. These markers match the actual upstreams SPEC §7.6
# classifies as GPL-3.0 / MPL-2.0, on the URL itself, which is much harder to get
# wrong than a metadata field.
COPYLEFT_URL_MARKERS = (
    ("hagezi", "GPL-3.0"),
    ("badmojr", "MPL-2.0 (1Hosts)"),
    ("1hosts", "MPL-2.0"),
    ("adguard", "GPL-3.0"),
    ("r-a-y/mobile-hosts", "GPL-3.0 (AdGuard mirrors)"),
    ("oisd", "GPL-3.0"),
    ("easylist", "GPL-3.0"),
    ("ublock", "GPL-3.0"),
)


def assert_permissive(sources=SOURCES) -> None:
    """Fail the build rather than bake a copyleft list into a signed image.

    This runs before a single byte is fetched. A licensing mistake that reaches
    `out/` is not a build failure, it is a release that has to be recalled.
    """
    for s in sources:
        if s.licence not in PERMISSIVE_LICENCES:
            raise SystemExit(
                f"REFUSING to bake source {s.key!r}: licence {s.licence!r} is not in "
                f"{sorted(PERMISSIVE_LICENCES)}.\n"
                f"Copyleft lists are shipped as URLs in prebuilt/profiles/*.txt and "
                f"compiled ON DEVICE, so the derivative work is created by the user "
                f"rather than distributed inside a verity-protected image "
                f"(SPEC §7.6, §10.5)."
            )
        low = s.url.lower()
        for marker, lic in COPYLEFT_URL_MARKERS:
            if marker in low:
                raise SystemExit(
                    f"REFUSING to bake source {s.key!r}: url contains {marker!r}, which "
                    f"is a known {lic} upstream, but it is declared as {s.licence!r}.\n"
                    f"If this is genuinely a relicensed mirror, prove it in "
                    f"prebuilt/README.md first and then add the exception here "
                    f"explicitly — do not relax the marker list."
                )
        if s.key in AGGREGATORS and not s.licence_caveat:
            raise SystemExit(
                f"REFUSING to bake source {s.key!r}: it is an aggregation of other "
                f"people's lists and carries no licence_caveat. Read the upstream's "
                f"own source table, record what the union actually contains, and "
                f"put it in licence_caveat — it is reproduced in both generated "
                f"artefacts so the encumbrance travels with the bytes."
            )

    # Loud on every single run, not once in a review. The one failure mode a
    # licensing control has is being quiet enough to forget.
    for s in sources:
        if s.licence_caveat:
            sys.stderr.write(f"\n⚠️  LICENCE CAVEAT — {s.name} (declared {s.licence}):\n"
                             f"    {s.licence_caveat}\n\n")


# ---------------------------------------------------------------------------
# Curated core
# ---------------------------------------------------------------------------
#
# The ad and analytics endpoints a phone actually hits, in volume, today. These
# are pinned to the top of the ranking and are exempt from the per-apex cap and
# from the SOFT exclusions (an ad host under a first-party apex, such as
# an.facebook.com or adservice.google.com, is exactly what we want to block).
#
# They are NOT exempt from the HARD exclusions, and they are NOT exempt from
# provenance: a core domain that is not present in a permissive source is
# reported and dropped, never baked. Name recognition is not a licence.
CURATED_CORE = (
    # Google display / video ad serving
    "googleads.g.doubleclick.net", "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net", "stats.g.doubleclick.net",
    "ad.doubleclick.net", "static.doubleclick.net", "cm.g.doubleclick.net",
    "googleads4.g.doubleclick.net", "doubleclick.net",
    "pagead2.googlesyndication.com", "tpc.googlesyndication.com",
    "googlesyndication.com", "partner.googleadservices.com",
    "www.googleadservices.com", "googleadservices.com",
    "pagead2.googleadservices.com", "adservice.google.com",
    # Google / Firebase measurement
    "app-measurement.com", "www.google-analytics.com", "ssl.google-analytics.com",
    "google-analytics.com", "analytics.google.com",
    "crashlytics.com",
    # Meta Audience Network (an. only — graph.facebook.com is app login and must
    # never be touched)
    "an.facebook.com",
    # Amazon advertising
    "amazon-adsystem.com", "aax.amazon-adsystem.com", "c.amazon-adsystem.com",
    "s.amazon-adsystem.com", "mads.amazon-adsystem.com",
    # Mobile ad SDKs (non-rewarded — rewarded SDKs are a carve-out, see below)
    "inmobi.com", "i.w.inmobi.com", "mopub.com", "ads.mopub.com", "smaato.net",
    "flurry.com", "data.flurry.com", "ads.flurry.com",
    # Product analytics
    "mixpanel.com", "api.mixpanel.com", "api.segment.io", "cdn.segment.com",
    "amplitude.com", "api.amplitude.com",
    "scorecardresearch.com", "b.scorecardresearch.com",
    "quantserve.com", "pixel.quantserve.com",
    # RTB exchanges and SSPs
    "criteo.com", "static.criteo.net", "gum.criteo.com", "bidder.criteo.com",
    "adnxs.com", "ib.adnxs.com", "secure.adnxs.com",
    "rubiconproject.com", "pixel.rubiconproject.com", "fastlane.rubiconproject.com",
    "ads.pubmatic.com", "openx.net", "us-u.openx.net", "casalemedia.com",
    "adsrvr.org", "match.adsrvr.org", "insight.adsrvr.org",
    "bidswitch.net", "sharethrough.com", "33across.com", "yieldmo.com",
    "smartadserver.com",
    # Content recommendation / chumbox
    "taboola.com", "cdn.taboola.com", "trc.taboola.com",
    "outbrain.com", "widgets.outbrain.com", "log.outbrain.com",
    # Adobe Experience Cloud
    "everesttech.net", "demdex.net", "dpm.demdex.net", "omtrdc.net", "2o7.net",
    # Regional heavyweights that dominate query volume outside the US/EU
    "mc.yandex.ru", "umeng.com", "umengcloud.com", "hm.baidu.com",
    "tongji.baidu.com", "pingma.qq.com", "analytics.163.com",
)

# ---------------------------------------------------------------------------
# HARD exclusions — nothing bypasses these, curated core included
# ---------------------------------------------------------------------------

# Rewarded-ad SDKs (SPEC §10.3 item 4). Blocking these does not remove an ad, it
# removes the user's reward: the "watch a video for 50 gems" button spins and
# then fails, and the report that comes back is "the ROM broke my game". They are
# an opt-in category in L1, which means they must not be pre-decided here.
REWARDED_AD_SDKS = frozenset({
    "applovin.com", "applvn.com", "applovin.io",
    "unityads.unity3d.com", "unityads.com", "unity3d.com",
    "ironsrc.com", "ironsource.mobi", "supersonicads.com",
    "vungle.com", "vungle.io",
    "adcolony.com", "adcolony.io",
    "chartboost.com", "chartboo.st",
    "tapjoy.com", "tapjoyads.com",
    "fyber.com", "inner-active.mobi",
})

# Third-party push delivery. Same failure class as blocking FCM (SPEC §10.3
# item 5): notifications silently stop for every app that uses the provider, with
# nothing anywhere connecting that to an ad blocker. These providers are
# analytics companies too, which is why the blocklists carry them — but push is
# the load-bearing half and this file cannot be undone.
THIRD_PARTY_PUSH = frozenset({
    "onesignal.com", "onesignal.io", "os.tc",
    "urbanairship.com", "airship.com", "asnapieu.com",
    "pushwoosh.com", "wonderpush.com",
    "clevertap.com", "wzrkt.com",
    "braze.com", "appboy.com", "appboy.eu",
    "leanplum.com", "moengage.com",
})

# ---------------------------------------------------------------------------
# SOFT exclusions — the curated core bypasses these
# ---------------------------------------------------------------------------

# Multi-tenant platforms. A hostname here belongs to whoever rented it this
# quarter; the tracker that justified the entry can be gone and the name reissued
# to someone else's API. That is survivable in an index we rebuild every day and
# is not survivable in an immutable file.
SHARED_INFRA_APEXES = frozenset({
    "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
    "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "akadns.net",
    "edgekey.net", "edgesuite.net", "edgecastcdn.net",
    "fastly.net", "fastlylb.net", "cloudflare.net", "cdn.cloudflare.net",
    "azureedge.net", "azurefd.net", "azurewebsites.net", "cloudapp.net",
    "trafficmanager.net", "msedge.net", "digitaloceanspaces.com",
    "googleusercontent.com", "appspot.com", "firebaseapp.com", "web.app",
    "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "r2.dev", "github.io", "gitlab.io", "glitch.me", "repl.co", "ngrok.io",
    "lovable.app", "b-cdn.net", "kxcdn.com", "stackpathdns.com", "llnwd.net",
    "cdn77.org", "hwcdn.net", "cachefly.net", "footprint.net", "gcdn.co",
    "wixsite.com", "weebly.com", "blogspot.com",
})

# First-party services whose apexes must not be swept in wholesale. Specific ad
# hosts underneath them are fair game and live in CURATED_CORE.
FIRST_PARTY_CRITICAL_APEXES = frozenset({
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "ytimg.com",
    "ggpht.com", "googlevideo.com", "android.com", "gmail.com", "goo.gl",
    "facebook.com", "fbcdn.net", "fb.com", "messenger.com", "instagram.com",
    "whatsapp.com", "whatsapp.net", "oculus.com",
    "twitter.com", "x.com", "twimg.com", "linkedin.com", "licdn.com",
    "paypal.com", "stripe.com", "github.com", "gitlab.com", "cloudflare.com",
    "mozilla.org", "mozilla.net", "wikipedia.org", "wikimedia.org",
    "spotify.com", "scdn.co", "netflix.com", "nflxvideo.net",
    "telegram.org", "t.me", "signal.org", "discord.com", "discordapp.com",
    "reddit.com", "redd.it", "redditmedia.com", "zoom.us", "slack.com",
    "dropbox.com", "office.com", "office365.com", "sharepoint.com",
})

# OEM and platform-vendor telemetry. SPEC §7.6 makes this an opt-in add-on
# category selected from ro.product.brand, which is a decision the user gets to
# make — so it must not be pre-made in the image. (peridot is Xiaomi; baking
# Xiaomi telemetry blocks here would also be the one change most likely to
# interact badly with MIUI-derived vendor code we do not control.)
OEM_TELEMETRY_APEXES = frozenset({
    "xiaomi.com", "xiaomi.net", "mi.com", "miui.com", "micloud.xiaomi.net",
    "samsung.com", "samsungapps.com", "samsungcloud.com", "samsungdm.com",
    "oppomobile.com", "heytapmobi.com", "heytapmobile.com", "coloros.com",
    "vivo.com.cn", "vivoglobal.com", "huawei.com", "hicloud.com", "dbankcloud.com",
    "oneplus.net", "oneplus.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "amazon.com", "media-amazon.com",
    "tiktokv.com", "byteoversea.com", "musical.ly",
})

# ---------------------------------------------------------------------------
# Domain validation — must agree with native/NrCanon.cpp
# ---------------------------------------------------------------------------
#
# A name this file blocks but the matcher would refuse to canonicalize is a name
# the two layers disagree about, and disagreement between L0 and L1 is exactly
# what the dual probe exists to detect. Keep these rules in step with
# nr_canonicalize() and nr_has_skip_suffix().
SKIP_SUFFIXES = (".local", ".onion", ".arpa", ".localhost")
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")
TLD_RE = re.compile(r"^[a-z][a-z0-9-]*$|^xn--[a-z0-9-]+$")
MAX_NAME = 253
MAX_LABEL = 63


def valid_domain(d: str) -> bool:
    if not d or len(d) > MAX_NAME or "." not in d:
        return False
    if d != d.lower() or d.startswith(".") or d.endswith("."):
        return False
    if any(d.endswith(s) for s in SKIP_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(d)
        return False          # nr_is_ip_literal() rejects these; so do we
    except ValueError:
        pass
    labels = d.split(".")
    if len(labels) < 2 or len(labels) > 16:   # NR_MAX_LABELS
        return False
    for lab in labels:
        if not lab or len(lab) > MAX_LABEL or not LABEL_RE.match(lab):
            return False
    return bool(TLD_RE.match(labels[-1]))


def apex(d: str) -> str:
    """Last two labels. Deliberately NOT a Public Suffix List lookup.

    A real PSL would treat foo.co.uk as an apex; this returns co.uk. That is the
    conservative direction for a per-apex CAP — it lumps every co.uk tracker into
    one bucket and lets fewer of them through — and it keeps a 6,000-line data
    dependency out of a build tool. It is used ONLY for the diversity cap and the
    operator-size signal, never for matching.
    """
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def suffix_chain(d: str):
    parts = d.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


# ---------------------------------------------------------------------------
# Fetch and parse
# ---------------------------------------------------------------------------

UA = "nullroute-gen_l0_hosts/1.0 (+https://github.com/BestROM; build tool, not a client)"


@dataclass
class Fetched:
    source: Source
    raw: bytes
    sha256: str
    when: str
    from_cache: bool = False
    domains: set[str] = field(default_factory=set)
    rejected: int = 0


def fetch_source(s: Source, cache_dir: str | None, offline: bool,
                 timeout: int = 120, tries: int = 3) -> Fetched:
    cache_path = None
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, f"{s.key}.raw")
    if cache_path and os.path.exists(cache_path) and offline:
        raw = open(cache_path, "rb").read()
        return Fetched(s, raw, hashlib.sha256(raw).hexdigest(),
                       datetime.fromtimestamp(os.path.getmtime(cache_path),
                                              timezone.utc).strftime("%Y-%m-%d"),
                       from_cache=True)
    if offline and not cache_path:
        raise SystemExit(f"--offline given but no --cache-dir holds {s.key!r}")

    last = None
    for attempt in range(1, tries + 1):
        try:
            req = urllib.request.Request(
                s.url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
            if cache_path:
                with open(cache_path, "wb") as f:
                    f.write(body)
            return Fetched(s, body, hashlib.sha256(body).hexdigest(),
                           datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            sys.stderr.write(f"  fetch {s.key} attempt {attempt}/{tries} failed: {e}\n")
            time.sleep(2 * attempt)
    # A partial blocklist is worse than a failed build: it looks like a success
    # and ships a floor with holes in it that nobody notices for a release.
    raise SystemExit(f"FATAL: could not fetch {s.key} ({s.url}): {last}")


SINK_IPS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255"})


def parse_source(f: Fetched) -> None:
    """Normalize one source into f.domains.

    hosts lines yield EVERY hostname after the IP, not just the first — a hosts
    line may legitimately carry several names and taking only $2 (which
    Re-Malwack does) silently drops the rest.
    """
    text = f.raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if f.source.fmt == "hosts":
            parts = line.split()
            if len(parts) < 2 or parts[0] not in SINK_IPS:
                continue
            names = parts[1:]
        else:
            names = line.split()[:1]
        for n in names:
            n = n.strip().rstrip(".").lower()
            if valid_domain(n):
                f.domains.add(n)
            else:
                f.rejected += 1


# ---------------------------------------------------------------------------
# Exclusions loaded from the sibling prebuilt/ lists
# ---------------------------------------------------------------------------

def load_rule_domains(path: str) -> set[str]:
    """Read neverblock/antifraud/attribution and return their bare domains.

    Reading the real files rather than duplicating their contents is the point:
    it is structurally impossible for L0 to contradict the ALLOW_FORCE floor or
    to pre-empt an opt-in carve-out, because both are derived from the same
    bytes the compile pipeline reads at stage 7(e)/7(f).
    """
    out: set[str] = set()
    if not os.path.exists(path):
        raise SystemExit(f"FATAL: exclusion list missing: {path}")
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        line = line.lstrip("!@=").lstrip("*.")     # §7.5 rule prefixes
        if valid_domain(line):
            out.add(line)
    if not out:
        raise SystemExit(f"FATAL: exclusion list parsed to zero domains: {path}")
    return out


@dataclass
class Exclusions:
    hard: set[str]
    soft: set[str]
    hits: Counter = field(default_factory=Counter)

    def blocked_by(self, d: str, is_core: bool) -> str | None:
        for suf in suffix_chain(d):
            if suf in self.hard:
                return f"hard:{suf}"
        if is_core:
            return None
        for suf in suffix_chain(d):
            if suf in self.soft:
                return f"soft:{suf}"
        return None


def build_exclusions(prebuilt_dir: str) -> Exclusions:
    hard: set[str] = set()
    for name in ("neverblock.txt", "antifraud.txt", "attribution.txt"):
        hard |= load_rule_domains(os.path.join(prebuilt_dir, name))
    hard |= REWARDED_AD_SDKS
    hard |= THIRD_PARTY_PUSH
    soft = set(SHARED_INFRA_APEXES) | set(FIRST_PARTY_CRITICAL_APEXES) | set(OEM_TELEMETRY_APEXES)
    return Exclusions(hard=hard, soft=soft)


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

# Leftmost labels that name an ad/telemetry endpoint outright. A weak signal on
# its own — it only ever breaks ties inside AdAway — but it correctly prefers
# ads.<operator> over an opaque per-region shard of the same operator.
AD_TOKENS = frozenset({
    "ad", "ads", "adserver", "adservice", "adsystem", "adx", "advert", "adv",
    "analytics", "analytic", "stats", "stat", "metrics", "metric", "telemetry",
    "track", "tracker", "tracking", "pixel", "beacon", "collect", "collector",
    "log", "logs", "logging", "event", "events", "sdk", "banner", "banners",
    "click", "clicks", "imp", "impression", "rtb", "bid", "bidder", "pagead",
})

SCORE_CORE = 10_000


def score(d: str, in_sources: dict[str, bool], apex_size: int, is_core: bool) -> int:
    """Rank by 'how likely is this exact name to be asked for, on a phone'.

    Exact-match is the whole constraint. A hosts file cannot block
    *.doubleclick.net, so the only entries worth their bytes are the specific
    FQDNs an SDK on this device will actually resolve. There is no telemetry to
    learn that from, so the ranking uses the best available proxies, strongest
    first: AdAway's mobile curation, then operator size, then name shape.
    """
    if is_core:
        s = SCORE_CORE
    else:
        s = 0
    for key, present in in_sources.items():
        if present:
            s += next(x.weight for x in SOURCES if x.key == key)

    # Operator size, log-scaled and capped hard at +12. Bigger operators are more
    # likely to be reached, but this must never grow into a reward for
    # per-customer subdomain sprawl — that is what the per-apex cap is for.
    s += min(12, int(4 * math.log2(1 + apex_size)))

    labels = d.count(".") + 1
    if labels == 2:
        s += 25          # the apex itself; SDKs and short links hit these directly
    elif labels == 3:
        s += 10
    elif labels >= 5:
        s -= 20          # deep names are per-region/per-tenant shards

    if d.split(".", 1)[0] in AD_TOKENS:
        s += 12
    return s


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

def build_timestamp() -> str:
    """Honour SOURCE_DATE_EPOCH so a rebuild from the same inputs is bit-identical.

    Without this the generated-on line is the only thing that changes between two
    runs over identical upstream bytes, which is enough to defeat a reproducible
    build and to make `git diff` on a regeneration useless for spotting real
    upstream churn.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (datetime.fromtimestamp(int(epoch), timezone.utc) if epoch
            else datetime.now(timezone.utc))
    return when.strftime("%Y-%m-%d %H:%M:%S UTC")


def _wrap(text: str, width: int) -> list[str]:
    """Greedy wrap. Not textwrap: this output is part of a reproducible artefact
    and textwrap's defaults (break_long_words, drop_whitespace) have changed
    behaviour across Python versions before."""
    if not text:
        return []
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        out.append(line)
    return out


def render(entries: list[str], fetched: list[Fetched], stats: dict) -> str:
    now = build_timestamp()
    out: list[str] = []
    a = out.append
    a("# /system/etc/hosts — Nullroute L0, the baked floor.")
    a("#")
    a(f"# GENERATED by tools/gen_l0_hosts.py on {now}.")
    a("# Do not hand-edit: the next regeneration silently discards your change.")
    a("# Edit the tool instead.")
    a("#")
    a("# This file is linearly rescanned by _gethtent() on every cache-missing DNS")
    a("# query, to the LAST BYTE when the name is not in it — which is the common")
    a("# case. Its cost is its length, paid by every app on the device, and it is")
    a(f"# sized for that: {stats['entries']} entries, {stats['bytes']} bytes.")
    a("# If you want more domains blocked, build a bigger NRDX index (L1). Do not")
    a("# lengthen this file.")
    a("#")
    a("# Sources baked into the signed image, with their declared licences. Lines")
    a("# marked '!' are caveats on that declaration and are NOT decoration — read")
    a("# them before shipping (see prebuilt/README.md §1).")
    for f in fetched:
        if not f.source.l0_eligible:
            continue
        a(f"#   {f.source.name} — {f.source.licence}")
        a(f"#     {f.source.url}")
        a(f"#     retrieved {f.when}, sha256 {f.sha256[:32]}…, {len(f.domains)} domains")
        for chunk in _wrap(f.source.licence_caveat, 68):
            a(f"#     ! {chunk}")
    a("#   Full provenance and licence URLs: packages/apps/Nullroute/prebuilt/README.md")
    a("#")
    a("# Sinkholed to 0.0.0.0. Note that Linux connect() to 0.0.0.0 is treated as")
    a("# INADDR_LOOPBACK, so a blocked app connects to itself rather than failing")
    a("# fast (SPEC §3.5). L1 returns EAI_NONAME instead and does not have that")
    a("# problem; the hosts layer has no way to express 'no such name'.")
    a("#")
    a("# IPv4 sinkholes only. An AAAA-only lookup misses this file and reaches DNS.")
    a("# Adding matching '::' lines would double the length and therefore double the")
    a("# per-query scan cost for every app on the device, to close a gap that L1 —")
    a("# which matches on the NAME and is address-family agnostic — closes anyway.")
    a("")
    for line in STOCK_LINES:
        a(line)
    a("")
    a("# L0 liveness probe (SPEC §6.7). Its twin, idx-probe.nullroute.invalid, is")
    a("# served by the index and must NOT appear here — the two probes disagreeing")
    a("# is what tells Diagnostics which layer died.")
    a(PROBE_LINE)
    a("")
    for d in entries:
        a(f"{SINK_IP} {d}")
    a("")
    return "\n".join(out)


def verify_output(text: str, excl: Exclusions, core: set[str], max_bytes: int) -> None:
    """Re-read what we are about to bake and prove it is what we think it is.

    This costs milliseconds and catches the class of bug where a refactor of the
    ranking quietly starts emitting a name from an exclusion list. The next place
    that mistake would surface is a device in someone's pocket that cannot
    receive push, three weeks and one OTA cycle later.
    """
    stock_seen, probes, names = [], [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if raw in STOCK_LINES:
            stock_seen.append(raw)
            continue
        parts = line.split()
        if len(parts) != 2:
            raise SystemExit(f"FATAL: malformed hosts line: {raw!r}")
        ip, name = parts
        if name.endswith(".nullroute.invalid"):
            probes.append(raw)
            continue
        if ip != SINK_IP:
            raise SystemExit(f"FATAL: unexpected sink address in {raw!r}")
        names.append(name)

    if stock_seen != list(STOCK_LINES):
        raise SystemExit(f"FATAL: stock localhost lines missing or altered: {stock_seen}")
    if probes != [PROBE_LINE]:
        raise SystemExit(f"FATAL: probe lines wrong: {probes}")
    if len(set(names)) != len(names):
        dupes = [n for n, c in Counter(names).items() if c > 1]
        raise SystemExit(f"FATAL: duplicate entries: {dupes[:10]}")
    for n in names:
        if not valid_domain(n):
            raise SystemExit(f"FATAL: {n!r} would not canonicalize in NrCanon.cpp")
        why = excl.blocked_by(n, n in core)
        if why:
            raise SystemExit(f"FATAL: {n!r} is excluded ({why}) but was emitted")
    if len(text.encode("utf-8")) > max_bytes:
        raise SystemExit(f"FATAL: {len(text.encode())} bytes exceeds budget {max_bytes}")


# ---------------------------------------------------------------------------

def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    ap = argparse.ArgumentParser(description="Generate the Nullroute L0 hosts file.")
    ap.add_argument("--out", default=os.path.join(repo, "prebuilt", "hosts"))
    ap.add_argument("--prebuilt-dir", default=os.path.join(repo, "prebuilt"),
                    help="where neverblock/antifraud/attribution.txt live")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    ap.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    ap.add_argument("--per-apex-cap", type=int, default=DEFAULT_PER_APEX_CAP)
    ap.add_argument("--cache-dir", default=None,
                    help="cache raw source downloads here (opt-in; keeps reruns cheap)")
    ap.add_argument("--offline", action="store_true",
                    help="use --cache-dir only; never touch the network")
    ap.add_argument("--stats", action="store_true", help="print selection diagnostics")
    args = ap.parse_args()

    assert_permissive()

    excl = build_exclusions(args.prebuilt_dir)
    sys.stderr.write(f"exclusions: {len(excl.hard)} hard, {len(excl.soft)} soft apexes\n")

    fetched: list[Fetched] = []
    for s in SOURCES:
        sys.stderr.write(f"fetching {s.key} …\n")
        f = fetch_source(s, args.cache_dir, args.offline)
        parse_source(f)
        fetched.append(f)
        sys.stderr.write(f"  {len(f.domains)} domains, {f.rejected} rejected, "
                         f"sha256 {f.sha256[:16]}\n")

    l0 = [f for f in fetched if f.source.l0_eligible]
    if not l0:
        raise SystemExit("FATAL: no L0-eligible sources")

    # The operator-size signal is taken over the whole permissive union, not just
    # the eligible slice: how many hostnames an operator runs is a property of the
    # operator, and StevenBlack sees far more of them than AdAway does.
    union: set[str] = set()
    for f in fetched:
        union |= f.domains
    apex_size = Counter(apex(d) for d in union)

    candidates = set()
    for f in l0:
        candidates |= f.domains
    core = {d for d in CURATED_CORE}

    # Provenance gate for the curated core. A recognisable name is not a licence:
    # if no permissive source carries it, it does not go in the image.
    core_unsourced = sorted(core - candidates)
    core &= candidates

    ranked = []
    dropped = Counter()
    for d in candidates:
        if len(d) > MAX_NAME_BYTES and d not in core:
            dropped["too_long"] += 1
            continue
        why = excl.blocked_by(d, d in core)
        if why:
            dropped[why.split(":", 1)[0]] += 1
            excl.hits[why] += 1
            continue
        in_src = {f.source.key: (d in f.domains) for f in l0}
        ranked.append((score(d, in_src, apex_size[apex(d)], d in core), len(d), d))

    # Deterministic: score desc, then shorter name (more entries per byte), then
    # lexicographic. Two runs over the same upstream bytes produce byte-identical
    # output, so a regeneration diff shows only real upstream churn.
    ranked.sort(key=lambda t: (-t[0], t[1], t[2]))

    header_and_stock = len(render([], fetched, {"entries": DEFAULT_MAX_ENTRIES,
                                                "bytes": args.max_bytes}).encode())
    budget = args.max_bytes - header_and_stock
    chosen: list[str] = []
    used = 0
    per_apex: Counter = Counter()
    capped = 0
    for sc, _ln, d in ranked:
        if len(chosen) >= args.max_entries:
            break
        if sc < SCORE_CORE:
            ax = apex(d)
            if per_apex[ax] >= args.per_apex_cap:
                capped += 1
                continue
            per_apex[ax] += 1
        cost = len(SINK_IP) + 1 + len(d) + 1
        if used + cost > budget:
            break
        chosen.append(d)
        used += cost

    chosen.sort()   # alphabetical on disk: the scan cost is length, not position,
                    # so order buys nothing at runtime and buys reviewable diffs
                    # at regeneration time.

    # The header states the file's own byte count, and stating it changes it.
    # Iterate to the fixed point rather than rendering twice and being off by the
    # width of the number — the whole point of printing it is that a reviewer can
    # trust it against `wc -c`.
    size = 0
    for _ in range(8):
        text = render(chosen, fetched, {"entries": len(chosen), "bytes": size})
        got = len(text.encode("utf-8"))
        if got == size:
            break
        size = got
    else:
        raise SystemExit("FATAL: header byte count did not converge")
    verify_output(text, excl, core, args.max_bytes)
    data = text.encode("utf-8")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as fh:
        fh.write(data)

    sys.stderr.write(
        f"\nwrote {args.out}\n"
        f"  {len(data)} bytes ({len(data)/1024:.1f} KB), "
        f"{len(text.splitlines())} lines, {len(chosen)} blocked entries\n"
        f"  candidates {len(candidates)}, core kept {len(core)}, "
        f"apex-capped {capped}\n"
        f"  dropped: {dict(dropped)}\n")
    if core_unsourced:
        sys.stderr.write(
            f"  NOT BAKED — curated-core names with no permissive source "
            f"({len(core_unsourced)}): {', '.join(core_unsourced)}\n"
            f"  (find a permissive source that carries them, or leave them to L1)\n")
    if args.stats:
        sys.stderr.write("\n  top apexes in output:\n")
        for ax, n in Counter(apex(d) for d in chosen).most_common(15):
            sys.stderr.write(f"    {n:4d}  {ax}\n")
        sys.stderr.write("\n  exclusion hits:\n")
        for k, n in excl.hits.most_common(25):
            sys.stderr.write(f"    {n:5d}  {k}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
