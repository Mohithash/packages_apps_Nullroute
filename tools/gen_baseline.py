#!/usr/bin/env python3
"""
Nullroute — generate prebuilt/baseline.domains.xz, the offline L1 seed
(SPEC §4 Phase 1, §7.1).

    python3 tools/gen_baseline.py --out prebuilt/baseline.domains.xz

`nullroute_seed` compiles this into a real NRDX index at first boot, before the
device has ever seen a network. That is what makes "protection is idle 💤 until
you download a list" — the state every other blocker has on a fresh flash —
simply not exist here (SPEC §9). It is also the last rung of the degradation
ladder in §6.3: current.nrdx -> previous.nrdx -> **baseline** -> L0 hosts -> pass
all. When an update goes wrong at 3 a.m. this is what the device falls back to.

LICENCE POSTURE. Same rule as gen_l0_hosts.py and enforced by the same guard:
only MIT / CC BY 3.0 / Unlicence material is baked into the verity-protected,
platform-signed image. The GPL-3.0 and MPL-2.0 lists (HaGeZi, AdGuard/r-a-y,
1Hosts, OISD) reach the device as URLs in prebuilt/profiles/*.txt and are
compiled ON DEVICE, so the merged derivative work is created by the user rather
than distributed by us (SPEC §7.6, §10.5).

FILE FORMAT. The consumer is `expand_frontrev()` / `read_header()` in
native/nullroute_seed.cpp, and THAT is the contract — this generator is written
against it rather than the other way round, because the seeder's parser is the
half that runs at post-fs-data on a device with no UI. The bytes are
xz(payload), where the payload is:

    line 1        "#NRBASE1 frontrev <free-form provenance, same line>\\n"
    then          front-coded records, and NOTHING else

A record is: one byte holding (0x20 + shared_prefix_len), the literal remainder
of the key, then '\\n'. `shared_prefix_len` is relative to the previous record
and is CAPPED AT 94 so the length byte stays printable (0x20..0x7e) and a plain
split on '\\n' is never ambiguous. The seeder clamps a shared count that exceeds
the previous record's length, so a truncated file degrades instead of reading
out of bounds.

There is no record count and there are NO comment lines inside the record
region. `expand_frontrev()` does not skip '#' lines — it would read '#' as a
length byte (0x23 -> shared 3), emit a garbage record AND poison `prev` for
every record after it. read_header() erases exactly the first line, so all
provenance and attribution has to live on that one line. It does, in full.

Each record's key is the domain with its LABELS reversed and rejoined:
`ads.example.com` -> `com.example.ads`; `NrCompileInput::reversed_labels` tells
the compiler to flip them back after nr_parse_line(). Records are sorted by key.

Three properties fall out of reversed-label order and are all load-bearing:

  1. Front coding gets its shared prefixes from the parts domains actually share
     (the TLD and the registrable name), which text sorted the normal way does
     not have.
  2. A parent sorts immediately before all of its children, so the suffix
     collapse of SPEC §6.5 step 6 is one linear pass with no lookups.
  3. It is the same order NrSort.cpp uses, so the seeder's merge is a straight
     scan with no re-sort.

Integrity is the sidecar `baseline.domains.xz.sha256` (sha256sum format), which
load_baseline() checks against the file as it sits on disk BEFORE decompressing
it. A `#sha256-records` line inside the payload cannot do that job here: it
would have to live in the record region, where a comment is corruption.
"""

from __future__ import annotations

import argparse
import hashlib
import lzma
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gen_l0_hosts import (          # noqa: E402  — same catalogue, same licence guard
    SOURCES,
    assert_permissive,
    build_timestamp,
    fetch_source,
    parse_source,
    valid_domain,
)

HEADER_MAGIC = "#NRBASE1 frontrev"

# native/nullroute_seed.cpp expand_frontrev(): the length byte is (0x20 + shared)
# and must stay printable, so shared saturates here. Saturating is lossless — the
# decoder rebuilds prev[:94] + remainder, and remainder simply carries the bytes
# the cap refused to elide.
MAX_SHARED = 94


def rev_key(domain: str) -> str:
    return ".".join(reversed(domain.split(".")))


def unrev_key(key: str) -> str:
    return ".".join(reversed(key.split(".")))


def collapse(keys: list[str]) -> tuple[list[str], int]:
    """Drop every key implied by a shorter one already in the set.

    x.example.com is redundant when example.com is present, because every rule
    in the baseline is K_SUFFIX — the matcher's suffix walk hits the parent on
    the way past.

    Sorted reversed-label order puts a parent immediately before its children,
    so this is one pass. The `+ "."` is not decoration: `com.examplefoo` also
    has `com.example` as a byte prefix and must NOT be collapsed into it.

    MEASURED on this corpus: −44.8%, far more than the −17.5% SPEC §6.5 records
    for BALANCED. That is not an error in either number — StevenBlack lists many
    operator apexes *and* their subdomains, and under K_SUFFIX every one of
    those subdomains is dead weight.

    Collapse is not purely a size optimisation and it is worth knowing why.
    Precedence is depth-based (§6.1): a deeper block beats a shallower allow. So
    uncollapsed, a user's `@example.com` still leaves `ads.example.com` blocked,
    while collapsed it does not — the child no longer exists as its own rule.
    That is the behaviour SPEC §6.5 already specifies by putting collapse at
    step 6, ahead of the user-rule overlay at step 7; doing it here rather than
    at first boot only moves the same operation earlier. Use --no-collapse if
    you ever need to measure against the uncollapsed corpus.
    """
    out: list[str] = []
    dropped = 0
    for k in keys:
        if out and k.startswith(out[-1] + "."):
            dropped += 1
            continue
        out.append(k)
    return out, dropped


def front_code(keys: list[str]) -> bytes:
    """Encode exactly what expand_frontrev() decodes: <0x20+shared> <rest> '\\n'."""
    out = bytearray()
    prev = ""
    for k in keys:
        n = 0
        limit = min(len(prev), len(k), MAX_SHARED)
        while n < limit and prev[n] == k[n]:
            n += 1
        rest = k[n:]
        # A key is never a strict prefix of its predecessor in sorted order, so
        # `rest` is never empty and a record is never a bare length byte.
        assert rest, f"empty remainder for {k!r} after {prev!r}"
        out.append(0x20 + n)
        out += rest.encode("ascii")
        out.append(0x0A)
        prev = k
    return bytes(out)


def decode(payload: bytes) -> list[str]:
    """Reference decoder — a line-for-line port of expand_frontrev(), clamp included.

    Kept in the generator on purpose: --verify runs the real output through it,
    so an encoder change the seeder could not undo fails the build here rather
    than at post-fs-data on a device that then silently ships with no baseline.
    """
    nl = payload.find(b"\n")
    if nl < 0:
        raise ValueError("no header line")
    head = payload[:nl].decode("utf-8")
    if not head.startswith(HEADER_MAGIC):
        raise ValueError(f"bad header: {head[:40]!r}")

    out: list[str] = []
    prev = ""
    pos = nl + 1
    while pos < len(payload):
        end = payload.find(b"\n", pos)
        if end < 0:
            end = len(payload)
        if end > pos:
            shared = payload[pos] - 0x20
            if shared < 0:
                raise ValueError(f"length byte {payload[pos]:#x} below 0x20")
            if shared > len(prev):
                raise ValueError("shared prefix longer than previous record")
            key = prev[:shared] + payload[pos + 1:end].decode("ascii")
            out.append(unrev_key(key))
            prev = key
        pos = end + 1
    return out


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    ap = argparse.ArgumentParser(description="Generate the Nullroute offline baseline seed.")
    ap.add_argument("--out", default=os.path.join(repo, "prebuilt", "baseline.domains.xz"))
    ap.add_argument("--cache-dir", default=None,
                    help="cache raw source downloads here (opt-in; keeps reruns cheap)")
    ap.add_argument("--offline", action="store_true",
                    help="use --cache-dir only; never touch the network")
    ap.add_argument("--no-collapse", action="store_true",
                    help="keep suffix-redundant entries (diagnostic only)")
    ap.add_argument("--no-verify", action="store_true")
    args = ap.parse_args()

    assert_permissive()

    fetched = []
    for s in SOURCES:
        sys.stderr.write(f"fetching {s.key} …\n")
        f = fetch_source(s, args.cache_dir, args.offline)
        parse_source(f)
        fetched.append(f)
        sys.stderr.write(f"  {len(f.domains)} domains, {f.rejected} rejected, "
                         f"sha256 {f.sha256[:16]}\n")

    union: set[str] = set()
    for f in fetched:
        union |= f.domains
    # parse_source already applied valid_domain(); re-asserting is cheap and this
    # blob is consumed by C++ running inside netd's boot path.
    bad = [d for d in union if not valid_domain(d)]
    if bad:
        raise SystemExit(f"FATAL: {len(bad)} invalid domains survived parsing: {bad[:5]}")

    keys = sorted(rev_key(d) for d in union)
    if args.no_collapse:
        dropped = 0
    else:
        keys, dropped = collapse(keys)

    records = front_code(keys)

    # Everything a reviewer or a field diagnosis needs, on the ONE line
    # read_header() is allowed to consume. CC BY 3.0 requires attribution and
    # this is where it survives: `xz -dc baseline.domains.xz | head -1`.
    prov = "; ".join(f"{f.source.name} ({f.source.licence}) {f.source.url} "
                     f"retrieved {f.when} sha256 {f.sha256[:16]}"
                     + (f" CAVEAT: {f.source.licence_caveat}" if f.source.licence_caveat else "")
                     for f in fetched)
    header = (f"{HEADER_MAGIC} generated={build_timestamp()} records={len(keys)} "
              f"union={len(union)} collapsed={dropped} "
              f"sha256-records={hashlib.sha256(records).hexdigest()} "
              f"every-entry-is=K_SUFFIX sources=[{prov}]")
    if "\n" in header:
        raise SystemExit("FATAL: header must be exactly one line")
    payload = header.encode("utf-8") + b"\n" + records

    # Dict size is chosen from the payload, not from a preset. xz preset 9 asks
    # for a 64 MiB dictionary, and the DECODER has to allocate it — that would be
    # 64 MiB of RSS inside nullroute_seed at post-fs-data, on the boot path, to
    # gain nothing at all on an input this size. A dictionary larger than the
    # input cannot find a match the smaller one missed. It also has to stay under
    # xz_decode()'s 64 MiB lzma_stream_decoder memlimit, which a preset-9 stream
    # would blow through — the decode would fail with LZMA_MEMLIMIT_ERROR and the
    # device would boot with no baseline at all.
    dict_size = 1 << max(20, min(23, (len(payload) - 1).bit_length()))
    blob = lzma.compress(
        payload, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64,
        filters=[{"id": lzma.FILTER_LZMA2,
                  "preset": 9 | lzma.PRESET_EXTREME,
                  "dict_size": dict_size}])

    if not args.no_verify:
        got = decode(lzma.decompress(blob))
        if len(set(got)) != len(got):
            raise SystemExit("FATAL: round-trip produced duplicates")
        if args.no_collapse:
            if sorted(got) != sorted(union):
                raise SystemExit("FATAL: round-trip lost or altered domains")
        else:
            # Collapse is only sound if every dropped domain is still matched by
            # a surviving parent. Check that directly rather than trusting the
            # pass that produced it.
            survivors = set(got)
            for d in union:
                if d in survivors:
                    continue
                parts = d.split(".")
                if not any(".".join(parts[i:]) in survivors for i in range(1, len(parts))):
                    raise SystemExit(f"FATAL: collapse orphaned {d!r}")

    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(blob)

    # sha256sum-format sidecar. load_baseline() reads the first whitespace-
    # delimited field and refuses to compile ANYTHING on a mismatch, which is
    # what turns "a prebuilt rule truncated the file" from a silently smaller
    # blocklist into a named failure in sys.nullroute.seed.
    blob_sha = hashlib.sha256(blob).hexdigest()
    with open(out_path + ".sha256", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{blob_sha}  {os.path.basename(out_path)}\n")

    sys.stderr.write(
        f"\nwrote {out_path}\n"
        f"  {len(union)} domains -> {len(keys)} after suffix collapse (-{dropped})\n"
        f"  front-coded {len(payload)} B -> xz {len(blob)} B "
        f"({len(blob)/1024:.1f} KB, dict {dict_size >> 20} MiB)\n"
        f"  sha256(blob)    {blob_sha}\n"
        f"  wrote {out_path}.sha256\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
