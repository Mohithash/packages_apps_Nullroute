#!/bin/bash
#
# Nullroute — post-build assertions against the BUILT image.
#
# Run after every `mka bacon`, from the tree root:
#     packages/apps/Nullroute/tools/ci_verify_image.sh
#
# WHY THIS FILE EXISTS
# --------------------
# The single riskiest step in the whole project is landing the resolver patch
# such that it actually ships inside the APEX that the device activates, and
# stays there. Not because it is hard, but because SUCCESS AND FAILURE LOOK
# IDENTICAL FROM USERSPACE. If the APEX is rebuilt without libnrfilter, or a
# prebuilt mainline APEX is installed over the source-built one, then the app,
# the UI, the index, the sepolicy, the canary and the query log all work
# flawlessly — and the device blocks nothing. There is prior art for exactly
# this failure shape in this project (the Privacy Kit release-signer mismatch).
#
# So this script is deliberately loud, deliberately paranoid, and deliberately
# collects EVERY failure before exiting rather than stopping at the first one:
# a maintainer who has to run it six times to find six problems will stop
# running it.
#
# Environment:
#   OUT / ANDROID_PRODUCT_OUT   product out dir (default out/target/product/peridot)
#   NR_STRICT=1                 turn the advisory checks into failures too

set -uo pipefail

OUT="${ANDROID_PRODUCT_OUT:-${OUT:-out/target/product/peridot}}"
SOONG_OUT="${OUT_DIR:-out}/soong"
STRICT="${NR_STRICT:-0}"

FAILURES=0
WARNINGS=0

fail() { printf 'FAIL  %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
warn() {
    if [ "$STRICT" = "1" ]; then fail "$*"; else
        printf 'WARN  %s\n' "$*" >&2; WARNINGS=$((WARNINGS + 1))
    fi
}
ok()   { printf 'ok    %s\n' "$*"; }
head1() { printf '\n== %s\n' "$*"; }

need_file() {
    # need_file <path> <what it proves> [consequence if absent]
    if [ -f "$1" ]; then
        ok "$2"
    else
        fail "$2 — missing: $1"
        [ $# -ge 3 ] && fail "  => $3"
    fi
}

if [ ! -d "$OUT" ]; then
    printf 'FAIL  product out dir not found: %s\n' "$OUT" >&2
    printf '      set OUT= or ANDROID_PRODUCT_OUT=, or run after a build.\n' >&2
    exit 1
fi
printf 'Nullroute image verification\n  OUT=%s\n' "$OUT"

###############################################################################
head1 "1. The resolver actually contains the filter"
###############################################################################
#
# Which markers to look for, and why NOT just "NRDX":
#
# NR_MAGIC is 0x5844524E — a NUMERIC constant. On arm64 the compiler
# materialises it as a movz/movk immediate pair, so the four bytes "NRDX" are
# not necessarily a contiguous printable run and `strings` may legitimately not
# find them in a correctly patched binary. Relying on it alone gives false
# failures; relying on it alone in the other direction (it happens to appear in
# unrelated data) gives false passes.
#
# The reliable markers are real string literals that only the patch introduces:
#   /data/misc/nullroute/...   the index and control paths in NrMap
#   sys.nullroute.filter       the state property NrFilter sets
#   NullrouteFilter            the logcat tag on every failure path
# We require the lowercase "nullroute" substring (covers the first two) and
# report the others.

RESOLVER_MARKER='nullroute'

scan_for_marker() {
    # scan_for_marker <file> ; returns 0 if the marker is present
    LC_ALL=C grep -a -q "$RESOLVER_MARKER" "$1" 2>/dev/null
}

APEX_FILE=""
for cand in "$OUT"/system/apex/com.android.tethering*.apex \
            "$OUT"/system/apex/com.android.tethering*.capex \
            "$OUT"/system/apex/com.android.resolv*.apex \
            "$OUT"/system/apex/com.android.resolv*.capex; do
    [ -f "$cand" ] && { APEX_FILE="$cand"; break; }
done

RESOLVER_PROVEN=0
RESOLVER_EVIDENCE=""

if [ -n "$APEX_FILE" ]; then
    ok "found shipping APEX: $(basename "$APEX_FILE")"
    case "$APEX_FILE" in
        *.apex)
            # apex_payload.img is STORED (not deflated) inside the apex zip, so
            # the payload's strings are present as raw bytes in the .apex file
            # itself. This is the strongest available check and needs no tools:
            # it inspects the exact artefact that will be flashed.
            if scan_for_marker "$APEX_FILE"; then
                RESOLVER_PROVEN=1
                RESOLVER_EVIDENCE="raw scan of the shipping .apex"
            fi
            ;;
        *.capex)
            # Compressed apex: the payload is deflated, so a raw scan cannot
            # work. deapexer is the only honest way in.
            if command -v deapexer >/dev/null 2>&1; then
                TMPX="$(mktemp -d)"
                if deapexer extract "$APEX_FILE" "$TMPX" >/dev/null 2>&1; then
                    SO="$(find "$TMPX" -name libnetd_resolv.so 2>/dev/null | head -1)"
                    if [ -n "$SO" ] && scan_for_marker "$SO"; then
                        RESOLVER_PROVEN=1
                        RESOLVER_EVIDENCE="deapexer extract of the shipping .capex"
                    fi
                fi
                rm -rf "$TMPX"
            else
                warn "deapexer not on PATH; cannot open the compressed APEX directly"
            fi
            ;;
    esac
else
    fail "no com.android.tethering / com.android.resolv APEX in $OUT/system/apex"
fi

if [ "$RESOLVER_PROVEN" = "0" ]; then
    # Fallback: Soong's APEX staging tree. This is the same libnetd_resolv.so
    # that gets packed, but it is one step upstream of the artefact that ships,
    # so a pass here is weaker evidence and says so.
    STAGED_SO="$(find "$SOONG_OUT/.intermediates" \
                     -path '*com.android.tethering*' -name libnetd_resolv.so \
                     2>/dev/null | head -1)"
    if [ -z "$STAGED_SO" ]; then
        STAGED_SO="$(find "$SOONG_OUT/.intermediates/packages/modules/DnsResolver" \
                         -name libnetd_resolv.so 2>/dev/null | head -1)"
    fi
    if [ -n "$STAGED_SO" ] && scan_for_marker "$STAGED_SO"; then
        RESOLVER_PROVEN=1
        RESOLVER_EVIDENCE="Soong staging copy ($STAGED_SO)"
        warn "the shipping APEX itself was not opened; verified the staged .so instead"
    fi
fi

if [ "$RESOLVER_PROVEN" = "1" ]; then
    ok "resolver carries the Nullroute filter — evidence: $RESOLVER_EVIDENCE"
else
    fail "RESOLVER BUILT WITHOUT THE NULLROUTE FILTER."
    fail "  Nothing on this image will block anything, and NOTHING ELSE WILL SHOW IT."
    fail "  Check, in order:"
    fail "    1. packages/modules/DnsResolver/Android.bp — libnetd_resolv must carry"
    fail "       whole_static_libs: [\"libnrfilter\"] and header_libs: [\"libnrformat_headers\"]"
    fail "    2. -DNULLROUTE_ENABLED is in that module's cflags"
    fail "    3. the H1 hook is in the resolv_getaddrinfo() definition that carries the"
    fail "       BODY, not the thin forwarding overload"
    fail "    4. no prebuilt mainline APEX is winning — see section 2 below"
fi

# Informational only, for the reason explained above.
if [ -n "$APEX_FILE" ] && LC_ALL=C grep -a -q 'NRDX' "$APEX_FILE" 2>/dev/null; then
    ok "the literal 'NRDX' is also present in the APEX"
fi

###############################################################################
head1 "2. Anti-substitution: no prebuilt mainline APEX won"
###############################################################################
#
# The make-time guard in vendor/bestrom/config/nullroute.mk only sees what has
# been declared by the time it is included. This is the backstop, and it looks
# at the finished image where nothing can hide.

BAD_APEX="$(ls "$OUT"/system/apex/ 2>/dev/null \
            | grep -Ei 'com\.google\.android\.(go\.)?(resolv|tethering)' || true)"
if [ -n "$BAD_APEX" ]; then
    fail "a prebuilt Google mainline APEX is on the image and will win over the"
    fail "  source-built resolver: $BAD_APEX"
else
    ok "no prebuilt resolv/tethering APEX on the image"
fi

###############################################################################
head1 "3. L0 — the baked hosts floor"
###############################################################################
#
# L0 is the layer that still works when the hook is dead, the index is corrupt,
# the app is uninstalled, or the device is in safe mode. If the module override
# lost to system/core/rootdir's etc_hosts, the file is the stock two lines and
# the floor is gone — which is invisible until the day it is needed.

HOSTS="$OUT/system/etc/hosts"
if [ -f "$HOSTS" ]; then
    if grep -q 'hosts-probe' "$HOSTS"; then
        ok "L0 hosts override won (hosts-probe entry present)"
    else
        fail "L0 hosts override did NOT win — $HOSTS has no hosts-probe line."
        fail "  \`overrides: [\"etc_hosts\"]\` lost. Run Spike 6 and switch to the"
        fail "  PRODUCT_COPY_FILES fallback documented in rom/nullroute.mk."
    fi
    HOSTS_LINES="$(wc -l < "$HOSTS" | tr -d ' ')"
    if [ "$HOSTS_LINES" -lt 500 ]; then
        fail "hosts file is only $HOSTS_LINES lines — the curated ~2,000-entry"
        fail "  core did not land; tools/gen_l0_hosts.py probably produced a stub."
    else
        ok "hosts file carries $HOSTS_LINES lines"
    fi
else
    fail "no $HOSTS at all"
fi

###############################################################################
head1 "4. The app and its ROM configuration"
###############################################################################

need_file "$OUT/system_ext/priv-app/Nullroute/Nullroute.apk" \
          "app installed as a privileged system_ext app"

need_file "$OUT/system_ext/etc/permissions/privapp-permissions-com.bestrom.nullroute.xml" \
          "privapp permission allowlist" \
          "under ro.control_privapp_permissions=enforce this ABORTS BOOT"
need_file "$OUT/system_ext/etc/permissions/nullroute-gid.xml" \
          "permission->gid misc mapping" \
          "without gid 9998 the app cannot traverse /data/misc at all"
need_file "$OUT/system_ext/etc/sysconfig/preinstalled-packages-platform-nullroute.xml" \
          "preinstall user-type config"
need_file "$OUT/system_ext/etc/sysconfig/sysconfig-nullroute.xml" \
          "power-save / data-saver exemptions" \
          "Doze then suppresses the refresh job and the blocklist silently goes stale"
need_file "$OUT/system_ext/etc/default-permissions/default-permissions-nullroute.xml" \
          "POST_NOTIFICATIONS pre-grant" \
          "a dead filter would have no way to tell the user"
need_file "$OUT/system_ext/etc/init/init.nullroute.rc" \
          "init script" \
          "no state dirs, no seeder, and netd finds nothing to map"

need_file "$OUT/system_ext/bin/nullroute_seed" "boot seeder binary"
need_file "$OUT/system_ext/bin/nrctl" "nrctl CLI"

need_file "$OUT/system_ext/etc/nullroute/baseline.domains.xz" \
          "baked baseline domains" \
          "first boot after a flash would filter nothing but L0"
need_file "$OUT/system_ext/etc/nullroute/baseline.domains.xz.sha256" \
          "baseline integrity sidecar" \
          "nullroute_seed only verifies the baseline IF this file is present; without it the check silently does not happen"
need_file "$OUT/system_ext/etc/nullroute/neverblock.txt" \
          "ALLOW_FORCE floor"
need_file "$OUT/system_ext/etc/nullroute/antifraud.txt" \
          "anti-fraud carve-out"
need_file "$OUT/system_ext/etc/nullroute/attribution.txt" \
          "attribution / deferred-deep-link carve-out" \
          "without it the MMP category blocks deep links and apps open to a blank screen"
for p in lite balanced aggressive; do
    need_file "$OUT/system_ext/etc/nullroute/profiles/$p.txt" "profile: $p"
done

# --- the shell arm of the nrctl control channel ---------------------------
#
# uid 0 and uid 1000 short-circuit checkComponentPermission(); uid 2000 does not,
# and com.android.shell cannot <uses-permission> a permission it has never heard
# of. Without this line `nrctl pause` from adb is dropped and `am` still prints
# result=0 — a mutating CLI that silently no-ops.
GIDXML="$OUT/system_ext/etc/permissions/nullroute-gid.xml"
if [ -f "$GIDXML" ]; then
    if grep -q 'assign-permission' "$GIDXML"; then
        ok "nrctl's shell arm is enabled (assign-permission present)"
    else
        fail "$GIDXML has no <assign-permission ... uid=\"shell\"/> —"
        fail "  nrctl's mutating verbs will silently do nothing from adb shell"
    fi
fi

# --- XML well-formedness --------------------------------------------------
#
# Every file in this section is parsed at boot by SystemConfig /
# DefaultPermissionGrantPolicy, and a parse error there is caught, logged once
# and otherwise ignored: the permission->gid mapping, the privapp allowlist or
# the Doze exemption simply does not exist, with a working-looking device to
# show for it. The trap that actually bit this repo was a `-----` underline
# inside an XML comment (`--` is not permitted in a comment), which no reviewer
# reads as a syntax error.
#
# The checker is chosen by PROVING it can parse, not by `command -v`: a stub on
# PATH that exits non-zero for every argument (the Windows Store python3 shim is
# the one people hit) would otherwise report every file as malformed and make the
# whole script cry wolf.
XMLPY=""
XMLLINT=""
for c in python3 python; do
    command -v "$c" >/dev/null 2>&1 || continue
    "$c" -c 'import xml.dom.minidom' >/dev/null 2>&1 && { XMLPY="$c"; break; }
done
if [ -z "$XMLPY" ] && command -v xmllint >/dev/null 2>&1; then
    printf '<a/>' > "$OUT/.nr_xmlprobe" 2>/dev/null &&
        xmllint --noout "$OUT/.nr_xmlprobe" >/dev/null 2>&1 && XMLLINT=1
    rm -f "$OUT/.nr_xmlprobe"
fi

xml_wellformed() {
    if [ -n "$XMLPY" ]; then
        "$XMLPY" -c 'import sys,xml.dom.minidom as m; m.parse(sys.argv[1])' "$1" \
            >/dev/null 2>&1
    else
        xmllint --noout "$1" >/dev/null 2>&1
    fi
}

if [ -z "$XMLPY" ] && [ -z "$XMLLINT" ]; then
    warn "no working python/xmllint on PATH; XML well-formedness not checked"
else
    for x in "$OUT"/system_ext/etc/permissions/*nullroute*.xml \
             "$OUT"/system_ext/etc/sysconfig/*nullroute*.xml \
             "$OUT"/system_ext/etc/default-permissions/*nullroute*.xml; do
        [ -f "$x" ] || continue
        if xml_wellformed "$x"; then
            ok "well-formed XML: $(basename "$x")"
        else
            fail "MALFORMED XML: $x"
            fail "  SystemConfig logs one exception and skips the WHOLE file"
        fi
    done
fi

# --- manifest vs privapp allowlist ----------------------------------------
#
# Under ro.control_privapp_permissions=enforce a signature|privileged permission
# in the manifest but not in the allowlist ABORTS BOOT, and the allowlist is
# frozen in the signed image. This cannot decide protectionLevel from here, so it
# lists the delta and makes a human look; over-listing the allowlist is free.
APK="$OUT/system_ext/priv-app/Nullroute/Nullroute.apk"
PRIVXML="$OUT/system_ext/etc/permissions/privapp-permissions-com.bestrom.nullroute.xml"
if [ -f "$APK" ] && [ -f "$PRIVXML" ] && command -v aapt2 >/dev/null 2>&1; then
    MISSING="$(aapt2 dump permissions "$APK" 2>/dev/null \
               | sed -n "s/^uses-permission: name='\(android\.permission\.[A-Z_]*\)'.*/\1/p" \
               | sort -u \
               | while read -r perm; do
                     grep -q "\"$perm\"" "$PRIVXML" || printf '%s ' "$perm"
                 done)"
    if [ -n "$MISSING" ]; then
        warn "manifest requests these android.permission.* that are NOT in the"
        warn "  privapp allowlist: $MISSING"
        warn "  Each one is fine ONLY if its protectionLevel lacks |privileged."
        warn "  Check before shipping: a wrong guess here aborts boot on a user build."
    else
        ok "every android.permission.* the manifest requests is allowlisted"
    fi
elif [ -f "$APK" ]; then
    warn "aapt2 not on PATH; manifest-vs-privapp-allowlist delta not checked"
fi

###############################################################################
head1 "5. SELinux landed"
###############################################################################

SEDIR="$OUT/system_ext/etc/selinux"
if [ -d "$SEDIR" ]; then
    for t in nullroute_index_file nullroute_ctl_file nullroute_log_file \
             nullroute_data_file nullroute_app nullroute_seed; do
        if grep -rqs "$t" "$SEDIR"; then
            ok "sepolicy type present: $t"
        else
            fail "sepolicy type MISSING from the built policy: $t"
        fi
    done

    if grep -rqs 'nullroute_prop' "$SEDIR"; then
        ok "property contexts carry nullroute_prop"
    else
        fail "nullroute_prop is not in the built property contexts — sys.nullroute.filter"
        fail "  will land on default_prop and netd's set_prop will be denied"
    fi

    # --- seapp_contexts ordering -------------------------------------------
    #
    # If a broader isPrivApp=true catch-all is evaluated first, the app lands in
    # priv_app instead of nullroute_app. Every rule in nullroute_app.te then
    # applies to a domain the app is never in: the UI works, the index builds,
    # the promotion succeeds, and netd blocks nothing — with no denial to
    # explain it, because priv_app appears in none of our rules.
    SEAPP=""
    for f in "$SEDIR/system_ext_seapp_contexts" \
             "$OUT/system/etc/selinux/plat_seapp_contexts"; do
        if [ -f "$f" ] && grep -q 'com\.bestrom\.nullroute' "$f"; then SEAPP="$f"; break; fi
    done
    if [ -z "$SEAPP" ]; then
        fail "no seapp_contexts entry for com.bestrom.nullroute anywhere on the image"
        fail "  => the app will run as priv_app and every nullroute_* grant is dead"
    else
        ok "seapp_contexts entry found in $(basename "$SEAPP")"
        NR_LINE="$(grep -n 'com\.bestrom\.nullroute' "$SEAPP" | head -1 | cut -d: -f1)"
        # A catch-all is an isPrivApp=true line with no name= qualifier.
        CATCHALL_LINE="$(grep -n 'isPrivApp=true' "$SEAPP" | grep -v 'name=' \
                         | head -1 | cut -d: -f1)"
        if [ -n "$CATCHALL_LINE" ] && [ "$NR_LINE" -gt "$CATCHALL_LINE" ]; then
            fail "seapp_contexts ORDERING: the nullroute entry is on line $NR_LINE but an"
            fail "  isPrivApp=true catch-all is on line $CATCHALL_LINE. Move ours above it."
        else
            ok "seapp_contexts ordering is correct"
        fi
    fi
else
    fail "no $SEDIR — system_ext sepolicy did not build"
fi

###############################################################################
head1 "6. addon.d must not restore a stale hosts file"
###############################################################################
#
# The addon.d survival list is applied by the OTA, after the new image is
# written. If etc/hosts is still in it, the first OTA silently reinstates the
# pre-OTA hosts file over the freshly built one — and it does so for the addon.d
# generation, not for this build, so every check you run today passes.
#
# BestROM: the file is 50-voltage.sh, not 50-lineage.sh, and nothing in the tree
# currently installs it, so no /system/addon.d is produced. Both names are
# checked so this stays honest on either tree; the source path missing entirely
# is itself reported, because a check that quietly matches nothing reads as a
# pass and that is the failure class this whole script exists to prevent.

_nr_addond_seen=0
for f in vendor/voltage/prebuilt/common/bin/50-voltage.sh \
         vendor/lineage/prebuilt/common/bin/50-lineage.sh \
         "$OUT/system/addon.d/50-voltage.sh" \
         "$OUT/system/addon.d/50-lineage.sh"; do
    if [ -f "$f" ]; then
        _nr_addond_seen=1
        if grep -q 'etc/hosts' "$f"; then
            fail "$f still lists etc/hosts in the addon.d survival list —"
            fail "  the first OTA will restore a stale hosts file over L0"
        else
            ok "$f no longer restores etc/hosts"
        fi
    fi
done
if [ "$_nr_addond_seen" = 0 ]; then
    warn "no addon.d survival script found in the tree or the image"
    warn "  nothing can restore a stale hosts file, but check the paths above"
fi

###############################################################################
head1 "Result"
###############################################################################

if [ "$FAILURES" -gt 0 ]; then
    printf '\nFAILED: %d problem(s), %d warning(s).\n' "$FAILURES" "$WARNINGS" >&2
    printf 'Do not flash this image expecting it to filter.\n' >&2
    exit 1
fi

if [ "$WARNINGS" -gt 0 ]; then
    printf '\nOK with %d warning(s). Re-run with NR_STRICT=1 to treat them as failures.\n' \
        "$WARNINGS"
else
    printf '\nOK\n'
fi

# Passing this script proves the artefacts are on the image. It does NOT prove
# the hook fires on the device — only Spike 1 and Spike 3 do that:
#   adb shell grep libnetd_resolv /proc/$(adb shell pidof netd)/maps
#   adb shell getprop sys.nullroute.filter        # must read ok:<gen>, not nomap:13
#   adb shell getent hosts idx-probe.nullroute.invalid   # must return 127.0.0.7
#   adb shell dmesg | grep 'avc.*nullroute'              # must be empty
exit 0
