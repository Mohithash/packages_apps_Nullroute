#!/bin/bash
#
# Nullroute — apply the resolver patch to packages/modules/DnsResolver.
#
#   apply.sh [--check|--revert] [<path to DnsResolver>]
#
# Why this is a script and not a set of .patch files: the four hunks land in
# functions whose SIGNATURES differ between AOSP main, Lineage and the various
# forks — `resolv_getaddrinfo()` has gained and lost parameters more than once,
# and getaddrinfo.cpp carries more than one declaration of it. A context diff
# against one tree either fails, or — far worse — applies with fuzz into the
# WRONG overload and produces a resolver that builds, boots and filters nothing.
# So we locate the definition that actually carries the body, assert that every
# identifier the hunk references exists in that signature, and refuse to guess.
#
# Two rules govern everything below:
#   1. IDEMPOTENT. Every insertion is fenced by NULLROUTE-BEGIN/END and skipped
#      if already present. Re-running is a no-op.
#   2. ALL OR NOTHING. Edits are staged into a temp directory and verified there;
#      the tree is only touched once every hunk is known good. A half-applied
#      patch is the failure mode this project can least afford, because it
#      compiles.
set -euo pipefail

BEGIN_MARK='// NULLROUTE-BEGIN'
END_MARK='// NULLROUTE-END'
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_FILES="NrFilter.h NrFilter.cpp nr_hook.h NrRingWriter.cpp"

MODE=apply
case "${1:-}" in
    --check)   MODE=check;  shift ;;
    --revert)  MODE=revert; shift ;;
    --help|-h) sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
esac

DNS="${1:-${ANDROID_BUILD_TOP:-}/packages/modules/DnsResolver}"

die()  { printf '\n!! FAILED: %s\n' "$*" >&2; exit 1; }
warn() { printf '## WARNING: %s\n' "$*" >&2; }
info() { printf '   %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[ -d "$DNS" ] || die "no such directory: $DNS (pass it as \$1, or set ANDROID_BUILD_TOP)"
GAI="$DNS/getaddrinfo.cpp"
GHN="$DNS/gethnamaddr.cpp"
BP="$DNS/Android.bp"
for f in "$GAI" "$GHN" "$BP"; do
    [ -f "$f" ] || die "$f is missing — is $DNS really packages/modules/DnsResolver?"
done
for f in $SRC_FILES; do
    [ -f "$SELF_DIR/nullroute/$f" ] || die "$SELF_DIR/nullroute/$f is missing"
done

# ---------------------------------------------------------------------------
# --revert
# ---------------------------------------------------------------------------
if [ "$MODE" = revert ]; then
    step "Reverting"
    for f in "$GAI" "$GHN" "$BP"; do
        awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
            index($0, b) { skip = 1 }
            !skip        { print }
            index($0, e) { skip = 0 }
        ' "$f" > "$f.nr.tmp"
        mv "$f.nr.tmp" "$f"
        info "cleaned $(basename "$f")"
    done
    rm -rf "$DNS/nullroute"
    info "removed $DNS/nullroute"
    echo; echo "OK — reverted."
    exit 0
fi

# ---------------------------------------------------------------------------
# Locating a definition
#
# Emits "<first line>:<line carrying the opening brace>:<kind>:<signature text>"
# for every occurrence, where kind is decl / fwd / body / unterminated. The
# caller asserts on the signature text before referencing any parameter by name.
# ---------------------------------------------------------------------------
find_definition() {   # <file> <return-type regex> <function name>
    awk -v want="$3" -v rt="$2" '
        function flush(kind) { print start ":" brace ":" kind ":" sig; state = 0 }
        state == 0 && $0 ~ ("^[ \t]*(static[ \t]+)?" rt "[ \t]+" want "[ \t]*\\(") {
            start = NR; sig = $0; state = 1
        }
        state == 1 {
            if (NR > start) sig = sig " " $0
            if ($0 ~ /;[ \t]*$/)  { brace = 0;  flush("decl");         next }
            if ($0 ~ /\{[ \t]*$/) { brace = NR; state = 2; look = 0; body = ""; next }
            if (NR - start > 16)  { brace = 0;  flush("unterminated"); next }
            next
        }
        state == 2 {
            # A thin forwarding overload delegates immediately; the definition
            # that carries the real body does not. Decide as early as possible —
            # scanning a fixed window past the brace would swallow the start of
            # the NEXT overload, which is exactly the one we are looking for.
            if ($0 ~ ("return[ \t]+" want "[ \t]*\\(")) { flush("fwd");  next }
            if ($0 ~ /^\}/)                             { flush("body"); next }
            if (++look >= 8)                            { flush("body"); next }
            next
        }
        END { if (state == 2) flush("body") }
    ' "$1"
}

pick_body_definition() {   # <file> <return-type regex> <function name>
    local file="$1" rt="$2" fn="$3" all bodies n
    all="$(find_definition "$file" "$rt" "$fn" || true)"
    [ -n "$all" ] || die "no definition of $fn() in $(basename "$file") — the tree has moved; patch by hand and update apply.sh"
    bodies="$(printf '%s\n' "$all" | awk -F: '$3 == "body"')"
    n="$(printf '%s\n' "$bodies" | grep -c . || true)"
    if [ "$n" -ne 1 ]; then
        printf '\nCandidates for %s() in %s:\n' "$fn" "$(basename "$file")" >&2
        printf '%s\n' "$all" | awk -F: '{ printf "   line %-6s %s\n", $1, $3 }' >&2
        die "expected exactly one body-carrying definition of $fn(), found $n. Refusing to guess which overload to hook."
    fi
    printf '%s\n' "$bodies"
}

# Assert that every identifier a hunk references really exists in the signature
# being patched. This is what keeps the hook signature-AGNOSTIC without letting
# it become signature-BLIND.
require_params() {   # <signature text> <what> <ident...>
    local sig="$1" what="$2" p; shift 2
    for p in "$@"; do
        printf '%s' "$sig" | grep -Eq "[^A-Za-z0-9_]${p}[^A-Za-z0-9_]" || die \
"$what: parameter '$p' is not in this tree's signature. Patch by hand and update apply.sh.
        signature seen: $sig"
    done
}

already() { grep -q 'NULLROUTE-BEGIN' "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Editing primitives — all operate on staged copies.
#
# head/tail rather than `awk -v text=...`: the inserted blocks are multi-line and
# contain quotes and slashes, and pushing them through an awk variable is a
# quoting accident waiting to happen.
# ---------------------------------------------------------------------------
insert_after_file() {   # <target> <line> <file holding the text>
    local t="$1" n="$2" txt="$3"
    { head -n "$n" "$t"; cat "$txt"; tail -n "+$((n + 1))" "$t"; } > "$t.tmp"
    mv "$t.tmp" "$t"
}

insert_include() {   # <target> <#include line>
    local last tmp
    last="$(grep -n '^#include' "$1" | tail -1 | cut -d: -f1)"
    [ -n "$last" ] || die "$(basename "$1") has no #include block"
    tmp="$WORK/inc.$$"
    printf '%s\n%s\n%s\n' "$BEGIN_MARK" "$2" "$END_MARK" > "$tmp"
    insert_after_file "$1" "$last" "$tmp"
}

# Add entries to an array property of a Soong module, creating the property if
# absent and expanding a single-line array into the multi-line form so the
# NULLROUTE markers can fence our entries (which is what makes --revert exact).
#
# Soong rejects a duplicated key outright, so blindly appending a second
# `header_libs: [...]` to a module that already has one turns the whole build
# into a parse error. Hence the merge rather than an append.
bp_add_array() {   # <file> <module> <property> <entries as bp text>
    local file="$1" mod="$2" prop="$3" add="$4" range s e
    range="$(awk -v mod="$mod" '
        /^[A-Za-z_]+[ \t]*\{/                      { start = NR; found = 0 }
        $0 ~ ("name:[ \t]*\"" mod "\"[ \t]*,")     { found = 1 }
        /^\}/ { if (found) { print start "," NR; exit } }
    ' "$file")"
    [ -n "$range" ] || die "module $mod not found in $(basename "$file")"
    s="${range%,*}"; e="${range#*,}"

    awk -v s="$s" -v e="$e" -v prop="$prop" -v add="$add" -v b="$BEGIN_MARK" -v em="$END_MARK" '
        BEGIN { done = 0 }
        {
            if (NR < s || NR > e || done) { print; next }
            if ($0 ~ ("^[ \t]*" prop "[ \t]*:[ \t]*\\[")) {
                i = index($0, "[")
                j = index($0, "]")
                if (j > 0) {
                    match($0, /^[ \t]*/); ind = substr($0, 1, RLENGTH)
                    inner = substr($0, i + 1, j - i - 1)
                    gsub(/^[ \t]+|[ \t]+$/, "", inner)
                    print substr($0, 1, i)
                    if (inner != "") {
                        if (inner !~ /,$/) inner = inner ","
                        printf "%s    %s\n", ind, inner
                    }
                    printf "%s    %s\n%s    %s\n%s    %s\n", ind, b, ind, add, ind, em
                    printf "%s%s\n", ind, substr($0, j)
                } else {
                    print
                    printf "        %s\n        %s\n        %s\n", b, add, em
                }
                done = 1
                next
            }
            if (NR == e) {
                one = add
                sub(/,[ \t]*$/, "", one)   # no dangling comma in a fresh one-line list
                printf "    %s\n    %s: [%s],\n    %s\n", b, prop, one, em
                print
                done = 1
                next
            }
            print
        }
        END { if (!done) exit 3 }
    ' "$file" > "$file.tmp" || die "could not add $prop to $mod in $(basename "$file")"
    mv "$file.tmp" "$file"
}

# ---------------------------------------------------------------------------
# Locate every hook site BEFORE touching anything
# ---------------------------------------------------------------------------
step "Locating hook sites in $DNS"

H1="$(pick_body_definition "$GAI" 'int' 'resolv_getaddrinfo')"
H1_BRACE="$(printf '%s' "$H1" | cut -d: -f2)"
H1_SIG="$(printf '%s' "$H1" | cut -d: -f4-)"
[ "$H1_BRACE" != "0" ] || die "resolv_getaddrinfo(): no opening brace found"
require_params "$H1_SIG" "H1 resolv_getaddrinfo" hostname servname hints netcontext res
info "H1 resolv_getaddrinfo() body opens at line $H1_BRACE"

H4="$(pick_body_definition "$GAI" 'bool' 'files_getaddrinfo')"
H4_BRACE="$(printf '%s' "$H4" | cut -d: -f2)"
H4_SIG="$(printf '%s' "$H4" | cut -d: -f4-)"
[ "$H4_BRACE" != "0" ] || die "files_getaddrinfo(): no opening brace found"
# H4 is a PERFORMANCE hunk and nothing else, so it is allowed to be inert but
# never allowed to be wrong. Without the queried name the predicate cannot tell
# `localhost` — which only /system/etc/hosts can answer — from a blocklist entry,
# so nr_hosts_layer_superseded(nullptr) returns false and the hunk compiles to a
# never-taken branch. Losing ~79 us on a cold query beats breaking loopback
# resolution device-wide.
if printf '%s' "$H4_SIG" | grep -Eq '[^A-Za-z0-9_]name[^A-Za-z0-9_]'; then
    H4_ARG='name'
else
    warn "files_getaddrinfo() has no parameter named 'name'; H4 will be INERT (the L0 hosts scan
             always runs). Everything still works, the cold-query fast path is just not taken.
             Fix by finding this tree's name parameter and updating the H4_ARG detection above."
    H4_ARG=''
fi
info "H4 files_getaddrinfo() body opens at line $H4_BRACE"

H2="$(pick_body_definition "$GHN" 'int' 'resolv_gethostbyname')"
H2_BRACE="$(printf '%s' "$H2" | cut -d: -f2)"
H2_SIG="$(printf '%s' "$H2" | cut -d: -f4-)"
[ "$H2_BRACE" != "0" ] || die "resolv_gethostbyname(): no opening brace found"
require_params "$H2_SIG" "H2 resolv_gethostbyname" name af hp buf buflen netcontext result
info "H2 resolv_gethostbyname() body opens at line $H2_BRACE"

# getaddrinfo_numeric() is the only resolver-internal symbol the patch calls. If
# a fork renamed or re-shaped it, the V_REDIRECT path — and with it the idx-probe
# liveness check, the one signal that proves the hook is live — stops working.
#
# It is preferred over the sibling explore_numeric() for three reasons: it has
# external linkage (explore_numeric is static, so its visibility depends on where
# the forward declaration sits relative to our hunk), it takes hints BY VALUE so
# there is no caller-owned pointer to outlive the call, and it is the very
# function _gethtent() uses to turn a hosts-file address string into an addrinfo
# — which is exactly what a redirect verdict is.
grep -qE '^[a-z_ ]*int[[:space:]]+getaddrinfo_numeric[[:space:]]*\(' "$GAI" || die \
    "getaddrinfo_numeric() not found in getaddrinfo.cpp; the V_REDIRECT hunk has nothing to call"

if [ "$MODE" = check ]; then
    if already "$GAI" && already "$GHN" && already "$BP" && [ -f "$DNS/nullroute/NrFilter.cpp" ]; then
        echo; echo "OK — patch is applied."
        exit 0
    fi
    echo; echo "NOT APPLIED (all hook sites located successfully; run without --check to apply)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Stage every edit, verify, then install
# ---------------------------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$GAI" "$WORK/getaddrinfo.cpp"
cp "$GHN" "$WORK/gethnamaddr.cpp"
cp "$BP"  "$WORK/Android.bp"

step "Staging edits"

# --- Android.bp ------------------------------------------------------------
if already "$WORK/Android.bp"; then
    info "Android.bp already patched"
else
    bp_add_array "$WORK/Android.bp" libnetd_resolv srcs \
        '"nullroute/NrFilter.cpp", "nullroute/NrRingWriter.cpp",'
    # libnrformat_headers is the SINGLE source of truth for the on-disk format.
    # There is deliberately no copied header in this tree: two byte-identical
    # copies drift the first time one repo is rebased and the other is not, and
    # the failure mode is a silently mis-parsed index inside netd.
    bp_add_array "$WORK/Android.bp" libnetd_resolv header_libs      '"libnrformat_headers",'
    bp_add_array "$WORK/Android.bp" libnetd_resolv whole_static_libs '"libnrfilter",'
    bp_add_array "$WORK/Android.bp" libnetd_resolv cflags            '"-DNULLROUTE_ENABLED",'
    info "Android.bp: srcs + header_libs + whole_static_libs + cflags"
fi

# --- getaddrinfo.cpp: H1 and H4 --------------------------------------------
if already "$WORK/getaddrinfo.cpp"; then
    info "getaddrinfo.cpp already patched"
else
    cat > "$WORK/h4.txt" <<EOF
$BEGIN_MARK
#ifdef NULLROUTE_ENABLED
    // L1 is authoritative, so skip the linear rescan of /system/etc/hosts that
    // this function performs — fopen, fgets, strcasecmp per token — on EVERY
    // cache-missing query.
    if (nr::hostsLayerSuperseded($H4_ARG)) return false;
#endif
$END_MARK
EOF
    cat > "$WORK/h1.txt" <<EOF
$BEGIN_MARK
#ifdef NULLROUTE_ENABLED
    // The null guard is NOT redundant with this function's own argument
    // validation. That validation sits a few lines BELOW; this hunk runs first,
    // by design, so that a block short-circuits everything downstream of it.
    // Dereferencing a null netcontext here would be a SIGSEGV inside netd, whose
    // init stanza carries \`onrestart restart zygote\` — a boot loop, not a failed
    // lookup. One perfectly-predicted branch is the whole cost of never finding
    // that out on a user's device.
    if (netcontext != nullptr && res != nullptr) {
        // netcontext->uid is the real caller uid — netd reads it from SO_PEERCRED
        // on the dnsproxyd socket — which is what makes per-app policy correct at
        // this layer and only approximate in any VpnService design.
        const nr::Verdict nrv = nr::hook(hostname, netcontext->uid);
        if (nrv.kind == nr::V_BLOCK) return nr::blockErrno();
        if (nrv.kind == nr::V_REDIRECT) {
            char nraddr[INET6_ADDRSTRLEN];
            if (nr::formatAddr(nrv, nraddr, sizeof(nraddr))) {
                // A fresh addrinfo rather than a copy of the caller's hints:
                // inheriting AI_CANONNAME would make the resolver try to fill a
                // canonical name for a synthetic answer.
                addrinfo nrpai = {};
                nrpai.ai_family = hints ? hints->ai_family : AF_UNSPEC;
                nrpai.ai_socktype = hints ? hints->ai_socktype : 0;
                nrpai.ai_protocol = hints ? hints->ai_protocol : 0;
                // RE-ENTRANCY, deliberate and bounded to exactly one extra level:
                // getaddrinfo_numeric() is a thin wrapper that calls back into
                // this very function with AI_NUMERICHOST. Termination rests on
                // nraddr always being a numeric literal (it comes from
                // inet_ntop) and on nr_canonicalize() refusing IP literals, so
                // the inner call returns V_PASS before it can redirect again.
                // If you ever make the matcher able to match an IP literal, this
                // becomes unbounded recursion inside netd — read nr_is_ip_literal()
                // before touching it.
                return getaddrinfo_numeric(nraddr, servname, nrpai, res);
            }
            // The address could not be rendered. Falling through would resolve,
            // for real, a name the policy already decided to intercept — a
            // SILENT filtering failure, which is the only outcome worse than a
            // loud one. Fail-open covers Nullroute being broken, not Nullroute
            // having already reached a verdict; degrade to the block.
            return nr::blockErrno();
        }
    }
#endif
$END_MARK
EOF
    # Apply the higher line number first so the other one stays valid, whichever
    # order the two functions happen to appear in.
    if [ "$H4_BRACE" -gt "$H1_BRACE" ]; then
        insert_after_file "$WORK/getaddrinfo.cpp" "$H4_BRACE" "$WORK/h4.txt"
        insert_after_file "$WORK/getaddrinfo.cpp" "$H1_BRACE" "$WORK/h1.txt"
    else
        insert_after_file "$WORK/getaddrinfo.cpp" "$H1_BRACE" "$WORK/h1.txt"
        insert_after_file "$WORK/getaddrinfo.cpp" "$H4_BRACE" "$WORK/h4.txt"
    fi
    insert_include "$WORK/getaddrinfo.cpp" '#include "nullroute/nr_hook.h"'
    info "getaddrinfo.cpp: H1 + H4 + include"
fi

# --- gethnamaddr.cpp: H2 ---------------------------------------------------
if already "$WORK/gethnamaddr.cpp"; then
    info "gethnamaddr.cpp already patched"
else
    cat > "$WORK/h2.txt" <<EOF
$BEGIN_MARK
#ifdef NULLROUTE_ENABLED
    // Guarded for the same reason as H1: this hunk runs before the function's own
    // argument validation, and both pointers are dereferenced below. A null deref
    // in netd restarts zygote.
    if (netcontext != nullptr && result != nullptr) {
        const nr::Verdict nrv = nr::hook(name, netcontext->uid);
        if (nrv.kind == nr::V_BLOCK) {
            *result = nullptr;
            return nr::blockErrno();
        }
        if (nrv.kind == nr::V_REDIRECT) {
            // getent(1) and every legacy gethostbyname() caller arrives here and
            // not through getaddrinfo, so the idx-probe liveness check has to
            // work on this path too.
            if (nr::fillHostent(nrv, name, af, hp, buf, buflen, result) == 0) return 0;
            // Wrong address family for this caller, or a scratch buffer too small
            // to hold the answer. Continuing to the normal lookup would resolve a
            // name the policy already intercepted, so degrade to the block rather
            // than leak past a verdict we have already reached.
            *result = nullptr;
            return nr::blockErrno();
        }
    }
#endif
$END_MARK
EOF
    insert_after_file "$WORK/gethnamaddr.cpp" "$H2_BRACE" "$WORK/h2.txt"
    insert_include "$WORK/gethnamaddr.cpp" '#include "nullroute/nr_hook.h"'
    info "gethnamaddr.cpp: H2 + include"
fi

# ---------------------------------------------------------------------------
# Verify the staged result before a single byte of the tree changes
# ---------------------------------------------------------------------------
step "Verifying staged result"
check_staged() {   # <file> <needle> <description>
    grep -q "$2" "$1" || die "staged $(basename "$1") is missing $3 — the tree was NOT modified"
}
check_staged "$WORK/Android.bp"      'nullroute/NrFilter.cpp'    'the srcs entry'
check_staged "$WORK/Android.bp"      'libnrformat_headers'       'header_libs'
check_staged "$WORK/Android.bp"      'libnrfilter'               'whole_static_libs'
check_staged "$WORK/Android.bp"      'NULLROUTE_ENABLED'         'the cflags define'
check_staged "$WORK/getaddrinfo.cpp" 'nr::hook(hostname'         'the H1 hunk'
check_staged "$WORK/getaddrinfo.cpp" 'nr::hostsLayerSuperseded'  'the H4 hunk'
check_staged "$WORK/getaddrinfo.cpp" 'nullroute/nr_hook.h'       'the include'
check_staged "$WORK/gethnamaddr.cpp" 'nr::hook(name'             'the H2 hunk'
check_staged "$WORK/gethnamaddr.cpp" 'nullroute/nr_hook.h'       'the include'

# Exactly one hook per site, no matter how many times this has been run.
for pair in 'getaddrinfo.cpp:nr::hook(hostname' 'gethnamaddr.cpp:nr::hook(name'; do
    f="${pair%%:*}"; n="${pair#*:}"
    c="$(grep -c "$n" "$WORK/$f" || true)"
    [ "$c" -eq 1 ] || die "staged $f has $c copies of the hook — idempotency is broken, the tree was NOT modified"
done
info "all hunks present exactly once"

step "Installing"
mkdir -p "$DNS/nullroute"
for f in $SRC_FILES; do
    if cmp -s "$SELF_DIR/nullroute/$f" "$DNS/nullroute/$f" 2>/dev/null; then
        info "nullroute/$f unchanged"
    else
        cp "$SELF_DIR/nullroute/$f" "$DNS/nullroute/$f"
        info "nullroute/$f installed"
    fi
done
cp "$WORK/Android.bp"      "$BP"
cp "$WORK/getaddrinfo.cpp" "$GAI"
cp "$WORK/gethnamaddr.cpp" "$GHN"
info "tree updated"

# ---------------------------------------------------------------------------
# Neighbouring-module sanity. Not fatal — apply.sh owns the resolver side only —
# but this exact mismatch is invisible at runtime, so say it loudly.
# ---------------------------------------------------------------------------
APP_BP="${ANDROID_BUILD_TOP:-}/packages/apps/Nullroute/Android.bp"
if [ -f "$APP_BP" ]; then
    APEX="$(grep -oE 'com\.android\.(tethering|resolv)' "$BP" | sort -u | head -1 || true)"
    if [ -n "$APEX" ] && ! grep -q "$APEX" "$APP_BP"; then
        warn "libnetd_resolv ships in $APEX, but packages/apps/Nullroute/Android.bp does not name it in
             apex_available for libnrfilter / libnrformat_headers. The APEX build will fail — or, worse,
             drop the filter. Add \"$APEX\" to apex_available on both modules."
    fi
fi

cat <<'DONE'

OK — patch applied.

Next:
    mka libnrformat_headers libnrfilter
    mka libnetd_resolv
    mka bacon && tools/ci_verify_image.sh

Then work through resolver-patch/README.md on the device. Landing this patch such
that it actually ships inside the ACTIVATED APEX is the single riskiest step in
the project: success and failure look identical from userspace.
DONE
