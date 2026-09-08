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
#
# H3 and H5 are allowed to be absent. `android.net.DnsResolver`'s raw-query path
# did not always exist and a fork is free not to carry it; H5 anchors on a CALL
# rather than on a function's opening brace, which is the least stable kind of
# anchor there is. Both are therefore located independently and REPORTED AS
# SKIPPED rather than failing the run — H1, H2 and H4 cover ~99% of traffic and
# must never be held hostage to either.
set -euo pipefail

BEGIN_MARK='// NULLROUTE-BEGIN'
END_MARK='// NULLROUTE-END'
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_FILES="NrFilter.h NrFilter.cpp nr_hook.h NrRingWriter.cpp NrResSend.cpp nr_wire.h NrCname.h NrCname.cpp"

MODE=apply
case "${1:-}" in
    --check)   MODE=check;  shift ;;
    --revert)  MODE=revert; shift ;;
    # Prints the header block above, up to (not including) the `set -euo` line,
    # so extending that comment never silently truncates --help.
    --help|-h) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d'; exit 0 ;;
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
    # Every file H3 could have landed in, whether or not it did. Files without a
    # marker are left ALONE rather than rewritten: an awk round-trip through a
    # file we never touched is a needless chance to lose a missing trailing
    # newline, and `--revert` has to be byte-exact for the verification gate to
    # be able to prove it.
    for f in "$GAI" "$GHN" "$BP" \
             "$DNS/res_send.cpp" "$DNS/DnsProxyListener.cpp" "$DNS/DnsResolver.cpp" \
             "$DNS/resolv.cpp"; do
        [ -f "$f" ] || continue
        grep -q 'NULLROUTE-BEGIN' "$f" || continue
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

# The single body-carrying definition, or nothing. Non-fatal — used where a
# missing definition is a legitimate outcome (H3).
try_body_definition() {   # <file> <return-type regex> <function name>
    local file="$1" rt="$2" fn="$3" bodies n
    [ -f "$file" ] || return 1
    bodies="$(find_definition "$file" "$rt" "$fn" 2>/dev/null | awk -F: '$3 == "body"' || true)"
    n="$(printf '%s\n' "$bodies" | grep -c . || true)"
    [ "$n" -eq 1 ] || return 1
    printf '%s\n' "$bodies"
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

# Does the signature really name every identifier a hunk is about to reference?
# This is what keeps the hooks signature-AGNOSTIC without letting them become
# signature-BLIND.
has_params() {   # <signature text> <ident...>
    local sig="$1" p; shift
    for p in "$@"; do
        printf '%s' "$sig" | grep -Eq "[^A-Za-z0-9_]${p}[^A-Za-z0-9_]" || return 1
    done
    return 0
}

require_params() {   # <signature text> <what> <ident...>
    local sig="$1" what="$2" p; shift 2
    for p in "$@"; do
        has_params "$sig" "$p" || die \
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

# ---------------------------------------------------------------------------
# H3 — the raw-query path (Phase 3). OPTIONAL: skipped, never fatal.
#
# The hook goes on resolv_res_nsend(), which is the EXTERNAL entry point behind
# DnsProxyListener's ResNSendCommand — i.e. android.net.DnsResolver.rawQuery().
# It is deliberately NOT res_nsend(): that is the INTERNAL one every getaddrinfo
# lookup also passes through, so hooking it would evaluate ~99% of the device's
# traffic a second time, several frames after H1 already decided it.
#
# The alternative anchor — a hunk inside ResNSendHandler::run() — would have to
# base64-decode the command argument itself and then reimplement the dnsproxyd
# reply framing to short-circuit it. resolv_res_nsend()'s contract is already
# exactly right: bytes in, bytes out, an rcode out-parameter, and a return value
# that is a length.
# ---------------------------------------------------------------------------
H3_ON=0
H3_FILE=""
H3_BRACE=0
H3_SKIP=""
H3_CTX=""
H3_MSG_PTR=""; H3_MSG_LEN=""; H3_ANS_PTR=""; H3_ANS_LEN=""

h3_locate() {
    local dpl="$DNS/DnsProxyListener.cpp" f def sig

    # The evidence that this tree has a raw-query path at all. Without it,
    # resolv_res_nsend() would have no caller and the hunk would be dead code.
    if [ ! -f "$dpl" ] || ! grep -q 'ResNSendCommand' "$dpl"; then
        H3_SKIP="no ResNSendCommand in this tree — there is no raw-query path to hook"
        return 1
    fi

    for f in res_send.cpp DnsProxyListener.cpp DnsResolver.cpp resolv.cpp; do
        def="$(try_body_definition "$DNS/$f" 'int' 'resolv_res_nsend' || true)"
        [ -n "$def" ] || continue
        H3_FILE="$DNS/$f"
        H3_BRACE="$(printf '%s' "$def" | cut -d: -f2)"
        sig="$(printf '%s' "$def" | cut -d: -f4-)"
        break
    done
    if [ -z "$H3_FILE" ] || [ "$H3_BRACE" = "0" ]; then
        H3_SKIP="no single body-carrying definition of resolv_res_nsend() found"
        return 1
    fi

    # Both spellings are in the wild.
    if   has_params "$sig" netContext; then H3_CTX=netContext
    elif has_params "$sig" netcontext; then H3_CTX=netcontext
    else
        H3_SKIP="resolv_res_nsend() has no netContext/netcontext parameter, so there is no uid to attribute the query to"
        return 1
    fi

    # Two parameter shapes: std::span (current) and the older pointer+length
    # pair. Anything else is a shape we have not seen and must not guess at.
    if has_params "$sig" msg ans rcode && printf '%s' "$sig" | grep -q 'span'; then
        H3_MSG_PTR='msg.data()'; H3_MSG_LEN='msg.size()'
        H3_ANS_PTR='ans.data()'; H3_ANS_LEN='ans.size()'
    elif has_params "$sig" msg msgLen ans ansLen rcode; then
        H3_MSG_PTR='msg';       H3_MSG_LEN='(size_t)msgLen'
        H3_ANS_PTR='ans';       H3_ANS_LEN='(size_t)ansLen'
    else
        H3_SKIP="unrecognised resolv_res_nsend() signature: $sig"
        return 1
    fi
    return 0
}

if h3_locate; then
    H3_ON=1
    info "H3 resolv_res_nsend() body opens at line $H3_BRACE in $(basename "$H3_FILE")"
else
    warn "H3 SKIPPED — $H3_SKIP.
             H1/H2/H4 are unaffected and still cover every getaddrinfo(),
             gethostbyname() and DnsResolver.query() caller. What is lost is
             android.net.DnsResolver.rawQuery(), which no longer sees a verdict."
fi

# ---------------------------------------------------------------------------
# H5 — CNAME uncloaking (Phase 5). OPTIONAL: skipped, never fatal.
#
# H1/H2/H3 all decide on the QUESTION. A CNAME-cloaked tracker is served under a
# first-party name that no blocklist can carry, and names itself only in the
# ANSWER — so this is the one hook that has to read a reply.
#
# The anchor is the getanswer() CALL inside dns_getaddrinfo(), not a function's
# opening brace, because that is the only point in the tree where the answer
# bytes and netcontext->uid are both in scope. Without the uid there is no
# per-app policy, and an EXEMPT app would silently have its answers dropped —
# which is exactly the kind of quiet wrongness this patch is written to avoid.
#
# getanswer() itself is the wrong seam for the same reason: it is `static` and
# takes no uid, so a hunk there could only enforce a device-wide policy while
# looking like it enforced the user's.
#
# gethnamaddr.cpp's own getanswer() is deliberately NOT hooked. It serves the
# legacy gethostbyname path, and doubling this hunk's surface to reach it is a
# bad trade for a path H2 already covers at the question.
# ---------------------------------------------------------------------------
H5_ON=0
H5_SKIP=""
H5_OBJ=""

h5_locate() {
    local def sig brace calls line

    def="$(try_body_definition "$GAI" 'int' 'dns_getaddrinfo' || true)"
    if [ -z "$def" ]; then
        H5_SKIP="no single body-carrying definition of dns_getaddrinfo() found"
        return 1
    fi
    brace="$(printf '%s' "$def" | cut -d: -f2)"
    sig="$(printf '%s' "$def" | cut -d: -f4-)"

    # The hunk dereferences netcontext for the uid. If this tree's signature does
    # not carry it, there is no caller identity here and the hook must not run.
    if ! has_params "$sig" netcontext; then
        H5_SKIP="dns_getaddrinfo() has no netcontext parameter, so there is no uid to attribute the answer to"
        return 1
    fi

    # The CALL, not the forward declaration and not the definition: an assignment
    # from getanswer(). Exactly one, or we are guessing which answer we filter.
    calls="$(grep -nE '=[[:space:]]*getanswer[[:space:]]*\(' "$GAI" | wc -l | tr -d ' ')"
    if [ "$calls" != "1" ]; then
        H5_SKIP="expected exactly one getanswer() call site in getaddrinfo.cpp, found $calls"
        return 1
    fi
    line="$(grep -nE '=[[:space:]]*getanswer[[:space:]]*\(' "$GAI" | cut -d: -f1)"
    if [ "$line" -le "$brace" ]; then
        H5_SKIP="the getanswer() call is not inside dns_getaddrinfo()"
        return 1
    fi

    # The answer buffer and its length reach us as members of the loop's query
    # object. Take the object's name from the call rather than assuming `query`,
    # and require the length member on the SAME line so the two cannot come from
    # different objects.
    H5_OBJ="$(sed -n "${line}p" "$GAI" |
              sed -n 's/.*getanswer[[:space:]]*([[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\)\.answer.*/\1/p')"
    if [ -z "$H5_OBJ" ]; then
        H5_SKIP="the getanswer() call does not pass a <obj>.answer buffer: $(sed -n "${line}p" "$GAI" | sed 's/^[[:space:]]*//')"
        return 1
    fi
    if ! sed -n "${line}p" "$GAI" | grep -q "${H5_OBJ}\.n[^A-Za-z0-9_]"; then
        H5_SKIP="the getanswer() call does not pass ${H5_OBJ}.n as the answer length"
        return 1
    fi

    # The hunk sets `he` so that an answer dropped here is indistinguishable from
    # an answer that legitimately contained nothing.
    if ! sed -n "${line}p" "$GAI" | grep -q '&he'; then
        H5_SKIP="the getanswer() call does not pass &he, so there is no herrno to set"
        return 1
    fi
    grep -q 'HOST_NOT_FOUND' "$GAI" || {
        H5_SKIP="HOST_NOT_FOUND is not used anywhere in getaddrinfo.cpp"
        return 1
    }
    return 0
}

if h5_locate; then
    H5_ON=1
    info "H5 answer hook anchors on the getanswer($H5_OBJ.answer, ...) call in getaddrinfo.cpp"
else
    warn "H5 SKIPPED — $H5_SKIP.
             H1/H2/H3/H4 are unaffected. What is lost is CNAME uncloaking: a
             tracker served under a first-party name still resolves, and the
             Advanced screen's switch will have no effect."
fi

if [ "$MODE" = check ]; then
    h3_applied=1
    if [ "$H3_ON" = 1 ]; then
        already "$H3_FILE" && [ -f "$DNS/nullroute/NrResSend.cpp" ] || h3_applied=0
    fi
    h5_applied=1
    if [ "$H5_ON" = 1 ]; then
        grep -q 'nr::cnameBlocked(' "$GAI" 2>/dev/null &&
            [ -f "$DNS/nullroute/NrCname.cpp" ] || h5_applied=0
    fi
    if already "$GAI" && already "$GHN" && already "$BP" \
       && [ -f "$DNS/nullroute/NrFilter.cpp" ] && [ "$h3_applied" = 1 ] \
       && [ "$h5_applied" = 1 ]; then
        echo
        if [ "$H3_ON" = 1 ]; then echo "OK — patch is applied (H1 H2 H3 H4)."
        else                      echo "OK — patch is applied (H1 H2 H4; H3 skipped)."; fi
        if [ "$H5_ON" = 1 ]; then echo "     H5 (CNAME uncloaking) applied."
        else                      echo "     H5 (CNAME uncloaking) SKIPPED: $H5_SKIP"; fi
        exit 0
    fi
    echo; echo "NOT APPLIED (all applicable hook sites located successfully; run without --check to apply)."
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
H3_STAGED=""
if [ "$H3_ON" = 1 ]; then
    H3_STAGED="$WORK/$(basename "$H3_FILE")"
    cp "$H3_FILE" "$H3_STAGED"
fi

step "Staging edits"

# --- Android.bp ------------------------------------------------------------
#
# NrResSend.cpp goes into srcs unconditionally, even where H3 was skipped. It
# compiles standalone — it references nothing but nr_hook.h, nr_wire.h and libc —
# so the build shape stays identical across trees, which is what keeps --check
# and the idempotency guarantee simple. Without its hunk it is simply never
# called.
if already "$WORK/Android.bp"; then
    info "Android.bp already patched"
else
    bp_add_array "$WORK/Android.bp" libnetd_resolv srcs \
        '"nullroute/NrFilter.cpp", "nullroute/NrRingWriter.cpp", "nullroute/NrResSend.cpp", "nullroute/NrCname.cpp",'
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

# --- getaddrinfo.cpp: H5 ---------------------------------------------------
#
# Staged AFTER H1/H4 and anchored by a fresh grep of the STAGED file, because
# those two have already shifted every line number below them. Its own marker
# means re-running is still a no-op even though getaddrinfo.cpp is by now
# `already` patched for a different hunk.
if [ "$H5_ON" = 1 ]; then
    if grep -q 'nr::cnameBlocked(' "$WORK/getaddrinfo.cpp"; then
        info "getaddrinfo.cpp already carries H5"
    else
        h5_line="$(grep -nE '=[[:space:]]*getanswer[[:space:]]*\(' "$WORK/getaddrinfo.cpp" |
                   cut -d: -f1)"
        if [ -z "$h5_line" ] || [ "$(printf '%s\n' "$h5_line" | wc -l | tr -d ' ')" != "1" ]; then
            die "the getanswer() call went missing from the staged getaddrinfo.cpp — the tree was NOT modified"
        fi

        cat > "$WORK/h5.txt" <<EOF
$BEGIN_MARK
#ifdef NULLROUTE_ENABLED
        // H5. The answer hook. H1 has already cleared the QUESTION, so anything
        // caught here is a name that only became visible in the REPLY: a
        // CNAME-cloaked tracker, served under a first-party subdomain no
        // blocklist can carry. nullroute/NrCname.h explains the shape.
        //
        // Guarded like every other hook site: this runs inside netd, whose init
        // stanza carries \`onrestart restart zygote\`, so a null deref is a boot
        // loop rather than a failed lookup.
        //
        // OFF unless NrControl::cname_uncloak is set — the default device pays
        // one relaxed byte load per answer for this line and nothing else.
        //
        // Dropping is a \`continue\`, not a return: the sibling A/AAAA query in
        // this loop is a separate answer and gets judged on its own bytes.
        // Setting \`he\` makes a dropped answer indistinguishable from one that
        // legitimately carried nothing, which is what the code below already
        // knows how to report.
        //
        // The length is clamped to the buffer's own size and not merely to zero.
        // \`${H5_OBJ}.n\` is a received byte count, and the ONE thing the parser
        // cannot defend itself against is being handed a length longer than the
        // allocation it was pointed at. Asserting that here costs a compare and
        // removes the question entirely.
        if (netcontext != nullptr &&
            nr::cnameBlocked(${H5_OBJ}.answer.data(),
                             (${H5_OBJ}.n > 0 &&
                              (size_t)${H5_OBJ}.n <= ${H5_OBJ}.answer.size())
                                     ? (size_t)${H5_OBJ}.n
                                     : (size_t)0,
                             netcontext->uid)) {
            he = HOST_NOT_FOUND;
            continue;
        }
#endif
$END_MARK
EOF
        insert_after_file "$WORK/getaddrinfo.cpp" "$((h5_line - 1))" "$WORK/h5.txt"

        # The include is fenced SEPARATELY and must not land inside H1's fence:
        # --revert's stripper is one boolean, so a nested BEGIN/END pair would
        # leave a stray marker behind and the revert would stop being byte-exact.
        # So skip past H1's END if the last #include is the one it inserted.
        h5_inc="$(grep -n '^#include' "$WORK/getaddrinfo.cpp" | tail -1 | cut -d: -f1)"
        [ -n "$h5_inc" ] || die "staged getaddrinfo.cpp has no #include block"
        if sed -n "$((h5_inc + 1))p" "$WORK/getaddrinfo.cpp" | grep -q 'NULLROUTE-END'; then
            h5_inc=$((h5_inc + 1))
        fi
        printf '%s\n%s\n%s\n' "$BEGIN_MARK" '#include "nullroute/NrCname.h"' "$END_MARK" \
            > "$WORK/h5inc.txt"
        insert_after_file "$WORK/getaddrinfo.cpp" "$h5_inc" "$WORK/h5inc.txt"
        info "getaddrinfo.cpp: H5 + include"
    fi
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

# --- H3 --------------------------------------------------------------------
if [ "$H3_ON" = 1 ]; then
    if already "$H3_STAGED"; then
        info "$(basename "$H3_FILE") already patched"
    else
        cat > "$WORK/h3.txt" <<EOF
$BEGIN_MARK
#ifdef NULLROUTE_ENABLED
    // H3. This is the EXTERNAL entry point: its only caller is DnsProxyListener's
    // ResNSendCommand handler, i.e. android.net.DnsResolver.rawQuery(). The
    // res_nsend() below is the INTERNAL one that res_nsearch()/res_nquery() — and
    // therefore every getaddrinfo() lookup — also reaches, so hooking that instead
    // would re-evaluate ~99% of the device's traffic several frames after H1 has
    // already decided it, double-count every block, and reach a second verdict on
    // a question H1 had acted on.
    //
    // Guarded for the same reason as H1 and H2: this hunk runs before the
    // function's own argument validation, and a null deref inside netd restarts
    // zygote.
    if ($H3_CTX != nullptr && rcode != nullptr) {
        // A positive return is a complete synthesized wire answer already in the
        // caller's buffer, with *rcode set to match — exactly the contract of the
        // real call below. Zero means "not ours", and zero is also what every
        // internal failure returns, so no raw query can fail because of Nullroute.
        //
        // \`event\` is deliberately left untouched: an intercepted query never
        // reached a transport, and filling in server statistics for a lookup that
        // did not happen would put fiction into the metrics. H1 does the same.
        const int nr_len = nr::resNSend($H3_MSG_PTR, $H3_MSG_LEN, ${H3_CTX}->uid,
                                        $H3_ANS_PTR, $H3_ANS_LEN, rcode);
        if (nr_len > 0) return nr_len;
    }
#endif
$END_MARK
EOF
        insert_after_file "$H3_STAGED" "$H3_BRACE" "$WORK/h3.txt"
        insert_include "$H3_STAGED" '#include "nullroute/nr_wire.h"'
        info "$(basename "$H3_FILE"): H3 + include"
    fi
fi

# ---------------------------------------------------------------------------
# Verify the staged result before a single byte of the tree changes
# ---------------------------------------------------------------------------
step "Verifying staged result"
check_staged() {   # <file> <needle> <description>
    grep -q "$2" "$1" || die "staged $(basename "$1") is missing $3 — the tree was NOT modified"
}
check_staged "$WORK/Android.bp"      'nullroute/NrFilter.cpp'    'the srcs entry'
check_staged "$WORK/Android.bp"      'nullroute/NrResSend.cpp'   'the H3 srcs entry'
check_staged "$WORK/Android.bp"      'libnrformat_headers'       'header_libs'
check_staged "$WORK/Android.bp"      'libnrfilter'               'whole_static_libs'
check_staged "$WORK/Android.bp"      'NULLROUTE_ENABLED'         'the cflags define'
check_staged "$WORK/getaddrinfo.cpp" 'nr::hook(hostname'         'the H1 hunk'
check_staged "$WORK/getaddrinfo.cpp" 'nr::hostsLayerSuperseded'  'the H4 hunk'
check_staged "$WORK/getaddrinfo.cpp" 'nullroute/nr_hook.h'       'the include'
check_staged "$WORK/gethnamaddr.cpp" 'nr::hook(name'             'the H2 hunk'
check_staged "$WORK/gethnamaddr.cpp" 'nullroute/nr_hook.h'       'the include'
check_staged "$WORK/Android.bp"      'nullroute/NrCname.cpp'     'the H5 srcs entry'

# Exactly one hook per site, no matter how many times this has been run.
IDEMPOTENCY='getaddrinfo.cpp:nr::hook(hostname gethnamaddr.cpp:nr::hook(name'
if [ "$H3_ON" = 1 ]; then
    check_staged "$H3_STAGED" 'nr::resNSend('        'the H3 hunk'
    check_staged "$H3_STAGED" 'nullroute/nr_wire.h'  'the H3 include'
    IDEMPOTENCY="$IDEMPOTENCY $(basename "$H3_FILE"):nr::resNSend("
fi
if [ "$H5_ON" = 1 ]; then
    check_staged "$WORK/getaddrinfo.cpp" 'nr::cnameBlocked('     'the H5 hunk'
    check_staged "$WORK/getaddrinfo.cpp" 'nullroute/NrCname.h'   'the H5 include'
    IDEMPOTENCY="$IDEMPOTENCY getaddrinfo.cpp:nr::cnameBlocked("
fi

# --revert strips everything between a BEGIN and the next END with a single
# boolean, so one fence nested inside another would leave a stray marker behind
# and revert would stop being byte-exact. getaddrinfo.cpp now carries three
# separate fences (H1, H4, H5) plus two includes, which is where that could first
# happen — so assert it cannot rather than trusting the insertion order.
for f in getaddrinfo.cpp gethnamaddr.cpp; do
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
        index($0, b) { if (open) { exit 3 } open = 1; next }
        index($0, e) { if (!open) { exit 4 } open = 0 }
        END { if (open) exit 5 }
    ' "$WORK/$f" || die "staged $f has unbalanced or nested NULLROUTE markers — the tree was NOT modified"
done

for pair in $IDEMPOTENCY; do
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
if [ "$H3_ON" = 1 ]; then
    # An `[ … ] && cp …` one-liner here would be a trap: under `set -e` the
    # compound's non-zero result when H3 is off exits the script mid-install.
    cp "$H3_STAGED" "$H3_FILE"
fi
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

echo
if [ "$H3_ON" = 1 ]; then
    echo "OK — patch applied (H1 H2 H3 H4)."
else
    echo "OK — patch applied (H1 H2 H4). H3 SKIPPED: $H3_SKIP"
fi
if [ "$H5_ON" = 1 ]; then
    echo "     H5 (CNAME uncloaking) applied. It stays inert until the Advanced"
    echo "     screen sets NrControl::cname_uncloak."
else
    echo "     H5 (CNAME uncloaking) SKIPPED: $H5_SKIP"
fi
cat <<'DONE'

Next:
    mka libnrformat_headers libnrfilter
    mka libnetd_resolv
    mka bacon && tools/ci_verify_image.sh

Then work through resolver-patch/README.md on the device. Landing this patch such
that it actually ships inside the ACTIVATED APEX is the single riskiest step in
the project: success and failure look identical from userspace.
DONE
