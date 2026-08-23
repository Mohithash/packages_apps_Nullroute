#!/bin/bash
#
# Nullroute — source-level verification gate.
#
#   tools/verify_source.sh [<blocklist.txt> ...]
#
# Runs everything that can be checked WITHOUT an Android build: compiles every
# native translation unit, runs the semantic test suite against real corpora,
# builds and briefly runs both fuzzers, and applies the resolver patch to a
# throwaway copy of a real DnsResolver tree to prove the hunks still land.
#
# This is the merge gate. tools/ci_verify_image.sh is its counterpart and runs
# against a BUILT image, because the one failure this design cannot detect from
# source is the resolver patch not actually shipping inside the activated APEX.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CXX="${CXX:-$(command -v clang++ || command -v g++)}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAIL=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }
skip() { printf '  --    %s\n' "$*"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# Android-only headers, stubbed so the netd-side translation units can be
# type-checked on a build host. The stubs are deliberately inert: this proves the
# code COMPILES, never that it behaves correctly against real bionic.
mkdir -p "$WORK/stub/sys" "$WORK/stub/log"
cat > "$WORK/stub/sys/system_properties.h" <<'H'
#pragma once
#include <stdint.h>
#define PROP_VALUE_MAX 92
typedef struct prop_info prop_info;
static inline const prop_info* __system_property_find(const char*) { return 0; }
static inline uint32_t __system_property_serial(const prop_info*) { return 0; }
static inline uint32_t __system_property_area_serial(void) { return 0; }
static inline void __system_property_read_callback(const prop_info*,
        void (*cb)(void*, const char*, const char*, uint32_t), void* c) { (void)cb; (void)c; }
static inline int __system_property_set(const char*, const char*) { return 0; }
static inline int __system_property_get(const char*, char* v) { if (v) v[0] = 0; return 0; }
H
cat > "$WORK/stub/log/log.h" <<'H'
#pragma once
#include <stdio.h>
#define ALOGE(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define ALOGW(...) ALOGE(__VA_ARGS__)
#define ALOGI(...) ALOGE(__VA_ARGS__)
#define ALOGD(...) ALOGE(__VA_ARGS__)
#define ALOGV(...) ALOGE(__VA_ARGS__)
#ifndef LOG_TAG
#define LOG_TAG "NullrouteFilter"
#endif
H

INC=(-I "$WORK/stub" -I "$ROOT/native/include" -I "$ROOT/resolver-patch/nullroute")
JNI_INC=()
for cand in "${JAVA_HOME:-}/include" /usr/lib/jvm/*/include; do
    [ -d "$cand" ] && { JNI_INC=(-I "$cand" -I "$cand/linux"); break; }
done

step "Compiling every native translation unit (-Wall -Wextra)"
for f in "$ROOT"/native/*.cpp "$ROOT"/resolver-patch/nullroute/*.cpp; do
    base="$(basename "$f")"
    extra=()
    case "$base" in
        jni_bridge.cpp)
            if [ ${#JNI_INC[@]} -eq 0 ]; then skip "$base (no JDK headers found)"; continue; fi
            extra=("${JNI_INC[@]}") ;;
    esac
    if "$CXX" -std=c++17 -O2 -c -Wall -Wextra -Wno-unused-parameter -DNULLROUTE_ENABLED \
        "${INC[@]}" "${extra[@]}" "$f" -o "$WORK/$base.o" 2> "$WORK/err.txt"; then
        ok "$base"
    else
        bad "$base"; sed 's/^/        /' "$WORK/err.txt" | head -12
    fi
done

step "Semantic test suite"
if "$CXX" -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter "${INC[@]}" \
    "$ROOT/native/NrCanon.cpp" "$ROOT/native/NrQuery.cpp" "$ROOT/native/NrBuilder.cpp" \
    "$ROOT/native/nrtest.cpp" -o "$WORK/nrtest" 2> "$WORK/err.txt"; then
    ok "nrtest built"
    if [ $# -gt 0 ]; then
        if "$WORK/nrtest" "$@" > "$WORK/t.log" 2>&1; then
            ok "$(grep -E 'ALL OK|FAILED' "$WORK/t.log" | tail -1)"
            grep -E 'built:|throughput:|false positives|sampled' "$WORK/t.log" | sed 's/^/        /'
        else
            bad "nrtest reported failures"; tail -25 "$WORK/t.log" | sed 's/^/        /'
        fi
    else
        skip "no corpus passed; run with a blocklist path to exercise it"
    fi
else
    bad "nrtest failed to build"; head -20 "$WORK/err.txt" | sed 's/^/        /'
fi

step "Fuzzers (merge gate)"
if "$CXX" -fsanitize=fuzzer,address -std=c++17 -O1 -g "${INC[@]}" \
    "$ROOT/native/NrCanon.cpp" "$ROOT/native/NrQuery.cpp" "$ROOT/native/NrBuilder.cpp" \
    "$ROOT/native/fuzz/nr_hostname_fuzzer.cpp" -o "$WORK/fz_host" 2> "$WORK/err.txt"; then
    if "$WORK/fz_host" -runs=40000 -max_len=300 > "$WORK/f1.log" 2>&1; then
        ok "nr_hostname_fuzzer: 40k runs clean"
    else
        bad "nr_hostname_fuzzer crashed"; tail -20 "$WORK/f1.log" | sed 's/^/        /'
    fi
else
    bad "nr_hostname_fuzzer failed to build"; head -12 "$WORK/err.txt" | sed 's/^/        /'
fi

if "$CXX" -fsanitize=fuzzer,address -std=c++17 -O1 -g "${INC[@]}" \
    "$ROOT/native/NrCanon.cpp" "$ROOT/native/NrQuery.cpp" "$ROOT/native/NrBuilder.cpp" \
    "$ROOT/native/fuzz/nr_index_fuzzer.cpp" -o "$WORK/fz_idx" 2> "$WORK/err.txt"; then
    # This is the one that matters: the index is written by the app and mapped
    # inside netd, whose init stanza carries `onrestart restart zygote`.
    if "$WORK/fz_idx" -runs=40000 -max_len=8192 > "$WORK/f2.log" 2>&1; then
        ok "nr_index_fuzzer: 40k runs clean"
    else
        bad "nr_index_fuzzer crashed"; tail -20 "$WORK/f2.log" | sed 's/^/        /'
    fi
else
    bad "nr_index_fuzzer failed to build"; head -12 "$WORK/err.txt" | sed 's/^/        /'
fi

step "Resolver patch against a real DnsResolver tree"
DNS_SRC="${DNSRESOLVER_SRC:-${ANDROID_BUILD_TOP:-}/packages/modules/DnsResolver}"
if [ -d "$DNS_SRC" ]; then
    cp -r "$DNS_SRC" "$WORK/DnsResolver"
    if bash "$ROOT/resolver-patch/apply.sh" "$WORK/DnsResolver" > "$WORK/p.log" 2>&1; then
        ok "applied"
        bash "$ROOT/resolver-patch/apply.sh" "$WORK/DnsResolver" > "$WORK/p2.log" 2>&1 \
            && ok "idempotent on re-run" || bad "re-run was not a no-op"
        bash "$ROOT/resolver-patch/apply.sh" --check "$WORK/DnsResolver" > /dev/null 2>&1 \
            && ok "--check detects applied state" || bad "--check disagrees with apply"
        for f in getaddrinfo.cpp gethnamaddr.cpp; do
            o=$(tr -cd '{' < "$WORK/DnsResolver/$f" | wc -c)
            c=$(tr -cd '}' < "$WORK/DnsResolver/$f" | wc -c)
            [ "$o" = "$c" ] && ok "$f braces balanced" || bad "$f braces UNBALANCED ($o/$c)"
        done
        bash "$ROOT/resolver-patch/apply.sh" --revert "$WORK/DnsResolver" > /dev/null 2>&1 \
            && ok "revert clean" || bad "revert failed"
        # Compare only the files the patch touches. A whole-tree diff also trips
        # over AOSP's symlinked .clang-format / rustfmt.toml, which `cp -r` does
        # not reproduce — that is an artifact of this harness, not of revert.
        rev_clean=1
        for f in Android.bp getaddrinfo.cpp gethnamaddr.cpp; do
            diff -q "$DNS_SRC/$f" "$WORK/DnsResolver/$f" > /dev/null 2>&1 || {
                bad "revert left $f modified"
                diff -u "$DNS_SRC/$f" "$WORK/DnsResolver/$f" | head -20 | sed 's/^/        /'
                rev_clean=0
            }
        done
        [ -e "$WORK/DnsResolver/nullroute" ] && { bad "revert left nullroute/ behind"; rev_clean=0; }
        [ "$rev_clean" = 1 ] && ok "revert restored every patched file byte-for-byte"
    else
        bad "apply.sh failed"; tail -20 "$WORK/p.log" | sed 's/^/        /'
    fi
else
    skip "no DnsResolver tree (set DNSRESOLVER_SRC or ANDROID_BUILD_TOP)"
fi

step "Licence posture"
# GPL-3.0 / MPL-2.0 lists must never be baked into a verity-protected signed
# image; they are fetched and compiled on-device so the derivative work is
# created by the user. Profile files carry URLs and are fine.
if [ -f "$ROOT/prebuilt/hosts" ]; then
    if grep -qiE 'hagezi|1hosts|badmojr|adguard|r-a-y' "$ROOT/prebuilt/hosts"; then
        bad "prebuilt/hosts references a copyleft source"
    else
        ok "prebuilt/hosts carries no copyleft source ($(wc -l < "$ROOT/prebuilt/hosts") lines, $(wc -c < "$ROOT/prebuilt/hosts") bytes)"
    fi
else
    bad "prebuilt/hosts is missing (Phase 0 does not ship)"
fi

printf '\n'
if [ "$FAIL" = 0 ]; then printf '\033[32mVERIFY OK\033[0m\n'; else printf '\033[31mVERIFY FAILED\033[0m\n'; fi
exit "$FAIL"
