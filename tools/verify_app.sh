#!/bin/bash
#
# Nullroute — app-side verification gate (the counterpart to verify_source.sh).
#
#   tools/verify_app.sh [<dir of dependency jars>]
#
# Two checks, in increasing order of how much setup they need:
#
#   1. aapt2 resource compile over the real res/ tree. Fully self-contained: it
#      needs only the Android SDK build-tools. This is what catches the class of
#      bug that blocks EVERY build downstream — a layout using a library
#      attribute in the framework namespace (android:menu instead of app:menu on
#      BottomNavigationView) fails here and nowhere earlier.
#
#   2. A full Kotlin compile of app/src/main/java against android.jar, a
#      synthesized R, and the androidx/Material jars. Needs a directory of
#      dependency jars; skipped without one.
#
# R is synthesized from res/ rather than produced by `aapt2 link` on purpose:
# linking needs every AAR's compiled resources so Material's styles resolve, and
# unpacking AARs is more machinery than this gate is worth. The synthesized R
# still gives the check that matters — every R.<type>.<name> the Kotlin
# references must name a resource that really exists in res/.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS="${1:-}"
PKG="com.bestrom.nullroute"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

FAIL=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }
skip() { printf '  --    %s\n' "$*"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

win() { command -v cygpath >/dev/null 2>&1 && cygpath -w "$1" || printf '%s' "$1"; }

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}}"
AAPT2="$(ls "$SDK"/build-tools/*/aapt2 "$SDK"/build-tools/*/aapt2.exe 2>/dev/null | sort -V | tail -1)"
AJ="$(ls "$SDK"/platforms/android-3[6-9]/android.jar 2>/dev/null | sort -V | tail -1)"

step "Resources"
if [ -z "$AAPT2" ]; then
    skip "no aapt2 under $SDK"
else
    mkdir -p "$W/flat"
    if "$AAPT2" compile --dir "$ROOT/app/src/main/res" -o "$(win "$W/flat/res.zip")" 2> "$W/e1.txt"; then
        ok "aapt2 compile: $(find "$ROOT/app/src/main/res" -name '*.xml' | wc -l) XML resources"
    else
        bad "aapt2 compile"; head -20 "$W/e1.txt" | sed 's/^/        /'
    fi
fi

step "Kotlin"
if [ -z "$DEPS" ] || [ ! -d "$DEPS" ]; then
    skip "no dependency-jar directory given; pass one to run the Kotlin compile"
elif [ -z "$AJ" ]; then
    skip "no android.jar under $SDK"
else
    # Pick an interpreter that actually RUNS. On Windows, `python3` is usually
    # the Microsoft Store alias stub, which exits 0 while printing an advert.
    PY=""
    for c in python3 python py; do
        p="$(command -v "$c" 2>/dev/null)" || continue
        "$p" -c 'import sys' >/dev/null 2>&1 && { PY="$p"; break; }
    done
    if [ -z "$PY" ]; then
        bad "no python on PATH; cannot synthesize R"
    elif "$PY" "$ROOT/tools/gen_r.py" "$ROOT/app/src/main/res" "$W/gen" "$PKG" > "$W/r.log" 2>&1; then
        ok "$(cat "$W/r.log")"
    else
        bad "R synthesis"; sed 's/^/        /' "$W/r.log"
    fi

    mkdir -p "$W/rout" "$W/out"
    javac -nowarn -d "$(win "$W/rout")" -cp "$(win "$AJ")" "$(win "$W/gen/R.java")" 2> "$W/e2.txt" \
        || { bad "R javac"; head -10 "$W/e2.txt" | sed 's/^/        /'; }

    G="$HOME/.gradle/caches/modules-2/files-2.1"
    KC="$(find "$G/org.jetbrains.kotlin/kotlin-compiler-embeddable" -name 'kotlin-compiler-embeddable-2.0.*.jar' 2>/dev/null | sort -V | tail -1)"
    KS="$(find "$G/org.jetbrains.kotlin/kotlin-stdlib" -name 'kotlin-stdlib-2.0.*.jar' 2>/dev/null | sort -V | tail -1)"
    CO="$(find "$G/org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm" -name '*.jar' 2>/dev/null | sort -V | tail -1)"
    TR="$(find "$G/org.jetbrains.intellij.deps/trove4j" -name '*.jar' 2>/dev/null | sort -V | tail -1)"
    AN="$(find "$G/org.jetbrains/annotations" -name 'annotations-2*.jar' 2>/dev/null | sort -V | tail -1)"

    if [ -z "$KC" ] || [ -z "$KS" ]; then
        skip "no Kotlin 2.0.x compiler in the Gradle cache"
    else
        # Only real app dependencies. A dependency dump usually also contains
        # Kotlin TOOLCHAIN jars (compiler plugins, kotlin-reflect, a newer
        # stdlib); those put metadata from a newer Kotlin on the path and produce
        # forty "incompatible version of Kotlin" errors that have nothing to do
        # with this source tree.
        CPJ="$(ls "$DEPS"/*.jar 2>/dev/null | grep -v 'org.jetbrains.kotlin-' | while read -r j; do printf '%s;' "$(win "$j")"; done)"
        java -cp "$(win "$KC");$(win "$KS");$(win "$CO");$(win "$TR");$(win "$AN")" \
            org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
            -no-stdlib -nowarn -jvm-target 17 \
            -cp "$(win "$AJ");$(win "$KS");$(win "$CO");$(win "$W/rout");$CPJ" \
            -d "$(win "$W/out")" "$ROOT/app/src/main/java" 2> "$W/e3.txt"
        # The compiler prefixes errors "e: " in some versions and emits a bare
        # "<file>:<line>:<col>: error:" in others. Match the word, not a prefix.
        n="$(grep -cE '(^e: |: error:)' "$W/e3.txt")"
        cls="$(find "$W/out" -name '*.class' | wc -l)"
        # Zero classes with zero errors means the compiler never ran — a silent
        # pass is exactly what this gate exists to prevent.
        if [ "$n" -eq 0 ] && [ "$cls" -gt 0 ]; then
            ok "compiled $cls classes from $(find "$ROOT/app/src/main/java" -name '*.kt' | wc -l) sources"
        elif [ "$n" -eq 0 ]; then
            bad "compiler produced no classes and no errors — it did not run"
            head -10 "$W/e3.txt" | sed 's/^/        /'
        else
            bad "$n Kotlin errors"
            grep -E '(^e: |: error:)' "$W/e3.txt" | sed "s|file://$ROOT/app/src/main/java/com/bestrom/nullroute/||" | head -25 | sed 's/^/        /'
        fi
    fi
fi

printf '\n'
if [ "$FAIL" = 0 ]; then printf '\033[32mAPP VERIFY OK\033[0m\n'; else printf '\033[31mAPP VERIFY FAILED\033[0m\n'; fi
exit "$FAIL"
