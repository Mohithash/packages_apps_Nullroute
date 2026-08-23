# Integration — Phase 2 compile/update pipeline (`pipeline`)

Everything this feature needs that lives in a **shared file I must not edit**.
Each block is exact and copy-pasteable, with the target file named.

Sections 1 and 2 are **required**: without them the tree does not build, because
`libnrcore` gains three translation units and one of them is referenced by
`NrBuilder.cpp`. Sections 3–5 are what turns the front-coded strings blob from
"built and tested" into "reachable from the app"; without them everything still
compiles and runs, and the Rules screen simply has no "this pattern matches N
entries" preview.

Files delivered by this task (no action needed on them):

```
native/include/NrParse.h      native/NrParse.cpp        line parser + the normalized record
native/include/NrCollapse.h   native/NrCollapse.cpp     suffix collapse, lifted out of the builder
native/include/NrStrings.h    native/NrStrings.cpp      front-coded NR_SEC_STR blob + range search
native/include/NrBuilder.h    native/NrBuilder.cpp      serializer only; kind-precedence dedupe; sidecar
tools/verify_source.sh        CORE_SRC named once, used by nrtest and both fuzzers
app/.../data/SourceCatalog.kt   full measured catalogue incl. add-ons + OEM/native by brand
app/.../data/Categories.kt      category model, FP-risk chips, the two allow carve-outs
app/.../data/RuleStore.kt       §7.5 syntax, rejection reasons, atomic writes
app/.../data/ProfileStore.kt    base + _added + _removed + "# OFF #" + custom profiles
app/.../net/Downloader.kt       Range version probe, conditional GET, gzip, resumable
app/.../net/SourceSync.kt       orchestration, per-source disposition, partial success
app/.../net/HotfixFeed.kt       BestROM allow hotfixes, allow-only by construction
app/.../build/IndexBuilder.kt   the pipeline + manifest + config fingerprint
app/.../build/CanarySet.kt      live CAPTIVE_PORTAL_*_URL, carve-outs, hotfixes
app/.../core/Generation.kt      promote / rollback / side-artefact lifecycle
app/.../job/UpdateJobService.kt JobScheduler, backoff, mid-write kill safety
app/src/main/res/values/strings_pipeline.xml   its own strings file
```

---

## 1. `Android.bp` — three new sources in `libnrcore` (REQUIRED)

`NrBuilder.cpp` no longer contains the parser or the collapse, and it now calls
`nr_strings_build()`. All three must be listed or the module does not link.

The existing comment above the module says NrStrings.cpp "does not exist yet" —
it does now, so replace that paragraph as well.

```soong
// NrBuilder.cpp is the serializer only. The line parser (NrParse.cpp), the
// suffix collapse (NrCollapse.cpp) and the UI-only front-coded rule text
// (NrStrings.cpp) are separate translation units so each can be reasoned about,
// timed and fuzzed without the others around it.
//
// Exceptions stay ENABLED here (unlike libnrfilter): this side allocates freely
// while merging hundreds of thousands of entries, and a std::bad_alloc that
// unwinds out of a build job is far better than an abort in the app process.
//
// FILE NAMES: the implementation of native/include/NrCtl.h is NrCtlCore.cpp, not
// NrCtl.cpp. `native/NrCtl.cpp` and `native/nrctl.cpp` differ only in case and so
// cannot coexist in a checkout on a case-insensitive filesystem; Soong does not
// care, a developer whose checkout silently loses one of the two very much does.
cc_library_static {
    name: "libnrcore",
    srcs: [
        "native/NrParse.cpp",
        "native/NrCollapse.cpp",
        "native/NrStrings.cpp",
        "native/NrBuilder.cpp",
        "native/NrRingReader.cpp",
        "native/NrCtlCore.cpp",
    ],
    ...unchanged...
}
```

And the host test target, which links the sources directly:

```soong
cc_binary_host {
    name: "nrtest",
    srcs: [
        "native/NrCanon.cpp",
        "native/NrQuery.cpp",
        "native/NrParse.cpp",
        "native/NrCollapse.cpp",
        "native/NrStrings.cpp",
        "native/NrBuilder.cpp",
        "native/nrtest.cpp",
    ],
    ...unchanged...
}
```

`libnrfilter` is **unchanged**. None of the three new units is linked into netd:
the parser and the collapse run in the app, and the strings blob is never mapped
by the resolver.

---

## 2. `native/nrtest.cpp` — the checks that cover the new code (REQUIRED-ish)

The 31 existing checks still pass unchanged; these are additive, and they are the
ones that caught two real bugs during this task (an upper bound that counted
`doubleclick-cn.net` as a subdomain of `doubleclick.net`, and a first-writer-wins
table dedupe that dropped a `K_SUFFIX` rule in favour of a `K_WILDCARD_ONLY` one
for `promotion.xmeye.net`).

Add `#include "NrStrings.h"` at the top, then this block just before the final
`printf("\n%s  (%d passed…")`:

```cpp
    /* ---- kind precedence in the table ------------------------------------
     * promotion.xmeye.net arrives from 1Hosts as `*.promotion.xmeye.net` and
     * from AdGuard Mobile Ads as `0.0.0.0 promotion.xmeye.net`. First-writer-wins
     * keeps the wildcard and the apex silently resolves. */
    {
        std::vector<BuildEntry> b2, a2;
        b2.push_back({"conflict.example", K_WILDCARD_ONLY, 1});
        b2.push_back({"conflict.example", K_SUFFIX, 2});
        std::vector<BuildRedirect> r2;
        BuildStats s2{};
        std::vector<uint8_t> blob2;
        if (!nr_build_index(b2, a2, r2, 1, 1, 0, &blob2, &s2)) { printf("  FAIL  conflict build\n"); ++g_fail; }
        NrIndex ix2{};
        if (!nr_index_validate(blob2.data(), blob2.size(), &ix2)) { printf("  FAIL  conflict validate\n"); ++g_fail; }
        else {
            check(ix2, "conflict.example",   V_BLOCK, "K_SUFFIX beats K_WILDCARD_ONLY on one name");
            check(ix2, "x.conflict.example", V_BLOCK, "and subdomains still block");
        }
    }

    /* ---- NR_SEC_STR: the range search the Rules screen depends on --------- */
    {
        std::vector<BuildEntry> sb, sa;
        sb.push_back({"nrtest-str.example",    K_EXACT,         900});  /* apex, does not subsume */
        sb.push_back({"a.nrtest-str.example",  K_SUFFIX,        901});
        sb.push_back({"b.nrtest-str.example",  K_WILDCARD_ONLY, 902});
        sb.push_back({"nrtest-str-x.example",  K_SUFFIX,        903});  /* '-' (0x2D) < '.' (0x2E) */
        sb.push_back({"nrtest-strfoo.example", K_SUFFIX,        904});
        sa.push_back({"c.nrtest-str.example",  K_SUFFIX,        905});

        std::vector<BuildRedirect> sr;
        BuildStats s3{};
        std::vector<uint8_t> idx3, str3;
        if (!nr_build_index(sb, sa, sr, 7, 1, 0, &idx3, &s3, &str3)) { printf("  FAIL  strings build\n"); ++g_fail; }

        NrIndex six{};
        NrStrings st{};
        if (!nr_index_validate(str3.data(), str3.size(), &six) || !nr_strings_open_index(six, &st)) {
            printf("  FAIL  strings sidecar does not open\n"); ++g_fail;
        } else {
            const NrIndex* mainIx = &ix;   /* the index built at the top of main() */
            if (mainIx->hdr->sec[NR_SEC_STR].len != 0) {
                printf("  FAIL  the index netd maps must NOT carry NR_SEC_STR\n"); ++g_fail;
            } else ++g_pass;

            static const char kBase[] = "nrtest-str.example";
            const NrStrPreview p = nr_strings_preview(st, kBase, strlen(kBase));
            if (p.apex == 1 && p.subdomains == 3 && p.allows == 1 && p.blocks == 3) ++g_pass;
            else { printf("  FAIL  preview apex=%u subs=%u\n", p.apex, p.subdomains); ++g_fail; }

            /* The neighbour that a single-span range gets wrong. */
            const NrStrPreview hy = nr_strings_preview(st, "nrtest-str-x.example", 20);
            if (hy.apex == 1 && hy.subdomains == 0) ++g_pass;
            else { printf("  FAIL  hyphen neighbour leaked\n"); ++g_fail; }
        }
    }
```

---

## 3. `native/NrCtlCore.cpp` — produce the sidecar from `nr_compile()`

`nr_build_index()` takes an optional trailing `std::vector<uint8_t>* strings_out`
(defaulted to `nullptr`, so every existing call site compiles unchanged). Two
edits make the compile step emit it.

In `struct NrCompileResult` (`native/include/NrCtl.h`), add:

```cpp
    std::vector<uint8_t>      strings;          /* NR_SEC_STR sidecar, may be empty */
    char                      strings_sha256_hex[65] = {};
```

In `nr_compile()` (NrCtlCore.cpp), change the build call and seal the sidecar the
same way the index is sealed:

```cpp
    BuildStats stats{};
    if (!nr_build_index(block, allow, redirects, spec.generation,
                        spec.built_at_ms ? spec.built_at_ms : nr_now_ms(),
                        spec.hash_seed, blob, &stats, &result->strings)) {
        if (err) *err = "nr_build_index failed (table sizing or bad input)";
        return false;
    }
```

and, next to the existing `nr_sha256(blob->data() + NR_PAGE, …)`:

```cpp
    /* The sidecar is an ordinary NRDX with only sec[NR_SEC_STR] populated, so it
     * seals, verifies and versions through exactly the same code as the index. */
    if (result->strings.size() > NR_PAGE) {
        uint8_t sd[32];
        nr_sha256(result->strings.data() + NR_PAGE, result->strings.size() - NR_PAGE, sd);
        memcpy(result->strings.data() + offsetof(NrHeader, sha256), sd, 32);
        nr_sha256_hex(sd, result->strings_sha256_hex);
    }
```

Finally, in `nr_json_compile()` add two keys (adding is safe, renaming is not):

```cpp
    jnum(&o, "strings_bytes", r.strings.size());               o.push_back(',');
    jnum(&o, "strings_count", r.stats.strings_count);          o.push_back(',');
```

---

## 4. `native/jni_bridge.cpp` — write the sidecar, and two read entry points

### 4a. In `nativeBuild()`, after the index is written

```cpp
        if (!nr_write_file_atomic(out.c_str(), blob.data(), blob.size(), &err)) { … }

        /* strings.<gen>.nrdx sits beside the index and is opened lazily by the
         * UI. Failing to write it costs the Rules preview and nothing else, so it
         * is deliberately NOT an error: an index that cannot be published because
         * a UI sidecar failed would be a worse product. */
        if (res.strings.size() > NR_PAGE) {
            std::string sp(out.c_str());
            const size_t slash = sp.rfind('/');
            char spath[PATH_MAX];
            snprintf(spath, sizeof(spath), "%s/strings.%lld.nrdx",
                     slash == std::string::npos ? "." : sp.substr(0, slash).c_str(),
                     (long long)generation);
            std::string serr;
            if (!nr_write_file_atomic(spath, res.strings.data(), res.strings.size(), &serr))
                ALOGW("nullroute: strings sidecar not written: %s", serr.c_str());
        }
```

### 4b. Two new entry points

```cpp
/*
 * nativeStringsPreview(String stringsPath, String base) -> String
 *
 * "This pattern matches N entries", answered in O(log n + k) by one binary
 * search per span plus a linear walk (§6.2). Read-only; the index is untouched.
 */
JNIEXPORT jstring JNICALL
Java_com_bestrom_nullroute_core_Native_nativeStringsPreview(JNIEnv* env, jobject,
                                                            jstring stringsPath, jstring base) {
    try {
        ScopedUtf path(env, stringsPath), b(env, base);
        if (path.empty()) {
            throw_java(env, "java/lang/IllegalArgumentException", "stringsPath is required");
            return nullptr;
        }
        ScopedIndex idx;
        std::string err;
        if (!nr_index_open_ro(path.c_str(), &idx.ix, &err)) {
            throw_java(env, "java/io/IOException",
                       std::string("nullroute: cannot read ") + path.c_str() + ": " + err);
            return nullptr;
        }
        NrStrings s;
        if (!nr_strings_open_index(idx.ix, &s)) {
            throw_java(env, "java/io/IOException", "nullroute: no NR_SEC_STR section");
            return nullptr;
        }
        const NrStrPreview p = nr_strings_preview(s, b.c_str(), strlen(b.c_str()));
        std::string o = "{";
        jbool(&o, "ok", true);                    o.push_back(',');
        jnum(&o, "apex", p.apex);                 o.push_back(',');
        jnum(&o, "subdomains", p.subdomains);     o.push_back(',');
        jnum(&o, "blocks", p.blocks);             o.push_back(',');
        jnum(&o, "allows", p.allows);             o.push_back(',');
        jnum(&o, "total_rules", nr_strings_count(s));
        o.push_back('}');
        return to_jstring(env, o);
    } catch (const std::exception& e) {
        throw_java(env, "java/lang/IllegalStateException", std::string("nullroute: ") + e.what());
        return nullptr;
    }
}

/*
 * nativeStringsList(String stringsPath, String base, int limit) -> String
 *
 * The rules themselves, forward order, for the expanded row. Bounded: a base of
 * "com" would otherwise materialise 200,000 strings on the UI thread.
 */
JNIEXPORT jstring JNICALL
Java_com_bestrom_nullroute_core_Native_nativeStringsList(JNIEnv* env, jobject,
                                                         jstring stringsPath, jstring base,
                                                         jint limit) { … same open, then:
        const NrStrRange r = nr_strings_range_for_suffix(s, b.c_str(), strlen(b.c_str()));
        // walk r.apex_begin..r.apex_end then r.sub_begin..r.sub_end with
        // nr_strings_seek()/nr_strings_next(), emitting nr_strings_rule() and the
        // NrStrMeta group/kind for each, up to `limit`.
}
```

Both need `#include "NrStrings.h"`, which `NrCtl.h` already pulls in through
`NrBuilder.h`.

---

## 5. `app/.../core/Native.kt` — the typed facade

```kotlin
    data class MatchPreview(
        val apex: Int,
        val subdomains: Int,
        val blocks: Int,
        val allows: Int,
        val totalRules: Int,
        val error: String? = null,
    ) {
        /**
         * The count to show for a rule of this kind. A `*.` rule covers
         * subdomains and NOT the apex, and reporting one number for all three
         * kinds is how a user comes to believe `@*.example.com` also allows
         * `example.com`.
         */
        fun matched(kind: RuleStore.RuleKind): Int = when (kind) {
            RuleStore.RuleKind.K_SUFFIX, RuleStore.RuleKind.K_FORCE -> apex + subdomains
            RuleStore.RuleKind.K_WILDCARD_ONLY -> subdomains
            RuleStore.RuleKind.K_EXACT -> apex
        }
    }

    /**
     * Counts the index entries a pattern would neutralise. Read-only; the index
     * is untouched. Returns a preview carrying [MatchPreview.error] rather than
     * throwing, because this runs on every keystroke in the Rules screen and one
     * bad character must not become a dialog.
     */
    fun stringsPreview(stringsPath: String, base: String): MatchPreview {
        if (!available) return MatchPreview(0, 0, 0, 0, 0, "no-jni")
        return try {
            val json = JSONObject(nativeStringsPreview(stringsPath, base))
            MatchPreview(
                apex = json.optInt("apex"),
                subdomains = json.optInt("subdomains"),
                blocks = json.optInt("blocks"),
                allows = json.optInt("allows"),
                totalRules = json.optInt("total_rules"),
            )
        } catch (t: Throwable) {
            MatchPreview(0, 0, 0, 0, 0, t.message ?: "preview failed")
        }
    }

    private external fun nativeStringsPreview(stringsPath: String, base: String): String
    private external fun nativeStringsList(stringsPath: String, base: String, limit: Int): String
```

The path to pass is `Paths.stringsBlob(generation)` for the generation
`current.nrdx` reports — i.e.
`Paths.stringsBlob(Native.verify(Paths.currentIndex.absolutePath).generation)`.
`core/Generation.kt` keeps two generations of side artefacts alive
(`Generation.sideArtefacts`), so the blob matching `previous.nrdx` survives a
rollback.

---

## 6. `app/.../ui/UpdateFragment.kt` — optional, richer per-source lines

`IndexBuilder.BuildStep` gained **no new subclasses** precisely so this file keeps
compiling untouched (a non-exhaustive `when` over a sealed class is an error in
Kotlin 1.7+). `Fetched` did gain fields with defaults, and they are worth showing:

```kotlin
            is IndexBuilder.BuildStep.Fetched -> {
                addRow(getString(R.string.update_row_sources), step.summary)
                step.sources.forEach { addRow("", it) }
                step.failures.forEach { addRow(getString(R.string.update_row_unavailable), it) }
            }
```

`step.nothingChanged` is true on the common daily run where the version probe
proved every list current; the compile is skipped entirely and `Outcome.Success`
comes back with `changed = false`, whose `message()` reads "Already up to date".

---

## 7. `app/.../data/Settings.kt` — delete a stale TODO

The file ends with:

```kotlin
    // TODO(Phase 2): category toggles and their FP-risk chips, the anti-fraud /
    // attribution carve-outs, and the update schedule editor.
```

Category state deliberately does **not** live in `Settings`. It has its own
DE-backed preferences file in `data/Categories.kt`, because the update job reads
it before first unlock and a category set in CE storage would silently compile as
"all off" on the first boot after a flash — producing an index quietly different
from the one the user configured. Replace the TODO with a pointer:

```kotlin
    // Category toggles live in data/Categories.kt, on their own DE-backed
    // preferences file — see the KDoc there for why they are not in this object.
    // TODO(Phase 3): log retention days and the redaction default.
```

---

## 8. Bug found in a file this task does not own

`app/src/main/res/layout/activity_main.xml:29` uses `android:menu` on
`BottomNavigationView`. `menu` is a **library** attribute, not a framework one, so
`aapt2` fails resource linking:

```
ERROR: activity_main.xml:29: AAPT: error: attribute android:menu not found.
```

The fix is two lines — declare the auto namespace on the root element and change
the prefix:

```xml
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    …
    <com.google.android.material.bottomnavigation.BottomNavigationView
        android:id="@+id/bottom_nav"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        app:menu="@menu/nav_main" />
```

This blocks `:app:processDebugResources`, i.e. the entire Gradle parity build,
and it will block `mka Nullroute` for the same reason.
