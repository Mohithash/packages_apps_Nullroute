/*
 * Nullroute — libnrjni, the app's only path into the native core.
 *
 * Three entry points, deliberately: build an index, ask about one host, validate
 * a file. Everything else the app needs (mode, uid policy, generation) is a store
 * into the mapped control page from Kotlin, not a call through here.
 *
 * WHY JSON STRINGS RATHER THAN OBJECTS. Building a Java object graph across JNI
 * means FindClass + GetMethodID + NewObject per field, all of it duplicated in
 * two languages and none of it checked by either compiler. A JSON string has one
 * producer (NrCtlCore.cpp) shared with `nrctl --json`, so the CLI and the app
 * cannot drift into disagreeing about a verdict — which is the failure this
 * project cares about most.
 *
 * NO C++ EXCEPTION MAY CROSS THE BOUNDARY. Unwinding through the JVM's frames is
 * undefined behaviour and shows up as an unrelated ART crash hours later, so
 * every entry point has a catch-all that converts to a Java throw. On the Java
 * side: a thrown exception means the operation did not happen; a returned string
 * always parses as JSON.
 *
 * The second parameter is declared `jobject` rather than `jclass` on purpose: a
 * Kotlin `object Native { external fun … }` compiles its members to INSTANCE
 * methods on the singleton, while a `@JvmStatic` companion compiles them to
 * statics. The parameter is unused and the ABI is identical either way, so the
 * facade can be written whichever way reads better.
 */
#include <jni.h>

#include <string.h>

#include <exception>
#include <new>
#include <string>
#include <vector>

#include "NrCtl.h"

using namespace nr;

namespace {

/* GetStringUTFChars + guaranteed release. A jstring may be null (Kotlin `String?`
 * or an omitted optional path), which is represented as an empty value rather
 * than a crash — every optional input to a build is legitimately absent. */
class ScopedUtf {
  public:
    ScopedUtf(JNIEnv* env, jstring s) : env_(env), js_(s) {
        if (js_) p_ = env_->GetStringUTFChars(js_, nullptr);
    }
    ~ScopedUtf() {
        if (js_ && p_) env_->ReleaseStringUTFChars(js_, p_);
    }
    ScopedUtf(const ScopedUtf&) = delete;
    ScopedUtf& operator=(const ScopedUtf&) = delete;

    const char* c_str() const { return p_ ? p_ : ""; }
    bool        empty() const { return !p_ || !*p_; }

  private:
    JNIEnv*     env_;
    jstring     js_;
    const char* p_ = nullptr;
};

/* An index mapping released on every path out, including the one where
 * nr_json_query() throws bad_alloc on a very long trace. Leaking an fd and a
 * multi-megabyte mapping per failed query would be invisible until the app hit
 * its fd limit hours later, which is the worst shape a leak can have. */
class ScopedIndex {
  public:
    ~ScopedIndex() { nr_index_close_ro(&ix); }
    ScopedIndex()                              = default;
    ScopedIndex(const ScopedIndex&)            = delete;
    ScopedIndex& operator=(const ScopedIndex&) = delete;
    NrIndexRO ix;
};

void throw_java(JNIEnv* env, const char* cls, const std::string& msg) {
    /* If an exception is already pending, adding another loses the first and the
     * original cause is what the user needs. */
    if (env->ExceptionCheck()) return;
    jclass c = env->FindClass(cls);
    if (!c) {
        env->ExceptionClear();
        c = env->FindClass("java/lang/RuntimeException");
        if (!c) return;
    }
    env->ThrowNew(c, msg.c_str());
    env->DeleteLocalRef(c);
}

jstring to_jstring(JNIEnv* env, const std::string& s) {
    jstring js = env->NewStringUTF(s.c_str());
    if (!js && !env->ExceptionCheck())
        throw_java(env, "java/lang/OutOfMemoryError", "cannot allocate the result string");
    return js;
}

}  // namespace

extern "C" {

/*
 * nativeBuild(String[] sourcePaths, String allowPath, String denyPath,
 *             String redirectPath, String outPath, long generation) -> String
 *
 * Compiles the given lists into a complete NRDX at `outPath` and returns the
 * build statistics as JSON. It does NOT publish: promotion is rename() plus a
 * release-store of want_generation, and that sequencing belongs to
 * core/Generation.kt, which also owns the canary and the rollback (§6.3).
 *
 * Group ids: sourcePaths[i] gets 1+i, so a verdict's group indexes straight back
 * into the array the caller passed and into manifest.<gen>.json.
 *
 * TWO INPUTS ARE NOT PARAMETERS, on purpose:
 *   - the never-block floor (/system_ext/etc/nullroute/neverblock.txt) is added
 *     as K_FORCE by this function, so no caller — and no user — can build an
 *     index without it. It is what keeps FCM push and the captive-portal check
 *     alive when a list goes wrong (§10.3.5), and an omissible floor is not a
 *     floor.
 *   - the idx-probe redirect is added for the same reason: without it the app's
 *     own liveness check can never go green, so no index may ship without one.
 * The opt-in carve-out categories ARE the caller's business and belong in
 * allowPath — only the app knows which categories the user turned on.
 *
 * Throws IllegalArgumentException (bad arguments), IOException (a required file
 * could not be read or the output could not be written), IllegalStateException
 * (the compile itself failed) or OutOfMemoryError.
 */
JNIEXPORT jstring JNICALL
Java_com_bestrom_nullroute_core_Native_nativeBuild(JNIEnv* env, jobject,
                                                   jobjectArray sourcePaths,
                                                   jstring allowPath, jstring denyPath,
                                                   jstring redirectPath, jstring outPath,
                                                   jlong generation) {
    try {
        ScopedUtf out(env, outPath);
        if (out.empty()) {
            throw_java(env, "java/lang/IllegalArgumentException", "outPath is required");
            return nullptr;
        }
        if (generation < 1) {
            /* Generation 0 means "no index" to the resolver: it would either never
             * map this file or remap it on every single query. */
            throw_java(env, "java/lang/IllegalArgumentException",
                       "generation must be >= 1");
            return nullptr;
        }

        NrCompileSpec spec;
        spec.generation  = (uint64_t)generation;
        spec.built_at_ms = nr_now_ms();

        const jsize n = sourcePaths ? env->GetArrayLength(sourcePaths) : 0;
        if (n > (jsize)NR_GROUP_SOURCE_MAX) {
            throw_java(env, "java/lang/IllegalArgumentException",
                       "too many sources for the 16-bit group id");
            return nullptr;
        }
        for (jsize i = 0; i < n; ++i) {
            jstring js = (jstring)env->GetObjectArrayElement(sourcePaths, i);
            ScopedUtf s(env, js);
            if (!s.empty()) {
                NrCompileInput in;
                in.path  = s.c_str();
                in.group = (uint16_t)(NR_GROUP_SOURCE_MIN + i);
                in.role  = NR_ROLE_LIST;
                /* A source that vanished mid-update is reported per-source in the
                 * result and does not abort the build; a build that silently
                 * became empty is the thing we refuse. */
                in.optional = true;
                spec.inputs.push_back(std::move(in));
            }
            if (js) env->DeleteLocalRef(js);
        }

        ScopedUtf deny(env, denyPath), allow(env, allowPath), redir(env, redirectPath);
        if (!deny.empty()) {
            NrCompileInput in;
            in.path     = deny.c_str();
            in.group    = NR_GROUP_USER_DENY;
            in.role     = NR_ROLE_LIST;
            in.optional = false;      /* the user typed these; losing them is a bug */
            spec.inputs.push_back(std::move(in));
        }
        if (!allow.empty()) {
            NrCompileInput in;
            in.path     = allow.c_str();
            in.group    = NR_GROUP_USER_ALLOW;
            in.role     = NR_ROLE_ALLOW;
            in.optional = false;
            spec.inputs.push_back(std::move(in));
        }
        if (!redir.empty()) {
            NrCompileInput in;
            in.path     = redir.c_str();
            in.group    = NR_GROUP_REDIRECT;
            in.role     = NR_ROLE_REDIRECT;
            in.optional = false;
            spec.inputs.push_back(std::move(in));
        }

        NrCompileInput floor;
        floor.path     = NR_PATH_NEVERBLOCK;
        floor.group    = NR_GROUP_FLOOR;
        floor.role     = NR_ROLE_FORCE;
        floor.optional = true;   /* absent on a stock-Android build; still built */
        spec.inputs.push_back(std::move(floor));

        BuildRedirect probe;
        probe.domain = NR_PROBE_IDX_NAME;
        probe.family = 2 /* AF_INET */;
        memset(probe.addr, 0, sizeof(probe.addr));
        probe.addr[0] = 127;
        probe.addr[3] = 7;
        spec.redirects.push_back(std::move(probe));

        std::vector<uint8_t> blob;
        NrCompileResult res;
        std::string err;
        if (!nr_compile(spec, &blob, &res, &err)) {
            const bool io = err.find("required input") != std::string::npos;
            throw_java(env, io ? "java/io/IOException" : "java/lang/IllegalStateException",
                       "nullroute: build failed: " + err);
            return nullptr;
        }
        if (!nr_write_file_atomic(out.c_str(), blob.data(), blob.size(), &err)) {
            throw_java(env, "java/io/IOException",
                       std::string("nullroute: cannot write ") + out.c_str() + ": " + err);
            return nullptr;
        }
        return to_jstring(env, nr_json_compile(res, out.c_str()));
    } catch (const std::bad_alloc&) {
        throw_java(env, "java/lang/OutOfMemoryError", "nullroute: out of memory while building");
        return nullptr;
    } catch (const std::exception& e) {
        throw_java(env, "java/lang/IllegalStateException",
                   std::string("nullroute: ") + e.what());
        return nullptr;
    } catch (...) {
        throw_java(env, "java/lang/IllegalStateException", "nullroute: unknown native failure");
        return nullptr;
    }
}

/*
 * nativeQuery(String indexPath, String host) -> String
 *
 * The verdict for one host, with the label depth it matched at, the source group
 * and the full per-depth walk, as JSON. Runs the same nr_evaluate() the resolver
 * runs inside netd, so the Query screen cannot tell the user something different
 * from what the device will actually do.
 *
 * A host the matcher declines to look at (IP literal, single label, .local and
 * friends) is not an error: it comes back with "evaluated": false and
 * "verdict": "PASS", which is exactly what the resolver would do with it.
 *
 * Throws IOException if the index cannot be read or does not validate.
 */
JNIEXPORT jstring JNICALL
Java_com_bestrom_nullroute_core_Native_nativeQuery(JNIEnv* env, jobject,
                                                   jstring indexPath, jstring host) {
    try {
        ScopedUtf path(env, indexPath), h(env, host);
        if (path.empty()) {
            throw_java(env, "java/lang/IllegalArgumentException", "indexPath is required");
            return nullptr;
        }
        ScopedIndex idx;
        std::string err;
        if (!nr_index_open_ro(path.c_str(), &idx.ix, &err)) {
            throw_java(env, "java/io/IOException",
                       std::string("nullroute: cannot read ") + path.c_str() + ": " + err);
            return nullptr;
        }
        return to_jstring(env, nr_json_query(idx.ix, path.c_str(), h.c_str()));
    } catch (const std::exception& e) {
        throw_java(env, "java/lang/IllegalStateException",
                   std::string("nullroute: ") + e.what());
        return nullptr;
    } catch (...) {
        throw_java(env, "java/lang/IllegalStateException", "nullroute: unknown native failure");
        return nullptr;
    }
}

/*
 * nativeVerify(String indexPath) -> String
 *
 * Structural validation, the sha256 seal and the liveness-probe check, as JSON.
 * This is the gate core/Generation.kt runs before promoting a staged index:
 * "ok": false means do not publish it.
 *
 * A file that fails validation is NOT an exception — an unpublishable index is a
 * normal outcome of a compile and the caller needs the reason to show the user.
 * Only a file that cannot be read at all throws.
 */
JNIEXPORT jstring JNICALL
Java_com_bestrom_nullroute_core_Native_nativeVerify(JNIEnv* env, jobject, jstring indexPath) {
    try {
        ScopedUtf path(env, indexPath);
        if (path.empty()) {
            throw_java(env, "java/lang/IllegalArgumentException", "indexPath is required");
            return nullptr;
        }
        NrVerifyReport r;
        nr_verify_index(path.c_str(), &r);
        if (!r.readable) {
            /* Only unreachable BYTES throw. An index that was read and did not
             * validate comes back as ok:false with a reason, because that is a
             * normal outcome of a compile and core/Generation.kt has to show the
             * user why it refused to promote — not catch an exception for it. */
            throw_java(env, "java/io/IOException",
                       std::string("nullroute: cannot read ") + path.c_str() + ": " + r.error);
            return nullptr;
        }
        return to_jstring(env, nr_json_verify(r));
    } catch (const std::exception& e) {
        throw_java(env, "java/lang/IllegalStateException",
                   std::string("nullroute: ") + e.what());
        return nullptr;
    } catch (...) {
        throw_java(env, "java/lang/IllegalStateException", "nullroute: unknown native failure");
        return nullptr;
    }
}

}  // extern "C"
