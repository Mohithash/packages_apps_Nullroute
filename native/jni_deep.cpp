/*
 * Nullroute — libnrjni, the Deep-mode (L2) entry points.
 *
 * Deep mode is a VpnService that terminates DNS in the app process. It must
 * reach exactly the same verdict the resolver hook inside netd reaches, for the
 * same name, from the same index — otherwise "why was this blocked?" has two
 * answers and the Query screen is lying about one of them. So there is no
 * matcher here: this file maps the index and calls nr_evaluate(), the same
 * object libnetd_resolv links (§6.1).
 *
 * WHY THIS IS NOT jni_bridge.cpp. That file answers cold questions — build an
 * index, explain one host, validate a file — and returns JSON because one
 * producer shared with `nrctl --json` is what stops the CLI and the app from
 * disagreeing. Deep mode asks a hot question, once per DNS query on the packet
 * path, and a JSON round trip per query would be absurd. The verdict therefore
 * comes back as a packed jlong with the redirect address written into a
 * caller-owned array, and only the diagnostics entry point emits JSON.
 *
 * NO C++ EXCEPTION MAY CROSS THE BOUNDARY. Unwinding through the JVM's frames is
 * undefined behaviour that surfaces as an unrelated ART crash much later, so
 * every entry point has a catch-all. The hot path additionally never *throws*:
 * it allocates nothing, does no I/O and takes one uncontended lock.
 *
 * SESSIONS ARE RECYCLED, NEVER FREED. The handle names a slot in a fixed static
 * pool plus the generation that occupied it. A call that races a close — the
 * packet thread evaluating while the service tears the tunnel down — therefore
 * touches memory that is always valid, sees a generation that no longer matches,
 * and returns "no verdict" (which relays the query). Handing Kotlin a raw
 * pointer and trusting it not to use it after close would make that race a
 * use-after-free inside the process that is holding the device's DNS.
 */
#include <jni.h>

#include <string.h>
#include <sys/stat.h>

#include <atomic>
#include <exception>
#include <mutex>
#include <new>
#include <string>

#include "NrCtl.h"

using namespace nr;

namespace {

/* Deep mode runs one tunnel at a time; the extra slots absorb a stop/start
 * overlap without ever reusing a live one. */
constexpr unsigned NR_DEEP_SLOTS = 4u;

/* Packed verdict layout — mirrored by DeepVerdict in deep/DeepVpnService.kt.
 * Adding a field is safe, moving one silently changes every decision. */
constexpr int NR_DEEP_SH_KIND     = 0;
constexpr int NR_DEEP_SH_DEPTH    = 8;
constexpr int NR_DEEP_SH_GROUP    = 16;
constexpr int NR_DEEP_SH_FAMILY   = 32;
constexpr int NR_DEEP_SH_RESPONSE = 40;
constexpr int NR_DEEP_SH_MODE     = 48;
constexpr int NR_DEEP_BIT_CTL     = 56;

/* The control page as it reads on a device that has none — a stock-Android
 * install, where /data/misc/nullroute does not exist. Zero is ENFORCE, response
 * EAI_NONAME, and every uid_policy byte NR_POLICY_ENFORCE, which is precisely
 * the intended default. It is `static` (i.e. in .bss, ~100 KiB) rather than
 * per-slot so four sessions do not cost four copies of it. */
const NrControl& default_control() {
    static const NrControl kZero{};
    return kZero;
}

struct DeepSlot {
    std::mutex mu;

    /* Bumped on every open, so a handle minted for a previous occupant can be
     * recognised and refused. Never reset. */
    uint32_t generation = 0;
    bool     in_use     = false;

    NrIndexRO   index;
    NrCtlMap    ctl;
    bool        have_ctl = false;
    std::string index_path;

    /* Staleness detection when there is no control page to watch: the identity
     * of the file we mapped. current.nrdx is replaced by rename(), so the inode
     * changes even though the path does not.
     *
     * The `idx_` prefix is not decoration: bionic's <sys/stat.h> defines
     * st_mtime as a MACRO (st_mtim.tv_sec), so a member of that name does not
     * compile against real headers even though it does against a stub. */
    dev_t   idx_dev     = 0;
    ino_t   idx_ino     = 0;
    int64_t idx_mtime_s = 0;
    int64_t idx_size    = 0;

    uint64_t opened_at_ms = 0;
    uint64_t evaluations  = 0;
    uint64_t remaps       = 0;
};

DeepSlot   g_slots[NR_DEEP_SLOTS];
std::mutex g_registry_mu;

inline jlong pack_handle(unsigned slot, uint32_t generation) {
    /* slot + 1 so that a zeroed handle is always invalid. */
    return (jlong)(((uint64_t)(slot + 1u) << 32) | (uint64_t)generation);
}

inline bool split_handle(jlong handle, unsigned* slot, uint32_t* generation) {
    const uint64_t h  = (uint64_t)handle;
    const uint64_t hi = h >> 32;
    if (hi == 0 || hi > NR_DEEP_SLOTS) return false;
    *slot       = (unsigned)(hi - 1u);
    *generation = (uint32_t)(h & 0xFFFFFFFFu);
    return true;
}

/* Records the identity of the mapped index so a replacement can be noticed
 * without a control page. Failure is not fatal: the worst outcome is that we
 * remap once per refresh interval on a device where stat() does not work. */
void record_identity(DeepSlot& s) {
    struct stat st;
    if (stat(s.index_path.c_str(), &st) == 0) {
        s.idx_dev     = st.st_dev;
        s.idx_ino     = st.st_ino;
        s.idx_mtime_s = (int64_t)st.st_mtime;
        s.idx_size    = (int64_t)st.st_size;
    } else {
        s.idx_dev     = 0;
        s.idx_ino     = 0;
        s.idx_mtime_s = 0;
        s.idx_size    = 0;
    }
}

/* True when the file at index_path is no longer the one we have mapped. */
bool identity_changed(const DeepSlot& s) {
    struct stat st;
    if (stat(s.index_path.c_str(), &st) != 0) return false;   /* gone: keep what we have */
    return st.st_dev != s.idx_dev || st.st_ino != s.idx_ino ||
           (int64_t)st.st_mtime != s.idx_mtime_s || (int64_t)st.st_size != s.idx_size;
}

void release_slot(DeepSlot& s) {
    nr_index_close_ro(&s.index);
    if (s.have_ctl) {
        nr_ctl_close(&s.ctl);
        s.have_ctl = false;
    }
    s.index_path.clear();
    s.in_use = false;
}

class ScopedUtf {
  public:
    ScopedUtf(JNIEnv* env, jstring s) : env_(env), js_(s) {
        if (js_) p_ = env_->GetStringUTFChars(js_, nullptr);
    }
    ~ScopedUtf() {
        if (js_ && p_) env_->ReleaseStringUTFChars(js_, p_);
    }
    ScopedUtf(const ScopedUtf&)            = delete;
    ScopedUtf& operator=(const ScopedUtf&) = delete;

    const char* c_str() const { return p_ ? p_ : ""; }
    bool        empty() const { return !p_ || !*p_; }

  private:
    JNIEnv*     env_;
    jstring     js_;
    const char* p_ = nullptr;
};

void throw_java(JNIEnv* env, const char* cls, const std::string& msg) {
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

std::string status_json(const DeepSlot& s) {
    const NrHeader* h = s.index.ix.hdr;
    std::string     out;
    out.reserve(512);
    out += "{\"ok\":true,\"path\":\"";
    nr_json_escape(s.index_path.c_str(), s.index_path.size(), &out);
    out += "\",\"generation\":" + std::to_string(h ? h->generation : 0ull);
    out += ",\"n_block\":" + std::to_string(h ? h->n_block : 0u);
    out += ",\"n_allow\":" + std::to_string(h ? h->n_allow : 0u);
    out += ",\"n_redirect\":" + std::to_string(h ? h->n_redirect : 0u);
    out += ",\"control_mapped\":";
    out += s.have_ctl ? "true" : "false";
    const NrControl& ctl = s.have_ctl ? *s.ctl.p : default_control();
    out += ",\"mode\":" + std::to_string((unsigned)ctl.mode);
    out += ",\"response_mode\":" + std::to_string((unsigned)ctl.response_mode);
    out += ",\"opened_at_ms\":" + std::to_string(s.opened_at_ms);
    out += ",\"evaluations\":" + std::to_string(s.evaluations);
    out += ",\"remaps\":" + std::to_string(s.remaps);
    out += "}";
    return out;
}

}  // namespace

extern "C" {

/*
 * nativeDeepOpen(String indexPath, String controlPath) -> long
 *
 * Maps the index read-only, and the control page too when one exists. Returns 0
 * if the index could not be mapped or validated — Deep mode refuses to establish
 * a tunnel it cannot filter with, because that would take the device's only VPN
 * slot and give nothing back.
 *
 * controlPath may be null or empty. On a stock-Android install there is no
 * /data/misc/nullroute and therefore no control page, and the defaults above are
 * exactly right: enforcing, EAI_NONAME, no per-app exemptions.
 *
 * Never throws. A caller that gets 0 has a reason to show the user, not an
 * exception to catch on a service-startup path.
 */
JNIEXPORT jlong JNICALL
Java_com_bestrom_nullroute_core_Native_nativeDeepOpen(JNIEnv* env, jobject,
                                                      jstring indexPath, jstring controlPath) {
    try {
        ScopedUtf index(env, indexPath), control(env, controlPath);
        if (index.empty()) return 0;

        std::lock_guard<std::mutex> registry(g_registry_mu);
        for (unsigned i = 0; i < NR_DEEP_SLOTS; ++i) {
            DeepSlot& s = g_slots[i];
            std::lock_guard<std::mutex> lock(s.mu);
            if (s.in_use) continue;

            std::string err;
            if (!nr_index_open_ro(index.c_str(), &s.index, &err)) return 0;

            s.index_path   = index.c_str();
            s.have_ctl     = false;
            s.opened_at_ms = nr_now_ms();
            s.evaluations  = 0;
            s.remaps       = 0;
            record_identity(s);

            if (!control.empty()) {
                /* Read-only: nothing in Deep mode is allowed to write the page
                 * the resolver and the UI share. A missing control page is the
                 * normal case off-ROM and is not an error. */
                std::string ctl_err;
                s.have_ctl = nr_ctl_open(control.c_str(), false, &s.ctl, &ctl_err);
            }

            s.generation += 1u;
            s.in_use = true;
            return pack_handle(i, s.generation);
        }
        return 0;   /* pool exhausted: a previous session was not closed */
    } catch (...) {
        return 0;
    }
}

/*
 * nativeDeepClose(long handle)
 *
 * Releases the mappings and returns the slot to the pool. The slot object itself
 * is never destroyed, so a concurrent evaluate() on a stale handle finds valid
 * memory and a generation that no longer matches. Idempotent.
 */
JNIEXPORT void JNICALL
Java_com_bestrom_nullroute_core_Native_nativeDeepClose(JNIEnv*, jobject, jlong handle) {
    try {
        unsigned slot;
        uint32_t generation;
        if (!split_handle(handle, &slot, &generation)) return;
        DeepSlot& s = g_slots[slot];
        std::lock_guard<std::mutex> lock(s.mu);
        if (!s.in_use || s.generation != generation) return;
        release_slot(s);
    } catch (...) {
        /* Nothing useful to report and nothing safe to throw from a teardown. */
    }
}

/*
 * nativeDeepEvaluate(long handle, byte[] name, int nameLen, int uid, byte[] outAddr) -> long
 *
 * THE hot path: one verdict per DNS query carried by the tunnel. Returns the
 * packed verdict described at the top of this file, or -1 for "no verdict", on
 * which the caller relays the query untouched. Every failure here is a relay,
 * never a block — Deep mode missing an advert is a nuisance, Deep mode
 * swallowing a lookup is a broken phone.
 *
 * `name` carries raw canonical bytes (lowercase, dot-separated, no trailing
 * root dot) rather than a String, deliberately: the matcher hashes the octets
 * the resolver would see, and a UTF-8 round trip through java.lang.String would
 * change them for any label that is not ASCII.
 *
 * UID HANDLING IS NOT A DETAIL. nr_evaluate() maps uid to an appId with
 * `uid % NR_AID_USER_OFFSET`, and uid_t is unsigned — so passing -1 for "not
 * known" would index uid_policy[67295] and apply some unrelated app's exemption
 * to every unattributed query. A negative uid therefore skips the per-app gate
 * entirely and evaluates the index with the mode gate applied by hand. Per-app
 * policy is exact at the resolver hook, where netd reads the real uid from
 * SO_PEERCRED, and is simply absent here rather than approximated.
 */
JNIEXPORT jlong JNICALL
Java_com_bestrom_nullroute_core_Native_nativeDeepEvaluate(JNIEnv* env, jobject, jlong handle,
                                                          jbyteArray name, jint nameLen, jint uid,
                                                          jbyteArray outAddr) {
    try {
        unsigned slot;
        uint32_t generation;
        if (!split_handle(handle, &slot, &generation)) return -1;
        if (!name || nameLen <= 0 || nameLen > (jint)NR_MAX_NAME) return -1;

        char buf[NR_MAX_NAME + 1];
        env->GetByteArrayRegion(name, 0, nameLen, reinterpret_cast<jbyte*>(buf));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return -1;
        }
        buf[nameLen] = '\0';

        Verdict v{};
        uint8_t mode = NR_MODE_ENFORCE;
        uint8_t resp = NR_RESP_NONAME;
        bool    ctl_mapped;
        {
            DeepSlot& s = g_slots[slot];
            std::lock_guard<std::mutex> lock(s.mu);
            if (!s.in_use || s.generation != generation) return -1;

            const NrControl& ctl = s.have_ctl ? *s.ctl.p : default_control();
            ctl_mapped = s.have_ctl;
            mode       = ctl.mode;
            resp       = ctl.response_mode;

            if (uid < 0) {
                /* See the uid note above. The mode gate still applies: a paused
                 * filter must be paused in the tunnel too, or Pause would mean
                 * "pause three quarters of it". */
                if (ctl.mode == NR_MODE_ENFORCE) {
                    v = nr_evaluate_index(s.index.ix, buf, (size_t)nameLen);
                } else {
                    v.kind = V_PASS;
                }
            } else {
                v = nr_evaluate(s.index.ix, ctl, buf, (size_t)nameLen, (uid_t)uid);
            }
            s.evaluations += 1;
        }

        if (v.kind == V_REDIRECT && outAddr) {
            const jsize want = (v.family == 10 /* AF_INET6 */) ? 16 : 4;
            if (env->GetArrayLength(outAddr) >= want) {
                env->SetByteArrayRegion(outAddr, 0, want,
                                        reinterpret_cast<const jbyte*>(v.addr));
            }
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                return -1;
            }
        }

        uint64_t packed = 0;
        packed |= (uint64_t)(uint8_t)v.kind << NR_DEEP_SH_KIND;
        packed |= (uint64_t)v.depth << NR_DEEP_SH_DEPTH;
        packed |= (uint64_t)v.group << NR_DEEP_SH_GROUP;
        packed |= (uint64_t)v.family << NR_DEEP_SH_FAMILY;
        packed |= (uint64_t)resp << NR_DEEP_SH_RESPONSE;
        packed |= (uint64_t)mode << NR_DEEP_SH_MODE;
        if (ctl_mapped) packed |= (uint64_t)1 << NR_DEEP_BIT_CTL;
        return (jlong)packed;
    } catch (...) {
        return -1;
    }
}

/*
 * nativeDeepRefresh(long handle) -> int
 *
 * 1 if a newer index was mapped, 0 if nothing had changed, -1 on a bad handle or
 * a failed remap.
 *
 * A failed remap KEEPS THE OLD MAPPING. An index that will not validate is a
 * reason to carry on filtering with the one that did, not a reason to stop
 * filtering — the same rule the resolver's NrMap follows, for the same reason.
 *
 * Cheap enough to call on a timer: with a control page it compares one word,
 * and without one it is a single stat().
 */
JNIEXPORT jint JNICALL
Java_com_bestrom_nullroute_core_Native_nativeDeepRefresh(JNIEnv*, jobject, jlong handle) {
    try {
        unsigned slot;
        uint32_t generation;
        if (!split_handle(handle, &slot, &generation)) return -1;

        DeepSlot& s = g_slots[slot];
        std::lock_guard<std::mutex> lock(s.mu);
        if (!s.in_use || s.generation != generation) return -1;

        const uint64_t mapped = s.index.ix.hdr ? s.index.ix.hdr->generation : 0ull;
        bool stale;
        if (s.have_ctl) {
            /* The app release-stores want_generation AFTER rename()ing the new
             * file into place, so observing the new value means the bytes are
             * already there (§6.3). */
            const uint64_t want =
                __atomic_load_n(&s.ctl.p->want_generation, __ATOMIC_ACQUIRE);
            stale = (want != 0ull && want != mapped);
        } else {
            stale = identity_changed(s);
        }
        if (!stale) return 0;

        NrIndexRO   fresh;
        std::string err;
        if (!nr_index_open_ro(s.index_path.c_str(), &fresh, &err)) return -1;

        nr_index_close_ro(&s.index);
        s.index = fresh;
        s.remaps += 1;
        record_identity(s);
        return 1;
    } catch (...) {
        return -1;
    }
}

/*
 * nativeDeepStatus(long handle) -> String
 *
 * Diagnostics only, never the hot path. Returns JSON; throws
 * IllegalStateException only if the result string cannot be allocated.
 */
JNIEXPORT jstring JNICALL
Java_com_bestrom_nullroute_core_Native_nativeDeepStatus(JNIEnv* env, jobject, jlong handle) {
    try {
        unsigned slot;
        uint32_t generation;
        std::string json;
        if (!split_handle(handle, &slot, &generation)) {
            json = "{\"ok\":false,\"error\":\"bad handle\"}";
        } else {
            DeepSlot& s = g_slots[slot];
            std::lock_guard<std::mutex> lock(s.mu);
            json = (!s.in_use || s.generation != generation)
                       ? std::string("{\"ok\":false,\"error\":\"closed\"}")
                       : status_json(s);
        }
        jstring js = env->NewStringUTF(json.c_str());
        if (!js && !env->ExceptionCheck()) {
            throw_java(env, "java/lang/OutOfMemoryError", "cannot allocate the result string");
        }
        return js;
    } catch (const std::exception& e) {
        throw_java(env, "java/lang/IllegalStateException", std::string("nullroute: ") + e.what());
        return nullptr;
    } catch (...) {
        throw_java(env, "java/lang/IllegalStateException", "nullroute: unknown native failure");
        return nullptr;
    }
}

}  // extern "C"
