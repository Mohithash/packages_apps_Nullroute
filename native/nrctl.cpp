/*
 * Nullroute — `nrctl`, the command-line face of the filter. /system_ext/bin/nrctl
 *
 * TWO CLASSES OF VERB, and the split is a security boundary, not a style choice:
 *
 *   READ verbs (status, query, verify, log, selftest) open the mapped files
 *   directly. `shell` has r_file_perms on nullroute_{index,ctl,log}_file
 *   (rom/sepolicy/nrctl.te) and nothing more, so these work from plain adb with
 *   no helper process and no privileged path to attack.
 *
 *   MUTATING verbs (pause, resume, off, update) own no write path at all. They
 *   send a broadcast to the app's CtlReceiver, which is the only writer of
 *   /data/misc/nullroute. There is deliberately no setuid binary and no
 *   root-required daemon here: the app already runs, already owns the files, and
 *   already has to serialise these operations against its own compile job.
 *   Because that receiver returns no result code, the mode-changing verbs then
 *   read control.bin back rather than trusting the broadcast's exit status.
 *
 * THE v8.2 BUG, structurally prevented. Re-Malwack advertised a domain-query verb
 * in --help and shipped a release whose CLI arm had been dropped, so `--help`
 * described a feature that silently did nothing. Here there is exactly ONE verb
 * table: help is generated from it and dispatch reads it, so a documented verb
 * without an implementation cannot be expressed. `nrctl selftest` then resolves
 * every verb through the same lookup the command line uses and executes it, so a
 * verb that resolves but does not work also fails, in CI, before the release.
 *
 * Exit codes (stable, for scripts):
 *   0  the command did what it said
 *   1  runtime failure (I/O, corrupt index, broadcast rejected)
 *   2  usage error
 *   3  unavailable — the file or the state being asked about does not exist yet
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>          /* getaddrinfo, for the Deep-mode probe */
#include <netinet/in.h>     /* sockaddr_in / INET_ADDRSTRLEN for the same */
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "NrCtl.h"
#include "NrRingReader.h"

using namespace nr;

#define NR_EXIT_OK          0
#define NR_EXIT_FAIL        1
#define NR_EXIT_USAGE       2
#define NR_EXIT_UNAVAILABLE 3

/* The CtlReceiver contract (§6.6). Both sides are ours and both are separately
 * built, so it is written out here in full — and the APP's constants are the
 * normative ones, because CtlReceiver is what the ROM actually ships:
 *
 *   action    com.bestrom.nullroute.action.CTL      (CtlReceiver.ACTION_CTL)
 *   component com.bestrom.nullroute/.ctl.CtlReceiver   (explicit — never a
 *             manifest-matched implicit broadcast)
 *   extras    verb   String   "pause"|"resume"|"off"|"update"|"check"|"mode"
 *             value  int      "mode" only
 *
 * The keys are bare `verb`/`value`, NOT namespaced `nr.verb`. A namespaced key
 * costs nothing to send and reads better, but the receiver calls
 * getStringExtra("verb"), so anything else arrives as null, falls into its
 * `else -> Log.w("unknown CTL verb")` arm and does nothing at all.
 *
 * THERE IS NO RESULT CONTRACT, and pretending otherwise is the trap here.
 * CtlReceiver never calls setResultCode()/setResultData(), so `am`/`cmd` always
 * reports the initial code 0 — including for a verb it silently dropped, and
 * including for a verb it never recognised. A CLI that reported that back as
 * success would be the v8.2 bug in its purest form: an advertised verb that
 * prints "ok" and changes nothing. So every verb that changes mode is CONFIRMED
 * by re-reading control.bin afterwards, and `update`, which has no immediate
 * observable, says "requested" rather than "done".
 *
 * The receiver additionally gates on getSentFromUid() ∈ {root, system, shell}.
 * Note that android:permission on the receiver means the SENDER must hold
 * com.bestrom.nullroute.permission.CTL; uid 0 and uid 1000 pass every permission
 * check by construction, uid 2000 (adb shell) does not unless the ROM ships the
 * <assign-permission ... uid="shell"/> line — so mutating verbs generally need
 * root or system, and say so when they are refused. */
#define NR_CTL_ACTION      "com.bestrom.nullroute.action.CTL"
#define NR_CTL_COMPONENT   "com.bestrom.nullroute/.ctl.CtlReceiver"
#define NR_CTL_EXTRA_VERB  "verb"
#define NR_CTL_EXTRA_VALUE "value"

/* FLAG_RECEIVER_FOREGROUND | FLAG_INCLUDE_STOPPED_PACKAGES. The second matters:
 * a force-stopped app receives no broadcasts at all, and "I force-stopped it and
 * now pause does nothing" is not a debugging experience anyone should have. */
#define NR_CTL_FLAGS "0x10000020"

/* ---------------------------------------------------------------------------
 * The second wave of verbs: apps, import, export, rollback, deep, panic.
 *
 * TWO EXTRAS ARE NEW, and they are new on BOTH sides. The receiver reads extras
 * by literal key, so these names have to match `CtlReceiver`'s constants exactly
 * or the verb marshals perfectly, is delivered successfully, and does nothing —
 * the failure this whole file is arranged around. What must exist in
 * ctl/CtlReceiver.kt is written out verbatim in docs/needs-deep.md:
 *
 *   const val EXTRA_PATH   = "path"     // import, export     --es path  <PATH>
 *   const val EXTRA_ENABLE = "enable"   // deep               --ez enable <bool>
 *   VERB_APPS/IMPORT/EXPORT/ROLLBACK/DEEP/PANIC = "apps"/"import"/…
 *
 * `apps` is not in that list because it is a READ verb: the per-app policy table
 * lives at NR_UID_POLICY_OFF inside control.bin, which `shell` can already map
 * read-only, so it needs no broadcast and no privilege.
 *
 * CONFIRMATION, verb by verb, because "the broadcast was delivered" proves
 * nothing (see the header comment on the result contract):
 *
 *   rollback  provable   — previous.nrdx's generation must become current's
 *   panic     provable   — control.bin::mode must become off
 *   export    provable   — the file must appear, if this shell can stat it
 *   import    NOT provable — the rebuild is asynchronous and minutes long
 *   deep      NOT provable — Deep mode's state is in the app's DE preferences,
 *                            which no shell can read; the probe below is
 *                            evidence, not proof, and is reported as such
 * ------------------------------------------------------------------------- */
#define NR_CTL_EXTRA_PATH   "path"
#define NR_CTL_EXTRA_ENABLE "enable"
#define NR_APP_PACKAGE      "com.bestrom.nullroute"

/* Where `export` writes when no path is given. Inside priv/ because the app owns
 * that directory through AID_MISC and can write it without SAF, a content
 * provider or any storage permission — and because a default that lands in
 * /sdcard would put the user's rule list somewhere every app can read. */
#define NR_PATH_EXPORT_DEFAULT NR_DIR_PRIV "/nullroute-settings.zip"

/* Deep mode's liveness probe. Mirrors core/Probes.kt (DEEP / DEEP_EXPECT); the
 * two `.invalid` probes in NrCtl.h are the resolver's and the hosts layer's, and
 * this one is answered inside the tunnel by the app rather than by anything
 * native, which is why it is not up there with them. docs/needs-deep.md asks for
 * it to be promoted into NrCtl.h so this duplicate can go. */
#define NR_PROBE_DEEP_NAME "vpn-probe.nullroute.invalid"
#define NR_PROBE_DEEP_ADDR "127.0.0.9"

namespace {

struct Ctx {
    bool json    = false;
    bool explain = false;
    bool dry_run = false;          /* selftest only: describe, never send */
    int  user    = 0;
    std::string index_path = NR_PATH_INDEX_CURRENT;
    std::string ctl_path   = NR_PATH_CONTROL;
    std::string ring_path  = NR_PATH_RING;
    std::vector<std::string> args; /* positional arguments after the verb */
    std::string last_command;      /* what the last broadcast would send */
};

typedef int (*VerbFn)(Ctx&);

struct Verb {
    const char* name;
    const char* usage;
    const char* summary;
    VerbFn      fn;
    bool        mutating;
};

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

void kv(const char* key, const char* fmt, ...) {
    printf("  %-12s", key);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

void warn(const char* fmt, ...) {
    fprintf(stderr, "nrctl: ");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

std::string human_bytes(uint64_t n) {
    char buf[48];
    if (n >= 1048576) snprintf(buf, sizeof(buf), "%.2f MB", n / 1048576.0);
    else if (n >= 1024) snprintf(buf, sizeof(buf), "%.1f KB", n / 1024.0);
    else snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)n);
    return buf;
}

/* Thousands separators, because "226398" and "22639" are indistinguishable at a
 * glance and this number is the one users compare between profiles. */
std::string human_count(uint64_t n) {
    char raw[32];
    snprintf(raw, sizeof(raw), "%llu", (unsigned long long)n);
    std::string out;
    const size_t len = strlen(raw);
    for (size_t i = 0; i < len; ++i) {
        if (i && (len - i) % 3 == 0) out.push_back(',');
        out.push_back(raw[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// The broadcast path
// ---------------------------------------------------------------------------

/* Runs argv, capturing stdout+stderr. Returns the exit status, or -1 if the
 * binary could not be run at all. */
int run_capture(const std::vector<std::string>& argv, std::string* out) {
    out->clear();
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    const pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const std::string& s : argv) cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);
        execv(cargv[0], cargv.data());
        _exit(127);
    }
    close(pipefd[1]);
    char buf[4096];
    for (;;) {
        const ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) { out->append(buf, (size_t)n); continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(pipefd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

struct BroadcastArg {
    const char* kind;   /* "--es" or "--ei" */
    std::string key, value;
};

/*
 * Marshals and sends the CTL broadcast. Prints NOTHING on success: only the
 * calling verb knows how to confirm that the receiver actually acted, and this
 * function can prove no more than "the intent was delivered to a receiver".
 * `err` receives a one-line reason on failure.
 */
int send_ctl(Ctx& ctx, const char* verb, const std::vector<BroadcastArg>& extras,
             std::string* err) {
    err->clear();

    /* `cmd activity` runs inside the already-started system_server; `am` spawns a
     * whole app_process VM to do the same thing. Prefer the cheap one and fall
     * back only if this build does not ship it. */
    std::vector<std::string> argv;
    if (access("/system/bin/cmd", X_OK) == 0) {
        argv = {"/system/bin/cmd", "activity", "broadcast"};
    } else if (access("/system/bin/am", X_OK) == 0) {
        argv = {"/system/bin/am", "broadcast"};
    } else if (ctx.dry_run) {
        /* A dry run marshals the intent and never execs, so a host or a chroot
         * with neither binary must still exercise the whole argument path — that
         * is the only thing `nrctl selftest` can check about this verb, and a
         * gate that skips itself off-device is not a gate. */
        argv = {"/system/bin/cmd", "activity", "broadcast"};
    } else {
        *err = "neither /system/bin/cmd nor /system/bin/am is available";
        return NR_EXIT_UNAVAILABLE;
    }
    char userbuf[16];
    snprintf(userbuf, sizeof(userbuf), "%d", ctx.user);
    argv.push_back("--user");
    argv.push_back(userbuf);
    argv.push_back("-a");
    argv.push_back(NR_CTL_ACTION);
    argv.push_back("-n");
    argv.push_back(NR_CTL_COMPONENT);
    argv.push_back("-f");
    argv.push_back(NR_CTL_FLAGS);
    argv.push_back("--es");
    argv.push_back(NR_CTL_EXTRA_VERB);
    argv.push_back(verb);
    for (const BroadcastArg& e : extras) {
        argv.push_back(e.kind);
        argv.push_back(e.key);
        argv.push_back(e.value);
    }

    ctx.last_command.clear();
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i) ctx.last_command.push_back(' ');
        ctx.last_command += argv[i];
    }
    if (ctx.dry_run) {
        if (!ctx.json) printf("would run: %s\n", ctx.last_command.c_str());
        return NR_EXIT_OK;
    }

    std::string out;
    const int rc = run_capture(argv, &out);
    if (rc < 0) {
        *err = "could not run " + argv[0];
        return NR_EXIT_FAIL;
    }

    if (out.find("Permission Denial") != std::string::npos ||
        out.find("SecurityException") != std::string::npos) {
        *err = "the app refused the broadcast (permission denied)";
        warn("mutating verbs need root or the system uid: CtlReceiver is guarded by");
        warn("com.bestrom.nullroute.permission.CTL, and adb shell (uid 2000) only holds");
        warn("it if the ROM ships <assign-permission ... uid=\"shell\"/>.");
        warn("try:  su -c 'nrctl %s'   or use the app / Quick Settings tile", verb);
        return NR_EXIT_FAIL;
    }
    /* `Broadcast completed: result=N` is printed by am's own result receiver, so
     * its ABSENCE means the intent never reached one — almost always because the
     * app is not installed on this user. Its PRESENCE means only that: N is the
     * initial code, and CtlReceiver never overwrites it. */
    if (out.find("result=") == std::string::npos) {
        *err = "no receiver answered on user " + std::to_string(ctx.user) +
               " — is Nullroute installed there?";
        if (!out.empty()) fputs(out.c_str(), stderr);
        return NR_EXIT_FAIL;
    }
    return NR_EXIT_OK;
}

/* ctl.mode as the resolver will see it. Returns false when control.bin cannot be
 * read at all, which on a user build is the normal outcome from a plain adb
 * shell: /data/misc/nullroute/ctl is 0770 system:misc. */
bool read_mode(const Ctx& ctx, uint8_t* out) {
    NrCtlMap m;
    if (!nr_ctl_open(ctx.ctl_path.c_str(), false, &m, nullptr)) return false;
    NrCtlSnapshot s;
    nr_ctl_read(m, &s);
    nr_ctl_close(&m);
    *out = s.mode;
    return true;
}

/* Every failure of a mutating verb reports through here, so the error text —
 * which includes strerror() output and a user-supplied user id — is escaped once
 * instead of being interpolated raw into JSON at four call sites. */
void print_ctl_error_json(const char* verb, const std::string& err) {
    std::string j = "{\"ok\":false,\"verb\":\"";
    nr_json_escape(verb, strlen(verb), &j);
    j += "\",\"error\":\"";
    nr_json_escape(err.data(), err.size(), &j);
    j += "\"}";
    printf("%s\n", j.c_str());
}

/*
 * Send a mode-changing verb and then PROVE it landed.
 *
 * The broadcast hops to the app process, which may be cold-started for it, maps
 * the control page and stores one byte — normally a few milliseconds, but a busy
 * boot is slower, so this polls rather than sleeping once. Without the poll the
 * only alternative is to believe `am`'s result code, which is the initial code 0
 * whatever the receiver did.
 */
int cmd_setmode(Ctx& ctx, const char* verb, uint8_t want) {
    std::string err;
    const int rc = send_ctl(ctx, verb, {}, &err);
    if (rc != NR_EXIT_OK) {
        warn("%s: %s", verb, err.c_str());
        if (ctx.json) print_ctl_error_json(verb, err);
        return rc;
    }
    if (ctx.dry_run) return NR_EXIT_OK;

    uint8_t seen = 0;
    bool readable = false, confirmed = false;
    for (int waited = 0; waited < 2000; waited += 50) {
        readable = read_mode(ctx, &seen);
        if (readable && seen == want) { confirmed = true; break; }
        usleep(50 * 1000);
    }

    if (ctx.json) {
        printf("{\"ok\":%s,\"verb\":\"%s\",\"confirmed\":%s,\"mode\":\"%s\"}\n",
               (confirmed || !readable) ? "true" : "false", verb,
               confirmed ? "true" : "false",
               readable ? nr_mode_name(seen) : "unreadable");
        return (confirmed || !readable) ? NR_EXIT_OK : NR_EXIT_FAIL;
    }
    if (confirmed) {
        printf("%s: mode is now %s\n", verb, nr_mode_name(want));
        return NR_EXIT_OK;
    }
    if (!readable) {
        /* Not a failure: the broadcast was delivered, we simply have no read
         * access from this domain. Saying "ok" would be a guess; saying "failed"
         * would be wrong. Say exactly what is known. */
        printf("%s: sent. Cannot confirm from this shell — control.bin is not\n"
               "  readable here (0770 system:misc). Re-check with the app, or with\n"
               "      su -c 'nrctl status'\n", verb);
        return NR_EXIT_OK;
    }
    warn("%s: the broadcast was delivered but mode is still %s after 2 s.", verb,
         nr_mode_name(seen));
    warn("CtlReceiver returns no result code, so this is the only evidence there is.");
    warn("Check:  adb logcat -s Nullroute   (an unrecognised verb logs there)");
    return NR_EXIT_FAIL;
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

int cmd_status(Ctx& ctx) {
    NrCtlMap ctl;
    std::string ctl_err;
    const bool have_ctl = nr_ctl_open(ctx.ctl_path.c_str(), false, &ctl, &ctl_err);
    NrCtlSnapshot s{};
    if (have_ctl) nr_ctl_read(ctl, &s);

    NrIndexRO idx;
    std::string idx_err;
    const bool have_idx = nr_index_open_ro(ctx.index_path.c_str(), &idx, &idx_err);

    NrRingReader ring;
    const bool have_ring = nr_ring_open(ctx.ring_path.c_str(), &ring, nullptr);

    const std::string filter = nr_prop_get(NR_PROP_FILTER, "unset");
    const std::string seed   = nr_prop_get(NR_PROP_SEED, "unset");
    const std::string mode_p = nr_prop_get(NR_PROP_MODE, "unset");
    const int64_t kill       = nr_prop_get_i64(NR_PROP_KILL, 0);
    const int64_t streak     = nr_prop_get_i64(NR_PROP_FAIL_STREAK, 0);

    char built[40] = "";
    if (have_idx) nr_format_ms(idx.ix.hdr->built_at_ms, built, sizeof(built));
    char mapped_at[40] = "";
    if (have_ctl) nr_format_ms(s.last_map_ms, mapped_at, sizeof(mapped_at));

    if (ctx.json) {
        /* Property values are arbitrary bytes from the point of view of this
         * process — netd writes `filter`, and root can setprop anything — so they
         * go through the escaper like every other untrusted string. Concatenating
         * them raw would let one quote turn the app's status parse into garbage. */
        auto jprop = [](const char* key, const std::string& v) {
            std::string s = std::string("\"") + key + "\":\"";
            nr_json_escape(v.data(), v.size(), &s);
            s += "\",";
            return s;
        };
        std::string j = "{";
        j += "\"ok\":true,";
        j += jprop("filter_prop", filter);
        j += jprop("seed_prop", seed);
        j += jprop("mode_prop", mode_p);
        j += "\"kill\":" + std::to_string(kill) + ",";
        j += "\"fail_streak\":" + std::to_string(streak) + ",";
        j += "\"control\":{\"present\":";
        j += have_ctl ? "true" : "false";
        if (have_ctl) {
            j += ",\"mode\":\"" + std::string(nr_mode_name(s.mode)) + "\"";
            j += ",\"response_mode\":\"" + std::string(nr_resp_name(s.response_mode)) + "\"";
            j += ",\"log_level\":" + std::to_string(s.log_level);
            j += ",\"want_generation\":" + std::to_string(s.want_generation);
            j += ",\"mapped_generation\":" + std::to_string(s.mapped_generation);
            j += ",\"q_total\":" + std::to_string(s.q_total);
            j += ",\"q_blocked\":" + std::to_string(s.q_blocked);
            j += ",\"filter_abi\":" + std::to_string(s.filter_abi);
            j += ",\"map_errors\":" + std::to_string(s.map_errors);
            j += ",\"ring_drops\":" + std::to_string(s.ring_drops);
            j += ",\"fault_count\":" + std::to_string(s.fault_count);
            j += ",\"last_map_ms\":" + std::to_string(s.last_map_ms);
        } else {
            j += ",\"error\":\"";
            nr_json_escape(ctl_err.data(), ctl_err.size(), &j);
            j += "\"";
        }
        j += "},\"index\":{\"present\":";
        j += have_idx ? "true" : "false";
        if (have_idx) {
            j += ",\"generation\":" + std::to_string(idx.ix.hdr->generation);
            j += ",\"bytes\":" + std::to_string(idx.map.size);
            j += ",\"n_block\":" + std::to_string(idx.ix.hdr->n_block);
            j += ",\"n_allow\":" + std::to_string(idx.ix.hdr->n_allow);
            j += ",\"n_redirect\":" + std::to_string(idx.ix.hdr->n_redirect);
            j += ",\"built_at\":\"" + std::string(built) + "\"";
        } else {
            j += ",\"error\":\"";
            nr_json_escape(idx_err.data(), idx_err.size(), &j);
            j += "\"";
        }
        j += "},\"log\":{\"present\":";
        j += have_ring ? "true" : "false";
        if (have_ring) {
            j += ",\"head\":" + std::to_string(nr_ring_head(ring));
            j += ",\"available\":" + std::to_string(nr_ring_available(ring));
        }
        j += "}}";
        printf("%s\n", j.c_str());
    } else {
        printf("Nullroute\n");
        kv("filter", "%s%s", filter.c_str(),
           filter == "unset" ? "   (the resolver has not reported in — see Diagnostics)" : "");
        if (have_ctl) {
            kv("mode", "%s   (persist property: %s)", nr_mode_name(s.mode), mode_p.c_str());
            kv("response", "%s", nr_resp_name(s.response_mode));
            /* Named here because `nrctl log` being empty is otherwise
             * indistinguishable from the filter being dead. */
            kv("logging", "%s",
               s.log_level == 0 ? "off" : (s.log_level == 1 ? "blocked only" : "everything"));
        } else {
            kv("mode", "unknown — %s", ctl_err.c_str());
        }
        kv("kill switch", "%s", kill ? "ON — filtering is disabled device-wide" : "off");
        if (have_idx) {
            kv("index", "generation %llu, %s, built %s",
               (unsigned long long)idx.ix.hdr->generation,
               human_bytes(idx.map.size).c_str(), built);
            kv("", "%s block / %s allow / %s redirect",
               human_count(idx.ix.hdr->n_block).c_str(),
               human_count(idx.ix.hdr->n_allow).c_str(),
               human_count(idx.ix.hdr->n_redirect).c_str());
        } else {
            kv("index", "NONE — %s", idx_err.c_str());
        }
        if (have_ctl) {
            kv("resolver", "mapped generation %llu%s, last mapped %s",
               (unsigned long long)s.mapped_generation,
               s.mapped_generation != s.want_generation ? " (STALE)" : "", mapped_at);
            const double pct = s.q_total ? (100.0 * (double)s.q_blocked / (double)s.q_total) : 0.0;
            kv("queries", "%s total, %s blocked (%.1f%%)",
               human_count(s.q_total).c_str(), human_count(s.q_blocked).c_str(), pct);
            if (s.map_errors || s.fault_count || s.ring_drops)
                kv("faults", "map_errors %u, fault_count %u, ring_drops %u",
                   s.map_errors, s.fault_count, s.ring_drops);
        }
        if (have_ring)
            kv("log", "%llu records available (%llu produced since boot)",
               (unsigned long long)nr_ring_available(ring),
               (unsigned long long)nr_ring_head(ring));
        kv("seed", "%s", seed.c_str());
        if (streak) kv("boot", "fail_streak %lld of %d before quarantine",
                       (long long)streak, NR_FAIL_STREAK_LIMIT);

        /* The single most useful line on this screen: the two states that look
         * identical from userspace but are not. */
        if (have_idx && filter == "unset")
            printf("\n  An index is present but the resolver never reported in.\n"
                   "  Check:  adb shell dmesg | grep 'avc.*nullroute'\n");
    }

    if (have_ctl) nr_ctl_close(&ctl);
    if (have_idx) nr_index_close_ro(&idx);
    if (have_ring) nr_ring_close(&ring);
    return (have_ctl || have_idx) ? NR_EXIT_OK : NR_EXIT_UNAVAILABLE;
}

// ---------------------------------------------------------------------------
// query
// ---------------------------------------------------------------------------

void print_query_human(Ctx& ctx, const NrIndexRO& idx, const char* host) {
    NrExplain e;
    nr_explain(idx.ix, host, strlen(host), &e);

    printf("%s\n", host);
    if (!e.usable) {
        kv("verdict", "NOT BLOCKED");
        /* Two different rejections, and the canonical form tells them apart: the
         * canonicalizer fills it in before the IP-literal and reserved-suffix
         * checks, but returns earlier than that for a name it cannot even
         * tokenize. Saying which one it was is the difference between "fix your
         * input" and "this is not something a blocklist can describe". */
        kv("reason", "%s",
           e.canon[0] ? "an IP literal or a reserved suffix (.local, .onion, "
                        ".arpa, .localhost) — a name-layer filter must not touch these"
                      : "not a multi-label hostname: no dot, empty, over 253 bytes, "
                        "or a label over 63");
        printf("\n");
        return;
    }

    switch (e.verdict.kind) {
        case V_BLOCK: {
            std::string group_name;
            const char* builtin = nr_group_builtin_name(e.verdict.group);
            if (builtin) {
                group_name = builtin;
            } else {
                std::string dir(ctx.index_path);
                const size_t sl = dir.rfind('/');
                dir = (sl == std::string::npos) ? std::string(".") : dir.substr(0, sl);
                nr_manifest_group_name(dir.c_str(), idx.ix.hdr->generation,
                                       e.verdict.group, &group_name);
            }
            kv("verdict", "BLOCKED");
            /* Which rule, at what depth, from which group — all three, always. */
            kv("rule", "%s", e.matched_rule);
            kv("depth", "%u of %u labels", e.verdict.depth, e.depth);
            kv("source", "group %u%s%s", e.verdict.group,
               group_name.empty() ? "" : " — ", group_name.c_str());
            if (group_name.empty() && !nr_group_builtin_name(e.verdict.group))
                kv("", "(no manifest for generation %llu, so the source has a "
                       "number but no name)",
                   (unsigned long long)idx.ix.hdr->generation);
            break;
        }
        case V_REDIRECT:
            kv("verdict", "REDIRECTED");
            kv("address", "%s", e.redirect_addr);
            kv("rule", "%s (exact FQDN)", e.canon);
            break;
        case V_PASS:
        default:
            kv("verdict", "NOT BLOCKED");
            if (e.allow_hit) {
                const char* an = nr_group_builtin_name(e.allow_group);
                const std::string named = an ? std::string(" — ") + an : std::string();
                kv("reason", "an allow rule covers it");
                kv("rule", "%s (%s, depth %u of %u labels)", e.allow_rule,
                   nr_kind_name(e.allow_kind), e.allow_depth, e.depth);
                kv("source", "group %u%s", e.allow_group, named.c_str());
            } else {
                kv("reason", "no rule in this index matches it");
                kv("checked", "%u suffixes, most specific first", e.depth);
            }
            break;
    }

    kv("index", "generation %llu (%s block rules)",
       (unsigned long long)idx.ix.hdr->generation,
       human_count(idx.ix.hdr->n_block).c_str());

    if (e.verdict.kind != V_BLOCK) {
        const char* note = nr_expected_absence_note(e.canon);
        if (note) printf("\n  note: %s\n", note);
        /* nrctl reads the resolver index and nothing else. The baked L0 hosts
         * layer blocks ~2,000 domains that will never appear here, so "not
         * blocked" from this tool is not "not blocked on this device". */
        printf("\n  This is the resolver index only. The built-in /system/etc/hosts\n"
               "  layer is separate and nrctl cannot see it — check it with:\n"
               "      getent hosts %s\n", e.canon);
    }

    if (ctx.explain) {
        printf("\n  walk (most specific first; * = the rule that applies):\n");
        for (unsigned i = 0; i < e.n_steps; ++i) {
            const NrExplainStep& s = e.steps[i];
            char blk[64] = "-", alw[64] = "-";
            if (s.block_hit)
                snprintf(blk, sizeof(blk), "%s g%u%s", nr_kind_name(s.block_kind),
                         s.block_group, s.block_applies ? " *" : " (kind n/a)");
            if (s.allow_hit)
                snprintf(alw, sizeof(alw), "%s g%u%s", nr_kind_name(s.allow_kind),
                         s.allow_group, s.allow_applies ? " *" : " (kind n/a)");
            printf("    %2u  %-40s block:%-22s allow:%s%s\n", s.depth,
                   nr_explain_suffix(e, i), blk, alw,
                   s.plausible ? "" : "   [skipped by label_mask]");
        }
    }
    printf("\n");
}

int cmd_query(Ctx& ctx) {
    if (ctx.args.empty()) {
        warn("query needs at least one domain");
        return NR_EXIT_USAGE;
    }
    NrIndexRO idx;
    std::string err;
    if (!nr_index_open_ro(ctx.index_path.c_str(), &idx, &err)) {
        warn("cannot read %s: %s", ctx.index_path.c_str(), err.c_str());
        warn("without an index nothing is filtered by the resolver layer.");
        if (ctx.json) printf("{\"ok\":false,\"error\":\"no index\"}\n");
        return NR_EXIT_UNAVAILABLE;
    }
    for (const std::string& host : ctx.args) {
        if (ctx.json) {
            /* One JSON object per line when several names are asked about, so
             * the output stays streamable and each line stands alone. */
            printf("%s\n", nr_json_query(idx, ctx.index_path.c_str(), host.c_str()).c_str());
        } else {
            print_query_human(ctx, idx, host.c_str());
        }
    }
    nr_index_close_ro(&idx);
    return NR_EXIT_OK;
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

int cmd_verify(Ctx& ctx) {
    const std::string path = ctx.args.empty() ? ctx.index_path : ctx.args[0];
    NrVerifyReport r;
    nr_verify_index(path.c_str(), &r);

    if (ctx.json) {
        printf("%s\n", nr_json_verify(r).c_str());
        return r.ok ? NR_EXIT_OK : NR_EXIT_FAIL;
    }

    printf("%s\n", path.c_str());
    if (!r.readable) {
        /* Exit 3, not 1: "there is no index here" is an expected state on a fresh
         * boot, and a script that treats it as a corruption will roll back a
         * device that is merely early. A file that IS there and does not validate
         * falls through to the full report below and exits 1. */
        kv("result", "UNREADABLE — %s", r.error.c_str());
        return NR_EXIT_UNAVAILABLE;
    }
    kv("result", "%s%s%s", r.ok ? "OK" : "FAILED", r.ok ? "" : " — ", r.error.c_str());
    kv("format", "NRDX v%u, %s", r.fmt_version, human_bytes(r.size).c_str());
    char built[40];
    nr_format_ms(r.built_at_ms, built, sizeof(built));
    kv("generation", "%llu, built %s", (unsigned long long)r.generation, built);
    kv("rules", "%s block / %s allow / %s redirect",
       human_count(r.n_block).c_str(), human_count(r.n_allow).c_str(),
       human_count(r.n_redirect).c_str());
    kv("tables", "bt_cap %u, at_cap %u, rt_cap %u (load %.0f%% / %.0f%%)",
       r.bt_cap, r.at_cap, r.rt_cap,
       r.bt_cap ? 100.0 * r.n_block / r.bt_cap : 0.0,
       r.at_cap ? 100.0 * r.n_allow / r.at_cap : 0.0);
    kv("labels", "min %u, max %u, mask 0x%04x", r.min_labels, r.max_labels, r.label_mask);
    kv("hash seed", "0x%016llx", (unsigned long long)r.hash_seed);
    switch (r.sha_state) {
        case 1:  kv("sha256", "match (%s)", r.sha_header); break;
        case 0:  kv("sha256", "MISMATCH\n              header %s\n              actual %s",
                    r.sha_header, r.sha_actual); break;
        default: kv("sha256", "not set — this blob was never sealed"); break;
    }
    kv("probe", "%s",
       r.probe_present ? r.probe_addr
                       : "MISSING — " NR_PROBE_IDX_NAME " has no redirect, so the "
                         "app's liveness check can never go green");
    return r.ok ? NR_EXIT_OK : NR_EXIT_FAIL;
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

int cmd_build(Ctx& ctx) {
    NrCompileSpec spec;
    std::string out_path;
    spec.generation  = 0;
    spec.built_at_ms = nr_now_ms();

    uint16_t next_group = NR_GROUP_SOURCE_MIN;
    for (size_t i = 0; i < ctx.args.size(); ++i) {
        const std::string& a = ctx.args[i];
        auto need = [&](const char* what) -> const char* {
            if (i + 1 >= ctx.args.size()) {
                warn("%s needs a value", what);
                return nullptr;
            }
            return ctx.args[++i].c_str();
        };
        if (a == "--out") {
            const char* v = need("--out");
            if (!v) return NR_EXIT_USAGE;
            out_path = v;
        } else if (a == "--gen") {
            const char* v = need("--gen");
            if (!v) return NR_EXIT_USAGE;
            spec.generation = strtoull(v, nullptr, 10);
        } else if (a == "--allow" || a == "--deny" || a == "--redirect" || a == "--force") {
            const char* v = need(a.c_str());
            if (!v) return NR_EXIT_USAGE;
            NrCompileInput in;
            in.path     = v;
            in.optional = false;
            if (a == "--allow")         { in.role = NR_ROLE_ALLOW;    in.group = NR_GROUP_USER_ALLOW; }
            else if (a == "--deny")     { in.role = NR_ROLE_LIST;     in.group = NR_GROUP_USER_DENY;  }
            else if (a == "--redirect") { in.role = NR_ROLE_REDIRECT; in.group = NR_GROUP_REDIRECT;   }
            else                        { in.role = NR_ROLE_FORCE;    in.group = NR_GROUP_FLOOR;      }
            spec.inputs.push_back(in);
        } else if (a.size() > 1 && a[0] == '-') {
            warn("unknown build option %s", a.c_str());
            return NR_EXIT_USAGE;
        } else {
            NrCompileInput in;
            in.path     = a;
            in.role     = NR_ROLE_LIST;
            in.group    = next_group++;
            in.optional = false;
            spec.inputs.push_back(in);
        }
    }
    if (out_path.empty() || spec.inputs.empty()) {
        warn("usage: nrctl build --out FILE --gen N [--allow F] [--deny F] "
             "[--redirect F] [--force F] SOURCE...");
        return NR_EXIT_USAGE;
    }
    if (spec.generation == NR_GEN_NONE) {
        warn("--gen must be >= 1 (generation 0 means 'no index' to the resolver)");
        return NR_EXIT_USAGE;
    }

    /* The liveness redirect, added by every producer. Without it the app's health
     * card cannot go green even when everything works (§3.4). */
    BuildRedirect probe;
    probe.domain = NR_PROBE_IDX_NAME;
    probe.family = AF_INET;
    memset(probe.addr, 0, sizeof(probe.addr));
    probe.addr[0] = 127; probe.addr[1] = 0; probe.addr[2] = 0; probe.addr[3] = 7;
    spec.redirects.push_back(probe);

    std::vector<uint8_t> blob;
    NrCompileResult res;
    std::string err;
    if (!nr_compile(spec, &blob, &res, &err)) {
        warn("build failed: %s", err.c_str());
        /* The message quotes a path taken from argv, so it goes through the
         * escaper — a build source called `a"b.txt` must not be able to make the
         * app's JSON parse fail instead of showing the error. */
        if (ctx.json) print_ctl_error_json("build", err);
        return NR_EXIT_FAIL;
    }
    if (!nr_write_file_atomic(out_path.c_str(), blob.data(), blob.size(), &err)) {
        warn("cannot write %s: %s", out_path.c_str(), err.c_str());
        return NR_EXIT_FAIL;
    }

    if (ctx.json) {
        printf("%s\n", nr_json_compile(res, out_path.c_str()).c_str());
        return NR_EXIT_OK;
    }
    printf("%s\n", out_path.c_str());
    kv("generation", "%llu", (unsigned long long)res.generation);
    kv("size", "%s", human_bytes(res.bytes).c_str());
    kv("block", "%s kept (%s parsed, %s collapsed away)",
       human_count(res.block_kept).c_str(), human_count(res.stats.block_in).c_str(),
       human_count(res.stats.block_collapsed).c_str());
    kv("allow", "%s", human_count(res.allow_kept).c_str());
    kv("redirect", "%s", human_count(res.redirects).c_str());
    kv("sha256", "%s", res.sha256_hex);
    kv("time", "%llu ms", (unsigned long long)res.elapsed_ms);
    for (const NrSourceStat& s : res.sources) {
        if (!s.present) {
            kv("source", "%s  MISSING (%s)", s.path.c_str(), s.error.c_str());
        } else {
            kv("source", "%s  group %u  %s parsed, %s rejected", s.path.c_str(), s.group,
               human_count(s.parsed).c_str(), human_count(s.rejected).c_str());
        }
    }
    return NR_EXIT_OK;
}

// ---------------------------------------------------------------------------
// log
// ---------------------------------------------------------------------------

int cmd_log(Ctx& ctx) {
    size_t max = 200;
    for (size_t i = 0; i < ctx.args.size(); ++i) {
        if (ctx.args[i] == "--max" && i + 1 < ctx.args.size())
            max = (size_t)strtoul(ctx.args[++i].c_str(), nullptr, 10);
    }
    if (max == 0 || max > NR_RING_SLOTS) max = NR_RING_SLOTS;

    NrRingReader r;
    std::string err;
    if (!nr_ring_open(ctx.ring_path.c_str(), &r, &err)) {
        warn("cannot read %s: %s", ctx.ring_path.c_str(), err.c_str());
        return NR_EXIT_UNAVAILABLE;
    }
    std::vector<NrLogRec> recs(max);
    const size_t n = nr_ring_drain(&r, recs.data(), max);

    if (!ctx.json && n == 0) {
        /* Empty is normal and does NOT mean the filter is dead: log_level 0 is
         * the default, and the writer only records what that level asks for. */
        printf("no records. Logging is off unless control.bin::log_level is 1\n"
               "(blocked only) or 2 (everything) — check with  nrctl status.\n");
    }
    for (size_t i = 0; i < n; ++i) {
        const NrLogRec& rec = recs[i];
        char name[NR_RING_NAME + 1];
        nr_ring_rec_name(rec, name);
        char ts[40];
        nr_format_ms(rec.ts_ms, ts, sizeof(ts));
        if (ctx.json) {
            std::string j = "{\"seq\":" + std::to_string(rec.seq);
            j += ",\"ts_ms\":" + std::to_string(rec.ts_ms);
            j += ",\"uid\":" + std::to_string(rec.uid);
            j += ",\"verdict\":\"" + std::string(nr_verdict_name(rec.verdict)) + "\"";
            j += ",\"depth\":" + std::to_string(rec.depth);
            j += ",\"group\":" + std::to_string(rec.rule_group);
            j += ",\"truncated\":";
            j += (rec.flags & 1) ? "true" : "false";
            j += ",\"name\":\"";
            nr_json_escape(name, strlen(name), &j);
            j += "\"}";
            printf("%s\n", j.c_str());
        } else {
            printf("%s  uid=%-6u %-8s d=%u g=%-5u %s%s\n", ts, rec.uid,
                   nr_verdict_name(rec.verdict), rec.depth, rec.rule_group, name,
                   (rec.flags & 1) ? " (truncated)" : "");
        }
    }
    if (!ctx.json && (r.dropped || r.torn))
        printf("\n%llu records were overwritten before they could be read, %llu were "
               "torn.\nThe log is best-effort by design and does not pretend to be "
               "complete.\n",
               (unsigned long long)r.dropped, (unsigned long long)r.torn);
    nr_ring_close(&r);
    return NR_EXIT_OK;
}

// ---------------------------------------------------------------------------
// mutating verbs
// ---------------------------------------------------------------------------

/* No MINUTES argument. CtlReceiver's `pause` arm is an unconditional
 * setMode(MODE_PAUSED) with no timer anywhere behind it, so a duration would be
 * accepted, ignored, and reported as honoured — a documented option that does
 * nothing is precisely the defect this CLI is built around. Re-add it here in
 * the same commit that gives the receiver a scheduled resume, not before. */
int cmd_pause(Ctx& ctx)  { return cmd_setmode(ctx, "pause",  NR_MODE_PAUSED); }
int cmd_resume(Ctx& ctx) { return cmd_setmode(ctx, "resume", NR_MODE_ENFORCE); }
int cmd_off(Ctx& ctx)    { return cmd_setmode(ctx, "off",    NR_MODE_OFF); }

/* `update` has no immediate observable: the receiver hands the work to
 * UpdateJobService and returns inside its ten-second budget while a full
 * recompile takes minutes. There is therefore nothing to confirm, and the
 * wording says so rather than claiming the lists were refreshed. */
int cmd_update(Ctx& ctx) {
    std::string err;
    const int rc = send_ctl(ctx, "update", {}, &err);
    if (rc != NR_EXIT_OK) {
        warn("update: %s", err.c_str());
        if (ctx.json) print_ctl_error_json("update", err);
        return rc;
    }
    if (ctx.dry_run) return NR_EXIT_OK;
    if (ctx.json) printf("{\"ok\":true,\"verb\":\"update\",\"confirmed\":false}\n");
    else printf("update: requested. The rebuild runs in the background and takes\n"
                "  minutes; watch it with  nrctl status  or the app's Update screen.\n");
    return NR_EXIT_OK;
}

/* Invoked by init on `on property:persist.sys.nullroute.mode=*` (§8.4). The
 * property is the on-disk source of truth for mode and control.bin::mode is
 * derived from it, so that two authorities can never disagree about a boolean.
 * Requires write access to control.bin, which only system and root have. */
int cmd_syncprop(Ctx& ctx) {
    const std::string v = nr_prop_get(NR_PROP_MODE, "");
    uint8_t mode = NR_MODE_ENFORCE;
    if (!v.empty() && !nr_mode_parse(v.c_str(), &mode)) {
        warn("%s has an unparseable value %s; leaving control.bin alone",
             NR_PROP_MODE, v.c_str());
        return NR_EXIT_FAIL;
    }
    NrCtlMap ctl;
    std::string err;
    if (!nr_ctl_open(ctx.ctl_path.c_str(), true, &ctl, &err)) {
        /* Expected and harmless when run as shell, or before the seeder has run
         * on a very early boot: init retries on the next property change. */
        warn("cannot open %s for writing: %s", ctx.ctl_path.c_str(), err.c_str());
        return NR_EXIT_UNAVAILABLE;
    }
    const bool ok = nr_ctl_set_mode(&ctl, mode);
    nr_ctl_close(&ctl);
    if (!ctx.json && ok) printf("mode = %s\n", nr_mode_name(mode));
    if (ctx.json) printf("{\"ok\":%s,\"mode\":\"%s\"}\n", ok ? "true" : "false",
                         nr_mode_name(mode));
    return ok ? NR_EXIT_OK : NR_EXIT_FAIL;
}

// ---------------------------------------------------------------------------
// apps — the per-app policy table (READ)
// ---------------------------------------------------------------------------

const char* policy_name(uint8_t p) {
    switch (p) {
        case NR_POLICY_ENFORCE: return "enforce";
        case NR_POLICY_EXEMPT:  return "exempt";
        case NR_POLICY_STRICT:  return "strict";
        default:                return "invalid";
    }
}

struct UidName {
    uint32_t    app_id;
    std::string pkg;
};

/*
 * appId -> package, from `cmd package list packages -U`.
 *
 * BEST EFFORT ON PURPOSE. This is cosmetic: the policy table is indexed by appId
 * and is complete without any of this. `cmd package` can be missing, can be
 * refused, and on a device with package-visibility filtering can return a subset
 * — so a failure here downgrades the output to bare appIds and says so, rather
 * than failing a read verb over a display detail.
 */
bool load_package_names(const Ctx& ctx, std::vector<UidName>* out) {
    if (access("/system/bin/cmd", X_OK) != 0) return false;
    char userbuf[16];
    snprintf(userbuf, sizeof(userbuf), "%d", ctx.user);

    std::string text;
    const std::vector<std::string> argv = {
        "/system/bin/cmd", "package", "list", "packages", "-U", "--user", userbuf,
    };
    if (run_capture(argv, &text) != 0) return false;

    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        const std::string line = text.substr(pos, eol - pos);
        pos = eol + 1;

        /* "package:com.example.thing uid:10123" */
        const size_t p = line.find("package:");
        const size_t u = line.find(" uid:");
        if (p == std::string::npos || u == std::string::npos || u <= p + 8) continue;

        UidName e;
        e.pkg = line.substr(p + 8, u - (p + 8));
        /* uid -> appId is `uid % AID_USER_OFFSET`, and AID_USER_OFFSET is the
         * same 100000 the table is sized to (NrControl.h) — a secondary user's
         * 1010123 and the owner's 10123 share one row, which is exactly what
         * Phase 5's per-user overrides are for. */
        e.app_id = (uint32_t)(strtoul(line.c_str() + u + 5, nullptr, 10) % NR_UID_POLICY_LEN);
        out->push_back(e);
    }
    return !out->empty();
}

const std::string* name_for(const std::vector<UidName>& names, uint32_t app_id) {
    for (const UidName& n : names)
        if (n.app_id == app_id) return &n.pkg;
    return nullptr;
}

/*
 * Lists the apps whose policy is not the default.
 *
 * The table is 100,000 bytes inside a page netd and the app both hold mapped, so
 * every row here is a plain byte load: a single byte cannot tear, and a row that
 * changes while we walk it produces a stale answer for that app and nothing
 * worse. A lock would buy exactness the moment after which it is stale anyway.
 *
 * Only the exceptions are printed. Listing 100,000 rows of "enforce" would be a
 * technically complete answer to a question nobody asked.
 */
int cmd_apps(Ctx& ctx) {
    NrCtlMap ctl;
    std::string err;
    if (!nr_ctl_open(ctx.ctl_path.c_str(), false, &ctl, &err)) {
        warn("cannot read %s: %s", ctx.ctl_path.c_str(), err.c_str());
        if (ctx.json) print_ctl_error_json("apps", err);
        return NR_EXIT_UNAVAILABLE;
    }
    if (ctl.p == nullptr || ctl.size < (size_t)NR_UID_POLICY_OFF + NR_UID_POLICY_LEN) {
        nr_ctl_close(&ctl);
        const std::string e = "control.bin is smaller than the per-app policy table";
        warn("%s", e.c_str());
        if (ctx.json) print_ctl_error_json("apps", e);
        return NR_EXIT_FAIL;
    }

    std::vector<UidName> names;
    const bool have_names = load_package_names(ctx, &names);

    /* An argument asks about ONE app, and then "enforce" is a real answer worth
     * printing — unlike in the list, where it is the default. */
    if (!ctx.args.empty()) {
        const std::string& want = ctx.args[0];
        uint32_t app_id = 0;
        bool resolved = false;
        if (want.find_first_not_of("0123456789") == std::string::npos && !want.empty()) {
            app_id = (uint32_t)(strtoul(want.c_str(), nullptr, 10) % NR_UID_POLICY_LEN);
            resolved = true;
        } else {
            for (const UidName& n : names) {
                if (n.pkg == want) { app_id = n.app_id; resolved = true; break; }
            }
        }
        if (!resolved) {
            nr_ctl_close(&ctl);
            warn("no package '%s' on user %d.%s", want.c_str(), ctx.user,
                 have_names ? "" : " (package names could not be listed here, so pass a uid)");
            return NR_EXIT_UNAVAILABLE;
        }
        const uint8_t p = ctl.p->uid_policy[app_id];
        if (ctx.json) {
            std::string j = "{\"ok\":true,\"app_id\":" + std::to_string(app_id);
            j += ",\"policy\":\"" + std::string(policy_name(p)) + "\"}";
            printf("%s\n", j.c_str());
        } else {
            printf("appId %u  %s\n", app_id, policy_name(p));
        }
        nr_ctl_close(&ctl);
        return NR_EXIT_OK;
    }

    std::vector<uint32_t> ids;
    for (uint32_t i = 0; i < NR_UID_POLICY_LEN; ++i)
        if (ctl.p->uid_policy[i] != NR_POLICY_ENFORCE) ids.push_back(i);

    if (ctx.json) {
        std::string j = "{\"ok\":true,\"user\":" + std::to_string(ctx.user);
        j += ",\"names_resolved\":";
        j += have_names ? "true" : "false";
        j += ",\"count\":" + std::to_string(ids.size()) + ",\"apps\":[";
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i) j += ",";
            j += "{\"app_id\":" + std::to_string(ids[i]);
            const std::string* pkg = name_for(names, ids[i]);
            if (pkg) {
                j += ",\"package\":\"";
                nr_json_escape(pkg->data(), pkg->size(), &j);
                j += "\"";
            }
            j += ",\"policy\":\"" +
                 std::string(policy_name(ctl.p->uid_policy[ids[i]])) + "\"}";
        }
        j += "]}";
        printf("%s\n", j.c_str());
    } else if (ids.empty()) {
        printf("Every app is on the default policy (enforce). Nothing is exempt.\n");
    } else {
        printf("apps whose policy is not the default, user %d:\n", ctx.user);
        for (uint32_t id : ids) {
            const std::string* pkg = name_for(names, id);
            printf("  %-8u %-9s %s\n", id, policy_name(ctl.p->uid_policy[id]),
                   pkg ? pkg->c_str() : "");
        }
        printf("\n  %zu app%s differ from 'enforce'; every other app is filtered.\n",
               ids.size(), ids.size() == 1 ? "" : "s");
        if (!have_names)
            printf("  Package names could not be listed from this shell, so only\n"
                   "  appIds are shown. `cmd package list packages -U` is the source.\n");
    }

    nr_ctl_close(&ctl);
    return NR_EXIT_OK;
}

// ---------------------------------------------------------------------------
// import / export / rollback / deep / panic — the second wave of mutating verbs
// ---------------------------------------------------------------------------

struct FileStamp {
    bool     present;
    bool     conclusive;  /* false when we were refused rather than answered */
    uint64_t size;
    int64_t  mtime_ns;
};

/* stat() with the distinction that matters here: ENOENT is an ANSWER ("it is not
 * there"), while EACCES is a refusal ("this shell cannot see"). Reporting the
 * second as the first is how a CLI ends up telling a user their export failed
 * when it is sitting on disk in a directory shell cannot traverse. */
FileStamp stamp_of(const char* path) {
    FileStamp s{false, false, 0, 0};
    struct stat st;
    if (stat(path, &st) == 0) {
        s.present = true;
        s.conclusive = true;
        s.size = (uint64_t)st.st_size;
        s.mtime_ns = (int64_t)st.st_mtim.tv_sec * 1000000000LL + (int64_t)st.st_mtim.tv_nsec;
    } else {
        s.conclusive = (errno == ENOENT);
    }
    return s;
}

bool read_generation(const char* path, uint64_t* out) {
    NrIndexRO idx;
    if (!nr_index_open_ro(path, &idx, nullptr)) return false;
    *out = idx.ix.hdr->generation;
    nr_index_close_ro(&idx);
    return true;
}

/* previous.nrdx lives beside whatever index we were pointed at, so --index keeps
 * working for a developer testing against a scratch directory. */
std::string sibling_of(const std::string& path, const char* name) {
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return std::string(name);
    return path.substr(0, slash + 1) + name;
}

int cmd_export(Ctx& ctx) {
    const std::string path = ctx.args.empty() ? NR_PATH_EXPORT_DEFAULT : ctx.args[0];
    if (path.empty() || path[0] != '/') {
        warn("export needs an absolute path (got '%s')", path.c_str());
        warn("the app writes this file itself, so a relative path would resolve");
        warn("against ITS working directory, not yours.");
        return NR_EXIT_USAGE;
    }

    const FileStamp before = stamp_of(path.c_str());
    std::string err;
    const int rc = send_ctl(ctx, "export", {{"--es", NR_CTL_EXTRA_PATH, path}}, &err);
    if (rc != NR_EXIT_OK) {
        warn("export: %s", err.c_str());
        if (ctx.json) print_ctl_error_json("export", err);
        return rc;
    }
    if (ctx.dry_run) return NR_EXIT_OK;

    /* An archive of a few thousand rules is written in well under a second, but
     * the app may be cold-started for the broadcast. */
    FileStamp after = before;
    bool written = false;
    for (int waited = 0; waited < 10000; waited += 100) {
        after = stamp_of(path.c_str());
        if (after.present && after.size > 0 &&
            (!before.present || after.mtime_ns != before.mtime_ns ||
             after.size != before.size)) {
            written = true;
            break;
        }
        usleep(100 * 1000);
    }

    if (ctx.json) {
        std::string j = "{\"ok\":";
        j += (written || !after.conclusive) ? "true" : "false";
        j += ",\"verb\":\"export\",\"path\":\"";
        nr_json_escape(path.data(), path.size(), &j);
        j += "\",\"confirmed\":";
        j += written ? "true" : "false";
        j += ",\"bytes\":" + std::to_string(after.size) + "}";
        printf("%s\n", j.c_str());
        return (written || !after.conclusive) ? NR_EXIT_OK : NR_EXIT_FAIL;
    }
    if (written) {
        printf("export: wrote %s (%s)\n", path.c_str(), human_bytes(after.size).c_str());
        return NR_EXIT_OK;
    }
    if (!after.conclusive) {
        /* priv/ is 0770 system:misc — from adb shell this is the NORMAL outcome
         * and saying "failed" would be wrong. */
        printf("export: sent. Cannot confirm from this shell — %s is not readable\n"
               "  here. Check with  su -c 'ls -l %s'\n", path.c_str(), path.c_str());
        return NR_EXIT_OK;
    }
    warn("export: the broadcast was delivered but nothing appeared at %s after 10 s.",
         path.c_str());
    warn("CtlReceiver returns no result code, so this is the only evidence there is.");
    warn("Check:  adb logcat -s Nullroute   (an unrecognised verb logs there)");
    return NR_EXIT_FAIL;
}

/*
 * `import` cannot be confirmed and does not pretend to be.
 *
 * The receiver parses the file into priv/deny.txt and priv/allow.txt and then
 * has to rebuild the index for any of it to reach the resolver, which takes
 * minutes. There is no intermediate observable, so this reports "requested" for
 * the same reason `update` does.
 */
int cmd_import(Ctx& ctx) {
    if (ctx.args.empty()) {
        warn("usage: nrctl import PATH   (a hosts, AdAway, ABP or bindhosts file)");
        return NR_EXIT_USAGE;
    }
    const std::string path = ctx.args[0];
    if (path[0] != '/') {
        warn("import needs an absolute path (got '%s')", path.c_str());
        return NR_EXIT_USAGE;
    }

    /* Only ENOENT is conclusive from here; a shell that cannot traverse the
     * parent gets EACCES and must not be told the file is missing. */
    if (access(path.c_str(), F_OK) != 0 && errno == ENOENT) {
        warn("import: no such file: %s", path.c_str());
        return NR_EXIT_UNAVAILABLE;
    }

    std::string err;
    const int rc = send_ctl(ctx, "import", {{"--es", NR_CTL_EXTRA_PATH, path}}, &err);
    if (rc != NR_EXIT_OK) {
        warn("import: %s", err.c_str());
        if (ctx.json) print_ctl_error_json("import", err);
        return rc;
    }
    if (ctx.dry_run) return NR_EXIT_OK;

    if (ctx.json) {
        std::string j = "{\"ok\":true,\"verb\":\"import\",\"confirmed\":false,\"path\":\"";
        nr_json_escape(path.data(), path.size(), &j);
        j += "\"}";
        printf("%s\n", j.c_str());
        return NR_EXIT_OK;
    }
    printf("import: requested %s\n", path.c_str());
    printf("  THE APP READS THIS FILE, NOT THIS SHELL. It must be readable by uid\n"
           "  " NR_APP_PACKAGE " — /data/local/tmp is not (that is shell's own\n"
           "  directory and apps cannot see into it). %s is.\n", NR_DIR_PRIV);
    printf("  Parsing is quick; the rebuild that puts the rules in front of the\n"
           "  resolver takes minutes. Watch it with  nrctl status  (the generation\n"
           "  number rises) or the app's Update screen.\n");
    return NR_EXIT_OK;
}

/*
 * `rollback` is the one verb here with a clean proof: the generation that
 * previous.nrdx carried must become the generation current.nrdx carries. That is
 * observable from a plain adb shell, so it is checked rather than assumed.
 */
int cmd_rollback(Ctx& ctx) {
    const std::string prev_path = sibling_of(ctx.index_path, "previous.nrdx");

    uint64_t prev = 0;
    if (!read_generation(prev_path.c_str(), &prev)) {
        warn("rollback: no usable previous index at %s", prev_path.c_str());
        warn("There is nothing to roll back to. A rollback is only possible after a");
        warn("successful update has demoted the index it replaced.");
        if (ctx.json)
            print_ctl_error_json("rollback", "no usable previous index");
        return NR_EXIT_UNAVAILABLE;
    }
    uint64_t cur = 0;
    const bool have_cur = read_generation(ctx.index_path.c_str(), &cur);
    if (have_cur && cur == prev) {
        warn("rollback: current and previous are both generation %llu; nothing to do",
             (unsigned long long)prev);
        if (ctx.json)
            print_ctl_error_json("rollback", "current and previous are the same generation");
        return NR_EXIT_UNAVAILABLE;
    }

    std::string err;
    const int rc = send_ctl(ctx, "rollback", {}, &err);
    if (rc != NR_EXIT_OK) {
        warn("rollback: %s", err.c_str());
        if (ctx.json) print_ctl_error_json("rollback", err);
        return rc;
    }
    if (ctx.dry_run) return NR_EXIT_OK;

    bool confirmed = false, readable = false;
    uint64_t seen = 0;
    for (int waited = 0; waited < 5000; waited += 100) {
        readable = read_generation(ctx.index_path.c_str(), &seen);
        if (readable && seen == prev) { confirmed = true; break; }
        usleep(100 * 1000);
    }

    if (ctx.json) {
        printf("{\"ok\":%s,\"verb\":\"rollback\",\"confirmed\":%s,"
               "\"wanted_generation\":%llu,\"generation\":%llu}\n",
               (confirmed || !readable) ? "true" : "false",
               confirmed ? "true" : "false",
               (unsigned long long)prev, (unsigned long long)seen);
        return (confirmed || !readable) ? NR_EXIT_OK : NR_EXIT_FAIL;
    }
    if (confirmed) {
        printf("rollback: current index is now generation %llu\n",
               (unsigned long long)prev);
        printf("  The resolver picks this up on its next query; `nrctl status` shows\n"
               "  mapped_generation catching up.\n");
        return NR_EXIT_OK;
    }
    if (!readable) {
        printf("rollback: sent. Cannot confirm from this shell — the index is not\n"
               "  readable here. Re-check with  su -c 'nrctl status'\n");
        return NR_EXIT_OK;
    }
    warn("rollback: the broadcast was delivered but the index is still generation %llu",
         (unsigned long long)seen);
    warn("after 5 s (wanted %llu). Check:  adb logcat -s Nullroute",
         (unsigned long long)prev);
    return NR_EXIT_FAIL;
}

/*
 * Does anything answer Deep mode's liveness probe?
 *
 * 1 = answered with the expected address, 0 = did not answer. This is EVIDENCE
 * AND NOT PROOF in both directions, and cmd_deep prints it as such: the tunnel
 * answers this name from inside itself, so a process whose DNS does not traverse
 * the VPN sees nothing whether Deep mode is up or not.
 */
int deep_probe_answers() {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    if (getaddrinfo(NR_PROBE_DEEP_NAME, nullptr, &hints, &res) != 0) return 0;

    int matched = 0;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family != AF_INET || p->ai_addr == nullptr) continue;
        const struct sockaddr_in* sin =
            (const struct sockaddr_in*)(const void*)p->ai_addr;
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr &&
            strcmp(buf, NR_PROBE_DEEP_ADDR) == 0) {
            matched = 1;
        }
    }
    freeaddrinfo(res);
    return matched;
}

/* True when SOME tun interface exists. Deep mode's tunnel is one of these, and
 * so is every other VPN on the device — which is the point: no tun at all is a
 * sound negative, a tun present names nobody. */
bool any_tun_interface() {
    FILE* f = fopen("/proc/net/dev", "re");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f) != nullptr) {
        const char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (strncmp(p, "tun", 3) == 0) { found = true; break; }
    }
    fclose(f);
    return found;
}

void deep_report_human(int probe, bool tun) {
    printf("Deep mode\n");
    kv("probe", "%s", probe ? "answered " NR_PROBE_DEEP_ADDR " — a tunnel is carrying this shell's DNS"
                            : "silent");
    kv("tun", "%s", tun ? "a tun interface exists (Deep mode, or any other VPN)"
                        : "no tun interface exists, so no VPN is established at all");
    printf("\n  Deep mode's on/off switch lives in the app's device-encrypted\n"
           "  preferences, which no shell can read, so this verb reports evidence\n"
           "  rather than state. A silent probe with a tun present is genuinely\n"
           "  undetermined: a root or shell process's lookups may not traverse the\n"
           "  VPN at all. Open the app's Deep mode screen for the authoritative\n"
           "  answer.\n");
}

int cmd_deep(Ctx& ctx) {
    /* Bare `deep` is a read verb: no broadcast, no privilege, no side effect. */
    if (ctx.args.empty()) {
        const int probe = deep_probe_answers();
        const bool tun = any_tun_interface();
        if (ctx.json) {
            printf("{\"ok\":true,\"verb\":\"deep\",\"probe\":\"%s\",\"tun_present\":%s,"
                   "\"confirmed\":false}\n",
                   probe ? "answered" : "silent", tun ? "true" : "false");
        } else {
            deep_report_human(probe, tun);
        }
        return NR_EXIT_OK;
    }

    const std::string& a = ctx.args[0];
    bool enable;
    if (a == "on" || a == "1" || a == "true") {
        enable = true;
    } else if (a == "off" || a == "0" || a == "false") {
        enable = false;
    } else {
        warn("usage: nrctl deep [on|off]");
        return NR_EXIT_USAGE;
    }

    std::string err;
    const int rc = send_ctl(ctx, "deep",
                            {{"--ez", NR_CTL_EXTRA_ENABLE, enable ? "true" : "false"}}, &err);
    if (rc != NR_EXIT_OK) {
        warn("deep: %s", err.c_str());
        if (ctx.json) print_ctl_error_json("deep", err);
        return rc;
    }
    if (ctx.dry_run) return NR_EXIT_OK;

    /* Turning it ON has to cross a VpnService.prepare() consent that may never
     * have been granted — in which case the app cannot establish anything and
     * nothing here will ever show a tunnel. Waiting a moment makes the probe
     * meaningful for the common case without implying the wait is a guarantee. */
    if (enable) usleep(2500 * 1000);
    const int probe = deep_probe_answers();
    const bool tun = any_tun_interface();

    if (ctx.json) {
        printf("{\"ok\":true,\"verb\":\"deep\",\"requested\":\"%s\",\"probe\":\"%s\","
               "\"tun_present\":%s,\"confirmed\":false}\n",
               enable ? "on" : "off", probe ? "answered" : "silent",
               tun ? "true" : "false");
        return NR_EXIT_OK;
    }
    printf("deep: %s requested. NOT CONFIRMED — see below.\n", enable ? "on" : "off");
    if (enable && !probe)
        printf("  Turning Deep mode on needs the user's VPN consent, which cannot be\n"
               "  granted from a shell. If it has never been granted on this device,\n"
               "  the app will ask the next time its Deep mode screen is opened.\n");
    deep_report_human(probe, tun);
    return NR_EXIT_OK;
}

/*
 * panic — the documented way out.
 *
 * One command that clears every switch at once, for the case this product's
 * failure mode actually looks like: DNS is broken, the user cannot load
 * anything, and the app is the last thing they can be asked to navigate. It is
 * therefore deliberately NOT just a broadcast:
 *
 *   1. the CTL broadcast, which is what clears mode AND Deep mode AND any
 *      pending update inside the app;
 *   2. `persist.sys.nullroute.mode=off`, which is an INDEPENDENT path to the
 *      same place — init has a property trigger on it that runs `nrctl syncprop`
 *      as system, so mode reaches control.bin even if the app never runs;
 *   3. the confirmation read of control.bin.
 *
 * What it cannot do from here is drop a live Deep-mode tunnel: that lives in the
 * app's process and only the app can tear it down. `--stop-app` is the escape
 * for that, and it is opt-in because force-stopping is a bigger hammer than most
 * of the situations that bring someone to this verb.
 *
 * The kill switch is deliberately NOT set here. It disables filtering device-wide
 * and needs a reboot, which is a heavier and less reversible thing than "switch
 * everything off"; it is printed as the next step instead.
 */
int cmd_panic(Ctx& ctx) {
    bool stop_app = false;
    for (const std::string& a : ctx.args) {
        if (a == "--stop-app") {
            stop_app = true;
        } else {
            warn("panic: unknown option '%s'", a.c_str());
            warn("usage: nrctl panic [--stop-app]");
            return NR_EXIT_USAGE;
        }
    }

    std::string err;
    const int rc = send_ctl(ctx, "panic", {}, &err);
    const bool broadcast_ok = (rc == NR_EXIT_OK);
    if (!broadcast_ok) warn("panic: broadcast failed: %s", err.c_str());
    if (ctx.dry_run) return NR_EXIT_OK;

    /* Independent of the app being alive, and of it having understood the verb. */
    const bool prop_ok = nr_prop_set(NR_PROP_MODE, "off");

    uint8_t seen = 0;
    bool readable = false, confirmed = false;
    for (int waited = 0; waited < 3000; waited += 100) {
        readable = read_mode(ctx, &seen);
        if (readable && seen == NR_MODE_OFF) { confirmed = true; break; }
        usleep(100 * 1000);
    }

    bool stopped = false;
    if (stop_app) {
        /* AFTER the confirmation window: force-stopping first would kill the app
         * before it could act on the broadcast we just sent it. */
        std::vector<std::string> argv;
        if (access("/system/bin/cmd", X_OK) == 0) {
            argv = {"/system/bin/cmd", "activity", "force-stop", NR_APP_PACKAGE};
        } else if (access("/system/bin/am", X_OK) == 0) {
            argv = {"/system/bin/am", "force-stop", NR_APP_PACKAGE};
        }
        if (!argv.empty()) {
            std::string out;
            stopped = run_capture(argv, &out) == 0;
            if (!stopped && !out.empty()) fputs(out.c_str(), stderr);
        }
    }

    if (ctx.json) {
        printf("{\"ok\":%s,\"verb\":\"panic\",\"broadcast\":%s,\"mode_property\":%s,"
               "\"confirmed\":%s,\"mode\":\"%s\",\"deep_confirmed\":false,"
               "\"app_stopped\":%s}\n",
               (confirmed || !readable) ? "true" : "false",
               broadcast_ok ? "true" : "false", prop_ok ? "true" : "false",
               confirmed ? "true" : "false",
               readable ? nr_mode_name(seen) : "unreadable",
               stopped ? "true" : "false");
        return (confirmed || !readable) ? NR_EXIT_OK : NR_EXIT_FAIL;
    }

    printf("panic:\n");
    kv("broadcast", "%s", broadcast_ok ? "delivered" : "FAILED");
    kv("mode prop", "%s", prop_ok ? NR_PROP_MODE "=off"
                                  : "could not set " NR_PROP_MODE " (needs root/system)");
    if (confirmed)      kv("filtering", "off — read back from control.bin");
    else if (!readable) kv("filtering", "sent; control.bin is not readable from this shell");
    else                kv("filtering", "STILL %s after 3 s", nr_mode_name(seen));
    kv("deep mode", "%s", stopped
        ? "the app was force-stopped, which drops any Deep-mode tunnel with it"
        : "requested off; NOT confirmable from a shell");

    printf("\n  Still broken? In order of severity:\n"
           "    nrctl panic --stop-app        force-stops the app, dropping the VPN\n"
           "    setprop %s 1 && reboot\n"
           "                                  the kill switch: filtering off device-wide\n",
           NR_PROP_KILL);
    if (!confirmed && readable)
        warn("CtlReceiver returns no result code, so the read-back above is the only "
             "evidence there is. Check:  adb logcat -s Nullroute");
    return (confirmed || !readable) ? NR_EXIT_OK : NR_EXIT_FAIL;
}

// ---------------------------------------------------------------------------
// help + dispatch + selftest
// ---------------------------------------------------------------------------

int cmd_help(Ctx& ctx);
int cmd_selftest(Ctx& ctx);

/* THE verb table. Help is printed from it and dispatch resolves through it, so
 * an entry cannot be documented without being implemented. */
const Verb kVerbs[] = {
    {"status", "", "what the filter is doing right now", cmd_status, false},
    {"query", "DOMAIN...", "would this domain be blocked, by which rule, and why",
     cmd_query, false},
    {"verify", "[FILE]", "structurally validate an index and check its sha256",
     cmd_verify, false},
    {"log", "[--max N]", "drain the resolver's query ring (Phase 3 writer)",
     cmd_log, false},
    {"apps", "[PKG|UID]", "per-app policy: which apps are exempt or strict",
     cmd_apps, false},
    {"pause", "", "stop filtering until resumed", cmd_pause, true},
    {"resume", "", "start filtering again", cmd_resume, true},
    {"off", "", "disable filtering entirely (survives until re-enabled)", cmd_off, true},
    {"update", "", "ask the app to refresh its lists and rebuild the index",
     cmd_update, true},
    {"import", "PATH", "import a hosts / AdAway / ABP / bindhosts file",
     cmd_import, true},
    {"export", "[PATH]", "write a settings + rules archive the app can restore",
     cmd_export, true},
    {"rollback", "", "put the previous index back and prove it landed",
     cmd_rollback, true},
    /* Marked mutating because `deep on|off` is; bare `deep` is a read and needs
     * no privilege, which the help text below spells out rather than leaving to
     * the annotation. */
    {"deep", "[on|off]", "Deep mode: Chrome and apps that run their own DNS",
     cmd_deep, true},
    {"panic", "[--stop-app]", "clear every switch at once — the last resort",
     cmd_panic, true},
    {"build", "--out F --gen N SOURCE...", "compile lists into an index (development)",
     cmd_build, false},
    {"syncprop", "", "mirror " NR_PROP_MODE " into control.bin (called by init)",
     cmd_syncprop, true},
    {"selftest", "", "prove every verb in this table is wired up", cmd_selftest, false},
    {"help", "", "this text", cmd_help, false},
};
const size_t kVerbCount = sizeof(kVerbs) / sizeof(kVerbs[0]);

const Verb* find_verb(const char* name) {
    for (size_t i = 0; i < kVerbCount; ++i)
        if (strcmp(kVerbs[i].name, name) == 0) return &kVerbs[i];
    return nullptr;
}

int cmd_help(Ctx& ctx) {
    (void)ctx;
    printf(
        "nrctl — Nullroute control\n"
        "\n"
        "usage: nrctl [--json] [--explain] [--index FILE] [--ctl FILE] [--ring FILE]\n"
        "             [--user N] VERB [ARGS]\n"
        "\n"
        "verbs:\n");
    for (size_t i = 0; i < kVerbCount; ++i) {
        char left[64];
        snprintf(left, sizeof(left), "%s %s", kVerbs[i].name, kVerbs[i].usage);
        printf("  %-32s %s%s\n", left, kVerbs[i].summary,
               kVerbs[i].mutating ? "  [needs root/system]" : "");
    }
    printf(
        "\n"
        "Read verbs open the mapped files directly and work as plain adb shell.\n"
        "pause/resume/off/update send a permission-guarded broadcast to the app, which\n"
        "is the only writer of /data/misc/nullroute; adb shell does not hold that\n"
        "permission unless the ROM assigns it, so run them under su, or use the app or\n"
        "the Quick Settings tile. pause/resume/off then re-read control.bin to prove\n"
        "the change landed — the receiver returns no result code, so a broadcast that\n"
        "'succeeded' is not evidence that anything happened.\n"
        "syncprop is the one mutating verb that writes control.bin itself; init runs it\n"
        "from a property trigger and it needs the system uid.\n"
        "\n"
        "WHAT EACH OF THE SECOND-WAVE VERBS CAN AND CANNOT PROVE\n"
        "  apps      a read. The per-app policy table is inside control.bin, which shell\n"
        "            can map read-only; package names come from `cmd package` and are\n"
        "            cosmetic, so bare appIds are shown when that is unavailable.\n"
        "  rollback  proved: previous.nrdx's generation must become current's.\n"
        "  export    proved when this shell can stat the path; priv/ is 0770 system:misc,\n"
        "            so from adb shell the honest answer is usually 'sent, cannot see'.\n"
        "  import    NOT proved. The file is parsed quickly and the rebuild that puts it\n"
        "            in front of the resolver takes minutes. Note the app reads the path,\n"
        "            not this shell: /data/local/tmp is unreadable to it.\n"
        "  deep      NOT proved. Deep mode's switch is in the app's device-encrypted\n"
        "            preferences and no shell can read it; bare `deep` reports the probe\n"
        "            and whether a tun exists, which is evidence, not state.\n"
        "  panic     proved for mode. It sends the broadcast AND sets\n"
        "            " NR_PROP_MODE "=off, which reaches control.bin\n"
        "            through init's syncprop trigger even if the app never runs. It\n"
        "            cannot drop a live Deep-mode tunnel — that needs --stop-app.\n"
        "\n"
        "exit codes: 0 ok, 1 failed, 2 usage, 3 unavailable\n"
        "\n"
        "TESTING WITH A DOMAIN THAT LOOKS LIKE IT SHOULD BE BLOCKED\n"
        "  The curated lists deliberately do NOT contain the apexes people reach for.\n"
        "  doubleclick.net, googleadservices.com, graph.facebook.com and\n"
        "  adservice.google.com are all ABSENT on purpose — Hagezi blocks the specific\n"
        "  ad subdomains (ad.ae.doubleclick.net, afs.googleadservices.com) instead, so\n"
        "  that logins and first-party traffic keep working. google-analytics.com IS\n"
        "  present. Test with that one.\n"
        "\n"
        "  `nrctl query` reads the resolver index only. The ~2,000-entry\n"
        "  /system/etc/hosts layer baked into the ROM is separate and invisible here;\n"
        "  check it with `getent hosts <name>`.\n"
        "\n"
        "recovery, when everything else has failed:\n"
        "  adb shell setprop " NR_PROP_KILL " 1 && adb reboot\n");
    return NR_EXIT_OK;
}

/*
 * The regression test for the failure this CLI is designed around: a verb that
 * is documented, resolves, and then does nothing. It runs every verb through
 * find_verb() — the same lookup main() uses — and executes it. Read verbs run
 * against a freshly built throwaway index; mutating verbs run in dry-run mode,
 * which still exercises the whole argument-marshalling path and asserts that the
 * intent they would send carries the right extras.
 *
 * Wired into CI via `nrctl selftest` (and reachable on-device from adb).
 */
int cmd_selftest(Ctx& ctx) {
    int failures = 0;
    auto fail = [&](const char* what) {
        printf("  FAIL  %s\n", what);
        ++failures;
    };
    auto pass = [&](const char* what) { printf("  ok    %s\n", what); };

    printf("verb table:\n");
    for (size_t i = 0; i < kVerbCount; ++i) {
        const Verb& v = kVerbs[i];
        if (!v.name || !*v.name || !v.usage || !v.summary || !v.fn) {
            fail("a verb entry is incomplete");
            continue;
        }
        if (find_verb(v.name) != &v) fail("a verb does not resolve to itself");
        for (size_t j = 0; j < i; ++j)
            if (strcmp(kVerbs[j].name, v.name) == 0) fail("duplicate verb name");
    }
    if (!failures) pass("every advertised verb resolves and has an implementation");

    if (nr_sha256_selftest()) pass("sha256 vectors");
    else fail("sha256 vectors");

    /* A throwaway index with one rule of each kind, built by the real compiler. */
    const char* tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/data/local/tmp";
    char src[PATH_MAX], idxp[PATH_MAX];
    snprintf(src, sizeof(src), "%s/nrctl-selftest-%d.txt", tmpdir, (int)getpid());
    snprintf(idxp, sizeof(idxp), "%s/nrctl-selftest-%d.nrdx", tmpdir, (int)getpid());

    static const char* kSrc =
        "0.0.0.0 blocked.selftest.example\n"
        "*.wild.selftest.example\n"
        "@allowed.blocked.selftest.example\n"
        "# a comment\n";
    {
        FILE* f = fopen(src, "w");
        if (!f) { fail("cannot write a scratch source file"); return NR_EXIT_FAIL; }
        fputs(kSrc, f);
        fclose(f);
    }

    Ctx sub;
    sub.dry_run    = true;
    sub.index_path = idxp;
    sub.args       = {"--out", idxp, "--gen", "1", src};
    if (find_verb("build")->fn(sub) == NR_EXIT_OK) pass("build produced an index");
    else fail("build");

    sub.args = {};
    if (find_verb("verify")->fn(sub) == NR_EXIT_OK) pass("verify accepted it");
    else fail("verify");

    /* The v8.2 case, asserted rather than eyeballed: the query arm must reach the
     * matcher and come back with a real verdict for a domain we just compiled. */
    {
        NrIndexRO idx;
        std::string err;
        if (!nr_index_open_ro(idxp, &idx, &err)) {
            fail("reopening the scratch index");
        } else {
            struct Case { const char* host; VerdictKind want; const char* why; };
            static const Case kCases[] = {
                {"blocked.selftest.example",         V_BLOCK,    "suffix rule blocks the apex"},
                {"deep.blocked.selftest.example",    V_BLOCK,    "suffix rule blocks subdomains"},
                {"allowed.blocked.selftest.example", V_PASS,     "more specific allow wins"},
                {"wild.selftest.example",            V_PASS,     "wildcard does not block its apex"},
                {"x.wild.selftest.example",          V_BLOCK,    "wildcard blocks subdomains"},
                {"unrelated.example",                V_PASS,     "unlisted domains pass"},
                {NR_PROBE_IDX_NAME,                  V_REDIRECT, "liveness probe redirects"},
            };
            int bad = 0;
            for (const Case& c : kCases) {
                NrExplain e;
                nr_explain(idx.ix, c.host, strlen(c.host), &e);
                if (e.verdict.kind != c.want) {
                    printf("  FAIL  query %s -> %s, wanted %s (%s)\n", c.host,
                           nr_verdict_name(e.verdict.kind), nr_verdict_name(c.want), c.why);
                    ++bad;
                } else if (c.want == V_BLOCK && (e.matched_rule[0] == '\0' || e.verdict.depth == 0)) {
                    /* A block that cannot name its own rule is the v8.2 bug in a
                     * different costume: the answer is right and useless. */
                    printf("  FAIL  query %s blocked but reported no rule/depth\n", c.host);
                    ++bad;
                }
            }
            /* Only claim the semantics if every case held. A summary line printed
             * unconditionally next to its own FAILs is how a red suite gets read
             * as green. */
            if (bad) failures += bad;
            else     pass("query answers with a rule, a depth and a group");

            /*
             * THE WIRE VOCABULARY, asserted rather than assumed.
             *
             * core/Native.kt matches `when (json.optString("verdict"))` against
             * "block"/"pass"/"redirect" and reads flat "rule"/"address" keys, and
             * verify() reads "sha256_ok". None of that is checked by either
             * compiler: rename a key here and the app does not fail, it silently
             * reports VerdictKind.UNKNOWN for every domain and sha256Ok=false for
             * every index. That is the same defect as an advertised verb with no
             * arm, one layer down, so it gets the same treatment.
             */
            const std::string qj = nr_json_query(idx, idxp, "deep.blocked.selftest.example");
            NrVerifyReport vr;
            nr_verify_index(idxp, &vr);
            const std::string vj = nr_json_verify(vr);
            if (qj.find("\"verdict\":\"block\"") == std::string::npos ||
                qj.find("\"rule\":\"blocked.selftest.example\"") == std::string::npos ||
                vj.find("\"sha256_ok\":true") == std::string::npos ||
                vj.find("\"bytes\":") == std::string::npos) {
                printf("  FAIL  the JSON does not use the vocabulary core/Native.kt parses\n"
                       "        query:  %s\n        verify: %s\n", qj.c_str(), vj.c_str());
                ++failures;
            } else {
                pass("query/verify JSON matches the app's parser");
            }
            nr_index_close_ro(&idx);
        }
    }

    /* Mutating verbs: dry-run, then assert the intent carries exactly what
     * CtlReceiver reads. This is the test that would have caught the extras being
     * sent as `nr.verb` while the receiver called getStringExtra("verb") — a
     * mismatch that costs nothing at build time and makes every mutating verb a
     * silent no-op on the device. The expected string is spelled out literally
     * rather than built from NR_CTL_EXTRA_VERB, so renaming the macro alone
     * cannot make this assertion agree with itself. */
    struct Mut { const char* verb; const char* must_contain; };
    static const Mut kMut[] = {
        {"pause",  "--es verb pause"},
        {"resume", "--es verb resume"},
        {"off",    "--es verb off"},
        {"update", "--es verb update"},
    };
    int bad_mut = 0;
    for (const Mut& m : kMut) {
        const Verb* v = find_verb(m.verb);
        if (!v) { fail("a mutating verb vanished from the table"); continue; }
        Ctx dry;
        dry.dry_run = true;
        dry.json    = true;   /* keep the dry-run quiet */
        if (v->fn(dry) != NR_EXIT_OK ||
            dry.last_command.find(NR_CTL_COMPONENT) == std::string::npos ||
            dry.last_command.find(NR_CTL_ACTION) == std::string::npos ||
            dry.last_command.find(m.must_contain) == std::string::npos) {
            printf("  FAIL  %s did not marshal a usable broadcast\n"
                   "        sent: %s\n", m.verb, dry.last_command.c_str());
            ++bad_mut;
        }
    }
    failures += bad_mut;
    if (!bad_mut) pass("pause/resume/off/update marshal the CtlReceiver intent");

    /*
     * The same assertion for the second wave, which needs its own table because
     * these verbs take arguments and two of them carry a SECOND extra. `path`
     * and `enable` are new keys on both sides of the contract, and a new key is
     * exactly where the "advertised verb that does nothing" bug comes back: the
     * receiver reads getStringExtra("path"), so `--es file` would marshal, send,
     * be delivered, and import nothing. Spelled out literally, for the reason the
     * block above gives.
     */
    struct Mut2 {
        const char*              verb;
        std::vector<std::string> args;
        std::string              must_contain;
    };
    std::vector<Mut2> kMut2 = {
        {"export", {"/data/misc/nullroute/priv/selftest.zip"},
         "--es path /data/misc/nullroute/priv/selftest.zip"},
        /* `import` refuses a path that is definitely absent, so it is pointed at
         * the scratch source file this test already wrote. */
        {"import", {src}, std::string("--es path ") + src},
        {"deep", {"on"}, "--ez enable true"},
        {"deep", {"off"}, "--ez enable false"},
        {"panic", {}, "--es verb panic"},
    };

    /* rollback reads previous.nrdx BEFORE it will send anything — correctly, it
     * refuses to ask for a rollback that cannot happen — so the precondition has
     * to exist for the marshalling to be reachable at all. A second index at a
     * different generation is the whole precondition. */
    char prevp[PATH_MAX];
    snprintf(prevp, sizeof(prevp), "%s/previous.nrdx", tmpdir);
    bool made_prev = false;
    if (access(prevp, F_OK) != 0) {
        Ctx b;
        b.dry_run = true;
        b.args = {"--out", prevp, "--gen", "2", src};
        made_prev = find_verb("build")->fn(b) == NR_EXIT_OK;
    }
    if (made_prev) {
        kMut2.push_back({"rollback", {}, "--es verb rollback"});
    } else {
        /* Printed, not silently skipped: a gate that quietly drops a case is a
         * gate that reports green for coverage it does not have. */
        printf("  note  rollback marshalling not asserted (%s is in the way)\n", prevp);
    }

    int bad_mut2 = 0;
    for (const Mut2& m : kMut2) {
        const Verb* v = find_verb(m.verb);
        if (!v) { fail("a second-wave verb is missing from the table"); continue; }
        Ctx dry;
        dry.dry_run    = true;
        dry.json       = true;
        dry.index_path = idxp;
        dry.args       = m.args;
        if (v->fn(dry) != NR_EXIT_OK ||
            dry.last_command.find(NR_CTL_COMPONENT) == std::string::npos ||
            dry.last_command.find(NR_CTL_ACTION) == std::string::npos ||
            dry.last_command.find(m.must_contain) == std::string::npos) {
            printf("  FAIL  %s did not marshal a usable broadcast\n"
                   "        wanted: %s\n        sent:   %s\n",
                   m.verb, m.must_contain.c_str(), dry.last_command.c_str());
            ++bad_mut2;
        }
    }
    failures += bad_mut2;
    if (!bad_mut2) pass("import/export/rollback/deep/panic marshal path and enable");

    /* `apps` is a read verb with no fixture: it must survive a missing control
     * page by reporting it, not by crashing or by inventing an empty table. */
    {
        Ctx a;
        a.json = true;
        a.ctl_path = "/nonexistent/nullroute/control.bin";
        const int arc = find_verb("apps")->fn(a);
        if (arc == NR_EXIT_UNAVAILABLE) pass("apps reports a missing control page");
        else fail("apps did not report a missing control page as unavailable");
    }

    if (made_prev) unlink(prevp);
    unlink(src);
    unlink(idxp);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL OK", failures,
           failures == 1 ? "" : "s");
    (void)ctx;
    return failures ? NR_EXIT_FAIL : NR_EXIT_OK;
}

}  // namespace

int main(int argc, char** argv) {
    Ctx ctx;
    int i = 1;
    for (; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--json")         ctx.json = true;
        else if (a == "--explain" || a == "-v") ctx.explain = true;
        else if (a == "--index" && i + 1 < argc) ctx.index_path = argv[++i];
        else if (a == "--ctl" && i + 1 < argc)   ctx.ctl_path   = argv[++i];
        else if (a == "--ring" && i + 1 < argc)  ctx.ring_path  = argv[++i];
        else if (a == "--user" && i + 1 < argc)  ctx.user       = atoi(argv[++i]);
        else if (a == "-h" || a == "--help")     return cmd_help(ctx);
        else break;
    }
    if (i >= argc) {
        cmd_help(ctx);
        return NR_EXIT_USAGE;
    }

    const Verb* v = find_verb(argv[i]);
    if (!v) {
        warn("unknown verb '%s'", argv[i]);
        cmd_help(ctx);
        return NR_EXIT_USAGE;
    }
    for (int j = i + 1; j < argc; ++j) ctx.args.push_back(argv[j]);
    return v->fn(ctx);
}
