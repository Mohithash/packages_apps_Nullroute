package com.bestrom.nullroute.core

import android.content.Context
import android.os.UserManager
import java.io.File

/**
 * Every path Nullroute touches, in one place, with the DE/CE split enforced by
 * construction rather than by convention.
 *
 * **Why the split matters.** The index and the control page live under
 * `/data/misc/nullroute` — Device Encrypted storage, mounted and readable at
 * `post-fs-data`, long before the user unlocks. That is what lets filtering be
 * live on the first boot after a flash, with no network and no unlock, and it is
 * why there is no "protection is idle" state in this product at all. Putting
 * either file under `/data/user/0/...` would produce an `ENOKEY` window on every
 * boot during which DNS is unfiltered and the app cannot even say so.
 *
 * The query log goes the other way, on purpose: it lives in **CE** storage
 * (`/data/user/<u>/com.bestrom.nullroute/databases`), so a seized-but-locked
 * device exposes no DNS history. Before first unlock the resolver's ring buffer
 * accumulates and may wrap; losing some log records is the correct trade against
 * leaking browsing history from a locked phone.
 *
 * The app manifest is `directBootAware` but deliberately **not**
 * `defaultToDeviceProtectedStorage` — the latter would drag the log into DE too.
 * So anything that must work pre-unlock asks for [de] explicitly.
 */
object Paths {

    // ---- DE: /data/misc/nullroute ------------------------------------------
    // Created 0771/0770 system:misc by init.nullroute.rc at post-fs-data. The
    // app reaches them via AID_MISC, granted by the <group gid="misc"/> mapping
    // on com.bestrom.nullroute.permission.STATE (§8.7).

    val misc = File("/data/misc/nullroute")

    val index = File(misc, "index")
    val ctl = File(misc, "ctl")
    val log = File(misc, "log")
    val priv = File(misc, "priv")

    val currentIndex = File(index, "current.nrdx")
    val previousIndex = File(index, "previous.nrdx")
    val quarantineIndex = File(index, "quarantine.nrdx")

    fun stagingIndex(generation: Long) = File(index, "staging.$generation.nrdx")
    fun stringsBlob(generation: Long) = File(index, "strings.$generation.nrdx")
    fun manifestJson(generation: Long) = File(index, "manifest.$generation.json")

    /**
     * 128 KiB shared control page. Pre-created at the right size and ownership by
     * `nullroute_seed`; neither netd nor the app ever creates it, because netd
     * runs as root and would otherwise leave a root-owned file the app cannot
     * write. If this file is missing, that is a seeder failure, not something to
     * paper over — see [ControlPage].
     */
    val controlBin = File(ctl, "control.bin")

    /** 256 KiB MPSC ring, netd rw / app ro. Consumed in Phase 3. */
    val ringBin = File(log, "ring.bin")

    // ---- DE: user state, never mapped by netd -------------------------------

    val allowTxt = File(priv, "allow.txt")
    val denyTxt = File(priv, "deny.txt")
    val redirectTxt = File(priv, "redirect.txt")

    /** `<name>_added.txt` / `<name>_removed.txt` overlays on the shipped profiles. */
    val userProfiles = File(priv, "profiles")

    /** Downloaded list bodies, `<sha1(url)>.raw` plus a `.meta` sidecar. */
    val downloadCache = File(priv, "cache")

    /** Scratch for the merged overlay files handed to the native builder. */
    val buildScratch = File(priv, "build")

    // ---- Read-only, shipped in the signed image -----------------------------

    val systemExtEtc = File("/system_ext/etc/nullroute")

    /**
     * The 98k permissive-licensed seed. Decompressed and compiled by
     * `nullroute_seed` (native, liblzma) on first boot — never by this app, which
     * has no xz decoder and no business creating the baseline.
     */
    val baselineXz = File(systemExtEtc, "baseline.domains.xz")

    val neverBlockTxt = File(systemExtEtc, "neverblock.txt")
    val antifraudTxt = File(systemExtEtc, "antifraud.txt")
    val attributionTxt = File(systemExtEtc, "attribution.txt")

    /** `{lite,balanced,aggressive}.txt` — URLs only, never list bodies (§7.6). */
    val builtinProfiles = File(systemExtEtc, "profiles")

    /** L0. Hardcoded as `_PATH_HOSTS` in bionic; we only ever read it. */
    val hostsFile = File("/system/etc/hosts")

    // ---- Context helpers ----------------------------------------------------

    /**
     * The Device-Encrypted context. Anything that must work before first unlock —
     * settings, boot receivers, the watchdog, the tile — reads and writes through
     * this, never through the caller's context, which may be CE.
     */
    fun de(context: Context): Context =
        if (context.isDeviceProtectedStorage) context
        else context.createDeviceProtectedStorageContext()

    /**
     * True once CE storage is usable. Phase 3's query log must check this before
     * opening its database; before unlock the answer is legitimately "not yet".
     */
    fun ceAvailable(context: Context): Boolean =
        context.getSystemService(UserManager::class.java)?.isUserUnlocked ?: false

    // TODO(Phase 3): queryLogDb(context) -> CE-storage SQLite, guarded by
    // ceAvailable(). Not created in Phase 1 — there is no ring consumer yet, and
    // an empty database in CE storage would only invite the assumption that
    // logging is on.

    /**
     * Creates the two scratch directories the app owns inside `priv/`. The four
     * top-level directories are init's job and are NOT created here: if they are
     * missing, the seeder did not run and silently creating them with the wrong
     * ownership would turn a loud failure into a quiet one.
     */
    fun ensureAppDirs(): Boolean = runCatching {
        downloadCache.isDirectory || downloadCache.mkdirs()
        buildScratch.isDirectory || buildScratch.mkdirs()
        downloadCache.isDirectory && buildScratch.isDirectory
    }.getOrDefault(false)

    /** True when the state tree init should have created is actually present. */
    fun stateTreeReady(): Boolean =
        index.isDirectory && ctl.isDirectory && priv.isDirectory
}
