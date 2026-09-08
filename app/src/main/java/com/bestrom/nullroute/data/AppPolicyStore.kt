package com.bestrom.nullroute.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Paths

/**
 * Per-app filtering policy: which apps the resolver skips.
 *
 * ## What the byte actually does
 *
 * `uid_policy[appId]` is read by `nr_evaluate()` inside netd, from the uid netd
 * took off `SO_PEERCRED` on the dnsproxyd socket. That is why per-app policy is
 * *correct* at this layer and only approximate in any VpnService design — nothing
 * here is inferred from a foreground-app guess.
 *
 * ## Two policies, not three
 *
 * `NR_POLICY_STRICT` exists in the header and **the resolver does not implement
 * it**: `nr_evaluate()` tests for `NR_POLICY_EXEMPT` and nothing else, so a
 * "Strict" switch would be a control that moves and changes nothing. It is
 * therefore not offered. When the resolver grows a meaning for it, this file is
 * where it gets one — see docs/needs-ui2.md.
 *
 * ## Why the durable key is a package name and not an appId
 *
 * The control page is a file, so a byte written into it survives a reboot — but
 * appIds do not survive an uninstall. Android reuses them, so a byte left set
 * against appId 10214 silently exempts whatever app installs next, and nothing on
 * the Apps screen would ever explain why that app is unfiltered.
 *
 * So the durable record is keyed on the **package name** and its value is the
 * **appId the byte was written to**. [reapplyAll] re-resolves the package at every
 * boot: if it is gone, or came back at a different appId, the old byte is cleared
 * before the record is dropped or moved. The worst case is then an exemption that
 * stops applying, never one that applies to the wrong app.
 *
 * Storage is DE-backed for the same reason as [Categories]: the resolver reads
 * the control page before first unlock, so the re-apply that repairs it after a
 * re-seed has to be able to run there too.
 */
object AppPolicyStore {

    private const val TAG = "Nullroute"
    private const val PREFS = "nullroute_uid_policy"

    /**
     * Below this, a uid is a platform component and not an installed app.
     *
     * The literal, not `Process.FIRST_APPLICATION_UID`: that constant is hidden
     * from the public SDK, and this module builds against `system_current` on
     * Soong and a plain `android.jar` under the Gradle parity build. A value that
     * compiles in one and not the other is a build break nobody sees until the
     * other tree is used.
     */
    private const val FIRST_APP_UID = 10_000

    /**
     * One row on the Apps screen: an **appId**, not a package. Several packages
     * can share one (a `sharedUserId`), and the resolver's byte is per appId, so
     * exempting one of them exempts all of them. The row says so rather than
     * pretending the switch is per-package.
     */
    data class AppEntry(
        val appId: Int,
        val label: String,
        val packages: List<String>,
        /** No package could be attributed to this appId; the label is "System". */
        val unattributed: Boolean,
        val system: Boolean,
        val exempt: Boolean,
        /**
         * Nullroute's own row. It is shown, and it is not switchable: the
         * liveness probe resolves `idx-probe.nullroute.invalid` from this
         * process, so exempting it would make Home report "not filtering" on a
         * healthy device. [ControlPage.setUidPolicy] refuses it too — this flag
         * exists so the screen can say why instead of appearing to do nothing.
         */
        val self: Boolean,
    ) {
        val shared: Boolean get() = packages.size > 1
    }

    /** Why a policy change did not take. Never silent — the screen shows these. */
    sealed class Result {
        object Ok : Result()
        object NoControlPage : Result()
        object RefusedSelf : Result()
        data class Failed(val reason: String) : Result()

        fun succeeded(): Boolean = this is Ok
    }

    // ---- reading ------------------------------------------------------------

    /**
     * Every appId with an installed package, plus any appId that only exists as
     * a stored policy.
     *
     * Blocking: `getInstalledApplications` is a binder call that returns a few
     * hundred records and each label is another lookup. Background thread.
     */
    fun load(context: Context): List<AppEntry> {
        val pm = context.packageManager
        val installed = runCatching {
            pm.getInstalledApplications(PackageManager.MATCH_DISABLED_COMPONENTS)
        }.getOrElse {
            Log.w(TAG, "cannot enumerate packages: ${it.message}")
            emptyList<ApplicationInfo>()
        }

        val byAppId = LinkedHashMap<Int, MutableList<ApplicationInfo>>()
        for (info in installed) {
            val appId = appIdOf(info.uid)
            if (appId < 0) continue
            byAppId.getOrPut(appId) { ArrayList() }.add(info)
        }

        val ownAppId = ControlPage.ownAppId()
        val rows = ArrayList<AppEntry>(byAppId.size)

        for ((appId, infos) in byAppId) {
            // A shared uid gets ONE row, labelled by the app the user is most
            // likely to recognise: the first non-system package, else the first.
            val primary = infos.firstOrNull { !isSystem(it) } ?: infos.first()
            val label = runCatching { pm.getApplicationLabel(primary).toString() }
                .getOrDefault("")
                .ifBlank { primary.packageName }
            rows += AppEntry(
                appId = appId,
                label = if (appId < FIRST_APP_UID) systemLabel(label, appId) else label,
                packages = infos.map { it.packageName }.sorted(),
                unattributed = false,
                system = appId < FIRST_APP_UID || infos.all { isSystem(it) },
                exempt = ControlPage.getUidPolicy(appId) == ControlPage.POLICY_EXEMPT,
                self = appId == ownAppId,
            )
        }

        // A stored policy whose package is gone still has a live byte in the
        // control page. Showing it — as "System", because that is genuinely all
        // we can say about it — is the only way the user can clear it.
        for (appId in storedAppIds(context)) {
            if (byAppId.containsKey(appId)) continue
            rows += AppEntry(
                appId = appId,
                label = systemLabel("", appId),
                packages = emptyList(),
                unattributed = true,
                system = true,
                exempt = ControlPage.getUidPolicy(appId) == ControlPage.POLICY_EXEMPT,
                self = appId == ownAppId,
            )
        }

        // Exempt first so the state the user changed is where they left it, then
        // installed apps before platform ones, then by label.
        return rows.sortedWith(
            compareByDescending<AppEntry> { it.exempt }
                .thenBy { it.system }
                .thenBy { it.label.lowercase() }
        )
    }

    private fun isSystem(info: ApplicationInfo): Boolean =
        (info.flags and (ApplicationInfo.FLAG_SYSTEM or
            ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0

    /**
     * The one honest label for a uid we cannot attribute to a package the user
     * would recognise. Naming it "System" and printing the uid is the whole of
     * what we know; inventing a friendlier name would be a guess presented as a
     * fact, and the uid is what makes the row actionable in a bug report.
     */
    private fun systemLabel(label: String, appId: Int): String =
        if (label.isBlank()) "System (uid $appId)" else "$label — system (uid $appId)"

    fun appIdOf(uid: Int): Int {
        val appId = uid % AID_USER_OFFSET
        return if (appId in 0 until UID_POLICY_LEN) appId else -1
    }

    // ---- writing ------------------------------------------------------------

    /**
     * Exempts or re-enrols an app, live on the resolver's very next query.
     *
     * The durable record is written **after** the byte, and only if the byte
     * took: a stored exemption that never reached the control page would show as
     * "Exempt" on this screen while the app is still being filtered, which is the
     * status-card lie in miniature.
     */
    fun setExempt(context: Context, entry: AppEntry, exempt: Boolean): Result {
        if (entry.self && exempt) return Result.RefusedSelf
        if (!ControlPage.isMapped && !ControlPage.open()) return Result.NoControlPage

        val policy = if (exempt) ControlPage.POLICY_EXEMPT else ControlPage.POLICY_ENFORCE
        if (!ControlPage.setUidPolicy(entry.appId, policy)) {
            return if (entry.self) Result.RefusedSelf
            else Result.Failed(ControlPage.lastError ?: "the control page rejected the write")
        }

        val editor = prefs(context).edit()
        val key = entry.packages.firstOrNull() ?: unattributedKey(entry.appId)
        // The VALUE is the appId this exemption was written to, not a boolean.
        // That is what lets [reapplyAll] clear a byte whose package has since
        // been uninstalled: without it the byte stays set, and the next app to
        // be handed that appId inherits an exemption nobody asked for.
        if (exempt) editor.putInt(key, entry.appId) else editor.remove(key)
        editor.apply()
        return Result.Ok
    }

    /**
     * Re-applies every stored exemption to the control page.
     *
     * This is not belt-and-braces. `nullroute_seed` owns `control.bin` and
     * re-creates it when it is missing or the wrong size, which zeroes
     * `uid_policy` — so without this the user's exemptions vanish on the first
     * boot after a flash and the only symptom is an app that quietly stopped
     * working again. Resolving the appId from the package name here is what stops
     * a reused appId inheriting somebody else's exemption.
     *
     * Returns how many were applied. Safe before first unlock.
     */
    fun reapplyAll(context: Context): Int {
        if (!ControlPage.isMapped && !ControlPage.open()) return 0
        val pm = context.packageManager
        val stored = prefs(context).all
        var applied = 0
        val stale = ArrayList<String>()

        for ((key, value) in stored) {
            val wroteTo = value as? Int ?: continue
            val appId = if (key.startsWith(UNATTRIBUTED_PREFIX)) {
                key.removePrefix(UNATTRIBUTED_PREFIX).toIntOrNull() ?: -1
            } else {
                runCatching { appIdOf(pm.getApplicationInfo(key, 0).uid) }.getOrDefault(-1)
            }

            // The package is gone. Clear the byte it was written to before
            // forgetting the record, or the appId Android hands out next
            // inherits an exemption nobody asked for — and nothing on the Apps
            // screen would ever explain why that app is not being filtered.
            if (appId < 0) {
                ControlPage.setUidPolicy(wroteTo, ControlPage.POLICY_ENFORCE)
                stale += key
                continue
            }

            // The package is still installed but was reinstalled into a
            // different appId. Same hazard, same fix.
            if (appId != wroteTo) {
                ControlPage.setUidPolicy(wroteTo, ControlPage.POLICY_ENFORCE)
                prefs(context).edit().putInt(key, appId).apply()
            }

            if (ControlPage.setUidPolicy(appId, ControlPage.POLICY_EXEMPT)) applied++
        }

        if (stale.isNotEmpty()) {
            val editor = prefs(context).edit()
            stale.forEach { editor.remove(it) }
            editor.apply()
        }
        return applied
    }

    /** For Diagnostics: `com.example.app=exempt`, one line each. */
    fun describe(context: Context): List<String> =
        prefs(context).all.entries
            .mapNotNull { (key, value) -> (value as? Int)?.let { key to it } }
            .sortedBy { it.first }
            .map { (key, appId) -> "$key=exempt appId=$appId" }

    // ---- storage ------------------------------------------------------------

    private const val UNATTRIBUTED_PREFIX = "uid:"

    private fun unattributedKey(appId: Int) = "$UNATTRIBUTED_PREFIX$appId"

    /**
     * appIds that have a stored exemption. Read from the stored VALUE rather
     * than only from `uid:` keys, so a package that was uninstalled between the
     * last boot and this screen still gets a row the user can switch off.
     */
    private fun storedAppIds(context: Context): List<Int> =
        prefs(context).all.values.mapNotNull { it as? Int }

    private fun prefs(context: Context) =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private const val AID_USER_OFFSET = 100_000
    private const val UID_POLICY_LEN = 100_000
}
