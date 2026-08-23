package com.bestrom.nullroute.data

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.StringRes
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.SysProp
import java.io.File

/**
 * The independent category toggles, and the two carve-outs that are the reason
 * this file is not just a list of extra URLs.
 *
 * ## Two kinds of toggle, pointing in opposite directions
 *
 * A [CategoryKind.BLOCK_ADDON] adds a list. Switching it on blocks *more*. These
 * are the six Re-Malwack has plus the OEM/native one, and the only thing we add
 * is an honest [FpRisk] chip on each.
 *
 * A [CategoryKind.ALLOW_CARVEOUT] does the opposite, and is the correction
 * Re-Malwack does not have. `antifraud.txt` and `attribution.txt` name domains
 * that *are* trackers and that other people's lists therefore block — and that
 * banking, delivery and ride-hailing apps are built on. So by default we compile
 * them in as **allow** rules, which strips them back out of every imported list;
 * the toggle, when the user turns it ON, simply stops emitting those allows and
 * lets the blocklists have their way.
 *
 * That inversion is worth being precise about, because it is the opposite of
 * what a "category switch" normally means:
 *
 * ```
 *   Anti-fraud fingerprinting = OFF (default) -> those domains are ALLOWED
 *   Anti-fraud fingerprinting = ON            -> the blocklists decide
 * ```
 *
 * §10.3.4 is the evidence: what breaks banking apps is not ad domains but device
 * fingerprinting (`h.online-metrix.net`, `*.threatmetrix.com`, `*.iovation.com`,
 * …), and what breaks delivery apps is deferred deep links (`*.appsflyer.com`,
 * `*.branch.io`, `*.app.link`, …). Both symptoms — "the app spins forever",
 * "onboarding loops" — are impossible for a user to attribute to a DNS filter.
 *
 * ## Storage
 *
 * Its own DE-backed preferences file rather than a corner of [Settings]. The
 * update job reads these before first unlock, and a category set that lived in
 * CE storage would silently compile as "all off" on the first boot after a
 * flash — producing an index that is quietly different from the one the user
 * configured, with nothing to show for it.
 */
object Categories {

    private const val PREFS = "nullroute_categories"

    const val ID_OEM_NATIVE = "oem_native"
    const val ID_MALWARE = "malware"
    const val ID_POPUP_ADS = "popup_ads"
    const val ID_NSFW = "nsfw"
    const val ID_GAMBLING = "gambling"
    const val ID_URL_SHORTENER = "url_shortener"
    const val ID_DOH_BYPASS = "doh_bypass"
    const val ID_TIKTOK = "tiktok"
    const val ID_WINOFFICE = "winoffice"

    const val ID_ANTIFRAUD = "antifraud"
    const val ID_ATTRIBUTION = "attribution"

    /**
     * How much collateral damage a category is known to cause, in the words the
     * chip actually uses. Not a severity scale for its own sake: [HIGH] and the
     * three named risks each describe a *specific* thing that stops working, so
     * that a user can decide instead of guessing.
     */
    enum class FpRisk(@StringRes val labelRes: Int, @StringRes val detailRes: Int) {
        LOW(R.string.risk_low, R.string.risk_low_detail),
        MEDIUM(R.string.risk_medium, R.string.risk_medium_detail),
        HIGH(R.string.risk_high, R.string.risk_high_detail),
        BREAKS_OWN_VPN(R.string.risk_own_vpn, R.string.risk_own_vpn_detail),
        BREAKS_BANKING(R.string.risk_banking, R.string.risk_banking_detail),
        BREAKS_DELIVERY(R.string.risk_delivery, R.string.risk_delivery_detail);

        /** Whether selecting this needs an explicit confirmation, not just a tap. */
        val needsConfirmation: Boolean
            get() = this == BREAKS_OWN_VPN || this == BREAKS_BANKING || this == BREAKS_DELIVERY
    }

    enum class CategoryKind {
        /** ON adds a blocklist. */
        BLOCK_ADDON,

        /** ON *stops* an allow overlay, letting the blocklists block. See the KDoc. */
        ALLOW_CARVEOUT,
    }

    data class Category(
        val id: String,
        val kind: CategoryKind,
        @StringRes val titleRes: Int,
        @StringRes val summaryRes: Int,
        val risk: FpRisk,
        /** Lists fetched when a BLOCK_ADDON is on. Empty for a carve-out. */
        val sources: List<SourceCatalog.Entry> = emptyList(),
        /** Shipped file whose domains form an ALLOW_CARVEOUT. Null for an add-on. */
        val carveOutFile: File? = null,
        val defaultOn: Boolean = false,
        val approxDomains: Int = sources.sumOf { it.approxDomains },
    ) {
        val needsConfirmation: Boolean get() = risk.needsConfirmation

        /**
         * What ON means for this row, in one clause. The carve-outs read
         * backwards from every other toggle in Android and the switch label has
         * to say so, or a user will turn "Anti-fraud fingerprinting" on believing
         * they are protecting themselves and break their bank.
         */
        @StringRes
        fun onMeansRes(): Int = when (kind) {
            CategoryKind.BLOCK_ADDON -> R.string.category_on_blocks
            CategoryKind.ALLOW_CARVEOUT -> R.string.category_on_stops_allowing
        }
    }

    // ---- the catalogue ------------------------------------------------------

    /**
     * Every category for *this* device. The OEM row is brand-dependent, so this
     * is a function rather than a val: a table computed at class-init time would
     * be wrong on any build where the brand property is read late.
     */
    fun all(): List<Category> {
        val out = ArrayList<Category>(11)

        oemSources().takeIf { it.isNotEmpty() }?.let { sources ->
            out += Category(
                id = ID_OEM_NATIVE,
                kind = CategoryKind.BLOCK_ADDON,
                titleRes = R.string.category_oem,
                summaryRes = R.string.category_oem_summary,
                risk = FpRisk.LOW,
                sources = sources,
                defaultOn = true,
            )
        }

        out += Category(
            id = ID_MALWARE,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_malware,
            summaryRes = R.string.category_malware_summary,
            risk = FpRisk.MEDIUM,
            sources = listOf(SourceCatalog.HAGEZI_TIF_MEDIUM),
        )
        out += Category(
            id = ID_POPUP_ADS,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_popup,
            summaryRes = R.string.category_popup_summary,
            risk = FpRisk.LOW,
            sources = listOf(SourceCatalog.HAGEZI_POPUPADS),
        )
        out += Category(
            id = ID_NSFW,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_nsfw,
            summaryRes = R.string.category_nsfw_summary,
            risk = FpRisk.LOW,
            sources = listOf(SourceCatalog.HAGEZI_NSFW),
        )
        out += Category(
            id = ID_GAMBLING,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_gambling,
            summaryRes = R.string.category_gambling_summary,
            risk = FpRisk.LOW,
            sources = listOf(SourceCatalog.HAGEZI_GAMBLING),
        )
        out += Category(
            id = ID_URL_SHORTENER,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_shortener,
            summaryRes = R.string.category_shortener_summary,
            risk = FpRisk.MEDIUM,
            sources = listOf(SourceCatalog.HAGEZI_URLSHORTENER),
        )
        out += Category(
            id = ID_TIKTOK,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_tiktok,
            summaryRes = R.string.category_tiktok_summary,
            risk = FpRisk.MEDIUM,
            sources = listOf(SourceCatalog.NATIVE_TIKTOK),
        )
        out += Category(
            id = ID_WINOFFICE,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_winoffice,
            summaryRes = R.string.category_winoffice_summary,
            risk = FpRisk.LOW,
            sources = listOf(SourceCatalog.NATIVE_WINOFFICE),
        )
        out += Category(
            id = ID_DOH_BYPASS,
            kind = CategoryKind.BLOCK_ADDON,
            titleRes = R.string.category_doh,
            summaryRes = R.string.category_doh_summary,
            risk = FpRisk.BREAKS_OWN_VPN,
            sources = listOf(SourceCatalog.HAGEZI_DOH_BYPASS),
        )

        out += Category(
            id = ID_ANTIFRAUD,
            kind = CategoryKind.ALLOW_CARVEOUT,
            titleRes = R.string.category_antifraud,
            summaryRes = R.string.category_antifraud_summary,
            risk = FpRisk.BREAKS_BANKING,
            carveOutFile = Paths.antifraudTxt,
            approxDomains = 40,
        )
        out += Category(
            id = ID_ATTRIBUTION,
            kind = CategoryKind.ALLOW_CARVEOUT,
            titleRes = R.string.category_attribution,
            summaryRes = R.string.category_attribution_summary,
            risk = FpRisk.BREAKS_DELIVERY,
            carveOutFile = Paths.attributionTxt,
            approxDomains = 30,
        )
        return out
    }

    fun byId(id: String): Category? = all().firstOrNull { it.id == id }

    /**
     * `ro.product.brand`, lowercased. peridot reports `xiaomi` (and `POCO` on
     * some SKUs, which maps to the same endpoints).
     */
    fun brand(): String = SysProp.get("ro.product.brand", "").trim().lowercase()

    private fun oemSources(): List<SourceCatalog.Entry> =
        listOfNotNull(SourceCatalog.nativeByBrand[brand()])

    // ---- state --------------------------------------------------------------

    private fun prefs(context: Context): SharedPreferences =
        Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isEnabled(context: Context, category: Category): Boolean =
        prefs(context).getBoolean(category.id, category.defaultOn)

    fun isEnabled(context: Context, id: String): Boolean =
        byId(id)?.let { isEnabled(context, it) } ?: false

    fun setEnabled(context: Context, id: String, enabled: Boolean) {
        prefs(context).edit().putBoolean(id, enabled).apply()
    }

    fun enabled(context: Context): List<Category> = all().filter { isEnabled(context, it) }

    // ---- what the build pipeline asks for -----------------------------------

    /**
     * Extra block lists to fetch, from every BLOCK_ADDON that is on.
     *
     * Returned as [SourceRef] so they flow through the same fetch, licence gate
     * and per-source failure reporting as a profile's own sources. A category
     * list that fails to download must be as visible as HaGeZi failing to
     * download; "you enabled malware blocking and it silently did nothing" is
     * exactly the failure this project refuses to ship.
     */
    fun blockSources(context: Context): List<SourceRef> =
        enabled(context)
            .filter { it.kind == CategoryKind.BLOCK_ADDON }
            .flatMap { it.sources }
            .distinctBy { it.url }
            .map { it.ref() }

    /**
     * The carve-out files whose contents must be compiled in as ALLOW rules —
     * that is, the carve-outs the user has **not** opted into.
     *
     * Reads the shipped file rather than a hardcoded list so a BestROM release
     * can add a newly-broken fingerprinting host without an APK update.
     */
    fun allowCarveOutDomains(context: Context): List<String> {
        val out = LinkedHashSet<String>()
        for (category in all()) {
            if (category.kind != CategoryKind.ALLOW_CARVEOUT) continue
            if (isEnabled(context, category)) continue      // opted IN: let lists block
            val file = category.carveOutFile ?: continue
            readDomains(file, out)
        }
        return out.toList()
    }

    /** Categories the user opted into, for the "why is this blocked" answer. */
    fun activeCarveOutIds(context: Context): List<String> =
        all().filter { it.kind == CategoryKind.ALLOW_CARVEOUT && isEnabled(context, it) }
            .map { it.id }

    private fun readDomains(file: File, into: MutableCollection<String>) {
        if (!file.isFile) return
        runCatching {
            file.forEachLine { raw ->
                // The shipped files carry `*.threatmetrix.com` as well as bare
                // names; both are kept verbatim, because the leading `*.` is a
                // real distinction the matcher honours and flattening it here
                // would silently widen a carve-out to cover the apex.
                val line = raw.substringBefore('#').trim().lowercase().removeSuffix(".")
                if (line.isEmpty()) return@forEachLine
                if (!line.contains('.')) return@forEachLine
                into += line
            }
        }
    }

    /**
     * One line per row for the Diagnostics bundle and the update manifest:
     * `id=on risk=BREAKS_BANKING kind=ALLOW_CARVEOUT`.
     */
    fun describe(context: Context): List<String> = all().map {
        "${it.id}=${if (isEnabled(context, it)) "on" else "off"} " +
            "risk=${it.risk.name} kind=${it.kind.name}"
    }
}
