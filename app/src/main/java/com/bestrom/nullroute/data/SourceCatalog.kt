package com.bestrom.nullroute.data

/**
 * The built-in source catalogue: every URL Nullroute knows about, what format it
 * arrives in, who owns it, and whether its content may be compiled into the
 * signed image.
 *
 * Measured 2026-08-23 against the live URLs — the domain counts are real, not
 * estimated, and three of them are corrections to what Re-Malwack fetches:
 *
 *  1. **the `wildcard` directory's `-onlydomains` files, never the mirror's
 *     `hosts` form.** Same list, 5.2x smaller (3.67 MB vs 19.12 MB for `multi`),
 *     and it preserves the wildcard semantics our matcher evaluates natively.
 *     HaGeZi's GitHub repo no longer has `hosts/` or `domains/` directories at
 *     all; those URLs 404.
 *  2. **Rem01Gaming is dropped.** No stated licence, 14 months stale, and its
 *     4,649 domains dedupe to nothing against what we already have.
 *  3. **blocklistproject stays out of the default profile.** It is Unlicense and
 *     therefore bakeable, but 234k domains of it in BALANCED is a false-positive
 *     budget nobody asked for.
 *
 * `pgl.yoyo.org` is also absent: no stated licence, and its 3,516 entries reach
 * us anyway inside StevenBlack's MIT aggregation.
 *
 * ## The bakeable flag
 *
 * [Licence.bakeable] is not decoration. `bakeable = false` means the list's
 * *content* must never appear in `prebuilt/baseline.domains.xz` or anywhere else
 * inside the signed image — only its URL ships, and the list is fetched and
 * compiled on the device so that the derivative work is created by the user.
 * See the [Licence] KDoc for why. [assertShippable] exists so that a build-time
 * or test-time caller can enforce it mechanically instead of trusting a review.
 */
object SourceCatalog {

    /**
     * @param groupId stable catalogue key. It identifies a source in settings,
     *   in the category toggles and in the update UI, and it must never be
     *   renumbered — a stored toggle would silently move to a different list.
     *
     *   It is deliberately **not** the `rule_group` written into index slots.
     *   `nativeBuild()` assigns those positionally (`sourcePaths[i]` becomes
     *   `1 + i`, see core/Native.kt), so the mapping from slot to source name is
     *   per-build and lives in `manifest.<gen>.json`, which
     *   [com.bestrom.nullroute.build.IndexBuilder] writes and
     *   `nr_manifest_group_name()` reads. Two ids for two lifetimes: one stable
     *   across releases, one stable across a single index.
     */
    data class Entry(
        val groupId: Int,
        val url: String,
        val label: String,
        val format: SourceFormat,
        val licence: Licence,
        val approxDomains: Int,
        val note: String = "",
    ) {
        val bakeable: Boolean get() = licence.bakeable

        /** `SourceRef` for a profile line, in the role this list is consumed as. */
        fun ref(role: SourceRole = SourceRole.BLOCK): SourceRef =
            SourceRef(url = url, label = label, enabled = true, role = role)
    }

    // ---- permissive: may be compiled into the image -------------------------

    val STEVENBLACK = Entry(
        groupId = 10,
        url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        label = "StevenBlack unified",
        format = SourceFormat.HOSTS,
        licence = Licence.MIT,
        approxDomains = 93_515,
    )

    val ADAWAY = Entry(
        groupId = 11,
        url = "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
        label = "AdAway",
        format = SourceFormat.HOSTS,
        licence = Licence.CC_BY_3_0,
        approxDomains = 6_541,
    )

    val NEXTDNS_CLICK_TRACKING = Entry(
        groupId = 12,
        url = "https://raw.githubusercontent.com/nextdns/click-tracking-domains/main/domains",
        label = "NextDNS click tracking",
        format = SourceFormat.DOMAINS,
        licence = Licence.MIT,
        approxDomains = 700,
    )

    val NEXTDNS_CNAME_CLOAKING = Entry(
        groupId = 13,
        url = "https://raw.githubusercontent.com/nextdns/cname-cloaking-blocklist/master/domains",
        label = "NextDNS CNAME cloaking",
        format = SourceFormat.DOMAINS,
        licence = Licence.MIT,
        approxDomains = 120,
    )

    val BLOCKLISTPROJECT_ADS = Entry(
        groupId = 14,
        url = "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
        label = "The Blocklist Project — ads",
        format = SourceFormat.DOMAINS,
        licence = Licence.UNLICENSE,
        approxDomains = 234_025,
        note = "Kept out of BALANCED on purpose: large, and its FP budget is unearned.",
    )

    // ---- copyleft: URL only, compiled on device -----------------------------

    val HAGEZI_LIGHT = Entry(
        groupId = 20,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
        label = "HaGeZi Light",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 42_350,
    )

    val HAGEZI_MULTI = Entry(
        groupId = 21,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        label = "HaGeZi Multi Pro",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 188_355,
    )

    val HAGEZI_PRO_PLUS = Entry(
        groupId = 22,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt",
        label = "HaGeZi Pro++",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 248_692,
    )

    val RAY_MOBILE_ADS = Entry(
        groupId = 23,
        url = "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileAds.txt",
        label = "AdGuard Mobile Ads",
        format = SourceFormat.HOSTS,
        licence = Licence.GPL_3_0,
        approxDomains = 926,
    )

    val RAY_MOBILE_SPYWARE = Entry(
        groupId = 24,
        url = "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardMobileSpyware.txt",
        label = "AdGuard Mobile Spyware",
        format = SourceFormat.HOSTS,
        licence = Licence.GPL_3_0,
        approxDomains = 1_123,
    )

    val RAY_ADGUARD_DNS = Entry(
        groupId = 25,
        url = "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt",
        label = "AdGuard DNS",
        format = SourceFormat.HOSTS,
        licence = Licence.GPL_3_0,
        approxDomains = 177_029,
    )

    val ONEHOSTS_LITE = Entry(
        groupId = 26,
        url = "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/wildcards.txt",
        label = "1Hosts Lite",
        format = SourceFormat.WILDCARDS,
        licence = Licence.MPL_2_0,
        approxDomains = 102_908,
    )

    // ---- allowlist seeds, applied on every build ----------------------------
    //
    // WARNING, and it is not a small one: `blocklist-referral` and
    // `whitelist-referral` are the SAME 1,604 domains with opposite intent.
    // Shipping both, or the wrong one, inverts the meaning of every entry.
    // Exactly one of them appears here, and it is the whitelist.

    val HAGEZI_ALLOW_REFERRAL = Entry(
        groupId = 30,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/whitelist-referral-onlydomains.txt",
        label = "HaGeZi referral allowlist",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 1_604,
    )

    val HAGEZI_ALLOW_KNOWN_ISSUES = Entry(
        groupId = 31,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/ultimate-known-issues.txt",
        label = "HaGeZi known issues allowlist",
        format = SourceFormat.DOMAINS,
        licence = Licence.GPL_3_0,
        approxDomains = 300,
    )

    /**
     * Three seeds that look like obvious additions and are deliberately **not**
     * applied. Kept in the catalogue rather than deleted so the next person to
     * suggest them finds the measurement instead of re-running it.
     *
     *  * `share/ad-shield-subdomains.txt` is ~86% blocklist; allowing all of it
     *    strips roughly 1,500 live ad hosts back out.
     *  * `share/apple-private-relay.txt` would half-nullify the DoH/VPN-bypass
     *    add-on, for a feature no Android device can use.
     *  * `share/microsoft.txt` is an unblock *menu*, not a list; applying it
     *    whole force-allows Microsoft telemetry everywhere.
     */
    val NOT_ALLOW_SEEDS: List<Entry> = listOf(
        Entry(32, "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/ad-shield-subdomains.txt",
            "HaGeZi ad-shield subdomains", SourceFormat.DOMAINS, Licence.GPL_3_0, 1_700,
            note = "86% blocklist — allowing it strips ~1,500 live ad hosts back out."),
        Entry(33, "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/apple-private-relay.txt",
            "Apple Private Relay", SourceFormat.DOMAINS, Licence.GPL_3_0, 60,
            note = "Would half-nullify the DoH/VPN-bypass add-on for an iOS-only feature."),
        Entry(34, "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/microsoft.txt",
            "Microsoft unblock menu", SourceFormat.DOMAINS, Licence.GPL_3_0, 400,
            note = "A menu, not a list: applying all of it force-allows MS telemetry."),
    )

    // ---- independent add-on toggles (§7.6) ----------------------------------
    //
    // Not part of any tier. Each is switched on separately, each carries an
    // FP-risk chip, and each is a source in its own right so the Query screen can
    // name it as the reason a domain was blocked. See [Categories] for the
    // toggles themselves.

    val HAGEZI_TIF_MEDIUM = Entry(
        groupId = 40,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
        label = "Malware & phishing (TIF medium)",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 368_823,
    )

    val HAGEZI_POPUPADS = Entry(
        groupId = 41,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
        label = "Pop-up ads",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 54_154,
    )

    val HAGEZI_NSFW = Entry(
        groupId = 42,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
        label = "Adult content",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 114_081,
    )

    val HAGEZI_GAMBLING = Entry(
        groupId = 43,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini-onlydomains.txt",
        label = "Gambling",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 107_997,
    )

    val HAGEZI_URLSHORTENER = Entry(
        groupId = 44,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/urlshortener-onlydomains.txt",
        label = "URL shorteners",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 2_400,
        note = "Shorteners carry legitimate links too; expect the odd dead link.",
    )

    val HAGEZI_DOH_BYPASS = Entry(
        groupId = 45,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        label = "DoH / VPN / proxy bypass",
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = 16_642,
        note = "Blocks the endpoints your OWN VPN or private DNS uses. Read the chip.",
    )

    // ---- OEM / native telemetry, keyed off ro.product.brand -----------------
    //
    // Re-Malwack's one genuinely clever profile trick, kept verbatim because it
    // is cheap and high value: the device knows its own brand, and a Xiaomi phone
    // has no use for Samsung's telemetry endpoints. peridot -> xiaomi.

    private fun native(id: Int, slug: String, label: String, domains: Int) = Entry(
        groupId = id,
        url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.$slug-onlydomains.txt",
        label = label,
        format = SourceFormat.WILDCARDS,
        licence = Licence.GPL_3_0,
        approxDomains = domains,
    )

    val NATIVE_XIAOMI = native(50, "xiaomi", "Xiaomi native telemetry", 120)
    val NATIVE_SAMSUNG = native(51, "samsung", "Samsung native telemetry", 90)
    val NATIVE_OPPO_REALME = native(52, "oppo-realme", "Oppo / realme native telemetry", 70)
    val NATIVE_VIVO = native(53, "vivo", "vivo native telemetry", 60)
    val NATIVE_HUAWEI = native(54, "huawei", "Huawei native telemetry", 80)
    val NATIVE_TIKTOK = native(55, "tiktok", "TikTok telemetry", 190)
    val NATIVE_WINOFFICE = native(56, "winoffice", "Windows / Office telemetry", 350)
    val NATIVE_AMAZON = native(57, "amazon", "Amazon device telemetry", 60)
    val NATIVE_APPLE = native(58, "apple", "Apple device telemetry", 70)

    /**
     * `ro.product.brand` (lowercased) to the native list for that brand.
     *
     * `poco` and `redmi` map to Xiaomi and `oneplus` to Oppo/realme because the
     * endpoints are shared — the brands are marketing, the telemetry backends are
     * not. An unknown brand gets no OEM list at all rather than a guess.
     */
    val nativeByBrand: Map<String, Entry> = mapOf(
        "xiaomi" to NATIVE_XIAOMI,
        "redmi" to NATIVE_XIAOMI,
        "poco" to NATIVE_XIAOMI,
        "samsung" to NATIVE_SAMSUNG,
        "oppo" to NATIVE_OPPO_REALME,
        "realme" to NATIVE_OPPO_REALME,
        "oneplus" to NATIVE_OPPO_REALME,
        "vivo" to NATIVE_VIVO,
        "iqoo" to NATIVE_VIVO,
        "huawei" to NATIVE_HUAWEI,
        "honor" to NATIVE_HUAWEI,
        "amazon" to NATIVE_AMAZON,
    )

    /** Add-ons that are not keyed to a brand. */
    val universalNativeAddOns: List<Entry> =
        listOf(NATIVE_TIKTOK, NATIVE_WINOFFICE, NATIVE_APPLE)

    /** Every entry, indexed for lookup by URL. */
    val all: List<Entry> = listOf(
        STEVENBLACK, ADAWAY, NEXTDNS_CLICK_TRACKING, NEXTDNS_CNAME_CLOAKING,
        BLOCKLISTPROJECT_ADS,
        HAGEZI_LIGHT, HAGEZI_MULTI, HAGEZI_PRO_PLUS,
        RAY_MOBILE_ADS, RAY_MOBILE_SPYWARE, RAY_ADGUARD_DNS, ONEHOSTS_LITE,
        HAGEZI_ALLOW_REFERRAL, HAGEZI_ALLOW_KNOWN_ISSUES,
        HAGEZI_TIF_MEDIUM, HAGEZI_POPUPADS, HAGEZI_NSFW, HAGEZI_GAMBLING,
        HAGEZI_URLSHORTENER, HAGEZI_DOH_BYPASS,
        NATIVE_XIAOMI, NATIVE_SAMSUNG, NATIVE_OPPO_REALME, NATIVE_VIVO,
        NATIVE_HUAWEI, NATIVE_TIKTOK, NATIVE_WINOFFICE, NATIVE_AMAZON, NATIVE_APPLE,
    ) + NOT_ALLOW_SEEDS

    private val urlIndex: Map<String, Entry> = all.associateBy { it.url }

    fun byUrl(url: String): Entry? = urlIndex[url.trim()]

    fun byGroupId(groupId: Int): Entry? = all.firstOrNull { it.groupId == groupId }

    /**
     * Allowlist sources merged into every build regardless of profile. These
     * exist because a blocklist author's idea of "tracker" and a user's idea of
     * "my parcel tracking link still has to work" differ, and the referral
     * allowlist is the maintained reconciliation of the two.
     */
    val alwaysAllowSources: List<Entry> = listOf(HAGEZI_ALLOW_REFERRAL, HAGEZI_ALLOW_KNOWN_ISSUES)

    // ---- built-in profiles --------------------------------------------------
    //
    // These are the FALLBACK. The authoritative definition is the shipped file
    // in /system_ext/etc/nullroute/profiles/, which an OTA can update without an
    // APK. This table is what the app uses when that file is missing — the
    // Gradle/stock-Android variant, or a partial flash — so the app still knows
    // what BALANCED means instead of presenting an empty profile picker.

    const val PROFILE_LITE = "lite"
    const val PROFILE_BALANCED = "balanced"
    const val PROFILE_AGGRESSIVE = "aggressive"

    const val DEFAULT_PROFILE = PROFILE_BALANCED

    /**
     * Profiles that need an explicit "I understand this may break apps"
     * confirmation before they are selected (§10.3.8).
     */
    val needsConfirmation: Set<String> = setOf(PROFILE_AGGRESSIVE)

    val builtInProfiles: List<Profile> = listOf(
        Profile(
            id = PROFILE_LITE,
            displayName = "Lite",
            description = "About 43,000 domains. The safest option: ad and tracker " +
                "endpoints with the lowest breakage risk.",
            sources = refs(HAGEZI_LIGHT, RAY_MOBILE_ADS, RAY_MOBILE_SPYWARE) + allowRefs(),
            builtIn = true,
        ),
        Profile(
            id = PROFILE_BALANCED,
            displayName = "Balanced",
            description = "About 226,000 domains. The default. Blocks most ads, " +
                "trackers and telemetry with very few false positives.",
            sources = refs(HAGEZI_MULTI, STEVENBLACK, RAY_MOBILE_ADS, RAY_MOBILE_SPYWARE) +
                allowRefs(),
            builtIn = true,
        ),
        Profile(
            id = PROFILE_AGGRESSIVE,
            displayName = "Aggressive",
            description = "About 443,000 domains. Blocks more, breaks more. Expect " +
                "to allow the occasional domain by hand.",
            sources = refs(
                HAGEZI_PRO_PLUS, STEVENBLACK, ONEHOSTS_LITE,
                RAY_ADGUARD_DNS, BLOCKLISTPROJECT_ADS,
            ) + allowRefs(),
            builtIn = true,
        ),
    )

    fun builtInProfile(id: String): Profile? = builtInProfiles.firstOrNull { it.id == id }

    private fun refs(vararg entries: Entry): List<SourceRef> = entries.map { it.ref() }

    private fun allowRefs(): List<SourceRef> =
        alwaysAllowSources.map { it.ref(SourceRole.ALLOW) }

    /**
     * Throws if [entry] may not be compiled into the signed image.
     *
     * Call this from anything that packages list *content* at build time
     * (`tools/gen_baseline.py` has the same rule on its side). It is a one-line
     * guard against the failure mode where somebody adds HaGeZi to the baseline
     * "just to make first boot better" and turns a ROM release into a GPLv3
     * distribution question.
     */
    fun assertShippable(entry: Entry) {
        require(entry.bakeable) {
            "${entry.label} is ${entry.licence.spdx}: its content must be fetched and " +
                "compiled on the device, never baked into the image"
        }
    }
}
