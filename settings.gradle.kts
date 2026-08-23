/*
 * Nullroute — Gradle parity build.
 *
 * The AUTHORITATIVE build is Soong (packages/apps/Nullroute/Android.bp). Gradle
 * exists for two reasons and no others:
 *   1. a ~20 s compile check without a 40-minute `mka` cycle;
 *   2. the Phase 4 stock-Android variant, where the same sources ship as a plain
 *      APK with a VpnService instead of a resolver hook.
 *
 * Both builds consume the SAME sources, so nothing in app/src may depend on
 * anything Soong cannot provide (no Compose, no ViewBinding, no DataBinding, no
 * BuildConfig, no androidx.datastore, no kotlinx.coroutines) or on anything
 * Gradle cannot provide (no SettingsLib, no @hide/@SystemApi symbols linked
 * directly — those go through reflection, which the sysconfig
 * `hidden-api-whitelisted-app` entry makes legal at runtime).
 */
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Nullroute"
include(":app")
