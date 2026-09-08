/*
 * Root build script. Deliberately empty of configuration: every setting that
 * matters is duplicated in Android.bp, and a setting that lives only here is a
 * setting the shipping build does not have.
 */
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
