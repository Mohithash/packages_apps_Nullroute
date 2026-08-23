plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    // The source manifest carries no package= (AGP 8 rejects it). Soong gets the
    // package back via the nullroute_soong_manifest genrule; Gradle gets it here.
    // These two must never diverge — the R class package and the privapp
    // allowlist key are both derived from it.
    namespace = "com.bestrom.nullroute"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.bestrom.nullroute"
        // Matches min_sdk_version in Android.bp. CtlReceiver.getSentFromUid()
        // needs API 34, so the receiver refuses every broadcast below it rather
        // than running with an unauthenticatable sender (see ctl/CtlReceiver.kt).
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "1.0-phase1"
    }

    buildFeatures {
        // Soong generates none of these. Leaving them off means the Gradle build
        // is a real parity check rather than a more permissive second build.
        buildConfig = false
        viewBinding = false
        dataBinding = false
        compose = false
    }

    buildTypes {
        release {
            // Mirrors `optimize: { enabled: false }` in Android.bp: androidx
            // preference and Material inflate views reflectively, and a shrinker
            // configured differently from the shipping build is worse than none.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    lint {
        // The Gradle build compiles against the public SDK while the shipping
        // build compiles against system_current, so lint flags privileged
        // permissions and reflective platform access it cannot see the grants
        // for. Soong is the gate that matters.
        abortOnError = false
        checkReleaseBuilds = false
    }

    packaging {
        // libnrjni.so is produced by Soong (cc_library_shared) and injected via
        // `jni_libs`. There is no NDK build here; Native.kt treats a missing
        // library as "no native support" and the app degrades to read-only
        // status reporting rather than crashing.
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.preference)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.material)
}
