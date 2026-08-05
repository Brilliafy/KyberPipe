import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.kyberpipe.client"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "org.kyberpipe.client"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
    testOptions {
        unitTests {
            // JVM tests exercise the poll wire logic + watermark with fakes;
            // any Android framework call they hit returns defaults instead of
            // throwing "not mocked".
            isReturnDefaultValues = true
        }
    }
    sourceSets {
        getByName("main") {
            jniLibs.srcDir("src/main/jniLibs")
            // AUDIT F9 (MEDIUM): the UniFFI-generated Kotlin binding is checked
            // in ONCE, in core-crypto/generated_kotlin, and consumed here via a
            // source-directory reference instead of a second copied file. The
            // legacy layout kept a byte-identical copy under
            // src/main/java/uniffi/core_crypto — any UniFFI change regenerated
            // one tree and not the other, and the stale Kotlin side called
            // UniffiLib symbols that no longer exist in the rebuilt .so
            // (UnsatisfiedLinkError on device with no compile-time error).
            // With this srcDir there is exactly one file; the `uniffi/`
            // subdirectory under it maps to the `uniffi.core_crypto` package
            // exactly as before.
            kotlin.srcDir("../../core-crypto/generated_kotlin")
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.fragment:fragment-ktx:1.5.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Biometric Step-Up Authorization
    implementation("androidx.biometric:biometric:1.1.0")
    // JNA binding runtime for UniFFI
    implementation("net.java.dev.jna:jna:5.16.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // CameraX
    val cameraxVersion = "1.6.1"
    implementation("androidx.camera:camera-core:$cameraxVersion")
    implementation("androidx.camera:camera-camera2:$cameraxVersion")
    implementation("androidx.camera:camera-lifecycle:$cameraxVersion")
    implementation("androidx.camera:camera-view:$cameraxVersion")

    // ML Kit Barcode Scanning
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    // ZXing fallback for dense QR codes
    implementation("com.google.zxing:core:3.5.3")
    
    // Security Crypto
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // JVM unit tests (verification-gap remediation: the poll wire logic and
    // the ratchet rollback watermark are exercised on the JVM with fakes).
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

