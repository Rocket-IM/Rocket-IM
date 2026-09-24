plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
val consumerApplicationId = providers.gradleProperty("interopApplicationId")
    .orElse("io.rocketsim.consumer.kotlin").get()
require(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+").matches(consumerApplicationId)) {
    "Invalid consumer application ID"
}
android {
    namespace = "io.rocketsim.consumer.kotlin"
    compileSdk = 36
    defaultConfig {
        applicationId = consumerApplicationId
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-stage0.1"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
dependencies { implementation("io.rocketsim:rockets-stage0:0.1.0-stage0.1") }
