plugins {
    id("com.android.library") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
    id("maven-publish")
}

group = "io.rocketsim"
version = "0.1.0-stage0.1"

android {
    namespace = "io.rocketsim.stage0"
    compileSdk = 36
    defaultConfig { minSdk = 24; consumerProguardFiles("consumer-rules.pro") }
    sourceSets["main"].java.srcDir("src/main/generated")
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    publishing { singleVariant("release") { withSourcesJar() } }
}

dependencies {
    // 由打包脚本按当前生成器运行时契约显式固定；不猜版本、不提供源码编译兜底。
    api("net.java.dev.jna:jna:${providers.gradleProperty("jnaVersion").get()}@aar")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "rockets-stage0"
                pom {
                    name.set("Rockets-IM Stage 0")
                    description.set("Local Stage 0 release package validation; no persistence or network engine.")
                }
            }
        }
        repositories { maven { url = uri(providers.gradleProperty("releaseRepository").get()) } }
    }
}
