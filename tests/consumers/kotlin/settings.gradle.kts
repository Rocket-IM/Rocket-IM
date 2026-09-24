pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri(providers.gradleProperty("releaseRepository").get()) }
        google()
        mavenCentral()
    }
}
rootProject.name = "RocketStage0Consumer"
include(":app")
