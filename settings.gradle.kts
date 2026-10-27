pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // kmp-negentropy (a Quartz dependency) is published on JitPack only.
        maven {
            url = uri("https://jitpack.io")
            content {
                includeGroup("com.vitorpamplona.negentropy")
            }
        }
    }
}

rootProject.name = "marmot-kmp"
include(":marmot")
// The raw QUIC binding of agent text streams, published as marmot-quic. JVM and Android only.
include(":marmot-quic")
// marmot-kmp against MDK, head to head. Not published.
include(":marmot-bench")

// Quartz (vitorpamplona/quartz), mls-kmp (vitorpamplona/mls-kmp), crypto-kmp
// (vitorpamplona/crypto-kmp) and quic-kmp (vitorpamplona/quic-kmp) come from Maven Central. To
// change one alongside Marmot, point Gradle at a local checkout and it builds that checkout instead of the published artifact:
//   ./gradlew -PquartzDir=../quartz :marmot:jvmTest
// When this build is itself an included build (Amethyst's -PmarmotKmpDir), the same -P flags reach
// this file too; the outer build includes those checkouts once for the whole composite, so skip them.
val isIncludedBuild = gradle.parent != null

providers.gradleProperty("quartzDir").orNull?.takeUnless { isIncludedBuild }?.let { dir ->
    includeBuild(dir) {
        dependencySubstitution {
            substitute(module("com.vitorpamplona.quartz:quartz")).using(project(":quartz"))
        }
    }
}

//   ./gradlew -PquartzDir=../quartz -PmlsKmpDir=../mls-kmp :marmot:jvmTest
providers.gradleProperty("mlsKmpDir").orNull?.takeUnless { isIncludedBuild }?.let { dir ->
    includeBuild(dir) {
        dependencySubstitution {
            substitute(module("com.vitorpamplona.mls:mls")).using(project(":mls"))
        }
    }
}

//   ./gradlew -PquicKmpDir=../quic-kmp :marmot-quic:jvmTest
providers.gradleProperty("quicKmpDir").orNull?.takeUnless { isIncludedBuild }?.let { dir ->
    includeBuild(dir) {
        dependencySubstitution {
            substitute(module("com.vitorpamplona.quic:quic")).using(project(":quic"))
        }
    }
}

//   ./gradlew -PquartzDir=../quartz -PcryptoKmpDir=../crypto-kmp :marmot:jvmTest
providers.gradleProperty("cryptoKmpDir").orNull?.takeUnless { isIncludedBuild }?.let { dir ->
    includeBuild(dir) {
        dependencySubstitution {
            substitute(module("com.vitorpamplona.crypto:crypto")).using(project(":crypto"))
        }
    }
}
