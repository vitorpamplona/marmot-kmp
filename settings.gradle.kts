pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// Quartz (from 2.19.0), crypto-kmp and libschnorr256k1-kotlin are released on Nostr + Blossom: the
// Magpie settings plugin serves their groups, trusting only the release key vitorpamplona.com names
// as `releases`, and gradle/magpie.lock pins that key and every resolved version's files. It also puts
// the publish plugin (com.vitorpamplona.magpie.publish) on the classpath, so build scripts apply that
// one by id alone.
plugins {
    id("com.vitorpamplona.magpie") version "0.2.0"
}

magpie {
    group("com.vitorpamplona.quartz")
    group("com.vitorpamplona.crypto")
    group("com.vitorpamplona.schnorr256k1")
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
