import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
}

// The raw QUIC binding of agent text stream previews (`transports/quic.md`), on quic-kmp. A module
// of its own because quic-kmp builds for the JVM and Android only, while :marmot also builds for
// Apple and Linux; the codecs it frames live in :marmot.
kotlin {
    // JVM 21, not :marmot's 17: quic-kmp targets 21, and a module cannot target below a dependency.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    android {
        namespace = "com.vitorpamplona.marmot.quic"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }

        withHostTest {}
    }

    sourceSets {
        commonMain.dependencies {
            api(project(":marmot"))
            implementation(libs.quic)
            implementation(libs.kotlinx.coroutines.core)
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
        }

        val jvmAndroid =
            create("jvmAndroid") {
                dependsOn(commonMain.get())
            }

        jvmMain {
            dependsOn(jvmAndroid)
        }

        androidMain {
            dependsOn(jvmAndroid)
        }

        jvmTest.dependencies {
            implementation(libs.secp256k1.kmp.jni.jvm)
        }

        getByName("androidHostTest").dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.secp256k1.kmp.jni.jvm)
        }
    }
}

// Forward the interop opt-ins from the Gradle JVM to the test workers. Without this,
// `-DmarmotQuicBroker=...` / `-DmarmotWn=...` never reach the tests and every interop case
// silently skips.
tasks.withType<Test>().configureEach {
    System.getProperty("marmotQuicBroker")?.let { systemProperty("marmotQuicBroker", it) }
    System.getProperty("marmotQuicBrokerPin")?.let { systemProperty("marmotQuicBrokerPin", it) }
    System.getProperty("marmotWn")?.let { systemProperty("marmotWn", it) }
}

mavenPublishing {
    configure(
        KotlinMultiplatform(
            sourcesJar = SourcesJar.Sources(),
        ),
    )

    // groupId and version come from the root gradle.properties, the artifactId from this
    // module's (marmot-quic), so a release publishes both artifacts at one version.
    publishToMavenCentral(automaticRelease = true)

    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name = "Marmot QUIC: the raw QUIC binding of Marmot agent text streams"
        description = "transports/quic.md for marmot-kmp, on the pure-Kotlin quic-kmp client, for JVM & Android"
        inceptionYear = "2026"
        url = "https://github.com/vitorpamplona/marmot-kmp/"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/vitorpamplona/marmot-kmp/blob/main/LICENSE"
            }
        }
        developers {
            developer {
                id = "vitorpamplona"
                name = "Vitor Pamplona"
                url = "http://vitorpamplona.com"
                email = "vitor@vitorpamplona.com"
            }
        }
        scm {
            url = "https://github.com/vitorpamplona/marmot-kmp/"
            connection = "https://github.com/vitorpamplona/marmot-kmp.git"
        }
    }
}
