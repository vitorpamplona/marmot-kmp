import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.serialization)
    alias(libs.plugins.vanniktech.mavenPublish)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    // JVM 17, like Quartz: a library cannot need a newer JVM than its users.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    android {
        namespace = "com.vitorpamplona.marmot"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }

        withHostTest {}
    }

    // The same native targets as Quartz.
    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    linuxX64()

    applyDefaultHierarchyTemplate()

    // Test vectors live in src/commonTest/resources. JVM tests read them from the classpath;
    // native test binaries have none, so they resolve paths against this variable.
    val resourcesRoot = project.file("src/commonTest/resources").absolutePath

    tasks.withType<Test>().configureEach {
        maxHeapSize = "4g"
        environment("TEST_RESOURCES_ROOT", resourcesRoot)
    }

    tasks.withType<KotlinNativeTest>().configureEach {
        environment("TEST_RESOURCES_ROOT", resourcesRoot)
        // Propagates the variable into the iOS simulator.
        environment("SIMCTL_CHILD_TEST_RESOURCES_ROOT", resourcesRoot)
    }

    sourceSets {
        commonMain.dependencies {
            // Events, tags, signers and the relay client. api: Marmot's API takes and returns them.
            api(libs.quartz)
            // The RFC 9420 engine. api: MlsGroupManager and the stores expose its types.
            api(libs.mls.kmp)
            // SHA, HKDF, ChaCha20-Poly1305 and secure random.
            api(libs.crypto)

            api(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.json)

            // @Immutable and @Stable
            implementation(libs.androidx.compose.runtime.annotation)
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
        }

        // JVM/Android-only tests (java.io, JUnit, the in-process relay).
        val jvmAndroidTest =
            create("jvmAndroidTest") {
                dependsOn(commonTest.get())
                dependencies {
                    // The in-process test relay stores events in quartz's SQLite store.
                    implementation(libs.androidx.sqlite.bundled)
                }
            }

        jvmTest {
            dependsOn(jvmAndroidTest)
            dependencies {
                // Quartz leaves the secp256k1 JNI variant to the app; tests are the app here.
                implementation(libs.secp256k1.kmp.jni.jvm)
                implementation(libs.androidx.sqlite.bundled.jvm)
            }
        }

        getByName("androidHostTest") {
            dependsOn(jvmAndroidTest)
            dependencies {
                implementation(libs.secp256k1.kmp.jni.jvm)
                implementation(libs.androidx.sqlite.bundled.jvm)
            }
        }
    }
}

// JVM-only APIs must not reach the source sets Apple and Linux compile.
apply(from = rootProject.file("gradle/kmp-purity.gradle.kts"))

mavenPublishing {
    // sources publishing is always enabled by the Kotlin Multiplatform plugin
    configure(
        KotlinMultiplatform(
            sourcesJar = SourcesJar.Sources(),
        ),
    )

    // groupId, artifactId, and version are configured via gradle.properties
    // (GROUP, POM_ARTIFACT_ID, VERSION_NAME) so CI can override VERSION_NAME
    // via ORG_GRADLE_PROJECT_VERSION_NAME without conflicting with a hardcoded value.
    publishToMavenCentral(automaticRelease = true)

    // CI provides the key (ORG_GRADLE_PROJECT_signingInMemoryKey); without one,
    // publishToMavenLocal still works for testing a local build in a consumer.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name = "Marmot: MLS group messaging over Nostr for Kotlin Multiplatform"
        description = "Marmot protocol (MIP-00..05) on Quartz and mls-kmp for JVM, Android, iOS, macOS & Linux"
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
