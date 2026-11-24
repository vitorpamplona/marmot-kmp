import org.jetbrains.kotlin.gradle.tasks.Kotlin2JsCompile
import org.jetbrains.kotlin.gradle.tasks.KotlinNativeCompile

plugins {
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.kotlinJvm) apply false
    alias(libs.plugins.androidKotlinMultiplatformLibrary) apply false
    alias(libs.plugins.serialization) apply false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.diffplugSpotless)
}

allprojects {
    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("src/**/*.kt")

            // Same ktlint and header as Quartz and Amethyst, so a file moved
            // between the repos formats identically on every side.
            ktlint("1.7.1")
            licenseHeaderFile(
                rootProject.file("spotless/copyright.kt"),
                "@file:|package|import|class|object|sealed|open|interface|abstract ",
            )
        }
    }
}

subprojects {
    afterEvaluate {
        // Kotlin Multiplatform registers no plain `test` task, so `./gradlew test` would skip
        // :marmot silently. Alias it onto jvmTest.
        if (plugins.hasPlugin("org.jetbrains.kotlin.multiplatform") &&
            tasks.findByName("test") == null &&
            tasks.findByName("jvmTest") != null
        ) {
            tasks.register("test") {
                group = "verification"
                description = "Runs the JVM unit tests for this Kotlin Multiplatform module."
                dependsOn("jvmTest")
            }
        }
    }
}

tasks.register<Copy>("installGitHook") {
    from("git-hooks/pre-commit")
    from("git-hooks/pre-push")
    into(".git/hooks")
    filePermissions { unix("rwxrwxrwx") }
}

// Kotlin/Native and Kotlin/JS klibs record the path of every source file. Recording it relative to
// this repository instead of the checkout's absolute path keeps a klib rebuilt in any folder
// byte-identical to the released one.
subprojects {
    val klibPathBase = "-Xklib-relative-path-base=${rootDir.absolutePath}"
    tasks.withType<KotlinNativeCompile>().configureEach { compilerOptions.freeCompilerArgs.add(klibPathBase) }
    tasks.withType<Kotlin2JsCompile>().configureEach { compilerOptions.freeCompilerArgs.add(klibPathBase) }
}

// The release gate (create-release.yml): a release's POM names the Quartz and mls-kmp versions it
// was built against, so each must resolve from Nostr + Blossom through Magpie before this library
// can be released. A GitHub tag is not enough: it is pushed before the Nostr publish, which can
// still fail or wait on the signer. Resolving the exact pinned versions asks Magpie for each one's
// signed release event and files, the same way a consumer would. Run it without -PquartzDir or
// -PmlsKmpDir, which would substitute the checkouts.
tasks.register("verifyDependenciesPublished") {
    group = "verification"
    description = "Fails unless the pinned Quartz and mls-kmp releases resolve through Magpie."
    val pinned =
        listOf(
            "com.vitorpamplona.quartz:quartz-jvm:${libs.versions.quartzKmp.get()}",
            "com.vitorpamplona.mls:mls-jvm:${libs.versions.mlsKmp.get()}",
        )
    val substituted = listOf("quartzDir", "mlsKmpDir").filter { providers.gradleProperty(it).isPresent }
    val resolved =
        provider {
            pinned.map { coordinates ->
                val config = configurations.detachedConfiguration(dependencies.create(coordinates)).apply { isTransitive = false }
                val artifacts = config.incoming.artifactView { lenient(true) }.artifacts
                val failure = artifacts.failures.firstOrNull()?.let { generateSequence(it) { e -> e.cause }.last().message }
                Triple(coordinates, artifacts.artifacts.isNotEmpty(), failure)
            }
        }
    doLast {
        check(substituted.isEmpty()) { "Run without ${substituted.joinToString { "-P$it" }}: it replaces the published artifact." }
        val missing = resolved.get().filterNot { it.second }
        check(missing.isEmpty()) {
            "Not published on Nostr + Blossom (Magpie could not resolve it), release it first: " +
                missing.joinToString { "${it.first} (${it.third ?: "no artifact"})" }
        }
        resolved.get().forEach { logger.lifecycle("Published: ${it.first}") }
    }
}
