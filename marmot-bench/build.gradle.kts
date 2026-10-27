import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinJvm)
    application
}

// marmot-kmp against MDK, head to head. Never published; see README.md.
application {
    mainClass.set("com.vitorpamplona.marmot.bench.MainKt")
    applicationName = "marmotbench"
    // `-XX:+UseSerialGC` keeps the allocation counter attributable to the
    // benchmark thread instead of to background GC worker threads, and a heap
    // big enough that a collection never lands mid-measurement. Both matter
    // more here than raw throughput: the number we care about is bytes
    // allocated per operation, and a GC pause inside a sample corrupts the
    // latency percentile it lands in.
    applicationDefaultJvmArgs = listOf("-Xmx4g", "-Xms4g", "-XX:+UseSerialGC", "-Dfile.encoding=UTF-8")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
    }
}

dependencies {
    implementation(project(":marmot"))
    implementation(libs.kotlinx.coroutines.core)

    // JNI secp256k1 backend quartz needs at runtime on plain JVM.
    runtimeOnly(libs.secp256k1.kmp.jni.jvm)
}
