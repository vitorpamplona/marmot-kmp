# Marmot KMP

[![GitHub downloads](https://img.shields.io/github/downloads/vitorpamplona/marmot-kmp/total?label=Downloads&labelColor=27303D&color=0D1117&logo=github&logoColor=FFFFFF&style=flat)](https://github.com/vitorpamplona/marmot-kmp/releases)
[![Last Version](https://img.shields.io/github/release/vitorpamplona/marmot-kmp.svg?maxAge=3600&label=Stable&labelColor=06599d&color=043b69)](https://github.com/vitorpamplona/marmot-kmp/releases/latest)
[![JitPack snapshots](https://img.shields.io/badge/snapshots-JitPack-27303D?labelColor=27303D&color=0877d2)](https://jitpack.io/#vitorpamplona/marmot-kmp)
[![CI](https://img.shields.io/github/actions/workflow/status/vitorpamplona/marmot-kmp/build.yml?labelColor=27303D)](https://github.com/vitorpamplona/marmot-kmp/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/github/license/vitorpamplona/marmot-kmp?labelColor=27303D&color=0877d2)](LICENSE)

Marmot, MLS group messaging over Nostr, for Kotlin
Multiplatform: JVM, Android, iOS, macOS and Linux. It implements MIP-00 to MIP-05 (KeyPackages,
groups, Welcomes, group messages, encrypted media, push notifications) and the current Marmot
profile on top of [Quartz](https://github.com/vitorpamplona/quartz) and the RFC 9420 engine
[mls-kmp](https://github.com/vitorpamplona/mls-kmp), and ships a headless client,
`MarmotManager`, that a front end drives to create, join, send to and sync groups.

It is the Marmot layer of [Amethyst](https://github.com/vitorpamplona/amethyst), its desktop app
and the `amy` CLI, and is tested against [MDK](https://github.com/marmot-protocol/mdk), the
reference implementation.

```kotlin
dependencies {
    implementation("com.vitorpamplona.marmot:marmot:<version>")
}
```

Releases are on Nostr + Blossom, through [Magpie](https://github.com/vitorpamplona/magpie)
(Maven Central up to 2.2.1), and so are the libraries it depends on. Add Magpie's settings
plugin in `settings.gradle.kts`: it serves these groups, trusting only the key
`vitorpamplona.com/.well-known/nostr.json` names as `releases`. Commit the `gradle/magpie.lock`
it writes; Gradle has to run on Java 21 or newer:

```kotlin
plugins {
    id("com.vitorpamplona.magpie") version "0.2.3"
}

magpie {
    group("com.vitorpamplona.marmot")
    group("com.vitorpamplona.quartz")
    group("com.vitorpamplona.crypto")
    group("com.vitorpamplona.schnorr256k1")
    group("com.vitorpamplona.negentropy")
    group("com.vitorpamplona.mls")
}
```

The Marmot event classes (`KeyPackageEvent`, `WelcomeEvent`, `GroupEvent`, the push events) are
part of Quartz, under `com.vitorpamplona.quartz.marmot`, so they parse typed with no setup.

```kotlin
val marmot =
    MarmotManager(
        signer = signer,                       // a Quartz NostrSigner
        store = myEncryptedMlsGroupStateStore, // persist group state; must encrypt at rest
        messageStore = myMessageStore,
        keyPackageStore = myKeyPackageStore,
        publisher = MarmotPublisher { event, relays -> client.publishAndConfirm(event, relays) },
    )
marmot.restoreAll()
```

The store interfaces live in `com.vitorpamplona.marmot.groups` and
`com.vitorpamplona.marmot.mip00KeyPackages`; in-memory versions exist for tests.

The agent text stream over raw QUIC (`marmot-quic`, kind 1200 stream starts) is retired, as the
spec and MDK 0.19.0 retired it: see [the plan](marmot/plans/2026-11-22-retire-agent-text-stream.md).
[marmot-bench](marmot-bench/README.md) measures this library against MDK, operation for operation.

## Developer Setup

```bash
./gradlew installGitHook
./gradlew -PquartzDir=../quartz :marmot:jvmTest   # -PquartzDir until the pinned Quartz is released
```

[AGENTS.md](AGENTS.md) has the project rules, for people and coding agents alike.
