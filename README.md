# Marmot KMP

[![GitHub downloads](https://img.shields.io/github/downloads/vitorpamplona/marmot-kmp/total?label=Downloads&labelColor=27303D&color=0D1117&logo=github&logoColor=FFFFFF&style=flat)](https://github.com/vitorpamplona/marmot-kmp/releases)
[![Last Version](https://img.shields.io/github/release/vitorpamplona/marmot-kmp.svg?maxAge=3600&label=Stable&labelColor=06599d&color=043b69)](https://github.com/vitorpamplona/marmot-kmp/releases/latest)
[![Magpie](https://img.shields.io/github/v/release/vitorpamplona/marmot-kmp?label=Magpie%20%28Nostr%20%2B%20Blossom%29&labelColor=27303D&color=7a4fd6)](#install)
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

## Install

Releases are published on Nostr and Blossom with [Magpie](https://github.com/vitorpamplona/magpie),
not on Maven Central (versions up to 2.2.1 are on Central). Magpie's settings plugin serves them to
Gradle, accepting only releases signed by the key `vitorpamplona.com/.well-known/nostr.json` names
as `releases`. In `settings.gradle.kts`:

```kotlin
plugins {
    id("com.vitorpamplona.magpie") version "0.2.0"
}

magpie {
    group("com.vitorpamplona.marmot")
}
```

Then depend on it as usual, and commit the `gradle/magpie.lock` the first build writes. Gradle has
to run on Java 21 or newer.

```kotlin
dependencies {
    implementation("com.vitorpamplona.marmot:marmot:<version>")
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

Agent text stream previews over raw QUIC (`transports/quic.md`) are a second artifact, for the JVM
and Android only, on [quic-kmp](https://github.com/vitorpamplona/quic-kmp):

```kotlin
dependencies {
    implementation("com.vitorpamplona.marmot:marmot-quic:<version>")
}
```

See [marmot-quic/README.md](marmot-quic/README.md). [marmot-bench](marmot-bench/README.md) measures
this library against MDK, operation for operation.

## Developer Setup

```bash
./gradlew installGitHook
./gradlew -PquartzDir=../quartz :marmot:jvmTest   # -PquartzDir until the pinned Quartz is released
```

[AGENTS.md](AGENTS.md) has the project rules, for people and coding agents alike.
