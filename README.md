# Marmot KMP

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
