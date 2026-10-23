# Marmot KMP

Marmot (MLS group messaging over Nostr, the `MIP-00`…`MIP-05` specs) as a Kotlin Multiplatform
library for JVM, Android, iOS, macOS and Linux, published to Maven Central as
`com.vitorpamplona.marmot:marmot`. It is built on [Quartz](https://github.com/vitorpamplona/quartz)
(events, signers, NIP-44/NIP-59, the relay client) and the RFC 9420 engine
[mls-kmp](https://github.com/vitorpamplona/mls-kmp), and is used by
[Amethyst](https://github.com/vitorpamplona/amethyst), its desktop app and the `amy` CLI.

The code was the `com.vitorpamplona.quartz.marmot` package of Quartz, plus the headless group
pipeline from Amethyst's `commons` (`MarmotManager` and friends). It moved here so clients that do
not speak Marmot don't carry an MLS engine. cordn, the other MLS binding, is
[cordn-kmp](https://github.com/vitorpamplona/cordn-kmp); the two never import each other.

The specs are the Marmot protocol's MIPs (the `marmot-protocol` organization on GitHub). Interop is
checked against MDK, the reference implementation (<https://github.com/marmot-protocol/mdk>), through
`marmot/tools/mdk-vector-gen` and the vectors in `marmot/src/commonTest/resources/marmot/`.

## Layout

- `marmot/`: the library module, `marmot/src/<sourceSet>/kotlin/com/vitorpamplona/marmot/…`.
  - `mip00KeyPackages/` … `mip05PushNotifications/`: one package per MIP (events, tags, codecs).
  - `foundation/`, `appComponents/`, `protocolCore/`: the current-profile foundation, the app
    components (`0x8001`…), and convergence, branch selection and the publish gate.
  - `groups/`: `MlsGroupManager`, the group policy and the store interfaces.
  - The package root: `MarmotInboundProcessor`/`MarmotOutboundProcessor`, subscriptions, filters,
    `MarmotEvents` (event-kind registration), `RecipientRelayFetcher`.
  - `client/`: the headless client a front end drives: `MarmotManager` (group lifecycle, send,
    ingest, restore), `MarmotSyncPolicy`, `MarmotPushCoordinator`, `MarmotAgentStreamWatcher`.
  - Tests: `commonTest`, `jvmAndroidTest` (JUnit, the in-process test relay in `testing/`),
    `jvmTest` (the `client/` suites and the scenario vectors in `jvmTest/resources/marmot/vectors`).
  - `marmot/tools/mdk-vector-gen`: Rust generator for the MDK vectors. `marmot/plans/`: design docs.
- `gradle/kmp-purity.gradle.kts`: the `verifyKmpPurity` task, the same file as Quartz's.
- `tools/ci/quartz-args.sh`: points the build at a Quartz checkout while the pinned Quartz release is
  not on Maven Central yet (CI and the pre-push hook call it).

## Rules

- **Protocol and headless client only.** No UI, no Compose UI, no app singletons. `@Immutable` and
  `@Stable` are the only Compose dependency. Platform storage, keystores and UI state belong to
  the app; the library defines the store interfaces (`MlsGroupStateStore`, `MarmotMessageStore`,
  `KeyPackageBundleStore`, …) and in-memory implementations, and an app's must encrypt at rest.
- **Quartz does not know Marmot.** The event classes register with Quartz's `EventFactory` through
  `MarmotEvents.register()`; every entry point (managers, processors, fetchers, the event
  companions) calls it. A new Marmot kind adds its builder there and its own `init` call.
- **Never depend on cordn-kmp**, and never let Quartz depend on this library.
- **Reuse Quartz's relay operations** (`fetchAll`, `fetchFirst`, `publishAndConfirm`, …, the
  `INostrClient` extensions in Quartz's `nip01Core/relay/client/accessories/`) instead of writing
  subscribe/collect loops.
- `commonMain` and `commonTest` stay free of JVM-only APIs; `verifyKmpPurity` and the metadata
  compiles catch most of it on Linux, CI's `test-apple` job the rest. Use `kotlin.concurrent.Volatile`
  and Quartz's `PlatformLock`/`ConcurrentMap`.
- Persisted formats are API: a store's bytes, a marker string, a derivation label. Changing one
  breaks every device that already wrote it.
- JVM target is 17. Releases follow semantic versioning; Amethyst pins a version.
- Commits: conventional commits (`feat:`, `fix:`, …). Never `--no-verify`.

## Verify, don't guess

Don't assert a diagnosis you haven't reproduced. If a claim is checkable in under a minute, check
it before stating it: write the failing case first, watch it fail, then explain.

## Build and test

```bash
./gradlew installGitHook                        # pre-commit (spotless) and pre-push (checks + tests)
./gradlew spotlessApply
./gradlew :marmot:jvmTest                       # also `./gradlew test`
./gradlew :marmot:verifyKmpPurity :marmot:compileCommonMainKotlinMetadata :marmot:compileAppleMainKotlinMetadata
./gradlew :marmot:linuxX64Test                  # the whole suite on Linux Native
./gradlew :marmot:iosSimulatorArm64Test         # macOS only
```

Until the Quartz version in `gradle/libs.versions.toml` is on Maven Central, add
`-PquartzDir=../quartz` (a checkout beside this repo); `-PmlsKmpDir` and `-PcryptoKmpDir` work the
same way. To try a change in Amethyst, build Amethyst with `-PmarmotKmpDir=../marmot-kmp`.

## Dependency licensing

Before adding a third-party dependency, read its actual `LICENSE`/`COPYING` file or published
POM, not your memory. This library is MIT and ships inside apps.

- Permissive (MIT, Apache-2.0, BSD, ISC, MPL-2.0, zlib, …): OK.
- LGPL, or GPL/EPL with a linking or Classpath exception: WARN. Acceptable, but say so in your
  summary, and confirm the exception exists in the license text.
- Anything stricter (GPL/AGPL without a linking exception, SSPL, proprietary): STOP. Don't add it;
  surface it and require an explicit call-out in the PR description for a maintainer to decide.

## Kotlin style

- **Log through Quartz's `Log`** (`com.vitorpamplona.quartz.utils.Log`), never `android.util.Log`.
  Interpolated messages use the lambda overload (`Log.d(TAG) { "…$x" }`); in a catch block pass the
  throwable (`Log.w(TAG, "…", e)`).
- **Hot paths use raw arrays and Quartz's `fast*` operators** on `TagArray`; don't "modernize" them
  into stdlib collection calls.
- **Never write fully-qualified class names inline in function bodies**: import the class (use
  `import … as Alias` for a real collision). Comments, KDoc and string literals are exempt.
- **Never put raw invisible or bidirectional Unicode characters in source files**: write them as
  `\uXXXX` escapes, even in test data. The one exception is U+200D inside a real emoji ZWJ sequence.

## Agent configuration (Claude Code + Codex)

Laid out like Quartz's: this file holds the rules, `.claude/CLAUDE.md` imports it with
`@../AGENTS.md`, skills (none yet) live in `.claude/skills/<name>/` with an `.agents/skills/<name>`
symlink, and the shared pre-push checks are in `tools/agent-hooks/` (`agent_config_check.py` runs
in CI too).

## Releasing

Release Quartz first if this version needs a new one. Bump `VERSION_NAME` in `gradle.properties`,
then push a `v<version>` tag. `create-release.yml` refuses to publish against an unpublished Quartz,
runs the Apple tests on macOS, then the checks, publishes to Maven Central and opens the GitHub
release. It needs `SONATYPE_USERNAME`, `SONATYPE_PASSWORD`, `SIGNING_PRIVATE_KEY` and
`SIGNING_PASSWORD`, the same secrets as Quartz.
