# app-event-vector-gen

Regenerates `marmot/src/commonTest/resources/marmot/app-events/`: the app events (the unsigned
rumors members send inside a group) of one real conversation between White Noise (MDK's `wn`/`wnd`)
and amy (marmot-kmp), each with what MDK made of it. `MarmotAppEventVectorTest` checks them on
every build, with no other client running.

- `mdk-<version>-sent.json`: rumors White Noise sent. The test reads each through marmot-kmp's API
  and must reach MDK's answer (THEIRS → US).
- `ours-read-by-mdk-<version>.json`: rumors marmot-kmp's builders sent (through amy), with what
  White Noise made of them (OURS → THEM). The test also rebuilds each one from the same inputs, so
  a change in what we send fails until this generator has run again and White Noise has read the
  new shape.

## Running it

Everything is local: one relay (`amy serve`) on 127.0.0.2, one loopback Blossom, one `wnd`. Before
the first message the group's media policy is moved to that Blossom, so nothing is uploaded
anywhere else.

```bash
./gradlew :marmot:jvmJar                       # the builders under test
WN_BIN_DIR=/path/to/mdk/target/release \       # wn + wnd of the MDK release in MDK_VERSION
AMY=/path/to/amethyst/cli/build/install/amy/bin/amy \
BLOSSOM_PY=/path/to/amethyst/cli/tests/marmot/blossom-server.py \
MDK_VERSION=0.19.0 \
marmot/tools/app-event-vector-gen/gen.sh
./gradlew :marmot:jvmTest --tests '*MarmotAppEventVectorTest'
```

Build amy with `./gradlew :cli:installDist` in Amethyst. `gen.sh` compiles `Inject.kt` with the
`kotlin-compiler-embeddable` of amy's Kotlin version from the Gradle cache (or `KOTLINC_JARS`)
against amy's runtime classpath, with `MARMOT_JAR` (default `marmot/build/libs/marmot-jvm.jar`)
first, so every OURS rumor is built by this checkout's marmot-kmp and sent from amy's account.
`OUT_DIR` and `WORK` override where the vectors and the run's scratch files go. A run takes about
a minute and a half.

## What a run does

1. White Noise creates the group, invites amy and makes it an admin; amy points the media policy
   at the loopback Blossom.
2. THEIRS, through `wn` verbs: text, a `nostr:npub` mention, an `@npub` mention, a reply, `+`,
   `-` and emoji reactions, an edit, an unreact, an admin's removal of its own message (MDK sends
   kind 4891, not 5, from an admin) and an encrypted image.
3. OURS, through `Inject.kt` (marmot-kmp's builders, or a hand-shaped rumor where no builder makes
   that shape): text, a mention with and without its `p` tag, replies by `q` (our builder), by `e`
   only, by both naming different messages, and by a `q` naming an address; `+`, `-`, emoji and
   NIP-30 custom-emoji reactions; an edit of our own message and of theirs; a kind 5 of our own
   message, of our reaction and of theirs; an admin removal; single and multiple choice polls; a
   valid vote on each, a vote for a missing option and two options on a single-choice poll; an
   image (`amy marmot media send`) and the same `imeta` with a `blurhash` field.
4. White Noise steps down as admin and deletes its own message, which is then a kind 5.
5. Capture: every rumor amy holds, `wn messages timeline list` (MDK's materialized timeline),
   `wn media list`, and whether each side decrypted the other's image. `build_vectors.py` writes
   the files.

## Format

One file per sender. Both carry the whole recorded `conversation` (every rumor, so effects can be
decided the way a client holding all of it decides them), the `members` and the `admins` at the
time of each 4891, and `cases`, one per step:

```json
{
  "name": "reply-q-and-e-differ",
  "source": "hand-shaped (no builder makes it), sent by amy",
  "builder": {"op": "raw", "kind": 9, "tags": [["e", "…"], ["q", "…"]], "content": "…"},
  "rumor": {"id": "…", "pubkey": "…", "created_at": 0, "kind": 9, "tags": [], "content": "…"},
  "context": ["ids of the conversation's events the rumor names"],
  "mdk": {"basis": "observed", "row": true, "reply_to_message_id": "…", "…": "what wn printed"},
  "expect": {"row": true, "reply_to": "…", "mentions": [], "media": []}
}
```

`expect` uses these keys, by kind:

| kind | keys |
|---|---|
| 9 chat | `row`, `reply_to`, `mentions` (sorted pubkeys), `media` (`url`, `mime`, `filename`, `dim`, `thumbhash`, hashes, `nonce`) |
| 1068 poll | `row`, `reply_to`, `poll` (`question`, `type`, `options`, `ends_at`) |
| 7 reaction | `row`, `reaction` (`target`, `emoji`, `custom_emoji_url`), `counted` (still on the target at the end) |
| 1009 edit | `row`, `edit` (`target`, `content`), `applied` (the edit the target shows) |
| 5 deletion | `row`, `deletes`, `applied` (the targets it removed) |
| 4891 removal | `row`, `removes`, `applied` |
| 1018 vote | `row`, `vote` (`poll`, `options`, `valid`, `counted`: the voter's vote at the end) |

`expect` is MDK's decision. Where wn prints it (rows, reply targets, reactions, edits, deletions,
removals, accepted attachments) it is what wn printed (`"basis": "observed"`). wn 0.19 prints no
mention classification, poll projection or tally, so those follow MDK's source, cited in the case
(`marmot-app` `notifications.rs` `message_text_mentions_account`; `cgka-traits` `polls.rs`;
`storage-sqlite` `timeline.rs` `effective_poll_votes`), as `build_vectors.py` implements them.

## Where marmot-kmp and MDK differ

None in these vectors. Known gaps the vectors do not reach: MDK reads message text as Markdown and
skips entities inside code spans when it looks for inline mentions, and
`MarmotMessageReferences.mentions` does not.
