# Device groups: interop with White Noise's linked devices, then linking our own (2026-11-21)

MDK turned device groups on by default (`136811c7`, #3519, shipped in 0.18.0 `34646a57`). Every White Noise build
now links devices, keeps a hidden per-account device group, adds siblings to chats with private KeyPackages and
advertises `0x800e` in its KeyPackages. This plan says what Amethyst and marmot-kmp need to (1) keep working with
White Noise accounts that have linked devices and (2) let an Amethyst device and a White Noise device be one linked
account.

## Baselines

| Thing | Head read |
|---|---|
| Spec `marmot-protocol/marmot` | `04fbdf8` (#512, version-3 sibling Welcome), on top of `71a388f` (#511, post-link chat inventory). The device-group documents are **drafts**: their encodings can change under the same ids. |
| MDK | `origin/master` `bf4778a3` (0.19.0-dev); 0.18.0 is `34646a57`. The 0.18.0 upgrade guide (`docs/integration/0.18.0.md`, "Device groups on by default") is the summary of what changed for hosts. |
| marmot-kmp | `origin/main` `7f0139e` (2.4.1). Builds against quartz 2.20.0, mls-kmp 1.4.1. |
| Previous review | `2026-11-18-mdk-0.17-resync.md`: `0x800d` rules, one Commit removes every leaf of an account, invite every device, `0x800f` entries carried as unknown data, pairing kinds 452-456 dropped by Amethyst. All done. |

Spec documents read: `features/device-group.md`, `features/device-pairing.md`, `features/account-sync.md` (sections
the device group cites), `app-components/device-roster-v1.md`, `device-tag-v1.md`, `account-devices-v1.md`,
`foundation/key-packages.md` ("Devices and publication slots", "Selection and lifecycle"), `foundation/registries.md`,
`foundation/canonical-encoding.md`, `changes.md` back to 2026-11-05.

## What a White Noise account with linked devices looks like from outside

- Each linked device publishes its own KeyPackage slot (kind 30443, its own `d`), so inviters still see one slot per
  device and still select every fresh one (`foundation/key-packages.md` "Selection and lifecycle": SHOULD select
  every valid fresh candidate, at most 20). Nothing about inviting changed.
- Each device's leaves and KeyPackages carry a `0x800f` device tag (opaque bytes to other accounts) and advertise
  `0x800d`, `0x800e`, `0x800f`.
- In a chat that requires `0x800d`, siblings add each other with **same-account Adds** of private KeyPackages and
  remove a gone sibling's leaves with **same-account Removes**. The Welcome of such an Add travels inside the device
  group (kind 461), not as a kind 444.
- A device that signs out through its siblings is removed by a sibling's same-account Remove instead of its own
  SelfRemove.
- A non-last admin's Leave is an admin-policy step-down then a SelfRemove.
- A White Noise device never puts its **own** account's published KeyPackages in a founding Add or a later Add
  (device-group.md "Private sibling Add admission", "Creating a chat"). It adds only siblings in its device group.

The consequence for a user who runs Amethyst and White Noise with the same key, without linking them: chats a White
Noise device of that account creates, and chats it is added to by a sibling, never include the Amethyst device. Chats
other accounts invite the account into still include every device. That is the reason for P1.

## Table

Status columns: **lib** = marmot-kmp, **app** = Amethyst (commons/commonsUI/amethyst/cli). "done" means verified in
code or by a test named in the 0.17 review.

### P0: interop breaks without it

| # | Behaviour | Spec / MDK | lib | app | Where |
|---|---|---|---|---|---|
| 0.1 | Same-account Adds and Removes in `0x800d` chats are valid from a non-admin; at most 20 leaves per account; same-account Commits score `ordinary`. | `account-devices-v1.md`; MDK `cgka-engine/src/own_account_devices.rs`, vectors `account-devices-*.v1.json` | done (0.17 #1) | n/a | lib |
| 0.2 | Leaves and KeyPackages with a `0x800f` entry are never rejected; a GroupContext that **requires** `0x800f` is rejected. | `device-tag-v1.md` "Registry", "Validity" | done (0.17 #5; rejection because we do not advertise `0x800f`) | n/a | lib. Must stay true once we advertise `0x800f` (P1 3.4): then add an explicit rule. |
| 0.3 | Groups that require `0x800e` are never joined except through a confirmed link. | `device-group.md` "Trust" | done implicitly: our KeyPackages do not advertise `0x800e`, so the engine refuses the Welcome. | n/a | lib. Becomes an explicit trust gate before we advertise `0x800e` (P1 1.6). |
| 0.4 | **Device-group app-event kinds (457 heartbeat, 458 gap-fill claim, 459/460 private KeyPackage request/hand-off, 461 sibling Welcome, 473 history delivery, 475/476 small state, 477 chat inventory) are ignored in any group but the trusted device group.** No chat projects one; a host does not send one as a custom event. | `device-group.md` "Surfaces", each kind's "Receiving"; `registries.md`; MDK `marmot-app/src/client/device_group/messages.rs:57` `is_device_group_kind` | **done this branch** (`aa73032`): ingest returns `Ignored` without persisting; `buildGroupMessage` refuses them. Was: every decrypted inner event stored and surfaced. | Amethyst indexes whatever `MarmotIngestResult.Message` carries, so nothing more to do. | lib. app: nothing once the library drops them; never offer these kinds to `sendCustomEvent`-style paths. |
| 0.5 | A Welcome rumor that names a sibling's KeyPackage (every device of the account gets one gift wrap per added KeyPackage) is "not addressed to this device", not a failure. | `protocol-core/joining.md` "Delivery"; MDK `5e25d953` | partial: terminal, but reported as `MarmotIngestResult.Failure` ("No matching KeyPackageBundle"). | logs a WARN per sibling Welcome. | lib: cosmetic, kept P2 (a new `WelcomeResult` subtype is source-breaking for exhaustive `when`s). |
| 0.6 | Removing an account removes every leaf; members and counts are per account. | `member-departure.md` | done (0.17 #2) | done (`37e15bcc42`) | — |
| 0.7 | Admin Leave as step-down then SelfRemove is accepted. | `member-departure.md` "Behavior" (marmot#502) | done (0.17 #5) | n/a | — |
| 0.8 | Live check with `wn` 0.18+: a linked White Noise pair in a chat Amethyst creates and in one it joins. | — | — | — | coordinator, see "Live test". |

### P1: an Amethyst device links with the account's other devices

Ordered by dependency. Every row is library work unless the Where column says app.

| # | Behaviour | Spec / MDK | lib | Where |
|---|---|---|---|---|
| 1.1 | `marmot.account.device-roster.v1` (`0x800e`): state and update codecs (canonical), validation, apply-a-diff, sorted ops, the never-added / never-removed requirement, one account per device group. | `device-roster-v1.md` (with byte vectors); MDK `traits/src/app_components/device_roster.rs:45-505` | **done**: codec (`b0812eb`); requirement rules in `DeviceRosterRules` via `MarmotGroupPolicy` (never added or dropped after creation, valid roster while required, one credential identity, no `0x800f` requirement anywhere), refusals tested by reason | lib |
| 1.2 | **AppDataUpdate diff semantics for `0x800e`.** Members apply the update as a diff to the parent's roster, not as a replacement. | `device-roster-v1.md` "Update" | **done**: mls-kmp `MlsGroupPolicy.resolveAppDataUpdate` (wt/appdata-update-hook `a859377`, unreleased); `MarmotGroupPolicy` applies the roster diff only while the parent requires `0x800e` | **mls-kmp**: a policy hook `resolveAppDataUpdate(componentId, parentBytes?, updateBytes): ByteArray` (identity by default) called there and wherever GroupContext extensions are recomputed for staging. marmot-kmp then plugs `DeviceRosterV1.applyUpdate`. Without it our device-group commits and MDK's diverge on the GroupContext and the device group forks. |
| 1.3 | `marmot.member.device-tag.v1` (`0x800f`): seal (ChaCha20-Poly1305 under `leaf_tag_key`, aad = leaf signature key), sign (`SignWithLabel "Marmot DeviceTag"`), open and verify against a roster (device, removed slot, unclaimed). | `device-tag-v1.md` (vectors); MDK `traits/src/app_components/device_tag.rs`, `cgka-engine/src/device_tag.rs`, `roster_tag_keys.rs` | **this branch**: `DeviceTagV1` codec, `produce`, `read`, vectors. | lib |
| 1.4 | Produce tags: every KeyPackage and every own LeafNode carries a tag once the device can tag; advertise `0x800f`; never require it. | `device-tag-v1.md` "Producing tags" | **done**: published KeyPackages (rotation manager hook), private KeyPackages, the creator leaf of chats and of the device group, and the new device's first-Commit leaf carry the tag once the device can tag. Not yet: retagging an older untagged chat leaf through a later UpdatePath (a SHOULD) | lib (`CurrentProfileGroupFactory`, `MlsGroupManager`) |
| 1.5 | Device pairing (kinds 452-456): strict JSON messages, commitment, SAS (seven emoji, Matrix table), MACs, the two state machines (first answer wins, one decision, confirm order, competing requests, 10 answers/hour, 600 s expiries, cancel semantics). Transport-neutral; secrets in memory only. | `device-pairing.md` (two vectors); MDK `crates/marmot-pairing` (all of it), `testdata/pairing-v1.json` | **this branch**: messages, derivations, emoji table, both sessions, spec + MDK vectors. | lib |
| 1.6 | Pairing over Nostr: rumor from the account to itself, NIP-59 gift wrap to own inbox relays; drop own Confirm echoes. | `transports/nostr.md` "Pairing delivery"; MDK `transport-nostr-adapter` `pairing` | **this branch**: `PairingDelivery.wrap/unwrap` | lib done; app: which relays (own 10050), subscribe to own wraps; today Amethyst drops 452-456 in `MarmotDevicePairing`: route them to `PairingDelivery.unwrap` instead |
| 1.7 | Device-group trust store: the trusted group id (set on create or on joining the link's Welcome only), the pending link record (session, `KeyPackageRef`, group id, sender signature key, wait end), reserved group id and KeyPackage, 600 s wait. Explicit local reset. | `device-group.md` "Trust", "Joining", "Explicit local reset" | **done** (lib): `DeviceGroupTrust` v1 (now also unlinked flag, linked ref, removal decisions, heartbeat times, removed slots, first-check slots, own rejections), stores, `DeviceGroupLinkJoinPolicy`; `resetLocalCopy` (explicit local reset) | lib (interface + in-memory), app (persisted, encrypted store). **New persisted format.** |
| 1.8 | Create the device group on approve (founding Add of exactly the confirmed KeyPackage, roster with both entries, account as sole admin, `0x800d` + `0x800e` required); or one Commit adding the confirmed KeyPackage and its `set_device`. Link made on the new device's first Commit; failed after 3600 s and undone with `remove_device`. | "Creating the device group", "Approving", "A link that is not taken up" | **done** (lib, in-process): create/approve/first Commit, link made; `checkLinkDeadlines` fails a link 3600 s after `linked_at` and undoes it (leaf + `remove_device`); the new device tells a failed link from an unlink | lib (`MarmotDeviceGroupManager`) |
| 1.9 | New device: join only the link's Welcome (group, signer leaf key, KeyPackage, `0x800e`), first Commit sets `tag_signature_key` and tags its leaf. | "Joining", "Matching leaves to devices" | **done** (lib, in-process): `joinLinkWelcome` (link's group id, signer leaf key, KeyPackage, `0x800e`, 600 s wait) and `stageFirstCommit` (tag key + tagged UpdatePath leaf) | lib |
| 1.10 | Slot announcements: announce `announced_key_package` in the roster before every publish; do not publish unannounced. | "Slot announcements" | **done** as API: `announcementNeeded` / `stageAnnouncement`. The app calls them before publishing a KeyPackage; publishing is not gated inside the library yet | lib (`KeyPackageRotationManager` gate) |
| 1.11 | Private KeyPackages: issue (tagged, not last-resort, stock 5→10, cap ≥300), request (459) / hand-off (460) codecs and rules, consume only through a sibling Welcome. | "Private KeyPackages"; MDK `cgka-engine/src/private_key_packages.rs`, `marmot-app/src/client/private_key_packages.rs` | **done**: issue (tagged, not last-resort, stock 5→10, cap 300), 459 answered once per event id, 460 accepted only whole and tagged as the sender's, used refs kept to `not_after`; `PrivateKeyPackageStore` v1 | lib. **New persisted format** (issued and held private KeyPackages with their owners). |
| 1.12 | Sibling Welcome (461) v1/v2/v3: codec, send after the Add is canonical, receive checks (trusted group, `to`, `from` in roster, sender tag, KeyPackage issued to `from`), repair after heartbeat. v3 forwarded `inviter`/`confirmed`. | "Sibling Welcomes" (#512) | **done**: v3 (confirmed copy, no generation: this client keeps none) sent after the Add; received only from a tagged roster device for a KeyPackage issued to it, joining with that bundle. Forwarded `inviter`/`confirmed` are read but not presented (Amethyst has no pending-invitation state). Repair (resend after heartbeat) not done | lib |
| 1.13 | Adding the new device to chats (approver) and filling a missing chat (gap-fill claim 458: canonical JSON, 600 s, lowest slot wins), creating a chat with siblings' private KeyPackages, never with own published ones. | "Adding the new device to chats", "Filling a missing chat", "Creating a chat" | **done**: `createChat` includes siblings' private KeyPackages (never published own ones: `addMemberInvites` refuses own-account invites in device-group mode), `addNewDeviceToChats` (approver), `fillMissingChats` (claim first, lowest live claimant adds) | lib |
| 1.14 | Heartbeats (457 `{"v":1}`, hourly, tagged leaf only), last activity. | "Heartbeats"; MDK `device_heartbeats.rs` | **done**: `heartbeatDue`/`heartbeatSent`, counted only from a tagged leaf, last activity per roster entry. Inactive marking (30/90 days) not done | lib |
| 1.15 | Post-link chat inventory (477): tokens, pages of 128, revision. Optional. | "Post-link chat inventory" (#511) | **done**: approver `chatInventory`, new device `remainingExpectedChats` | lib; app shows "N chats left" |
| 1.16 | Remove a device (one Commit: remove leaf + `remove_device` + `set_rejected_slot removed`), delete its slot (kind 5), siblings remove its chat leaves (same-account Remove), delete exchanged private KeyPackages; the removed device's unlinked flow. | "Removing a device", "On the removed device" | **done**: `stageRemoveDevice` (leaf + `remove_device` + `removed` record), `removeGoneDevicesFromChats` (same-account Remove), private KeyPackages of gone slots dropped, the removed device marks itself unlinked and discards its copy; `expireRemovedRecords` (30 days). Slot deletion (kind 5) is the app's | lib; app: Devices screen "Remove", "This device was unlinked" notice |
| 1.17 | Sign out through siblings (`leaving`) or on its own. | "Signing out" | **done** through siblings: `stageSignOut` (`leaving`) and `pendingDepartures`. Signing out on its own is the app's existing leave path | lib; app: sign-out path calls it |
| 1.18 | New sign-ins: complete checks of own slots, first-check classification, Link / Not now / This wasn't me (`not_me`), warning; a KeyPackage in our own slot we did not make. | "New sign-ins", "Rejections" | **done** as classification: `recordFirstCheck`, `classifySignIns` (own, linked, rejected, removed incl. after the record expires per MDK 2d509151, already signed in, new), `rejectSignIn` (`not_me`). Reading the account's publications and the warning UI are the app's | lib (classification, store interface), app (prompts, warning). **New persisted format** (sign-in list, answers). |
| 1.19 | Devices screen: list, rename (`rename_id`), the three settings, client/platform. | "Devices", "Labels, clients and platforms" | missing | app (UI, strings), lib (roster edits) |

### P2

| # | Behaviour | Where |
|---|---|---|
| 2.1 | Account sync: small-state updates/broadcast requests (475/476), invitation decisions by admission generation, history deliveries (473, Blossom), backups and the recovery key. White Noise's linked devices use these to agree on accepted/declined invitations and to bring history. Without them a linked Amethyst device asks its user about each invitation itself. | lib + app |
| 2.2 | Inactive devices (30/90 days), moves between device groups, a previously-linked-slot context, compromise warning details. | lib + app |
| 2.3 | `WelcomeResult` "not addressed to this device" (row 0.5). | lib (next major or an `Ignored` reason) |

## Library vs app split

**marmot-kmp** (everything another Marmot client would need to agree with us): the two component codecs and their
receiver rules, the pairing protocol and its Nostr rumors, the device-group app-event codecs and rules, the trust,
link, private-KeyPackage, sign-in and removal state machines, and the **store interfaces** with in-memory versions:
`DeviceGroupTrustStore` (trusted group, pending link, removal decisions, unlinked marker), `PrivateKeyPackageStore`,
`SiblingWelcomeStore` (retained bodies for repair), `SignInStore`, `RosterTagKeyStore` (keys kept 30 days).

**Amethyst**: encrypted-at-rest implementations of those stores, which relays pairing traffic uses, the Devices
screen (link with seven emoji and their descriptions as `commonsUI` strings, rename, settings, remove), the sign-in
prompt and warning, the "unlinked" notice, notification suppression for the device group, `amy devices list|link|remove`
verbs (thin over the library), and keeping the device group out of `marmotGroupList`.

## Persisted formats (API)

**New in this branch, both unreleased (version 1 may still change before the first release):**

- `DeviceGroupTrust` v1 (`features/deviceGroup/DeviceGroupTrust.kt`), Marmot binary profile, in order:
  `uint8 version = 1; opaque own_slot[32]; optional<opaque<V>> trusted_mls_group_id;
  optional<opaque<V>> trusted_nostr_group_id; optional<opaque<V>> tag_signing_seed;
  optional<PendingLinkV1> pending_link; optional<opaque<V>> linked_key_package_ref; uint8 unlinked;
  ApprovalV1 approvals<V>; SlotTime removal_decisions<V>; uint64 last_heartbeat_sent;
  ActivityV1 activity<V>; SlotTime removed_slots<V>; optional<SlotId first_check_slots<V>>;
  SlotTime own_rejections<V>`, with `PendingLinkV1 = session, key_package_event, key_package_ref,
  device_group_id, welcome_sender_key, existing_device_slot (each opaque<V>), uint64 wait_until`,
  `ApprovalV1 = opaque slot[32]; uint64 linked_at; uint8 outcome (0 pending, 1 made, 2 failed);
  opaque leaf_signature_key<V>`, `SlotTime = opaque slot[32]; uint64 time`,
  `ActivityV1 = opaque slot[32]; uint64 linked_at; uint64 last_activity`. Holds the tag signing seed:
  encrypt at rest.
- `PrivateKeyPackages` v1 (`features/deviceGroup/PrivateKeyPackages.kt`): `uint8 version = 1;
  IssuedV1 issued<V>; HeldV1 held<V>; RefV1 used<V>; opaque answered_request_id[32]<V>`, with
  `IssuedV1 = opaque to_slot[32]; opaque ref<V>; uint64 not_before; uint64 not_after; uint64 handed_at;
  opaque bundle<V>` (mls-kmp `KeyPackageBundleCodec`, private keys), `HeldV1 = opaque from_slot[32];
  opaque ref<V>; uint64 not_before; uint64 not_after; opaque key_package_mls_message<V>`,
  `RefV1 = opaque ref<V>; uint64 not_after`. Holds private keys: encrypt at rest.
- Kept in memory only, by design or for now: the founding device's material between its Confirm and
  the founding Add (a restart abandons that link), live gap-fill claims (the spec allows forgetting
  them), and the post-link inventory pages (a lost inventory only hides progress).


Nothing in this branch changes a store's bytes: the new code is codecs and in-memory state machines. The pairing
sessions keep their secrets in memory only, as the spec requires. These will be new persisted formats when they land,
and each needs a versioned encoding from the start: the pending link record (1.7), trusted-group id and removal
decisions (1.7, 1.16), issued/held private KeyPackages (1.11), retained sibling Welcome bodies (1.12), sign-in list and
answers (1.18), kept tag keys (1.3 cleanup). The `0x800e` roster and `0x800f` tag bytes are group state, frozen by the
spec vectors imported here.

## Library dependencies

- **mls-kmp** (blocks 1.8 onward): AppDataUpdate diff resolution hook (1.2). Probably also an accessor for a leaf's
  `leaf_node_source` (sibling Welcome repair checks `update`/`commit` vs `key_package`) — check before asking.
- **quartz**: none found. NIP-59 self-addressed gift wraps, kind 5 `a`-tag deletions and NIP-44 v2 extended length are
  already there (the 0.17 review relied on them).

## Live test (for the coordinator once Amethyst is wired)

With `wn`/`wnd` at `bf4778a3` (`cli/tests/marmot/state/mdk/target/release`) against `amy serve`:

1. P0, today: `wnd` twice with one nsec (A1, A2); `wn devices link` on A2, compare the seven emoji on A1, link. B is
   `amy`. `amy group create` with A's npub: both A1 and A2 get Welcomes (B invites every slot). A1 and A2 read B's
   message; B reads both. A2 sends; B sees one member A, not two. `amy group remove A`: one Commit removes both
   leaves; both A devices leave the chat. Repeat with A1 creating the chat and inviting B: A2 is added by A1's
   same-account Add after B joined; B must accept that Commit (non-admin, `0x800d`) and keep decrypting.
2. P0: grep `amy`'s stored messages for kinds 457-477: none.
3. P1, once wired: `amy devices link` as the new device against A1, then as the approving device for a fresh `wnd`.

## Done on this branch (`wt/device-groups`)

| Commit | What |
|---|---|
| `49a2c9d` | This plan. |
| `aa73032` | P0 0.4: device-group kinds ignored in chats, never sent to one. |
| `b0812eb` | 1.1: `DeviceRosterV1` codec, validation, diff apply; spec vectors + MDK invariant tests. |
| `3e582c1` | 1.3: `DeviceTagV1` produce/open/read; spec vector byte-exact. |
| `5bea577` | 1.5: pairing messages, derivations, emoji table, both state machines; MDK `pairing-v1.json` through both. |
| `a817aa7` | Codecs of 457, 458, 459, 460, 461 v1-v3, 477 (token vector). |
| `8709ffe` | 1.6 (library half): pairing over NIP-59 self-addressed gift wraps. |

Nothing here is wired into `MarmotManager` yet, and no KeyPackage advertises `0x800e`/`0x800f`, so
behaviour towards White Noise is unchanged except row 0.4.

## Second pass (on top of the table above)

| Repo | Commit | What |
|---|---|---|
| mls-kmp `wt/appdata-update-hook` | `a859377` | `MlsGroupPolicy.resolveAppDataUpdate` (identity default), applied for local, inbound and external commits; ABI dump; guide row. |
| marmot-kmp | `26b415c` | Roster diff and requirement rules in the policy; `DeviceGroupTrust` + store; `DeviceGroupLinkJoinPolicy`; `MarmotDeviceGroupManager`; `DeviceGroupLinkTest` (pairing over gift wraps, founding Add, link Welcome, first Commit, roster bytes equal on both devices, tags read on both). |

**The switch:** `MarmotManager(…, deviceGroupConfig = MarmotDeviceGroupConfig(trustStore,
privateKeyPackageStore, relays))`. Null, the default, keeps device groups off: `supportedComponents`
unchanged, every device-group app event ignored. Set, `MarmotManager.deviceGroups` runs everything above
and every KeyPackage and leaf advertises `0x800e`/`0x800f` (tagged once the device can tag).

(Earlier note:) The flag: `0x800e`/`0x800f` are OFF by default. `SUPPORTED_COMPONENTS` (what KeyPackages and leaves
advertise unless told otherwise) is unchanged; only callers that pass
`DEVICE_GROUP_SUPPORTED_COMPONENTS` advertise them, and nothing in the library or Amethyst does yet.

## Next library steps, in order

1. mls-kmp hook for AppDataUpdate resolution (1.2), released.
2. `MarmotGroupPolicy`: the `0x800e` requirement rules (never added or removed after creation, one
   credential identity, roster valid after every Commit, no `remove`), and the explicit "no group
   requires `0x800f`" rule. Only then advertise `0x800e`/`0x800f` and tag KeyPackages/leaves (1.4).
3. `DeviceGroupTrustStore` + `MarmotDeviceGroupManager`: create/approve/join (1.7-1.9) with an
   in-process end-to-end test: pairing over `PairingDelivery`, the founding Add, the new device's
   tagging first Commit, link made. MDK's `cgka-engine/tests/account_devices/link_device.rs` and
   `device_group_welcome.rs` are the cases to port.
4. Slot announcements (1.10), private KeyPackages + sibling Welcomes (1.11-1.12), gap filling and
   chat creation with siblings (1.13), heartbeats (1.14), removal and sign-out (1.16-1.17), sign-ins
   (1.18).

## Fourth pass: closing the library gaps

| Gap | Now | Where |
|---|---|---|
| Device-group Commits outside the publish gate and convergence | **done**. Every device-group Commit is published by `MarmotManager.commitAndPublish` (publish-before-apply, obligations) and inbound ones go through `MarmotManager.ingest` like any group's, so a fork settles by the same branch selection. MDK does the same: the device group runs through the one CGKA engine and is only hidden from the host (`marmot-app/src/client/device_group.rs` `host_may_see_group` ~L197), and a roster update is `privileged` because it is admin-required (`cgka-engine/src/commit_class.rs` `priority` ~L61-70, `convergence.rs` `tip_priority_str` ~L149), which `MarmotCommitClass` already scores. The device group is tracked, subscribed and gated like a chat (`MarmotManager.adoptCreatedDeviceGroup`/`adoptJoinedDeviceGroup`); its founding Add uses the empty-obligation exception; the new device's Welcome goes as a kind 444 to the account itself and `ingest` routes a Welcome naming the link's KeyPackage to `joinLinkWelcome`. `deviceGroups.refresh()` runs after every ingested group event. Test: `aForkedDeviceGroupSettlesOnOneBranchOnBothDevices`. | lib |
| App events from older epochs | **done**: sender claims are recorded per epoch (last 16) and an app event of an older epoch whose secrets the device still holds reads its sender from them; heartbeats stay current-epoch only, as the spec says. Duplicates are dropped by `processGroupEvent` as for chats. Claims are memory only: after a restart, events older than the first epoch seen since are dropped. Test: `anOlderEpochsDeviceGroupMessageStillReadsItsSender`. | lib |
| Account sync (473/475/476) | **done for small state**: `InvitationGeneration` (spec vector), the 475/476 codecs, merge rules for `read`/`pin`/`mute`/`archive`/`invite`, `AccountSyncStore` v1. Generations are recorded at every join and founding (post-founding context), inherited through version-2 sibling Welcomes, never derived from a sibling Add; a founder holds an implicit accept. `recordLeave` records a decline before the user's Leave; a winning decline for a copy's generation makes its siblings leave and holds automatic sibling Adds. Broadcast on start (with a request), daily, and once an hour in answer. **Not done**: resending items of a withdrawn update (MAY send everything again; a daily broadcast covers it), history (473: keys, bundles, deliveries via Blossom) and backups (recovery key, archives, pointer). This client has no pending-invitation state, so accepts are only retained and forwarded. Tests: `AccountSyncTest`, `aDeclineOnOneDeviceTakesTheOtherOutOfThatInvitation`, `settingsAndReadPositionsReachTheSiblingAndARequestGetsABroadcast`. | lib; app owns read/pin/mute/archive values |
| Sibling Welcome repair | **done**: sent bodies retained to the private KeyPackage's `not_after` (`PrivateKeyPackages.repairs`), resent in a fresh carrier once the target's last activity is 600 s past the carrier, unless the chat tree shows its leaf past `key_package`. Simplification: the carrier time is when it was built, not when a relay first accepted it. Test: `aLostSiblingWelcomeIsSentAgainAfterTheTargetRuns`. | lib |
| Inactive marking | **done, simplified**: 30 days without activity (or since `linked_at`) marks `inactive`, 90 removes (no decision, no slot deletion), own entry back to `active` after a heartbeat. The spec's "caught up" clocks (paused while behind, reset after a 24 h gap) are not modelled. | lib |
| Re-tagging old leaves | **done**: `retagOwnLeaves` self-updates each chat whose own leaf reads untagged; the app spreads the calls out. Test: `oldLeavesAreRetaggedAndQuietSiblingsGoInactiveThenOut`. | lib |
| Moves between device groups | **not done (big)**: a second pending link while trusting a group, Made with its atomic trust switch, carrying `not_me`/`removed` records, `moved` status and the old siblings' cleanup, old-group work isolation. Until then a device that trusts a group refuses to pair as a new device; the user resets (`resetLocalCopy`) and links fresh. | lib |

**Persisted formats added this pass (unreleased, version 1):**
- `AccountSyncState` v1 (`features/accountSync/AccountSync.kt`): `uint8 version = 1; opaque
  item_json<V> items<V>; Generation generations<V>; uint64 last_broadcast; uint64
  last_request_answered`, `Generation = opaque mls_group_id<V>; opaque generation[32]`; each item is its
  canonical 475 item object as UTF-8 JSON.
- `PrivateKeyPackages` v1 gains `RepairV1 repairs<V>`, `RepairV1 = opaque to_slot[32]; opaque
  chat_nostr_id<V>; opaque ref<V>; uint64 not_after; uint64 published_at; opaque content<V>`.

## Ready for default-on?

Not yet, but close. What is left is bounded and listed above: moves, history deliveries and backups,
the "caught up" inactivity clocks, persisted per-epoch claims, and the withdrawn-update resend. None of
it is needed for interop with White Noise's linking, chats, sibling adds and invitation decisions, so
the switch can go on for real users once Amethyst wires the checklist in the report and a live test
with `wn` passes; a default-on release should wait for history deliveries (a newly linked device
otherwise shows chats without their history) and moves.

## Third pass: what flipping the switch still needs

Library, before an app turns `deviceGroupConfig` on for users:

- Device-group Commits go through `MarmotDeviceGroupManager`'s staging, not `MarmotManager`'s
  publish gate and convergence engine: inbound device-group Commits must be routed to
  `deviceGroups.processCommit` (today `MarmotManager.ingest` treats them like any group's), and a fork
  of the device group is not resolved by convergence yet.
- Device-group app events are accepted only from the epoch the receiver holds (the spec reads the
  sender's tag in the epoch the message was sent in); older ones are dropped.
- Sibling Welcome repair (resend after a heartbeat), inactive marking (30/90 days), moves between
  device groups, account sync (475/476/473: invitation decisions, history) and retagging old untagged
  chat leaves are not done. Without account sync a linked device answers invitations on its own.
- Publishing a KeyPackage is not gated on its announcement inside the library: the app must call
  `announcementNeeded`/`stageAnnouncement` first.

So the library is ready for an opt-in, test-account rollout behind the switch, not for a default-on
release.

## Fifth pass: rebase onto the stream retirement, MDK 0.19.0, and the first live link (2026-11-22)

Rebased onto `753239d` (agent text stream retired). The device group is built through
`MarmotGroupState.buildDictionary`, which refuses `0x8006`, so it never includes it; the
leaf-component `createGroup` overload lost its unused `agentTextStream` input. Ingest checks the
trusted device group first, then the retired kind 1200, then device-group kinds elsewhere.

MDK `bf4778a3`..0.19.0 (`3fce9546`), device-group changes:

| MDK | What | Here |
|---|---|---|
| `0b223879` (mdk#3594) | A withdrawn device-group commit owes the small state again | **ported**: `onDeviceGroupRewound`, called when convergence rewinds the trusted device group, queues every item on `drainOutbox` |
| `2346c6a8` | One check decides whether maintenance runs (unlinked, sign-out held, frozen) | scheduling, no wire change: the app's tick skips the passes once `trust().unlinked` |
| `ff5320a8`, `f170e0cc` | Stream retirement | already `753239d` |
| `470d4b4d`, `0e22bcd5` | Due times; sender-side Welcome audit rows | before `bf4778a3`; scheduling and local audit only, skipped |
| `46d29b19`, `1ad676ac` | Tagged local sends, draft attachments | not device groups |

Spec #511/#512 were already in (rows 1.12, 1.15).

**Interop fix found live against `wn devices link`:** MDK takes a link as made only when the new
device's first Commit sets `tag_signature_key` to the signature key of the leaf the link added
(`marmot-app` `device_pairing/live.rs` `link_verdict`), and finds a device's pre-link leaves by that
key. The spec only says "each device makes its own tag signature key pair". With a fresh pair the
White Noise approver kept the link `linking` and never added the Amethyst device to its chats. The
new device now uses the confirmed KeyPackage's leaf key as its tag key (`linkTagSeed`). Our own
approver still accepts any key, as the spec allows.

## Sixth pass: own roster fields, renames, relay moves and history deliveries (2026-11-23)

| Gap | Now |
|---|---|
| 1.19 labels, clients, platforms | **done**: `MarmotDeviceGroupConfig.client`/`platform` go in this device's founding entry, its first Commit, its slot announcements and `stageOwnEntryRefresh` (only its own entry); `approve(…, ownLabel)` names the founding entry; `stageRename(slot, label)` writes the label and a fresh `rename_id`, every other field kept. Not done: the user-edit recovery (kept written/replaced `rename_id`s re-applied after a lost fork); a rename that loses a fork is lost and the user renames again. |
| The device group's relays | **done**: `relayProvider` is read when the group is founded (an app whose lists load late no longer founds it on its defaults); `stageRelays` moves the routing of an existing one, `nostr_group_id` kept. |
| History deliveries (473) | **done, inline**: history keys derived from the tag signing seed (labelled HKDF, then HPKE `DeriveKeyPair`; no store layout change), written in the founding entry, the first Commit and own-entry updates. A same-account Add whose publication succeeded owes the chat's history; `historyDeliveries(now)` seals each bundle (ChaCha20-Poly1305, zero nonce) to the sibling's key, at most 8 inline bundles, newest kept. Receiving checks the exact encoding, `to`, `from` = the sending tag, opens `sealed`, checks the hash, imports events it does not hold (`persistDecryptedMessage`) and reports them (`drainImportedHistory`); a delivery for a chat not held yet is kept until its sibling Welcome joins. Blossom: received through an app's `historyBlobFetcher`; never sent. Not done: attachment keys and moderation grants (both optional, not sent), owed histories and kept deliveries across a restart (memory only), re-owing a withdrawn delivery. Tests: `DeviceGroupHistoryTest`. |

## Seventh pass: the gaps after the sixth (2026-11-23)

| Gap | Now |
|---|---|
| A rename that loses a fork | **done**: `stageRename` keeps the edit (`DeviceGroupWork.KeptEdit`: the label, the `rename_id`s it wrote and the ones it replaced, from before its Commit goes out); `stageEditRecovery` reads its standing while the device group is `Stable` (`MarmotManager.lifecycle`) and makes it again with a fresh `rename_id` when the roster holds a replaced id, keeps it when it holds a written one, and drops it when another edit stands or the device left. Label-only: this client makes no settings edits, so recovery never invents settings. A rename to the label the roster already shows cancels a lost edit. Tests: `aRenameWhoseCommitWasLostIsMadeAgain`, `aRenameThatLosesARealForkComesBack`. |
| Owed histories and kept deliveries across a restart | **done**: `DeviceGroupWork` v1 (below) in a new `DeviceGroupWorkStore` (`MarmotDeviceGroupConfig.workStore`, in memory by default): owed histories, deliveries waiting for their chat or blob (their exact 473 content and the bundle key and hash they opened to; a fetched blob is fetched again), kept edits, imported attachment keys. Test: `owedHistoriesAndKeptDeliveriesSurviveARestart`, frozen bytes in `theWorkRecordRoundTripsAndKeepsItsLayout`. |
| History through Blossom | **done**: `historyBlobUploader` (the app's BUD-02 upload to its own servers, the account's kind 10063 in Amethyst). A history that fits `MAX_HISTORY_BUNDLES` inline bundles goes inline; a longer one goes as up to 8 bundles of up to 8 MiB through Blossom, each delivery naming the servers that took its blob; an upload that fails leaves the history owed. `HistoryBundles.split` now sizes bundles incrementally (it re-encoded the whole bundle per event, quadratic at 8 MiB). Receiving was already in (`historyBlobFetcher`). Test: `aLongHistoryGoesThroughBlossomAndImports`. |
| The app hears of imported history before it is stored | **done** (2026-11-24): `beforeHistoryImport(nostrGroupId, events)` runs with a bundle's fresh events before any of them is stored, so an app writes down durably that they are read (Amethyst: no notification, sound or badge for old messages) before a process death could restore them as unread. A throw refuses the bundle: nothing stored or drained, the delivery kept (with its ciphertext) for the next `importKeptHistory` pass until it expires. Tests: `theImportHookSeesTheFreshEventsBeforeTheStoreHoldsAnyOfThem`, `aThrowingImportHookLeavesTheStoreUntouchedAndTheDeliveryKept`. |
| Attachment keys and moderation grants | **done**, as `account-sync.md` "History bundles" defines them. Sending: each event's `grant` is the verdict this device recorded for a 1985 or 4891 (`MarmotManager.moderationVerdict`), and `keys` hold the `file_key` of each `encrypted-media-v2` reference, derived from the media secret of the event's epoch (`EncryptedMediaV2.fileKeyOf`) or an imported key it holds. Receiving: a key naming none of the event's references is dropped alone; kept keys go in `DeviceGroupWork` and `MarmotManager.mediaCipherForMessage` opens a file with one (`EncryptedMediaV2Cipher.withFileKey`) when the epoch's secret is not held; a `grant` becomes the event's recorded verdict before it is stored (`recordImportedModerationVerdict`; a verdict already held wins). Test: `historyCarriesAttachmentKeysAndModerationGrants`. |
| Moves between device groups | **done**, as `device-group.md` "Moving between device groups" defines them. A linked device pairs again as the new device; `joinLinkWelcome` records the destination (`DeviceGroupTrust.move`: its ids, the destination tag seed, the link's ref) without changing trust; `stageFirstCommit` targets the destination; once the roster there lists this device with its tag key and the destination is `Stable`, `refresh` makes the move in one trust write: destination ids and seed, the old roster's rejected slots to carry, the group left (`movedFrom`); owed histories and kept edits of the old group are dropped (old-group work). `stageMoveFollowUp` then imports the carried `not_me`/`removed` records the destination neither lists as a device nor rejects, and commits the old entry as `moved` in the old group (every other field kept), discarding the old copy once `moved` stands or that branch no longer includes it. An old sibling's `stageMovedCleanup` removes a `moved` device's leaf and entry in one Commit, with no rejection, no chat removal and no slot deletion. Removed from the destination before Made: the move failed and the original trust stays. While moving, the device answers no pairing Request and `approve` refuses. `isOwnDeviceGroup` hides the destination, the group left and any group carrying a roster. Not done: the old-sibling "guidance" hints and the suppression of Link/This wasn't me questions about old siblings (UI hints, no protocol effect). Tests: `aDeviceMovesToAnotherDeviceGroup`, `aMoveTheDestinationUndoesLeavesTheOriginalTrust`. |

**Persisted formats added or changed this pass:**

- `DeviceGroupTrust` **version 2**: version 1's fields, then `optional<MoveV1> move; optional<MovedFromV1>
  moved_from; CarriedV1 carried<V>`, with `MoveV1 = opaque group_id<V>; opaque nostr_group_id<V>; opaque
  tag_signing_seed<V>; opaque linked_key_package_ref<V>`, `MovedFromV1 = opaque group_id<V>; opaque
  nostr_group_id<V>`, `CarriedV1 = opaque slot[32]; uint8 reason; uint64 rejected_at; optional<opaque<V>>
  tag_signature_key`. A record with no move fields is still written as version 1, so a library that reads
  only version 1 keeps reading it; version 1 still decodes.
- `DeviceGroupWork` version 1 (`features/deviceGroup/DeviceGroupWork.kt`): `uint8 version = 1; OwedV1 owed<V>;
  KeptV1 kept<V>; EditV1 edits<V>; KeyV1 keys<V>`, with `OwedV1 = opaque chat<V>; opaque slot[32]; uint64
  owed_at`, `KeptV1 = opaque content<V>; opaque key[32]; opaque ciphertext_sha256[32]; uint64 read_at`,
  `EditV1 = opaque slot[32]; opaque label<V>; optional<uint32> settings; opaque written<V>; opaque
  replaced<V>` (runs of 16-byte `rename_id`s), `KeyV1 = opaque chat<V>; opaque ciphertext_sha256[32]; opaque
  file_key[32]`. Holds bundle and attachment keys: encrypt at rest.
