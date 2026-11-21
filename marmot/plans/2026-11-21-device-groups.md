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
| 1.4 | Produce tags: every KeyPackage and every own LeafNode carries a tag once the device can tag; advertise `0x800f`; never require it. | `device-tag-v1.md` "Producing tags" | partial: the creator's founding leaf and the new device's first-Commit leaf are tagged (`MarmotDeviceGroupManager`); KeyPackages are not tagged yet; `0x800e`/`0x800f` advertised only through the opt-in `CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS` (default OFF) | lib (`CurrentProfileGroupFactory`, `MlsGroupManager`) |
| 1.5 | Device pairing (kinds 452-456): strict JSON messages, commitment, SAS (seven emoji, Matrix table), MACs, the two state machines (first answer wins, one decision, confirm order, competing requests, 10 answers/hour, 600 s expiries, cancel semantics). Transport-neutral; secrets in memory only. | `device-pairing.md` (two vectors); MDK `crates/marmot-pairing` (all of it), `testdata/pairing-v1.json` | **this branch**: messages, derivations, emoji table, both sessions, spec + MDK vectors. | lib |
| 1.6 | Pairing over Nostr: rumor from the account to itself, NIP-59 gift wrap to own inbox relays; drop own Confirm echoes. | `transports/nostr.md` "Pairing delivery"; MDK `transport-nostr-adapter` `pairing` | **this branch**: `PairingDelivery.wrap/unwrap` | lib done; app: which relays (own 10050), subscribe to own wraps; today Amethyst drops 452-456 in `MarmotDevicePairing`: route them to `PairingDelivery.unwrap` instead |
| 1.7 | Device-group trust store: the trusted group id (set on create or on joining the link's Welcome only), the pending link record (session, `KeyPackageRef`, group id, sender signature key, wait end), reserved group id and KeyPackage, 600 s wait. Explicit local reset. | `device-group.md` "Trust", "Joining", "Explicit local reset" | **done** (lib): `DeviceGroupTrust` (versioned codec), `DeviceGroupTrustStore`, `InMemoryDeviceGroupTrustStore`; the link-only join is `DeviceGroupLinkJoinPolicy`, and `MarmotGroupPolicy.validateJoin` refuses every other `0x800e` Welcome. Explicit local reset: missing | lib (interface + in-memory), app (persisted, encrypted store). **New persisted format.** |
| 1.8 | Create the device group on approve (founding Add of exactly the confirmed KeyPackage, roster with both entries, account as sole admin, `0x800d` + `0x800e` required); or one Commit adding the confirmed KeyPackage and its `set_device`. Link made on the new device's first Commit; failed after 3600 s and undone with `remove_device`. | "Creating the device group", "Approving", "A link that is not taken up" | **done** (lib, in-process): `MarmotDeviceGroupManager.confirmTarget/approve/applyStaged/processCommit`; link made on the new device's first Commit. The 3600 s failure and its undo: missing | lib (`MarmotDeviceGroupManager`) |
| 1.9 | New device: join only the link's Welcome (group, signer leaf key, KeyPackage, `0x800e`), first Commit sets `tag_signature_key` and tags its leaf. | "Joining", "Matching leaves to devices" | **done** (lib, in-process): `joinLinkWelcome` (link's group id, signer leaf key, KeyPackage, `0x800e`, 600 s wait) and `stageFirstCommit` (tag key + tagged UpdatePath leaf) | lib |
| 1.10 | Slot announcements: announce `announced_key_package` in the roster before every publish; do not publish unannounced. | "Slot announcements" | missing | lib (`KeyPackageRotationManager` gate) |
| 1.11 | Private KeyPackages: issue (tagged, not last-resort, stock 5→10, cap ≥300), request (459) / hand-off (460) codecs and rules, consume only through a sibling Welcome. | "Private KeyPackages"; MDK `cgka-engine/src/private_key_packages.rs`, `marmot-app/src/client/private_key_packages.rs` | codecs **this branch**; stock/rules missing | lib. **New persisted format** (issued and held private KeyPackages with their owners). |
| 1.12 | Sibling Welcome (461) v1/v2/v3: codec, send after the Add is canonical, receive checks (trusted group, `to`, `from` in roster, sender tag, KeyPackage issued to `from`), repair after heartbeat. v3 forwarded `inviter`/`confirmed`. | "Sibling Welcomes" (#512) | codec **this branch**; flows missing | lib |
| 1.13 | Adding the new device to chats (approver) and filling a missing chat (gap-fill claim 458: canonical JSON, 600 s, lowest slot wins), creating a chat with siblings' private KeyPackages, never with own published ones. | "Adding the new device to chats", "Filling a missing chat", "Creating a chat" | claim codec **this branch**; flows missing. `KeyPackageUtils.selectAllForInvite` must exclude the own account once a device group is trusted. | lib |
| 1.14 | Heartbeats (457 `{"v":1}`, hourly, tagged leaf only), last activity. | "Heartbeats"; MDK `device_heartbeats.rs` | codec **this branch** | lib |
| 1.15 | Post-link chat inventory (477): tokens, pages of 128, revision. Optional. | "Post-link chat inventory" (#511) | token + content codec **this branch** | lib; app shows "N chats left" |
| 1.16 | Remove a device (one Commit: remove leaf + `remove_device` + `set_rejected_slot removed`), delete its slot (kind 5), siblings remove its chat leaves (same-account Remove), delete exchanged private KeyPackages; the removed device's unlinked flow. | "Removing a device", "On the removed device" | missing | lib; app: Devices screen "Remove", "This device was unlinked" notice |
| 1.17 | Sign out through siblings (`leaving`) or on its own. | "Signing out" | missing | lib; app: sign-out path calls it |
| 1.18 | New sign-ins: complete checks of own slots, first-check classification, Link / Not now / This wasn't me (`not_me`), warning; a KeyPackage in our own slot we did not make. | "New sign-ins", "Rejections" | missing | lib (classification, store interface), app (prompts, warning). **New persisted format** (sign-in list, answers). |
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

**New in this branch: `DeviceGroupTrust`, version 1** (`features/deviceGroup/DeviceGroupTrust.kt`), the
one store this work adds. Marmot binary profile: `uint8 version = 1; opaque own_slot[32];
optional<opaque<V>> trusted_mls_group_id; optional<opaque<V>> trusted_nostr_group_id;
optional<opaque<V>> tag_signing_seed; optional<PendingLinkV1> pending_link; ApprovalV1 approvals<V>`, where
`PendingLinkV1 = session, key_package_event, key_package_ref, device_group_id, welcome_sender_key,
existing_device_slot (each opaque<V>), uint64 wait_until` and `ApprovalV1 = opaque slot[32]; uint64
linked_at; uint8 outcome (0 pending, 1 made, 2 failed)`. It holds the tag signing seed: an app's store
MUST encrypt it at rest. A change to its layout is a new version byte, never an edit of version 1. The
founding device's pre-creation material (group id, leaf key, roster key) between its Confirm and the
founding Add is memory only, so a restart there abandons the link (the new device's 600 s wait ends it).


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

The flag: `0x800e`/`0x800f` are OFF by default. `SUPPORTED_COMPONENTS` (what KeyPackages and leaves
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
