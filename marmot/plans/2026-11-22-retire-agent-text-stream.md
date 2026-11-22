# Retire the agent text stream over QUIC (2026-11-22)

The spec retired `marmot.group.agent-text-stream.quic.v1` and its raw QUIC binding in
marmot-protocol/marmot #513 (with #514 and #515, SC-086), and MDK followed in 0.19.0
(`f170e0cc` "Remove the retired QUIC agent text stream", `ff5320a8` "Stop creating and
advertising the retired agent text stream"). The normative text is
`app-components/agent-text-stream-quic-v1.md`, "Retirement", which overrides the rest of that
document. This change follows it and MDK, and goes no further.

## Removed

- The `marmot-quic` module (raw QUIC transport, broker and direct interop tests) and its quic-kmp
  dependency, CI steps and release module.
- In `marmot`: the record codec, crypto, transcript, publisher, subscriber, `QuicVarInt`, the QUIC
  binding and stream transport, `MarmotAgentStreamWatcher`, `MarmotManager.buildAgentStreamStart`,
  `buildAgentStreamFinal`, `agentTextStreamCrypto`, `MlsGroup.agentTextStreamSecret`, and the
  `agentTextStream` parameter of `CurrentProfileGroupFactory.createGroup` and
  `MarmotGroupState.buildDictionary`. This removes public API: the next release is a major (3.0.0).

## What clients stop doing, and where

- New groups never include `0x8006` (`protocol-core/group-setup.md`): the factory cannot add it,
  and `buildDictionary` refuses it in `extraRequiredComponents`.
- No update replaces `0x8006` state and nothing adds it to the required `app_components`:
  `MlsGroupManager.stageAppDataUpdate` refuses both. Removal stays possible, but nothing commits it
  on its own ("A client MUST NOT commit this removal unless its user asks it to").
- No kind 1200 and no `stream`/`stream-start`/`stream-hash`/`stream-chunks` tag on a kind 9 we
  send: `MarmotOutboundProcessor.buildAppEvent` refuses them (`AgentTextStreamRetirement`), so a
  send queued before an upgrade fails at drain instead of publishing, as in MDK.
- No candidate in a kind 1200 is ever contacted: there is no QUIC code left.

## Receiving from older clients

- A received kind 1200 ingests as `MarmotIngestResult.Ignored("retired agent text stream start")`,
  is not persisted and never reaches a front end. It stays in `NON_TIMELINE_KINDS` for any that an
  older build stored.
- A kind 9 with stream tags is an ordinary chat message: nothing reads those tags.

## Kept, and why

- Support for `0x8006` in `SUPPORTED_COMPONENTS` and the `receive` role `0xF2D1` in the leaf
  capabilities ("A client SHOULD keep advertising support for this component and the `receive`
  role capability"). `send` and `fanout` were already not advertised.
- `AgentTextStreamQuicPolicyV1` and `AgentTextStreamRoles`: the 12-byte state is decoded and
  validated when read, on every Commit applied (`MarmotGroupPolicy.validateResultingState`,
  new here: before, an invalid update from an older client was accepted; MDK validates the same
  bytes on every update) and at join, where the `required_member_roles` check runs. As in MDK, the
  member-role check is not added to received Commits.
- Existing groups keep `0x8006` through every commit that carries the dictionary forward (renames,
  member changes, activations).
- `AgentTextStreamRetirement` holds the reserved identifiers: component id and name, kind 1200,
  the exporter label and context, both ALPNs; the role extension types and names stay in
  `AgentTextStreamRoles`.

## Vectors

`marmot/tools/mdk-vector-gen` creates no `0x8006` group, so no vector changes.
