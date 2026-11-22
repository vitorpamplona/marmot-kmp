/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.marmot.client

import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.appComponents.LegacyAgentTextStreamGroup
import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamQuicPolicyV1
import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamRoles
import com.vitorpamplona.marmot.foundation.appEvents.MarmotAppEvent
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.groups.currentGroupState
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import com.vitorpamplona.quartz.utils.TimeUtils
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The retirement of the agent text stream over QUIC
 * (`app-components/agent-text-stream-quic-v1.md`, "Retirement"; MDK 0.19.0),
 * through the app layer.
 *
 * Every client that implemented it put `0x8006` into each group it created,
 * so the groups these tests build are the ones an older build left behind:
 * they must keep loading, admitting members, renaming and validating Commits,
 * while nothing new is streamed, created or shown.
 */
class MarmotAgentTextStreamRetirementTest {
    private val nostrGroupId = "c".repeat(64)

    private class Device(
        keyPair: KeyPair = KeyPair(),
    ) {
        val signer = NostrSignerInternal(keyPair)
        val mlsStore = SnapshotStateStore()
        val messageStore = SnapshotMessageStore()
        val manager = MarmotManager(signer, mlsStore, messageStore, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)

        fun group(nostrGroupId: HexKey) = manager.groupManager.getGroup(nostrGroupId)!!

        /** A copy of this device's group under [policy], to build or receive bytes without touching the manager. */
        fun copy(
            nostrGroupId: HexKey,
            policy: MlsGroupPolicy = MarmotGroupPolicy,
        ) = MlsGroup.restore(group(nostrGroupId).saveState(), policy)
    }

    /** Marmot's rules minus the sender-side refusals, as an older or hostile client would send. */
    private object Unchecked : MlsGroupPolicy by MarmotGroupPolicy {
        override fun authorizeCommit(
            group: GroupView,
            proposals: List<PendingProposal>,
            committerLeafIndex: Int,
        ) = Unit

        override fun validateResultingState(
            parentExtensions: List<Extension>,
            proposals: List<PendingProposal>,
            committerLeafIndex: Int,
            resulting: GroupView,
        ) = Unit
    }

    private val default = AgentTextStreamQuicPolicyV1.userToAgentDefault()

    private fun policy(
        required: Int = AgentTextStreamRoles.RECEIVE,
        allowed: Int = AgentTextStreamRoles.RECEIVE or AgentTextStreamRoles.SEND,
        frame: Long = 4096,
    ) = AgentTextStreamQuicPolicyV1(required, allowed, frame, 0, 0)

    /**
     * Alice's store holds a group an older build created with `0x8006`; she
     * restores it and adds Bob, who joins it through the Welcome.
     */
    private suspend fun legacyGroup(
        alice: Device,
        bob: Device,
    ) {
        val legacy =
            LegacyAgentTextStreamGroup.create(
                signer = alice.signer,
                nostrGroupId = nostrGroupId.hexToByteArray(),
                relays = listOf("wss://relay.invalid"),
                profile = GroupProfileV1("legacy", ""),
            )
        alice.mlsStore.save(nostrGroupId, legacy.saveState().encodeTls())
        alice.manager.restoreAll()

        val (_, welcomes) = alice.manager.addMembers(nostrGroupId, listOf(bob.manager.generateKeyPackageEvent(relays = emptyList())), emptyList())
        assertIs<MarmotIngestResult.JoinedGroup>(bob.manager.ingest(welcomes.single().giftWrapEvent))
    }

    private fun Device.requires0x8006() = group(nostrGroupId).currentGroupState().requires(AgentTextStreamQuicPolicyV1.COMPONENT_ID)

    @Test
    fun aLegacyGroupLoadsAdmitsAMemberAndKeeps0x8006ThroughARename() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            legacyGroup(alice, bob)
            for (device in listOf(alice, bob)) {
                assertTrue(device.requires0x8006())
                assertEquals(default, device.group(nostrGroupId).currentGroupState().agentTextStream)
            }

            val rename = alice.manager.setGroupProfile(nostrGroupId, "renamed", "")
            assertIs<MarmotIngestResult.Commit>(bob.manager.ingest(rename.signedEvent))
            for (device in listOf(alice, bob)) {
                val state = device.group(nostrGroupId).currentGroupState()
                assertEquals("renamed", state.profile?.name)
                assertTrue(state.requires(AgentTextStreamQuicPolicyV1.COMPONENT_ID), "a rename keeps 0x8006 required")
                assertEquals(default, state.agentTextStream, "a rename keeps 0x8006 state")
            }

            // And it survives a restart.
            val restarted = MarmotManager(alice.signer, alice.mlsStore, alice.messageStore, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
            restarted.restoreAll()
            assertEquals(
                default,
                restarted.groupManager
                    .getGroup(nostrGroupId)!!
                    .currentGroupState()
                    .agentTextStream,
            )
        }

    @Test
    fun weNeverReplaceOrAdd0x8006State() =
        runBlocking<Unit> {
            val alice = Device()
            legacyGroup(alice, Device())
            assertFailsWith<IllegalArgumentException> {
                alice.manager.groupManager.stageAppDataUpdate(nostrGroupId, AgentTextStreamQuicPolicyV1.COMPONENT_ID, policy(frame = 8192).encode())
            }

            val fresh = Device()
            fresh.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"), GroupProfileV1("new", ""))
            val required = ComponentsList.supportedOrRequired(fresh.group(nostrGroupId).appDataDictionary())
            assertFailsWith<IllegalArgumentException> {
                fresh.manager.groupManager.stageAppDataUpdate(
                    nostrGroupId,
                    ComponentsList.APP_COMPONENTS_ID,
                    ComponentsList.encode(required + AgentTextStreamQuicPolicyV1.COMPONENT_ID),
                )
            }
        }

    /** "They do not change which Commits are valid": an older admin's valid update is accepted. */
    @Test
    fun aValidLegacyUpdateFromAnAdminIsAccepted() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            legacyGroup(alice, bob)

            val older = alice.copy(nostrGroupId)
            older.proposeAppDataUpdate(AgentTextStreamQuicPolicyV1.COMPONENT_ID, policy(frame = 8192).encode())
            val commit = older.commit()

            val received = bob.copy(nostrGroupId)
            received.processFramedCommit(commit.framedCommitBytes)
            assertEquals(older.epoch, received.epoch)
            assertEquals(policy(frame = 8192), received.currentGroupState().agentTextStream)
        }

    @Test
    fun anInvalidLegacyUpdateIsRefused() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            legacyGroup(alice, bob)
            val invalid =
                listOf(
                    // required is not a subset of allowed
                    "020100001000000000000000",
                    // frame length over 65519
                    "01030000fff0000000000000",
                    // not 12 bytes
                    "0103000010000000000000",
                )
            for (hex in invalid) {
                val older = alice.copy(nostrGroupId, Unchecked)
                older.proposeAppDataUpdate(AgentTextStreamQuicPolicyV1.COMPONENT_ID, hex.hexToByteArray())
                val commit = older.commit()

                val received = bob.copy(nostrGroupId)
                val epoch = received.epoch
                assertFailsWith<Exception>(hex) { received.processFramedCommit(commit.framedCommitBytes) }
                assertEquals(epoch, received.epoch)
            }
        }

    @Test
    fun aNonAdminsLegacyUpdateIsRefused() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            legacyGroup(alice, bob)

            val older = bob.copy(nostrGroupId, Unchecked)
            older.proposeAppDataUpdate(AgentTextStreamQuicPolicyV1.COMPONENT_ID, policy(frame = 8192).encode())
            val commit = older.commit()

            val received = alice.copy(nostrGroupId)
            val epoch = received.epoch
            assertFailsWith<IllegalStateException> { received.processFramedCommit(commit.framedCommitBytes) }
            assertEquals(epoch, received.epoch)
        }

    private fun Device.rumor(
        kind: Int,
        content: String,
        tags: Array<Array<String>> = emptyArray(),
    ): Event = RumorAssembler.assembleRumor(signer.pubKey, Event.build(kind, content, TimeUtils.now()) { tags.forEach { add(it) } })

    @Test
    fun weNeverSendAStreamStartOrAStreamTaggedKind9() =
        runBlocking<Unit> {
            val alice = Device()
            legacyGroup(alice, Device())
            assertFailsWith<IllegalArgumentException> {
                alice.manager.buildGroupMessage(nostrGroupId, alice.rumor(1200, "", arrayOf(arrayOf("stream", "ab".repeat(32)))))
            }
            for (tag in listOf("stream", "stream-start", "stream-hash", "stream-chunks")) {
                assertFailsWith<IllegalArgumentException>(tag) {
                    alice.manager.buildGroupMessage(nostrGroupId, alice.rumor(9, "final", arrayOf(arrayOf(tag, "00"))))
                }
            }
        }

    /** An older client's traffic, built below the send gate this client applies to itself. */
    private suspend fun Device.olderClientSends(event: Event) = manager.outboundProcessor.buildGroupEventFromBytes(nostrGroupId, MarmotAppEvent.fromEvent(event).encodeToPayload()).signedEvent

    @Test
    fun aReceivedStreamStartIsNotShownAndATaggedKind9IsOrdinaryChat() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            legacyGroup(alice, bob)
            val streamId = "ab".repeat(32)

            val start = alice.rumor(1200, "", arrayOf(arrayOf("stream", streamId), arrayOf("route", "quic"), arrayOf("broker", "quic://127.0.0.1:4433")))
            val ignored = assertIs<MarmotIngestResult.Ignored>(bob.manager.ingest(alice.olderClientSends(start)))
            assertEquals("retired agent text stream start", ignored.reason)

            val final =
                alice.rumor(
                    9,
                    "the whole answer",
                    arrayOf(arrayOf("stream", streamId), arrayOf("stream-hash", "cd".repeat(32)), arrayOf("stream-chunks", "3")),
                )
            assertIs<MarmotIngestResult.Message>(bob.manager.ingest(alice.olderClientSends(final)))

            val stored = bob.manager.loadStoredMessages(nostrGroupId).mapNotNull { Event.fromJsonOrNull(it) }
            assertTrue(stored.none { it.kind == 1200 }, "a stream start is not kept for display")
            val shown = stored.single { it.id == final.id }
            assertEquals("the whole answer", shown.content)
            assertTrue(MarmotAppEvent.isTimelineRow(shown.kind, shown.pubKey, bob.signer.pubKey))
        }
}
