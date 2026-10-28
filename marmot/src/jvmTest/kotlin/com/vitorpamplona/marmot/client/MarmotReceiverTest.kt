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
import com.vitorpamplona.marmot.foundation.appEvents.MarmotAppEvent
import com.vitorpamplona.quartz.marmot.mip02Welcome.WelcomeEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip59Giftwrap.wraps.GiftWrapEvent
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The reactions both front ends owe what they receive, in one place: Amethyst's live
 * subscription and amy's catch-up each kept their own copy, and the copies drifted.
 */
class MarmotReceiverTest {
    private val nostrGroupId = "2".repeat(64)

    private class Member {
        val signer = NostrSignerInternal(KeyPair())
        val messageStore = SnapshotMessageStore()
        val manager = MarmotManager(signer, SnapshotStateStore(), messageStore, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
        val seen = mutableListOf<Pair<Event, MarmotIngestResult>>()

        fun receiver(maxPendingPerGroup: Int = MarmotReceiver.DEFAULT_MAX_PENDING_PER_GROUP) = MarmotReceiver(manager, maxPendingPerGroup) { event, result -> seen += event to result }

        suspend fun keyPackage() = manager.generateKeyPackageEvent(relays = emptyList())

        suspend fun systemRows(groupId: String) = manager.loadStoredMessages(groupId).mapNotNull { Event.fromJsonOrNull(it) }.filter { it.kind == MarmotAppEvent.KIND_SYSTEM }
    }

    private suspend fun Member.createGroup() = manager.createCurrentProfileGroup(nostrGroupId = nostrGroupId, relays = listOf("wss://relay.invalid"), profile = GroupProfileV1("receiver", ""))

    @Test
    fun `a message ahead of its commit opens once the commit lands`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            bob.manager.ingest(bobWelcome!!.giftWrapEvent)

            val (addCarol, _) = alice.manager.addMember(nostrGroupId, Member().keyPackage(), emptyList())
            val message =
                alice.manager
                    .buildTextMessage(nostrGroupId, "sent after Carol joined")
                    .outbound.signedEvent

            val receiver = bob.receiver()
            // The relay hands Bob the message before the commit it was sent after.
            assertIs<MarmotIngestResult.UndecryptableOuter>(receiver.receive(message))
            assertEquals(1, receiver.pendingCount(nostrGroupId))

            assertIs<MarmotIngestResult.Commit>(receiver.receive(addCarol!!.signedEvent))

            assertEquals(0, receiver.pendingCount(nostrGroupId))
            val replayed = bob.seen.last()
            assertEquals(message.id, replayed.first.id)
            assertIs<MarmotIngestResult.Message>(replayed.second, "the held message must open after the commit")
        }

    @Test
    fun `the hold is bounded and drops the oldest`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            bob.manager.ingest(bobWelcome!!.giftWrapEvent)

            val (addCarol, _) = alice.manager.addMember(nostrGroupId, Member().keyPackage(), emptyList())
            val first =
                alice.manager
                    .buildTextMessage(nostrGroupId, "one")
                    .outbound.signedEvent
            val second =
                alice.manager
                    .buildTextMessage(nostrGroupId, "two")
                    .outbound.signedEvent

            val receiver = bob.receiver(maxPendingPerGroup = 1)
            receiver.receive(first)
            receiver.receive(second)
            receiver.receive(second) // a relay re-delivering it is not a second entry
            assertEquals(1, receiver.pendingCount(nostrGroupId))

            receiver.receive(addCarol!!.signedEvent)

            val opened = bob.seen.filter { it.second is MarmotIngestResult.Message }.map { it.first.id }
            assertEquals(listOf(second.id), opened)
        }

    @Test
    fun `two departures in one batch go out in one commit`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            val carol = Member()
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            bob.manager.ingest(bobWelcome!!.giftWrapEvent)
            val (addCarol, carolWelcome) = alice.manager.addMember(nostrGroupId, carol.keyPackage(), emptyList())
            bob.manager.ingest(addCarol!!.signedEvent)
            carol.manager.ingest(carolWelcome!!.giftWrapEvent)

            // Both leave at the same epoch. Committing Bob's before Carol's proposal is applied
            // would move the group past the epoch Carol's was sent in, and she would never leave.
            val bobLeaves = bob.manager.leaveGroup(nostrGroupId).signedEvent
            val carolLeaves = carol.manager.leaveGroup(nostrGroupId).signedEvent

            val receiver = alice.receiver()
            assertIs<MarmotIngestResult.ProposalStaged>(receiver.receive(bobLeaves))
            assertIs<MarmotIngestResult.ProposalStaged>(receiver.receive(carolLeaves))
            assertTrue(receiver.hasStagedProposals())

            assertEquals(setOf(nostrGroupId), receiver.commitStagedProposals().keys)
            assertEquals(1, alice.manager.memberCount(nostrGroupId))
            assertTrue(receiver.commitStagedProposals().isEmpty(), "nothing is left staged")
        }

    @Test
    fun `a non-admin stages a departure and leaves it for an admin`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            val carol = Member()
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            bob.manager.ingest(bobWelcome!!.giftWrapEvent)
            val (addCarol, carolWelcome) = alice.manager.addMember(nostrGroupId, carol.keyPackage(), emptyList())
            bob.manager.ingest(addCarol!!.signedEvent)
            carol.manager.ingest(carolWelcome!!.giftWrapEvent)

            val receiver = bob.receiver()
            receiver.receive(carol.manager.leaveGroup(nostrGroupId).signedEvent)

            assertTrue(receiver.commitStagedProposals().isEmpty(), "bob is not an admin")
            assertEquals(3, bob.manager.memberCount(nostrGroupId))
        }

    @Test
    fun `a welcome unwrapped by the client still shows the first change after joining`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            val rumor = (bobWelcome!!.giftWrapEvent as GiftWrapEvent).unwrapAndUnsealOrNull(bob.signer)
            assertIs<MarmotIngestResult.JoinedGroup>(bob.manager.ingestWelcome(assertIs<WelcomeEvent>(rumor)))
            assertIs<MarmotIngestResult.Ignored>(bob.manager.ingestWelcome(rumor), "a replayed Welcome is done")

            val (addCarol, _) = alice.manager.addMember(nostrGroupId, Member().keyPackage(), emptyList())
            bob.manager.ingest(addCarol!!.signedEvent)

            // Joining must set the baseline. Without it the commit that added Carol became the
            // baseline instead, and Bob's timeline never said that she joined.
            assertEquals(1, bob.systemRows(nostrGroupId).size)
        }
}
