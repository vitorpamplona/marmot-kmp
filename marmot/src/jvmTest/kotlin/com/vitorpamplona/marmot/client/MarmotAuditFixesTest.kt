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

import com.vitorpamplona.marmot.GroupEventResult
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.groups.MarmotMessageStore
import com.vitorpamplona.quartz.marmot.mip03GroupMessages.GroupEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** The library audit's confirming cases for the inbound pipeline around [MarmotManager]. */
class MarmotAuditFixesTest {
    private val nostrGroupId = "5".repeat(64)

    private class Member(
        val messageStore: MarmotMessageStore = SnapshotMessageStore(),
        val stateStore: SnapshotStateStore = SnapshotStateStore(),
    ) {
        val signer = NostrSignerInternal(KeyPair())
        val manager = MarmotManager(signer, stateStore, messageStore, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
        val seen = mutableListOf<Pair<Event, MarmotIngestResult>>()

        fun receiver() = MarmotReceiver(manager) { event, result -> seen += event to result }

        suspend fun keyPackage() = manager.generateKeyPackageEvent(relays = emptyList())
    }

    private suspend fun Member.createGroup() = manager.createCurrentProfileGroup(nostrGroupId = nostrGroupId, relays = listOf("wss://relay.invalid"), profile = GroupProfileV1("audit", ""))

    @Test
    fun `a commit that arrives before the proposal it names applies once the proposal lands`() =
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

            val carolLeaves = carol.manager.leaveGroup(nostrGroupId).signedEvent
            val aliceReceiver = alice.receiver()
            assertIs<MarmotIngestResult.ProposalStaged>(aliceReceiver.receive(carolLeaves))
            val commit = aliceReceiver.commitStagedProposals().getValue(nostrGroupId).signedEvent

            // Bob's relay hands him the commit first.
            val receiver = bob.receiver()
            val early = receiver.receive(commit)
            assertIs<MarmotIngestResult.Failure>(early)
            assertEquals(1, receiver.pendingCount(nostrGroupId), "the commit is held, not dropped")

            assertIs<MarmotIngestResult.ProposalStaged>(receiver.receive(carolLeaves))
            assertEquals(0, receiver.pendingCount(nostrGroupId))
            assertIs<MarmotIngestResult.Commit>(bob.seen.last().second, "the held commit applies once its proposal is staged")
            assertEquals(2, bob.manager.memberCount(nostrGroupId))
        }

    @Test
    fun `two copies of one message processed at once are delivered once`() =
        runBlocking<Unit> {
            repeat(20) { round ->
                val alice = Member()
                val bob = Member()
                alice.createGroup()
                val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
                bob.manager.ingest(bobWelcome!!.giftWrapEvent)
                val message =
                    alice.manager
                        .buildTextMessage(nostrGroupId, "once $round")
                        .outbound.signedEvent as GroupEvent

                val results =
                    (1..2)
                        .map { async(Dispatchers.Default) { bob.manager.inboundProcessor.processGroupEvent(message) } }
                        .awaitAll()

                assertEquals(1, results.count { it is GroupEventResult.ApplicationMessage }, "round $round: $results")
                assertEquals(1, results.count { it is GroupEventResult.Duplicate }, "round $round: $results")
            }
        }

    /** Counts whole-log reads, to show a restart no longer makes one per group. */
    private class CountingMessageStore(
        private val inner: SnapshotMessageStore = SnapshotMessageStore(),
    ) : MarmotMessageStore by inner {
        var logReads = 0
        var expiryReads = 0
        private val newest = mutableMapOf<String, Long>()

        override suspend fun loadExpiries(nostrGroupId: String): Map<String, Long> {
            expiryReads++
            return inner.loadExpiries(nostrGroupId)
        }

        override suspend fun appendMessage(
            nostrGroupId: String,
            innerEventJson: String,
        ) {
            inner.appendMessage(nostrGroupId, innerEventJson)
            Event.fromJsonOrNull(innerEventJson)?.let { newest[nostrGroupId] = maxOf(newest[nostrGroupId] ?: 0L, it.createdAt) }
        }

        override suspend fun loadMessages(nostrGroupId: String): List<String> {
            logReads++
            return inner.loadMessages(nostrGroupId)
        }

        override suspend fun newestMessageCreatedAt(nostrGroupId: String): Long? = newest[nostrGroupId]
    }

    @Test
    fun `a restart takes each group's newest message time from the store without reading its log`() =
        runBlocking<Unit> {
            val alice = Member()
            val bobMessages = CountingMessageStore()
            val bob = Member(bobMessages)
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            bob.manager.ingest(bobWelcome!!.giftWrapEvent)
            assertIs<MarmotIngestResult.Message>(
                bob.manager.ingest(
                    alice.manager
                        .buildTextMessage(nostrGroupId, "hello")
                        .outbound.signedEvent,
                ),
            )
            bob.manager.groupManager.flushReceivedState()

            val restarted = MarmotManager(bob.signer, bob.stateStore, bobMessages, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
            bobMessages.logReads = 0
            restarted.restoreAll()
            assertEquals(0, bobMessages.logReads)
            assertTrue(restarted.subscriptionManager.activeGroupFilters().any { it.since != null }, "the group's subscription resumes from its newest message")
        }

    @Test
    fun `a batch of messages reads the group's expiry table once, not once per message`() =
        runBlocking<Unit> {
            val alice = Member()
            val bobMessages = CountingMessageStore()
            val bob = Member(bobMessages)
            alice.createGroup()
            val (_, bobWelcome) = alice.manager.addMember(nostrGroupId, bob.keyPackage(), emptyList())
            bob.manager.ingest(bobWelcome!!.giftWrapEvent)
            val messages =
                (1..10).map {
                    alice.manager
                        .buildTextMessage(nostrGroupId, "m$it")
                        .outbound.signedEvent
                }

            bobMessages.expiryReads = 0
            messages.forEach { assertIs<MarmotIngestResult.Message>(bob.manager.ingest(it)) }
            assertEquals(1, bobMessages.expiryReads)
        }
}
