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
import com.vitorpamplona.marmot.groups.MlsGroupStateStore
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.relay.normalizer.NormalizedRelayUrl
import com.vitorpamplona.quartz.nip01Core.relay.normalizer.RelayUrlNormalizer
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Convergence across restarts (`protocol-core/durability.md`, "Restart equivalence").
 *
 * Two members commit from the same epoch, and each only hears of the other's Commit in a LATER
 * process, the way `amy` runs every command. A restart must not change what the group converges
 * on: the retained window a fork is resolved over has to be as durable as the group state.
 */
class MarmotConvergenceRestartTest {
    private val nostrGroupId = "e".repeat(64)

    private class Member {
        val signer = NostrSignerInternal(KeyPair())
        val store: MlsGroupStateStore = SnapshotStateStore()
        val messages = SnapshotMessageStore()
        val bundles = SnapshotBundleStore()
        val published = mutableListOf<Event>()
        private val relay = MarmotPublisher { event, _ -> published.add(event).let { true } }
        var manager = build()

        fun build() = MarmotManager(signer, store, messages, bundles, publisher = relay)

        /** A new process over the same stores. */
        suspend fun restart() {
            manager = build()
            manager.restoreAll()
        }
    }

    private suspend fun threeMembers(): List<Member> {
        val alice = Member()
        val bob = Member()
        val carol = Member()
        alice.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"), GroupProfileV1("fork", ""))
        for (m in listOf(bob, carol)) {
            val kp = m.manager.generateKeyPackageEvent(relays = emptyList())
            val (commit, welcome) = alice.manager.addMember(nostrGroupId, kp, emptyList())
            // Those already in the group apply the Add; the new member joins from the Welcome.
            if (m === carol) bob.manager.ingest(commit!!.signedEvent)
            m.manager.ingest(welcome!!.giftWrapEvent)
        }
        val epoch =
            alice.manager.groupManager
                .getGroup(nostrGroupId)!!
                .epoch
        assertEquals(
            epoch,
            bob.manager.groupManager
                .getGroup(nostrGroupId)!!
                .epoch,
        )
        assertEquals(
            epoch,
            carol.manager.groupManager
                .getGroup(nostrGroupId)!!
                .epoch,
        )
        return listOf(alice, bob, carol)
    }

    private fun Member.context() =
        manager.groupManager
            .snapshot(nostrGroupId)!!
            .groupContext
            .toTlsBytes()

    @Test
    fun aForkHeardOfOnlyAfterARestartStillConverges() =
        runBlocking {
            val (alice, bob, carol) = threeMembers()

            // Two Commits on one parent, each applied by its author, neither seen by the other.
            val fromBob = bob.manager.selfUpdate(nostrGroupId).signedEvent
            val fromCarol = carol.manager.selfUpdate(nostrGroupId).signedEvent

            // Each hears of the other's only in its next run.
            bob.restart()
            carol.restart()
            bob.manager.ingest(fromCarol)
            carol.manager.ingest(fromBob)
            // Alice stays up and sees both, Bob's first.
            alice.manager.ingest(fromBob)
            alice.manager.ingest(fromCarol)
            for (m in listOf(alice, bob, carol)) m.manager.driveConvergenceToSettlement(pollMs = 20)

            assertContentEquals(alice.context(), bob.context(), "Bob must land on Alice's branch")
            assertContentEquals(alice.context(), carol.context(), "Carol must land on Alice's branch")
        }

    @Test
    fun aRestartedMemberStillRecognizesItsOwnCommitsEcho() =
        runBlocking {
            val (_, bob, _) = threeMembers()
            val own = bob.manager.selfUpdate(nostrGroupId).signedEvent
            val before = bob.context()

            bob.restart()
            bob.manager.ingest(own)

            assertTrue(
                bob.manager.inboundProcessor
                    .openConvergencePasses()
                    .isEmpty(),
                "an echo opens no pass",
            )
            assertContentEquals(before, bob.context())
        }

    /**
     * A one-shot catch-up ([MarmotSyncPolicy.syncIncoming]) with no scope to carry a pass: the
     * fork it finds is settled before it returns, or the process ends with the group split.
     */
    @Test
    fun aCatchUpResolvesTheForkItFoundBeforeReturning() =
        runBlocking {
            val (alice, bob, carol) = threeMembers()
            val fromBob = bob.manager.selfUpdate(nostrGroupId).signedEvent
            val fromCarol = carol.manager.selfUpdate(nostrGroupId).signedEvent
            alice.manager.ingest(fromBob)
            alice.manager.ingest(fromCarol)
            alice.manager.driveConvergenceToSettlement(pollMs = 20)

            carol.restart()
            val relay = RelayUrlNormalizer.normalizeOrNull("wss://relay.invalid")!!
            val sync =
                MarmotSyncPolicy(
                    marmot = carol.manager,
                    userPubKey = carol.signer.pubKey,
                    cursors =
                        object : MarmotSyncPolicy.Cursors {
                            override var giftWrapSince: Long? = null

                            override fun groupSince(groupId: HexKey): Long? = null

                            override fun setGroupSince(
                                groupId: HexKey,
                                value: Long,
                            ) {}
                        },
                    relays =
                        object : MarmotSyncPolicy.Relays {
                            override suspend fun inboxRelays() = setOf(relay)

                            override suspend fun outboxRelays() = setOf(relay)

                            override suspend fun keyPackageRelays() = emptySet<NormalizedRelayUrl>()

                            override suspend fun anyRelays() = setOf(relay)

                            override fun groupRelays(nostrGroupId: HexKey) = setOf(relay)
                        },
                    drain = { _, _ -> listOf(relay to fromCarol, relay to fromBob) },
                    publish = { _, _ -> },
                )
            sync.syncIncoming(timeoutMs = 10)

            assertTrue(
                carol.manager.inboundProcessor
                    .openConvergencePasses()
                    .isEmpty(),
                "the pass ends with the run",
            )
            assertContentEquals(alice.context(), carol.context(), "Carol must land on Alice's branch")
        }
}
