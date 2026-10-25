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
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * [MarmotManager.leave]: the whole departure, including the admin step-down
 * MIP-03 requires before a SelfRemove and the heir that keeps the group from
 * being left without an admin.
 */
class MarmotLeaveTest {
    private val nostrGroupId = "2".repeat(64)

    private class Member {
        val signer = NostrSignerInternal(KeyPair())
        val messages = SnapshotMessageStore()
        val manager = MarmotManager(signer, SnapshotStateStore(), messages, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
        val pubKey get() = signer.pubKey
    }

    /** Alice founds the group and adds [others]; everyone ends up on the same epoch. */
    private suspend fun group(
        alice: Member,
        vararg others: Member,
    ) {
        alice.manager.createCurrentProfileGroup(
            nostrGroupId = nostrGroupId,
            relays = listOf("wss://relay.invalid"),
            profile = GroupProfileV1("departures", ""),
        )
        if (others.isEmpty()) return
        val (commit, welcomes) =
            alice.manager.addMembers(nostrGroupId, others.map { it.manager.generateKeyPackageEvent(relays = emptyList()) }, emptyList())
        assertNull(commit)
        welcomes.forEach { delivery -> others.first { it.pubKey == delivery.recipientPubKey }.manager.ingest(delivery.giftWrapEvent) }
    }

    @Test
    fun `the sole admin hands the role to a member before leaving`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            group(alice, bob)

            val departure = alice.manager.leave(nostrGroupId)
            val stepDown = assertNotNull(departure.stepDown, "an admin must step down before a SelfRemove")
            val selfRemove = assertNotNull(departure.selfRemove)
            assertFalse(alice.manager.isMember(nostrGroupId))

            bob.manager.ingest(stepDown.signedEvent)
            assertEquals(
                listOf(bob.pubKey),
                bob.manager
                    .groupView(nostrGroupId)
                    ?.adminPubkeys
                    ?.toList(),
            )
            assertIs<MarmotIngestResult.ProposalStaged>(bob.manager.ingest(selfRemove.signedEvent))
            assertNotNull(bob.manager.commitStagedProposalsIfAdmin(nostrGroupId), "the heir commits the departure")
            assertEquals(listOf(bob.pubKey), bob.manager.memberPubkeys(nostrGroupId).map { it.pubkey })
        }

    @Test
    fun `an admin with a co-admin steps down without naming an heir`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            val carol = Member()
            group(alice, bob, carol)
            val promote = alice.manager.setGroupAdmins(nostrGroupId, listOf(alice.pubKey, carol.pubKey))
            bob.manager.ingest(promote.signedEvent)

            val departure = alice.manager.leave(nostrGroupId)
            bob.manager.ingest(assertNotNull(departure.stepDown).signedEvent)
            assertEquals(
                setOf(carol.pubKey),
                bob.manager
                    .groupView(nostrGroupId)
                    ?.adminPubkeys
                    ?.toSet(),
            )
        }

    @Test
    fun `an admin whose co-admin already left still names an heir`() =
        runBlocking<Unit> {
            // The admin list may name someone who is no longer in the tree. Dropping
            // only ourselves would leave no admin among the members, which every peer
            // refuses as admin depletion.
            val alice = Member()
            val bob = Member()
            group(alice, bob)
            val stranger = NostrSignerInternal(KeyPair()).pubKey
            val promote = alice.manager.setGroupAdmins(nostrGroupId, listOf(alice.pubKey, stranger))
            bob.manager.ingest(promote.signedEvent)

            val departure = alice.manager.leave(nostrGroupId)
            bob.manager.ingest(assertNotNull(departure.stepDown).signedEvent)
            assertEquals(
                setOf(stranger, bob.pubKey),
                bob.manager
                    .groupView(nostrGroupId)
                    ?.adminPubkeys
                    ?.toSet(),
            )
        }

    @Test
    fun `a member who is not an admin only proposes the SelfRemove`() =
        runBlocking<Unit> {
            val alice = Member()
            val bob = Member()
            group(alice, bob)

            val departure = bob.manager.leave(nostrGroupId)
            assertNull(departure.stepDown)
            assertIs<MarmotIngestResult.ProposalStaged>(alice.manager.ingest(assertNotNull(departure.selfRemove).signedEvent))
        }

    @Test
    fun `the last member leaves without publishing anything`() =
        runBlocking<Unit> {
            // Nobody is left to commit a SelfRemove, and an admin may not propose one.
            val alice = Member()
            group(alice)

            val departure = alice.manager.leave(nostrGroupId)
            assertNull(departure.stepDown)
            assertNull(departure.selfRemove)
            assertFalse(alice.manager.isMember(nostrGroupId))
        }

    @Test
    fun `a reset drops the decrypted message logs with the groups`() =
        runBlocking<Unit> {
            // The logs are the plaintext of every message. A reset that wipes the groups
            // and keeps them leaves that plaintext on disk with nothing that refers to it.
            val alice = Member()
            group(alice)
            val text = alice.manager.buildTextMessage(nostrGroupId, "hello")
            alice.manager.persistDecryptedMessage(nostrGroupId, text.innerEvent.toJson())
            assertEquals(1, alice.messages.loadMessages(nostrGroupId).size)

            alice.manager.resetAllState()
            assertFalse(alice.manager.isMember(nostrGroupId))
            assertEquals(emptyList(), alice.messages.loadMessages(nostrGroupId))
        }
}
