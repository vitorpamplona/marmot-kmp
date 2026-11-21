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
package com.vitorpamplona.marmot.features.deviceGroup

import com.vitorpamplona.marmot.OutboundGroupEvent
import com.vitorpamplona.marmot.appComponents.DeviceStatusV1
import com.vitorpamplona.marmot.appComponents.DeviceTagV1
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.appComponents.RejectionReasonV1
import com.vitorpamplona.marmot.client.ACCEPTING_RELAY
import com.vitorpamplona.marmot.client.MarmotIngestResult
import com.vitorpamplona.marmot.client.MarmotManager
import com.vitorpamplona.marmot.client.SnapshotBundleStore
import com.vitorpamplona.marmot.client.SnapshotMessageStore
import com.vitorpamplona.marmot.client.SnapshotStateStore
import com.vitorpamplona.marmot.client.ingest
import com.vitorpamplona.marmot.features.accountSync.SmallStateItem
import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.marmot.features.devicePairing.ExistingDevicePairing
import com.vitorpamplona.marmot.features.devicePairing.NewDevicePairing
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageUtils
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.quartz.marmot.mip00KeyPackages.KeyPackageEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.utils.TimeUtils
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device groups end to end, in process, through `MarmotManager` with its device-group switch on:
 * devices A and B of one account link; A creates a chat with a third account C and B joins it through
 * a sibling Welcome built from one of its private KeyPackages, and reads C's message; C invites the
 * account and both devices join; C removes the account and both leave; A removes B from the device
 * group and B stops receiving it. Plus gap filling, the link deadline, sign-out, slot announcements,
 * the post-link inventory and sign-in classification.
 */
@OptIn(ExperimentalEncodingApi::class)
class DeviceGroupChatsTest {
    private val now = 1_800_000_000L
    private val relays = listOf("wss://relay.invalid")

    private inner class Device(
        keys: KeyPair,
        deviceGroups: Boolean = true,
    ) {
        val signer = NostrSignerInternal(keys)
        val manager =
            MarmotManager(
                signer,
                SnapshotStateStore(),
                SnapshotMessageStore(),
                SnapshotBundleStore(),
                publisher = ACCEPTING_RELAY,
                deviceGroupConfig = if (deviceGroups) MarmotDeviceGroupConfig(InMemoryDeviceGroupTrustStore(), InMemoryPrivateKeyPackageStore(), relays) else null,
            )
        val groups get() = manager.deviceGroups!!

        suspend fun slot(): String = manager.keyPackageRotationManager.getOrCreateSlotDTag(KeyPackageUtils.PRIMARY_SLOT)

        suspend fun ingest(events: List<OutboundGroupEvent>) = events.map { manager.ingest(it.signedEvent) }
    }

    private class Linked(
        val link: ConfirmedLink,
        val keyPackage: KeyPackageEvent,
        val bundle: KeyPackageBundle,
    )

    private suspend fun pair(
        a: Device,
        b: Device,
    ): Linked {
        val kp = b.manager.generateKeyPackageEvent(relays = emptyList())
        val kpBytes = Base64.decode(kp.content)
        val kpRef = KeyPackageUtils.decodeKeyPackage(kpBytes).reference().toHexKey()
        val bundle = assertNotNull(b.manager.keyPackageRotationManager.findBundleByRef(KeyPackageUtils.decodeKeyPackage(kpBytes).reference()))
        val account = b.signer.pubKey
        val newDevice = NewDevicePairing.start(account, kp.id, kpRef, now)
        val existing = ExistingDevicePairing(account, a.slot())
        existing.receive(newDevice.requestMessage, now, now)
        val answer = existing.answer(newDevice.sessionId, ExistingDevicePairing.PublishedKeyPackage(kp.id, kpRef), now)
        val reveal = assertIs<NewDevicePairing.Event.Reveal>(newDevice.receive(answer, now)).reveal
        existing.receive(reveal, now, now)
        val (groupId, key) = a.groups.confirmTarget()
        newDevice.receive(existing.confirmLink(newDevice.sessionId, groupId, key, now), now)
        val linked = assertIs<NewDevicePairing.Confirmation.Linked>(newDevice.confirmMatch(now))
        b.groups.recordLink(linked.link, now)
        assertIs<ExistingDevicePairing.Event.Linked>(existing.receive(linked.confirm, now, now))
        return Linked(linked.link, kp, bundle)
    }

    /** A and B of one account, linked and with B's first Commit applied on both. */
    private suspend fun linkedPair(): Triple<Device, Device, String> {
        val keys = KeyPair()
        val a = Device(keys)
        val b = Device(keys)
        a.groups.start()
        b.groups.start()
        val linked = pair(a, b)
        val founding = a.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B", now)
        val welcome = assertNotNull(a.groups.applyStaged(founding).welcome)
        // The device group's Welcome travels as a kind 444 to the account itself; B joins it as its link's.
        assertIs<MarmotIngestResult.JoinedGroup>(b.manager.ingest(welcome.giftWrapEvent))
        a.manager.ingest(assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event).signedEvent)
        return Triple(a, b, founding.nostrGroupId)
    }

    private suspend fun invite(
        to: Device,
        of: Device,
    ): MarmotManager.MemberInvite {
        val kp = of.manager.generateKeyPackageEvent(relays = emptyList())
        return MarmotManager.MemberInvite(of.signer.pubKey, Base64.decode(kp.content), kp.id)
    }

    private fun texts(
        device: Device,
        chat: String,
    ) = runBlocking {
        device.manager
            .loadStoredMessages(chat)
            .mapNotNull { Event.fromJsonOrNull(it) }
            .filter { it.kind == 9 }
            .map { it.content }
    }

    @Test
    fun aLinkedDeviceGetsItsChatsAndLeavesThemWithItsAccount() =
        runBlocking<Unit> {
            val (a, b, deviceGroup) = linkedPair()
            val c = Device(KeyPair(), deviceGroups = false)

            // KeyPackages a published once it could tag carry its tag.
            val tagged = KeyPackageUtils.decodeKeyPackage(Base64.decode(a.manager.generateKeyPackageEvent(relays = emptyList()).content))
            assertEquals(DeviceTagV1.Claim.Device(a.slot()), DeviceTagV1.read(tagged.leafNode, a.groups.roster()!!))

            // B hands A private KeyPackages through the device group.
            val handOffs = b.groups.topUpSiblings(now)
            assertTrue(handOffs.isNotEmpty())
            a.ingest(handOffs).forEach { assertIs<MarmotIngestResult.Ignored>(it) }
            assertEquals(MarmotDeviceGroupManager.STOCK_TARGET, a.groups.heldFrom(b.slot(), now))
            // The device group's traffic never shows as a chat message.
            assertTrue(a.manager.loadStoredMessages(deviceGroup).isEmpty())

            // A creates a chat with C; B is in its founding Add through a private KeyPackage.
            val chat = "c1".repeat(32)
            val created = a.groups.createChat(chat, relays, GroupProfileV1("trip", ""), listOf(invite(a, c)), now)
            assertTrue(created.missing.isEmpty())
            assertEquals(1, created.result.welcomes.size, "only C gets a kind 444 Welcome")
            assertIs<MarmotIngestResult.JoinedGroup>(
                c.manager.ingest(
                    created.result.welcomes
                        .single()
                        .giftWrapEvent,
                ),
            )
            b.ingest(created.deviceGroupEvents)
            assertTrue(b.manager.groupManager.isMember(chat), "B joined through its sibling Welcome")
            assertEquals(MarmotDeviceGroupManager.STOCK_TARGET - 1, a.groups.heldFrom(b.slot(), now))

            // Both of the account's leaves read as their devices, on both devices.
            for (d in listOf(a, b)) assertEquals(setOf(DeviceTagV1.Claim.Device(a.slot()), DeviceTagV1.Claim.Device(b.slot())), d.groups.claims(chat).toSet())

            // B reads C's message, and C sees one member for the account.
            val hello = c.manager.buildTextMessage(chat, "hello from C")
            assertIs<MarmotIngestResult.Message>(b.manager.ingest(hello.outbound.signedEvent))
            assertIs<MarmotIngestResult.Message>(a.manager.ingest(hello.outbound.signedEvent))
            assertEquals(listOf("hello from C"), texts(b, chat))
            assertEquals(2, c.manager.leafIndicesOf(chat, a.signer.pubKey).size)

            // C invites the account into a chat of its own: every published slot, so both devices join.
            val chat2 = "c2".repeat(32)
            c.manager.createCurrentProfileGroup(chat2, relays, GroupProfileV1("c's", ""))
            val (_, welcomes) = c.manager.addMemberInvites(chat2, listOf(invite(c, a), invite(c, b)), emptyList())
            assertIs<MarmotIngestResult.JoinedGroup>(a.manager.ingest(welcomes[0].giftWrapEvent))
            assertIs<MarmotIngestResult.JoinedGroup>(b.manager.ingest(welcomes[1].giftWrapEvent))
            assertTrue(a.manager.groupManager.isMember(chat2) && b.manager.groupManager.isMember(chat2))

            // C removes the account: one Commit takes both leaves out.
            val removal = c.manager.removeAccount(chat2, a.signer.pubKey)
            a.manager.ingest(removal.signedEvent)
            b.manager.ingest(removal.signedEvent)
            assertFalse(a.manager.groupManager.isMember(chat2))
            assertFalse(b.manager.groupManager.isMember(chat2))

            // A removes B from the device group; then from the chats B's leaf is still in.
            val remove = a.groups.stageRemoveDevice(b.slot(), now + 10)
            a.groups.applyStaged(remove)
            assertEquals(
                RejectionReasonV1.REMOVED,
                a.groups
                    .roster()!!
                    .rejectedSlot(b.slot())!!
                    .reason,
            )
            b.groups.processCommit(deviceGroup, remove.framedCommitBytes)
            assertTrue(b.groups.trust().unlinked)
            assertFalse(b.groups.isTrustedDeviceGroup(deviceGroup))
            assertNull(b.manager.groupManager.getGroup(deviceGroup))
            assertEquals(DeviceTagV1.Claim.RemovedSlot(b.slot()), a.groups.claims(chat).first { it != DeviceTagV1.Claim.Device(a.slot()) })
            val cleanup = a.groups.removeGoneDevicesFromChats()
            assertEquals(1, cleanup.size)
            b.manager.ingest(cleanup.single().signedEvent)
            c.manager.ingest(cleanup.single().signedEvent)
            assertFalse(b.manager.groupManager.isMember(chat))
            assertEquals(1, c.manager.leafIndicesOf(chat, a.signer.pubKey).size)

            // B no longer receives the device group: A's heartbeat reaches nothing there.
            val beat = assertNotNull(a.groups.heartbeatDue(now + 7200))
            assertFalse(b.manager.ingest(beat.signedEvent) is MarmotIngestResult.Message)
            assertNull(b.manager.groupManager.getGroup(deviceGroup))
        }

    @Test
    fun aForkedDeviceGroupSettlesOnOneBranchOnBothDevices() =
        runBlocking<Unit> {
            val (a, b, deviceGroup) = linkedPair()
            // Both devices commit from the same epoch: two roster updates on one parent.
            val fromA = assertNotNull(a.groups.applyStaged(a.groups.stageAnnouncement("a1".repeat(32))).event)
            val fromB = assertNotNull(b.groups.applyStaged(b.groups.stageAnnouncement("b1".repeat(32))).event)
            a.manager.ingest(fromB.signedEvent)
            b.manager.ingest(fromA.signedEvent)
            a.manager.driveConvergenceToSettlement(pollMs = 1)
            b.manager.driveConvergenceToSettlement(pollMs = 1)
            a.groups.refresh()
            b.groups.refresh()

            val ga = a.manager.groupManager.getGroup(deviceGroup)!!
            val gb = b.manager.groupManager.getGroup(deviceGroup)!!
            assertEquals(ga.epoch, gb.epoch)
            assertContentEquals(ga.epochAuthenticator, gb.epochAuthenticator)
            val roster = a.groups.roster()!!
            assertEquals(roster, b.groups.roster())
            // Exactly one announcement won; the other device announces again before it publishes.
            val won = listOf(roster.device(a.slot())!!.announcedKeyPackage == "a1".repeat(32), roster.device(b.slot())!!.announcedKeyPackage == "b1".repeat(32))
            assertEquals(1, won.count { it })
            assertTrue(a.groups.announcementNeeded("a1".repeat(32)) || b.groups.announcementNeeded("b1".repeat(32)))
        }

    @Test
    fun anOlderEpochsDeviceGroupMessageStillReadsItsSender() =
        runBlocking<Unit> {
            val (a, b, _) = linkedPair()
            // B hands A private KeyPackages; A commits before reading them.
            val handOffs = b.groups.topUpSiblings(now)
            assertNotNull(a.groups.applyStaged(a.groups.stageAnnouncement("a2".repeat(32))).event)
            assertNotNull(a.groups.applyStaged(a.groups.stageAnnouncement("a3".repeat(32))).event)
            // Two epochs later A still holds the hand-offs' epoch secrets and the sender's tag there.
            a.ingest(handOffs)
            assertEquals(MarmotDeviceGroupManager.STOCK_TARGET, a.groups.heldFrom(b.slot(), now))
        }

    @Test
    fun aDeclineOnOneDeviceTakesTheOtherOutOfThatInvitation() =
        runBlocking<Unit> {
            val (a, b, _) = linkedPair()
            val c = Device(KeyPair(), deviceGroups = false)
            val chat = "a7".repeat(32)
            c.manager.createCurrentProfileGroup(chat, relays, null)
            val (_, welcomes) = c.manager.addMemberInvites(chat, listOf(invite(c, a), invite(c, b)), emptyList())
            a.manager.ingest(welcomes[0].giftWrapEvent)
            b.manager.ingest(welcomes[1].giftWrapEvent)
            // One Add result, one generation, on both devices.
            val mlsId =
                a.manager.groupManager
                    .getGroup(chat)!!
                    .groupId
                    .toHexKey()
            val generation = assertNotNull(a.groups.smallState().generations[mlsId])
            assertEquals(generation, b.groups.smallState().generations[mlsId])

            // A's user leaves: A records a decline first; B, reading it, leaves too.
            val updates = a.groups.recordLeave(chat, now)
            assertEquals(1, updates.size)
            b.ingest(updates)
            val held = b.groups.smallState().held("$mlsId/invite/$generation") as SmallStateItem.Invite
            assertFalse(held.accept)
            val leave = b.groups.drainOutbox().single()
            assertIs<MarmotIngestResult.ProposalStaged>(c.manager.ingest(leave.signedEvent))
        }

    @Test
    fun settingsAndReadPositionsReachTheSiblingAndARequestGetsABroadcast() =
        runBlocking<Unit> {
            val (a, b, _) = linkedPair()
            val c = Device(KeyPair(), deviceGroups = false)
            a.ingest(b.groups.topUpSiblings(now))
            val chat = "a8".repeat(32)
            val created = a.groups.createChat(chat, relays, null, listOf(invite(a, c)), now)
            b.ingest(created.deviceGroupEvents)
            // The founded copy's generation is inherited through the version-2 sibling Welcome.
            val mlsId =
                a.manager.groupManager
                    .getGroup(chat)!!
                    .groupId
                    .toHexKey()
            assertEquals(a.groups.smallState().generations[mlsId], b.groups.smallState().generations[mlsId])
            assertTrue((a.groups.smallState().held("$mlsId/invite/${a.groups.smallState().generations[mlsId]}") as SmallStateItem.Invite).accept)

            b.ingest(a.groups.changeSetting(chat, "pin", "true", now))
            b.ingest(a.groups.markRead(chat, 1, now, "ee".repeat(32), now))
            val state = b.groups.smallState()
            assertEquals("true", (state.held("$mlsId/pin") as SmallStateItem.Versioned).value)
            assertEquals("ee".repeat(32), (state.held("$mlsId/read") as SmallStateItem.Read).id)
            // A read position never moves back.
            assertTrue(a.groups.markRead(chat, 0, now, "ff".repeat(32), now).isEmpty())

            // B starts: it broadcasts and asks; A answers with everything it holds.
            val start = b.groups.broadcastDue(now, start = true)
            a.ingest(start)
            assertTrue(a.groups.drainOutbox().isNotEmpty())
            assertTrue(a.groups.broadcastDue(now).isNotEmpty())
            assertTrue(a.groups.broadcastDue(now + 60).isEmpty(), "the next broadcast waits a day")
            assertTrue(a.groups.broadcastDue(now + MarmotDeviceGroupManager.BROADCAST_INTERVAL_SECS).isNotEmpty())
        }

    @Test
    fun aLostSiblingWelcomeIsSentAgainAfterTheTargetRuns() =
        runBlocking<Unit> {
            val (a, b, _) = linkedPair()
            val c = Device(KeyPair(), deviceGroups = false)
            val real = TimeUtils.now()
            a.ingest(b.groups.topUpSiblings(real - 1000))
            val chat = "a9".repeat(32)
            a.groups.createChat(chat, relays, null, listOf(invite(a, c)), real - 1000) // its 461 is lost
            assertTrue(a.groups.siblingWelcomeRepairs(real).isEmpty(), "not due before B has run")
            b.groups.heartbeatSent(0)
            a.ingest(listOf(assertNotNull(b.groups.heartbeatDue(real - 100))))
            val again = a.groups.siblingWelcomeRepairs(real)
            assertEquals(1, again.size)
            b.ingest(again)
            assertTrue(b.manager.groupManager.isMember(chat))
            assertTrue(a.groups.siblingWelcomeRepairs(real + 1).isEmpty())
        }

    @Test
    fun oldLeavesAreRetaggedAndQuietSiblingsGoInactiveThenOut() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            a.groups.start()
            b.groups.start()
            val c = Device(KeyPair(), deviceGroups = false)
            val chat = "aa".repeat(32)
            a.manager.createCurrentProfileGroup(chat, relays, null)
            c.manager.ingest(
                a.manager
                    .addMemberInvites(chat, listOf(invite(a, c)), emptyList())
                    .second
                    .single()
                    .giftWrapEvent,
            )
            val linked = pair(a, b)
            val founding = a.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B", now)
            b.manager.ingest(assertNotNull(a.groups.applyStaged(founding).welcome).giftWrapEvent)
            a.manager.ingest(assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event).signedEvent)

            // A's chat leaf predates its tag; a self-update tags it.
            assertEquals(listOf<DeviceTagV1.Claim>(DeviceTagV1.Claim.Unclaimed), a.groups.claims(chat))
            val retag = a.groups.retagOwnLeaves().single()
            c.manager.ingest(retag.signedEvent)
            assertEquals(listOf<DeviceTagV1.Claim>(DeviceTagV1.Claim.Device(a.slot())), a.groups.claims(chat))

            // B goes quiet: inactive after 30 days, removed after 90.
            assertNull(a.groups.stageInactivity(now + MarmotDeviceGroupManager.INACTIVE_AFTER_SECS - 1))
            val inactive = assertNotNull(a.groups.stageInactivity(now + MarmotDeviceGroupManager.INACTIVE_AFTER_SECS))
            b.manager.ingest(assertNotNull(a.groups.applyStaged(inactive).event).signedEvent)
            assertEquals(
                DeviceStatusV1.INACTIVE,
                b.groups
                    .roster()!!
                    .device(b.slot())!!
                    .status,
            )
            val out = assertNotNull(a.groups.stageInactivity(now + MarmotDeviceGroupManager.REMOVE_INACTIVE_AFTER_SECS))
            b.manager.ingest(assertNotNull(a.groups.applyStaged(out).event).signedEvent)
            assertNull(a.groups.roster()!!.device(b.slot()))
            assertTrue(b.groups.trust().unlinked)
        }

    @Test
    fun aSiblingMissingFromAChatIsFilledAfterAClaim() =
        runBlocking<Unit> {
            val (a, b, _) = linkedPair()
            val c = Device(KeyPair(), deviceGroups = false)
            // No private KeyPackage yet: B is left out of the founding Add, and asked for some.
            val chat = "d1".repeat(32)
            val created = a.groups.createChat(chat, relays, null, listOf(invite(a, c)), now)
            assertEquals(listOf(b.slot()), created.missing)
            assertFalse(b.manager.groupManager.isMember(chat))
            c.manager.ingest(
                created.result.welcomes
                    .single()
                    .giftWrapEvent,
            )

            b.ingest(listOf(a.groups.requestKeyPackages(b.slot(), 3, now)))
            a.ingest(b.groups.drainOutbox())
            assertEquals(3, a.groups.heldFrom(b.slot(), now))

            val first = a.groups.fillMissingChats(now)
            assertEquals(1, first.claims.size)
            assertTrue(first.adds.isEmpty(), "a claim goes out before the Add")
            b.ingest(first.claims)
            val second = a.groups.fillMissingChats(now + 1)
            val add = second.adds.single()
            c.manager.ingest(add.result.event!!.signedEvent)
            b.ingest(add.deviceGroupEvents)
            assertTrue(b.manager.groupManager.isMember(chat))
            val hi = c.manager.buildTextMessage(chat, "late hello")
            assertIs<MarmotIngestResult.Message>(b.manager.ingest(hi.outbound.signedEvent))
        }

    @Test
    fun aLinkNotTakenUpIsUndoneAndTheNewDeviceIsNotUnlinked() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            a.groups.start()
            b.groups.start()
            val linked = pair(a, b)
            val founding = a.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B", now)
            a.groups.applyStaged(founding)
            b.groups.joinLinkWelcome(founding.welcomeBytes!!, linked.bundle, now)
            assertNull(a.groups.checkLinkDeadlines(now + MarmotDeviceGroupManager.FIRST_COMMIT_DEADLINE_SECS - 1))
            val undo = assertNotNull(a.groups.checkLinkDeadlines(now + MarmotDeviceGroupManager.FIRST_COMMIT_DEADLINE_SECS))
            val undoEvent = assertNotNull(a.groups.applyStaged(undo).event)
            assertNull(a.groups.roster()!!.device(b.slot()))
            assertNull(a.groups.roster()!!.rejectedSlot(b.slot()), "an undone link leaves no record: the slot can link again")
            assertEquals(
                DeviceGroupTrust.Outcome.FAILED,
                a.groups
                    .trust()
                    .approvals
                    .single()
                    .outcome,
            )
            b.manager.ingest(undoEvent.signedEvent)
            assertFalse(b.groups.trust().unlinked, "a failed link is not an unlink")
            assertNull(b.groups.trust().trustedGroupId)
        }

    @Test
    fun theApproverAddsANewDeviceToItsExistingChats() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            a.groups.start()
            b.groups.start()
            // A chat A had before B existed.
            val c = Device(KeyPair(), deviceGroups = false)
            val chat = "f1".repeat(32)
            a.manager.createCurrentProfileGroup(chat, relays, null)
            c.manager.ingest(
                a.manager
                    .addMemberInvites(chat, listOf(invite(a, c)), emptyList())
                    .second
                    .single()
                    .giftWrapEvent,
            )

            val linked = pair(a, b)
            val founding = a.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B", now)
            a.groups.applyStaged(founding)
            b.groups.joinLinkWelcome(founding.welcomeBytes!!, linked.bundle, now)
            // Nothing is added before the link is made.
            assertTrue(a.groups.addNewDeviceToChats(b.slot(), now).isEmpty())
            a.manager.ingest(assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event).signedEvent)
            a.ingest(b.groups.topUpSiblings(now))

            // A's leaf in the old chat predates its tag, so the chat does not read A as a device yet,
            // but a same-account Add of B still goes through; C applies it.
            val adds = a.groups.addNewDeviceToChats(b.slot(), now)
            assertEquals(1, adds.size)
            c.manager.ingest(
                adds
                    .single()
                    .result.event!!
                    .signedEvent,
            )
            b.ingest(adds.single().deviceGroupEvents)
            assertTrue(b.manager.groupManager.isMember(chat))
            assertEquals(2, c.manager.leafIndicesOf(chat, a.signer.pubKey).size)

            // An explicit local reset forgets the device group and keeps the chat.
            b.groups.resetLocalCopy()
            assertNull(b.groups.trust().trustedGroupId)
            assertNull(b.manager.groupManager.getGroup(founding.nostrGroupId))
            assertTrue(b.manager.groupManager.isMember(chat))
        }

    @Test
    fun aSigningOutDeviceIsRemovedByItsSibling() =
        runBlocking<Unit> {
            val (a, b, deviceGroup) = linkedPair()
            val leaving = b.groups.stageSignOut()
            a.manager.ingest(assertNotNull(b.groups.applyStaged(leaving).event).signedEvent)
            assertEquals(
                DeviceStatusV1.LEAVING,
                a.groups
                    .roster()!!
                    .device(b.slot())!!
                    .status,
            )
            assertEquals(listOf(b.slot()), a.groups.pendingDepartures())
            val removal = a.groups.stageRemoveDevice(b.slot(), now)
            a.groups.applyStaged(removal)
            assertNull(a.groups.roster()!!.device(b.slot()))
        }

    @Test
    fun slotAnnouncementsInventoryHeartbeatsAndSignIns() =
        runBlocking<Unit> {
            val (a, b, deviceGroup) = linkedPair()
            // A device announces a KeyPackage before it publishes it.
            val ref = "ab".repeat(32)
            assertTrue(a.groups.announcementNeeded(ref))
            val announce = a.groups.stageAnnouncement(ref)
            b.manager.ingest(assertNotNull(a.groups.applyStaged(announce).event).signedEvent)
            assertFalse(a.groups.announcementNeeded(ref))
            assertEquals(
                ref,
                b.groups
                    .roster()!!
                    .device(a.slot())!!
                    .announcedKeyPackage,
            )

            // The approver reports the chats the new device can expect.
            val c = Device(KeyPair(), deviceGroups = false)
            a.ingest(b.groups.topUpSiblings(now))
            val chat = "e1".repeat(32)
            val created = a.groups.createChat(chat, relays, null, listOf(invite(a, c)), now)
            b.ingest(a.groups.chatInventory(b.slot(), 1, now))
            // The sibling Welcome is not delivered yet: one chat remains.
            assertEquals(1L, b.groups.remainingExpectedChats())
            b.ingest(created.deviceGroupEvents)
            assertEquals(0L, b.groups.remainingExpectedChats())

            // Heartbeats count once B's tagged leaf sends them.
            b.ingest(listOf(assertNotNull(a.groups.heartbeatDue(now))))
            // Counted at the earlier of its created_at and when B read it (the real clock here).
            assertTrue(assertNotNull(b.groups.lastActivity(a.slot())) <= now)

            // Sign-ins: the first check's slots were here first; anything later is new; a removed
            // slot's old publication stays out (MDK 2d509151), a later one is a sign-in again.
            val stranger = "99".repeat(32)
            a.groups.recordFirstCheck(listOf(a.slot(), b.slot(), "77".repeat(32)))
            val classes =
                a.groups.classifySignIns(
                    listOf(
                        MarmotDeviceGroupManager.Publication(a.slot(), now),
                        MarmotDeviceGroupManager.Publication(b.slot(), now),
                        MarmotDeviceGroupManager.Publication("77".repeat(32), now),
                        MarmotDeviceGroupManager.Publication(stranger, now),
                    ),
                )
            assertEquals(MarmotDeviceGroupManager.SignInClass.OWN, classes[a.slot()])
            assertEquals(MarmotDeviceGroupManager.SignInClass.LINKED, classes[b.slot()])
            assertEquals(MarmotDeviceGroupManager.SignInClass.ALREADY_SIGNED_IN, classes["77".repeat(32)])
            assertEquals(MarmotDeviceGroupManager.SignInClass.NEW_SIGN_IN, classes[stranger])
            val reject = assertNotNull(a.groups.rejectSignIn(stranger, now))
            a.groups.applyStaged(reject)
            assertEquals(MarmotDeviceGroupManager.SignInClass.REJECTED, a.groups.classifySignIns(listOf(MarmotDeviceGroupManager.Publication(stranger, now)))[stranger])

            val remove = a.groups.stageRemoveDevice(b.slot(), now)
            a.groups.applyStaged(remove)
            // The removed record expires from the roster; the slot's old publication still raises nothing.
            val expired = a.groups.trust()
            assertTrue(expired.removedSlots.any { it.slot == b.slot() })
            assertNull(a.groups.expireRemovedRecords(now + MarmotDeviceGroupManager.REMOVED_RECORD_SECS - 1))
            a.groups.applyStaged(assertNotNull(a.groups.expireRemovedRecords(now + MarmotDeviceGroupManager.REMOVED_RECORD_SECS)))
            assertNull(a.groups.roster()!!.rejectedSlot(b.slot()))
            assertEquals(MarmotDeviceGroupManager.SignInClass.REMOVED, a.groups.classifySignIns(listOf(MarmotDeviceGroupManager.Publication(b.slot(), now)))[b.slot()])
            assertEquals(
                MarmotDeviceGroupManager.SignInClass.NEW_SIGN_IN,
                a.groups.classifySignIns(listOf(MarmotDeviceGroupManager.Publication(b.slot(), now + MarmotDeviceGroupManager.DIRECTORY_SKEW_SECS + 1)))[b.slot()],
            )
        }
}
