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
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
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
        a.groups.applyStaged(founding)
        b.groups.joinLinkWelcome(founding.welcomeBytes!!, linked.bundle, now)
        val first = b.groups.stageFirstCommit()
        a.groups.processCommit(founding.nostrGroupId, first.framedCommitBytes)
        b.groups.applyStaged(first)
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
            a.groups.applyStaged(undo)
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
            b.groups.processCommit(founding.nostrGroupId, undo.framedCommitBytes)
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
            val first = b.groups.stageFirstCommit()
            a.groups.processCommit(founding.nostrGroupId, first.framedCommitBytes)
            b.groups.applyStaged(first)
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
            b.groups.applyStaged(leaving)
            a.groups.processCommit(deviceGroup, leaving.framedCommitBytes)
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
            a.groups.applyStaged(announce)
            b.groups.processCommit(deviceGroup, announce.framedCommitBytes)
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
