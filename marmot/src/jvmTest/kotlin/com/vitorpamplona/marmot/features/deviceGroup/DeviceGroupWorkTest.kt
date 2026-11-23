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
import com.vitorpamplona.marmot.appComponents.EncryptedMediaPolicyV2
import com.vitorpamplona.marmot.appComponents.EncryptedMediaReferenceV2
import com.vitorpamplona.marmot.appComponents.EncryptedMediaV2
import com.vitorpamplona.marmot.appComponents.MediaLocatorV2
import com.vitorpamplona.marmot.appComponents.RejectionReasonV1
import com.vitorpamplona.marmot.client.ACCEPTING_RELAY
import com.vitorpamplona.marmot.client.MarmotIngestResult
import com.vitorpamplona.marmot.client.MarmotManager
import com.vitorpamplona.marmot.client.SnapshotBundleStore
import com.vitorpamplona.marmot.client.SnapshotMessageStore
import com.vitorpamplona.marmot.client.SnapshotStateStore
import com.vitorpamplona.marmot.client.ingest
import com.vitorpamplona.marmot.features.accountSync.HistoryDelivery
import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.marmot.features.devicePairing.ExistingDevicePairing
import com.vitorpamplona.marmot.features.devicePairing.NewDevicePairing
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageUtils
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
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device-group work beyond linking: a rename that loses a fork is made again, owed histories and kept
 * deliveries survive a restart, long histories go through Blossom, histories carry attachment keys
 * and moderation grants, and a device moves from one device group to another.
 */
@OptIn(ExperimentalEncodingApi::class)
class DeviceGroupWorkTest {
    private val now = TimeUtils.now()
    private val relays = listOf("wss://relay.invalid")

    /** One device's stores, so a [Device] can be built again over them as after a restart. */
    private class Stores(
        val keys: KeyPair,
    ) {
        val mls = SnapshotStateStore()
        val messages = SnapshotMessageStore()
        val bundles = SnapshotBundleStore()
        val trust = InMemoryDeviceGroupTrustStore()
        val privateKeyPackages = InMemoryPrivateKeyPackageStore()
        val work = InMemoryDeviceGroupWorkStore()
    }

    private inner class Device(
        val stores: Stores,
        deviceGroups: Boolean = true,
    ) {
        constructor(keys: KeyPair, deviceGroups: Boolean = true) : this(Stores(keys), deviceGroups)

        val signer = NostrSignerInternal(stores.keys)
        val manager =
            MarmotManager(
                signer,
                stores.mls,
                stores.messages,
                stores.bundles,
                publisher = ACCEPTING_RELAY,
                deviceGroupConfig =
                    if (deviceGroups) {
                        MarmotDeviceGroupConfig(stores.trust, stores.privateKeyPackages, relays, workStore = stores.work)
                    } else {
                        null
                    },
            )
        val groups get() = manager.deviceGroups!!

        suspend fun slot(): String = manager.keyPackageRotationManager.getOrCreateSlotDTag(KeyPackageUtils.PRIMARY_SLOT)

        suspend fun ingest(events: List<OutboundGroupEvent>) = events.map { manager.ingest(it.signedEvent) }

        /** The same device after a restart: a new manager over the same stores. */
        suspend fun restarted(): Device =
            Device(stores).also {
                it.manager.restoreAll()
                it.groups.start()
            }
    }

    private class Linked(
        val link: ConfirmedLink,
        val keyPackage: KeyPackageEvent,
    )

    private suspend fun pair(
        a: Device,
        b: Device,
    ): Linked {
        val kp = b.manager.generateKeyPackageEvent(relays = emptyList())
        val kpRef = KeyPackageUtils.decodeKeyPackage(Base64.decode(kp.content)).reference().toHexKey()
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
        return Linked(linked.link, kp)
    }

    /** [a] approves [b] into its device group (founding it if it has none); B's first Commit applied on both. */
    private suspend fun link(
        a: Device,
        b: Device,
        label: String = "B",
    ): String {
        a.groups.start()
        b.groups.start()
        val linked = pair(a, b)
        val add = a.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), label, now)
        val applied = a.groups.applyStaged(add)
        val welcome = assertNotNull(applied.welcome)
        assertIs<MarmotIngestResult.JoinedGroup>(b.manager.ingest(welcome.giftWrapEvent))
        assertTrue(b.groups.firstCommitDue())
        a.manager.ingest(assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event).signedEvent)
        return add.nostrGroupId
    }

    private suspend fun invite(of: Device): MarmotManager.MemberInvite {
        val kp = of.manager.generateKeyPackageEvent(relays = emptyList())
        return MarmotManager.MemberInvite(of.signer.pubKey, Base64.decode(kp.content), kp.id)
    }

    private suspend fun texts(
        device: Device,
        chat: String,
    ) = device.manager
        .loadStoredMessages(chat)
        .mapNotNull { Event.fromJsonOrNull(it) }
        .filter { it.kind == 9 }
        .map { it.content }
        .sorted()

    /** A chat [a] holds with a third account [c], with [messages] from C in it. */
    private suspend fun chatWithC(
        a: Device,
        c: Device,
        chat: String,
        messages: List<String>,
    ) {
        a.manager.createCurrentProfileGroup(chat, relays, null)
        c.manager.ingest(
            a.manager
                .addMemberInvites(chat, listOf(invite(c)), emptyList())
                .second
                .single()
                .giftWrapEvent,
        )
        messages.forEach {
            a.manager.ingest(
                c.manager
                    .buildTextMessage(chat, it)
                    .outbound.signedEvent,
            )
        }
    }

    /** [a] adds its sibling [b] to [chat]; returns the sibling Welcomes for B and tells C. */
    private suspend fun addSibling(
        a: Device,
        b: Device,
        c: Device,
    ): List<OutboundGroupEvent> {
        a.ingest(b.groups.topUpSiblings(now))
        val add = a.groups.addNewDeviceToChats(b.slot(), now).single()
        c.manager.ingest(add.result.event!!.signedEvent)
        return add.deviceGroupEvents
    }

    // ---- 4: renames that lose a fork ------------------------------------------------------------

    @Test
    fun aRenameWhoseCommitWasLostIsMadeAgain() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            link(a, b)
            // A renames B, but its Commit never lands: B's own announcement takes that epoch.
            assertNotNull(a.groups.stageRename(b.slot(), "Phone"))
            assertEquals(listOf(b.slot() to "Phone"), a.groups.keptEdits())
            a.manager.ingest(assertNotNull(b.groups.applyStaged(b.groups.stageAnnouncement("b1".repeat(32))).event).signedEvent)
            assertEquals(
                "B",
                a.groups
                    .roster()
                    ?.device(b.slot())
                    ?.label,
            )

            // The roster still holds the id A's edit replaced: the rename is made again on top of B's change.
            val again = assertNotNull(a.groups.stageEditRecovery())
            b.manager.ingest(assertNotNull(a.groups.applyStaged(again).event).signedEvent)
            for (d in listOf(a, b)) {
                val entry = assertNotNull(d.groups.roster()?.device(b.slot()))
                assertEquals("Phone", entry.label)
                assertEquals("b1".repeat(32), entry.announcedKeyPackage, "the other change is kept")
            }
            // Applied now: kept for a later fork, nothing more to do.
            assertNull(a.groups.stageEditRecovery())
            assertEquals(1, a.groups.keptEdits().size)

            // Another user edit that stands drops A's.
            a.manager.ingest(assertNotNull(b.groups.applyStaged(assertNotNull(b.groups.stageRename(b.slot(), "Mine"))).event).signedEvent)
            assertNull(a.groups.stageEditRecovery())
            assertTrue(a.groups.keptEdits().isEmpty())
            assertEquals(
                "Mine",
                a.groups
                    .roster()
                    ?.device(b.slot())
                    ?.label,
            )
        }

    @Test
    fun aRenameThatLosesARealForkComesBack() =
        runBlocking<Unit> {
            var lostOnce = false
            repeat(16) {
                val keys = KeyPair()
                val a = Device(keys)
                val b = Device(keys)
                val deviceGroup = link(a, b)
                // A renames B while B announces a KeyPackage: two Commits on one parent.
                val rename = a.groups.applyStaged(assertNotNull(a.groups.stageRename(b.slot(), "Laptop"))).event!!
                val announce = b.groups.applyStaged(b.groups.stageAnnouncement("b2".repeat(32))).event!!
                a.manager.ingest(announce.signedEvent)
                b.manager.ingest(rename.signedEvent)
                a.manager.driveConvergenceToSettlement(pollMs = 1)
                b.manager.driveConvergenceToSettlement(pollMs = 1)
                a.groups.refresh()
                b.groups.refresh()
                if (a.groups
                        .roster()
                        ?.device(b.slot())
                        ?.label != "Laptop"
                ) {
                    lostOnce = true
                    val again = assertNotNull(a.groups.stageEditRecovery(), "the lost rename is made again")
                    b.manager.ingest(assertNotNull(a.groups.applyStaged(again).event).signedEvent)
                }
                assertEquals(
                    "Laptop",
                    a.groups
                        .roster()
                        ?.device(b.slot())
                        ?.label,
                )
                assertEquals(a.groups.roster(), b.groups.roster())
                assertTrue(a.groups.isTrustedDeviceGroup(deviceGroup))
                if (lostOnce) return@runBlocking
            }
        }

    /**
     * The harness's test 53, one process per step: two devices rename at once from the same epoch,
     * and each hears of the other's Commit only after a restart. The fork must still be resolved,
     * and the rename that lost it made again, so both renames stand on both devices.
     */
    @Test
    fun twoRenamesAtOnceAcrossRestartsBothStand() =
        runBlocking<Unit> {
            val keys = KeyPair()
            var a = Device(keys)
            var b = Device(keys)
            link(a, b)
            val aSlot = a.slot()
            val bSlot = b.slot()
            val renameB = a.groups.applyStaged(assertNotNull(a.groups.stageRename(bSlot, "Fork-A"))).event!!
            val renameA = b.groups.applyStaged(assertNotNull(b.groups.stageRename(aSlot, "Fork-B"))).event!!

            a = a.restarted()
            b = b.restarted()
            a.manager.ingest(renameA.signedEvent)
            b.manager.ingest(renameB.signedEvent)
            for (d in listOf(a, b)) {
                d.manager.driveConvergenceToSettlement(pollMs = 1)
                d.groups.refresh()
            }
            assertEquals(a.groups.roster(), b.groups.roster(), "both devices settle on one branch")

            // The device whose rename lost makes it again, once, in its next run.
            for ((loser, other) in listOf(a to b, b to a)) {
                val again = loser.groups.stageEditRecovery() ?: continue
                other.manager.ingest(assertNotNull(loser.groups.applyStaged(again).event).signedEvent)
            }
            for (d in listOf(a, b)) {
                d.groups.refresh()
                val roster = assertNotNull(d.groups.roster())
                assertEquals("Fork-A", roster.device(bSlot)?.label)
                assertEquals("Fork-B", roster.device(aSlot)?.label)
            }
        }

    // ---- 5: owed histories and kept deliveries survive a restart ---------------------------------

    @Test
    fun owedHistoriesAndKeptDeliveriesSurviveARestart() =
        runBlocking<Unit> {
            val keys = KeyPair()
            var a = Device(keys)
            var b = Device(keys)
            val c = Device(KeyPair(), deviceGroups = false)
            val chat = "d5".repeat(32)
            chatWithC(a, c, chat, listOf("one", "two"))
            link(a, b)
            val welcomes = addSibling(a, b, c)
            assertEquals(1, a.groups.owedHistoryCount())

            a = a.restarted()
            assertEquals(1, a.groups.owedHistoryCount(), "the owed history is still owed after a restart")
            val deliveries = a.groups.historyDeliveries(now)
            assertEquals(1, deliveries.size)
            assertEquals(0, a.restarted().groups.owedHistoryCount(), "and forgotten for good once sent")

            // B reads the delivery before its chat's Welcome, then restarts: the delivery waits on.
            b.ingest(deliveries)
            assertEquals(1, b.groups.keptHistoryCount())
            b = b.restarted()
            assertEquals(1, b.groups.keptHistoryCount())
            b.ingest(welcomes)
            assertEquals(0, b.groups.keptHistoryCount())
            assertEquals(listOf("one", "two"), texts(b, chat))
        }

    @Test
    fun theWorkRecordRoundTripsAndKeepsItsLayout() {
        val work =
            DeviceGroupWork(
                owed = listOf(DeviceGroupWork.OwedHistory("01".repeat(32), "02".repeat(32), 7)),
                kept = listOf(DeviceGroupWork.KeptDelivery("{}", ByteArray(32) { 3 }, ByteArray(32) { 4 }, 9)),
                edits = listOf(DeviceGroupWork.KeptEdit("05".repeat(32), "Phone", null, listOf("06".repeat(16)), listOf("07".repeat(16))), DeviceGroupWork.KeptEdit("08".repeat(32), "", 3, emptyList(), emptyList())),
                attachmentKeys = listOf(DeviceGroupWork.AttachmentKey("09".repeat(32), "0a".repeat(32), "0b".repeat(32))),
            )
        val bytes = work.encode()
        assertEquals(work, DeviceGroupWork.decode(bytes))
        // Version 1, frozen: a change here breaks every device that saved one.
        assertEquals(
            "014049200101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202" +
                "02020202020202020000000000000007404b027b7d030303030303030303030303030303030303030303030303030303030303030304040404040404" +
                "040404040404040404040404040404040404040404040404040000000000000009407105050505050505050505050505050505050505050505050505" +
                "050505050505050550686f6e650010060606060606060606060606060606061007070707070707070707070707070707080808080808080808080808" +
                "080808080808080808080808080808080808080800010000000300004061200909090909090909090909090909090909090909090909090909090909" +
                "0909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" +
                "0b0b0b0b0b0b0b",
            bytes.toHexKey(),
        )
        assertEquals(DeviceGroupWork(), DeviceGroupWork.decode(DeviceGroupWork().encode()))
    }

    @Test
    fun aTrustRecordWithoutAMoveIsStillVersionOne() {
        val plain = DeviceGroupTrust("aa".repeat(32), trustedGroupId = "bb".repeat(16), trustedNostrGroupId = "cc".repeat(32))
        val v1 = plain.encode()
        assertEquals(1, v1[0].toInt(), "no move fields: written as version 1, which older readers take")
        assertEquals(plain, DeviceGroupTrust.decode(v1))
        val moving =
            plain.copy(
                move = DeviceGroupTrust.Move("dd".repeat(16), "ee".repeat(32), "ff".repeat(32), "11".repeat(32)),
                movedFrom = DeviceGroupTrust.MovedFrom("22".repeat(16), "33".repeat(32)),
                carriedRejections = listOf(DeviceGroupTrust.CarriedRejection("44".repeat(32), RejectionReasonV1.REMOVED.code, 5, "55".repeat(32)), DeviceGroupTrust.CarriedRejection("66".repeat(32), RejectionReasonV1.NOT_ME.code, 6, null)),
            )
        val v2 = moving.encode()
        assertEquals(2, v2[0].toInt())
        assertEquals(moving, DeviceGroupTrust.decode(v2))
        assertContentEquals(v1, v2.copyOfRange(0, v1.size).also { it[0] = 1 }, "version 2 is version 1's fields, then the move")
    }

    // ---- 6: long histories through Blossom -------------------------------------------------------

    @Test
    fun aLongHistoryGoesThroughBlossomAndImports() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            val c = Device(KeyPair(), deviceGroups = false)
            val chat = "d6".repeat(32)
            val long = (0 until 260).map { "message $it " + "x".repeat(900) }
            chatWithC(a, c, chat, long)
            link(a, b)
            val welcomes = addSibling(a, b, c)

            val blobs = HashMap<String, ByteArray>()
            var failUploads = true
            a.groups.historyBlobUploader = { ciphertext ->
                if (failUploads) {
                    null
                } else {
                    blobs[HistoryDelivery.hash(ciphertext).toHexKey()] = ciphertext
                    listOf("http://127.0.0.1:1/")
                }
            }
            // An upload that fails leaves the history owed.
            assertTrue(a.groups.historyDeliveries(now).isEmpty())
            assertEquals(1, a.groups.owedHistoryCount())
            failUploads = false
            val deliveries = a.groups.historyDeliveries(now)
            assertEquals(0, a.groups.owedHistoryCount())
            assertTrue(deliveries.size in 1..MarmotDeviceGroupManager.MAX_HISTORY_BUNDLES)
            assertEquals(deliveries.size, blobs.size)

            b.ingest(welcomes)
            val fetched = ArrayList<String>()
            b.groups.historyBlobFetcher = { url, max ->
                fetched.add(url)
                blobs[url.substringAfterLast('/')]?.takeIf { it.size <= max }
            }
            b.ingest(deliveries)
            assertEquals(deliveries.size, b.groups.keptHistoryCount(), "a Blossom delivery waits for its fetch")
            b.groups.importKeptHistory(now)
            assertEquals(0, b.groups.keptHistoryCount())
            assertTrue(fetched.all { it.startsWith("http://127.0.0.1:1/") && it.length == "http://127.0.0.1:1/".length + 64 })
            assertEquals(long.sorted(), texts(b, chat), "the whole history arrived, past what inline deliveries hold")
        }

    // ---- 7: attachment keys and moderation grants ------------------------------------------------

    @Test
    fun historyCarriesAttachmentKeysAndModerationGrants() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            val c = Device(KeyPair(), deviceGroups = false)
            val chat = "d7".repeat(32)
            chatWithC(a, c, chat, listOf("before the picture"))
            // C sends a picture; A, an admin, removes another of C's messages.
            val plaintext = "a marmot in the snow".encodeToByteArray()
            val encrypted = c.manager.encryptMediaForSend(chat, plaintext, "image/jpeg", "marmot.jpg")
            val reference =
                EncryptedMediaReferenceV2(
                    locators = listOf(MediaLocatorV2(EncryptedMediaPolicyV2.INITIAL_LOCATOR_KIND, "https://blossom.invalid/x")),
                    ciphertextSha256 = encrypted.result.ciphertextSha256,
                    plaintextSha256 = encrypted.result.plaintextSha256,
                    nonce = encrypted.result.nonce,
                    mediaType = "image/jpeg",
                    filename = "marmot.jpg",
                )
            val picture = c.manager.buildMediaMessage(chat, reference, "look", sourceEpoch = encrypted.epoch)
            a.manager.ingest(picture.outbound.signedEvent)
            val spam = c.manager.buildTextMessage(chat, "spam")
            a.manager.ingest(spam.outbound.signedEvent)
            val removal = a.manager.buildAdminDeletionMessage(chat, spam.innerEvent.id)
            c.manager.ingest(removal.outbound.signedEvent)
            assertEquals(listOf(spam.innerEvent.id), a.manager.adminRemovalTargets(chat, removal.innerEvent))

            link(a, b)
            val welcomes = addSibling(a, b, c)
            val deliveries = a.groups.historyDeliveries(now)
            b.ingest(welcomes)
            b.ingest(deliveries)

            // B never held the picture's epoch: the key the history brought opens it.
            assertNull(b.manager.mediaSecretForMessage(chat, picture.innerEvent.id))
            val cipher = assertNotNull(b.manager.mediaCipherForMessage(chat, picture.innerEvent.id, reference))
            assertContentEquals(plaintext, cipher.decrypt(encrypted.result.ciphertext))
            assertNotNull(b.groups.importedFileKey(chat, reference.ciphertextSha256.toHexKey()))
            // The removal came with its grant: B applies it although it never knew the admins then.
            assertEquals(listOf(spam.innerEvent.id), b.manager.adminRemovalTargets(chat, removal.innerEvent))

            // The keys are kept across a restart.
            val again = b.restarted()
            assertNotNull(again.manager.mediaCipherForMessage(chat, picture.innerEvent.id, reference))
            assertNotEquals(0, plaintext.size)
            assertTrue(EncryptedMediaV2.KEY_LENGTH == 32)
        }

    // ---- 8: moving between device groups ---------------------------------------------------------

    @Test
    fun aDeviceMovesToAnotherDeviceGroup() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            val c = Device(keys)
            val d = Device(keys)
            val first = link(a, b)
            val second = link(c, d)
            assertNotEquals(first, second)
            // A's user said "This wasn't me" about a slot: the record B carries over.
            val stranger = "5a".repeat(32)
            b.manager.ingest(assertNotNull(a.groups.applyStaged(assertNotNull(a.groups.rejectSignIn(stranger, now))).event).signedEvent)

            // B moves to C's device group through an ordinary confirmed link.
            val linked = pair(c, b)
            val add = c.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B moved", now)
            val applied = c.groups.applyStaged(add)
            d.manager.ingest(assertNotNull(applied.event).signedEvent)
            assertIs<MarmotIngestResult.JoinedGroup>(b.manager.ingest(assertNotNull(applied.welcome).giftWrapEvent))
            assertTrue(b.groups.isMoving())
            assertEquals(first, b.groups.deviceGroupNostrId(), "the original group stays trusted until the move is made")
            assertTrue(b.groups.isOwnDeviceGroup(second), "the destination is a device group, never a chat")
            assertTrue(b.groups.firstCommitDue())

            val firstCommit = assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event)
            c.manager.ingest(firstCommit.signedEvent)
            d.manager.ingest(firstCommit.signedEvent)
            b.groups.refresh()
            assertEquals(second, b.groups.deviceGroupNostrId(), "made: the destination is the sole trusted group")
            assertTrue(!b.groups.isMoving())
            assertEquals(
                first,
                b.groups
                    .trust()
                    .movedFrom
                    ?.nostrGroupId,
            )

            // The carried rejection goes into the new roster.
            val carry = assertNotNull(b.groups.stageMoveFollowUp())
            val carried = assertNotNull(b.groups.applyStaged(carry).event)
            c.manager.ingest(carried.signedEvent)
            assertEquals(
                RejectionReasonV1.NOT_ME,
                c.groups
                    .roster()
                    ?.rejectedSlot(stranger)
                    ?.reason,
            )

            // Then B tells the old group it moved, and A cleans its entry up without rejecting it.
            val moved = assertNotNull(b.groups.applyStaged(assertNotNull(b.groups.stageMoveFollowUp())).event)
            a.manager.ingest(moved.signedEvent)
            assertEquals(
                DeviceStatusV1.MOVED,
                a.groups
                    .roster()
                    ?.device(b.slot())
                    ?.status,
            )
            val cleanup = assertNotNull(a.groups.applyStaged(assertNotNull(a.groups.stageMovedCleanup())).event)
            assertNull(a.groups.roster()?.device(b.slot()))
            assertNull(a.groups.roster()?.rejectedSlot(b.slot()), "a moved device is not rejected")
            b.manager.ingest(cleanup.signedEvent)
            assertNull(b.groups.stageMoveFollowUp())
            assertNull(b.groups.trust().movedFrom, "the old copy is discarded")
            assertNull(b.manager.groupManager.getGroup(first))
            assertEquals(second, b.groups.deviceGroupNostrId())
            assertTrue(!b.groups.trust().unlinked, "leaving the old group is not an unlink")
            assertEquals(
                setOf(c.slot(), d.slot(), b.slot()),
                c.groups
                    .roster()
                    ?.devices
                    ?.map { it.slot }
                    ?.toSet(),
            )
        }

    /**
     * The desktop's move in the live test: the old sibling (amy, one process per command) committed
     * twice while the moving device was busy joining, so the `moved` Commit lands on a parent the
     * old group already left. The longer branch wins on both sides, and the mover makes `moved`
     * again on it instead of discarding a copy whose `moved` nobody else holds.
     */
    @Test
    fun aMovedCommitThatLosesAForkIsMadeAgain() =
        runBlocking<Unit> {
            val keys = KeyPair()
            var a = Device(keys)
            val b = Device(keys)
            val c = Device(keys)
            val d = Device(keys)
            val first = link(a, b)
            val second = link(c, d)

            val linked = pair(c, b)
            val applied = c.groups.applyStaged(c.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B moved", now))
            d.manager.ingest(assertNotNull(applied.event).signedEvent)
            b.manager.ingest(assertNotNull(applied.welcome).giftWrapEvent)
            val firstCommit = assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event)
            c.manager.ingest(firstCommit.signedEvent)
            b.groups.refresh()
            assertEquals(second, b.groups.deviceGroupNostrId())

            // Meanwhile A, in the old group, commits twice; B has not seen either.
            val a1 = assertNotNull(a.groups.applyStaged(assertNotNull(a.groups.stageRename(a.slot(), "A1"))).event)
            val a2 = assertNotNull(a.groups.applyStaged(assertNotNull(a.groups.stageRename(a.slot(), "A2"))).event)
            val moved = assertNotNull(b.groups.applyStaged(assertNotNull(b.groups.stageMoveFollowUp())).event)

            // A hears of `moved` in a later run; B of A's two Commits after its own.
            a = a.restarted()
            a.manager.ingest(moved.signedEvent)
            b.manager.ingest(a1.signedEvent)
            b.manager.ingest(a2.signedEvent)
            for (dev in listOf(a, b)) dev.manager.driveConvergenceToSettlement(pollMs = 1)
            a.groups.refresh()
            b.groups.refresh()
            assertEquals(
                DeviceStatusV1.ACTIVE,
                a.groups
                    .roster()
                    ?.device(b.slot())
                    ?.status,
                "the longer branch, without `moved`, wins",
            )

            // B is still in the old group, on A's branch, and says `moved` again there.
            val again = assertNotNull(b.groups.stageMoveFollowUp(), "a `moved` that lost its fork is made again")
            assertEquals(first, again.nostrGroupId)
            a.manager.ingest(assertNotNull(b.groups.applyStaged(again).event).signedEvent)
            assertEquals(
                DeviceStatusV1.MOVED,
                a.groups
                    .roster()
                    ?.device(b.slot())
                    ?.status,
            )
            val cleanup = assertNotNull(a.groups.applyStaged(assertNotNull(a.groups.stageMovedCleanup())).event)
            b.manager.ingest(cleanup.signedEvent)
            assertNull(b.groups.stageMoveFollowUp())
            assertNull(b.manager.groupManager.getGroup(first), "the old copy goes once the old group lets it go")
            assertNull(a.groups.roster()?.device(b.slot()))
            assertEquals(
                "A2",
                a.groups
                    .roster()
                    ?.device(a.slot())
                    ?.label,
            )
        }

    @Test
    fun aMoveTheDestinationUndoesLeavesTheOriginalTrust() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            val c = Device(keys)
            val d = Device(keys)
            val first = link(a, b)
            link(c, d)
            val linked = pair(c, b)
            val applied = c.groups.applyStaged(c.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B", now))
            b.manager.ingest(assertNotNull(applied.welcome).giftWrapEvent)
            assertTrue(b.groups.isMoving())
            // No first Commit within the hour: C undoes the link.
            val undo = assertNotNull(c.groups.checkLinkDeadlines(now + MarmotDeviceGroupManager.FIRST_COMMIT_DEADLINE_SECS))
            b.manager.ingest(assertNotNull(c.groups.applyStaged(undo).event).signedEvent)
            b.groups.refresh()
            assertTrue(!b.groups.isMoving())
            assertEquals(first, b.groups.deviceGroupNostrId(), "the original trust is unchanged")
            assertTrue(!b.groups.trust().unlinked)
        }
}
