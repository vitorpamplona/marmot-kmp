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
import com.vitorpamplona.marmot.client.ACCEPTING_RELAY
import com.vitorpamplona.marmot.client.MarmotIngestResult
import com.vitorpamplona.marmot.client.MarmotManager
import com.vitorpamplona.marmot.client.SnapshotBundleStore
import com.vitorpamplona.marmot.client.SnapshotMessageStore
import com.vitorpamplona.marmot.client.SnapshotStateStore
import com.vitorpamplona.marmot.client.ingest
import com.vitorpamplona.marmot.features.accountSync.HistoryBundles
import com.vitorpamplona.marmot.features.accountSync.HistoryDelivery
import com.vitorpamplona.marmot.features.accountSync.HistoryEvent
import com.vitorpamplona.marmot.features.accountSync.HistoryKeys
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
import com.vitorpamplona.quartz.nip01Core.signers.eventTemplate
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import com.vitorpamplona.quartz.nipC7Chats.ChatEvent
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
 * The roster fields a device writes for itself (client, platform, history key, its founding label),
 * renames, moving the device group to new relays, and history deliveries (kind 473) to a newly
 * linked device.
 */
@OptIn(ExperimentalEncodingApi::class)
class DeviceGroupHistoryTest {
    private val now = TimeUtils.now()
    private val relays = listOf("wss://relay.invalid")

    private inner class Device(
        keys: KeyPair,
        deviceGroups: Boolean = true,
        client: String = "",
        platform: String = "",
        relayProvider: (suspend () -> List<String>)? = null,
    ) {
        val signer = NostrSignerInternal(keys)
        val manager =
            MarmotManager(
                signer,
                SnapshotStateStore(),
                SnapshotMessageStore(),
                SnapshotBundleStore(),
                publisher = ACCEPTING_RELAY,
                deviceGroupConfig =
                    if (deviceGroups) {
                        MarmotDeviceGroupConfig(InMemoryDeviceGroupTrustStore(), InMemoryPrivateKeyPackageStore(), relays, relayProvider = relayProvider, client = client, platform = platform)
                    } else {
                        null
                    },
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

    /** A founds the device group with [ownLabel] for itself and links B; B's first Commit applied on both. */
    private suspend fun link(
        a: Device,
        b: Device,
        ownLabel: String = "",
    ): String {
        a.groups.start()
        b.groups.start()
        val linked = pair(a, b)
        val founding = a.groups.approve(linked.link, Base64.decode(linked.keyPackage.content), b.slot(), "B", now, ownLabel = ownLabel)
        val welcome = assertNotNull(a.groups.applyStaged(founding).welcome)
        assertIs<MarmotIngestResult.JoinedGroup>(b.manager.ingest(welcome.giftWrapEvent))
        a.manager.ingest(assertNotNull(b.groups.applyStaged(b.groups.stageFirstCommit()).event).signedEvent)
        return founding.nostrGroupId
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

    @Test
    fun eachDeviceWritesItsOwnClientPlatformAndHistoryKeyAndAnyDeviceRenames() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys, client = "amethyst", platform = "Desktop")
            val b = Device(keys, client = "amy", platform = "Linux")
            link(a, b, ownLabel = "Laptop")

            for (d in listOf(a, b)) {
                val roster = assertNotNull(d.groups.roster())
                val ea = assertNotNull(roster.device(a.slot()))
                val eb = assertNotNull(roster.device(b.slot()))
                assertEquals("Laptop", ea.label, "the founding entry carries the label the user gave")
                assertEquals("amethyst" to "Desktop", ea.client to ea.platform)
                assertEquals("B", eb.label)
                assertEquals("amy" to "Linux", eb.client to eb.platform, "the new device writes its own in its first Commit")
                assertNotNull(ea.historyKey)
                assertNotNull(eb.historyKey)
            }
            assertNull(a.groups.stageOwnEntryRefresh(), "an entry already current needs no update")

            // B renames A; the label and a fresh rename_id change, nothing else.
            val before = assertNotNull(b.groups.roster()?.device(a.slot()))
            val rename = assertNotNull(b.groups.stageRename(a.slot(), "Work laptop"))
            a.manager.ingest(assertNotNull(b.groups.applyStaged(rename).event).signedEvent)
            val after = assertNotNull(a.groups.roster()?.device(a.slot()))
            assertEquals("Work laptop", after.label)
            assertNotEquals(before.renameId, after.renameId)
            assertEquals(before.copy(label = after.label, renameId = after.renameId), after)
            assertNull(a.groups.stageRename(a.slot(), "Work laptop"), "renaming to the same label is a no-op")
        }

    @Test
    fun theDeviceGroupStartsOnTheProvidersRelaysAndMovesWithTheAccount() =
        runBlocking<Unit> {
            val keys = KeyPair()
            var accountRelays = listOf("wss://b.relay.invalid/", "wss://a.relay.invalid/")
            val a = Device(keys, relayProvider = { accountRelays })
            val b = Device(keys)
            val deviceGroup = link(a, b)
            assertEquals(listOf("wss://a.relay.invalid/", "wss://b.relay.invalid/"), a.manager.groupView(deviceGroup)?.relays)

            assertNull(a.groups.stageRelays(accountRelays), "the same relays need no Commit")
            accountRelays = listOf("wss://c.relay.invalid/")
            val move = assertNotNull(a.groups.stageRelays(accountRelays))
            b.manager.ingest(assertNotNull(a.groups.applyStaged(move).event).signedEvent)
            for (d in listOf(a, b)) assertEquals(listOf("wss://c.relay.invalid/"), d.manager.groupView(deviceGroup)?.relays)
            assertTrue(a.groups.isTrustedDeviceGroup(deviceGroup) && b.groups.isTrustedDeviceGroup(deviceGroup), "the group id is kept")
        }

    @Test
    fun aNewlyLinkedDeviceGetsTheEarlierMessagesOfTheChatsItIsAddedTo() =
        runBlocking<Unit> {
            val keys = KeyPair()
            val a = Device(keys)
            val b = Device(keys)
            val c = Device(KeyPair(), deviceGroups = false)
            // A chat A had, with messages from both sides, before B existed.
            val chat = "d4".repeat(32)
            a.manager.createCurrentProfileGroup(chat, relays, null)
            c.manager.ingest(
                a.manager
                    .addMemberInvites(chat, listOf(invite(c)), emptyList())
                    .second
                    .single()
                    .giftWrapEvent,
            )
            val fromC = c.manager.buildTextMessage(chat, "hello from C")
            a.manager.ingest(fromC.outbound.signedEvent)
            val fromA = a.manager.buildTextMessage(chat, "hi from A")
            c.manager.ingest(fromA.outbound.signedEvent)
            assertEquals(listOf("hello from C", "hi from A"), texts(a, chat))

            link(a, b)
            a.ingest(b.groups.topUpSiblings(now))
            val adds = a.groups.addNewDeviceToChats(b.slot(), now)
            assertEquals(1, adds.size)
            c.manager.ingest(
                adds
                    .single()
                    .result.event!!
                    .signedEvent,
            )
            assertEquals(1, a.groups.owedHistoryCount())

            // The deliveries go out before B has the chat: B keeps them until its sibling Welcome joins.
            val deliveries = a.groups.historyDeliveries(now)
            assertEquals(1, deliveries.size)
            assertEquals(0, a.groups.owedHistoryCount())
            b.ingest(deliveries).forEach { assertIs<MarmotIngestResult.Ignored>(it) }
            assertEquals(1, b.groups.keptHistoryCount())
            b.ingest(adds.single().deviceGroupEvents)
            assertTrue(b.manager.groupManager.isMember(chat))
            assertEquals(0, b.groups.keptHistoryCount())
            assertEquals(listOf("hello from C", "hi from A"), texts(b, chat))
            val imported = b.groups.drainImportedHistory().single()
            assertEquals(chat, imported.nostrGroupId)
            assertEquals(2, imported.events.size)
            assertTrue(imported.events.all { it is ChatEvent || it.kind != 9 }, "imported events are typed")
            assertEquals(imported.events.map { it.id }.toSet(), imported.epochs.keys)

            // Live traffic still reads after the import, and a second import adds nothing.
            val later = c.manager.buildTextMessage(chat, "after the link")
            assertIs<MarmotIngestResult.Message>(b.manager.ingest(later.outbound.signedEvent))
            b.ingest(deliveries)
            assertTrue(b.groups.drainImportedHistory().isEmpty())
            assertEquals(listOf("after the link", "hello from C", "hi from A"), texts(b, chat))
        }

    @Test
    fun aDeliveryIsTheExactEncodingAndOpensOnlyForItsReceiver() {
        val receiver = HistoryKeys.keyPair(ByteArray(32) { 7 })
        val other = HistoryKeys.keyPair(ByteArray(32) { 8 })
        val from = "aa".repeat(32)
        val to = "bb".repeat(32)
        val chat = "cc".repeat(16)
        val key = ByteArray(32) { 1 }
        val hash = ByteArray(32) { 2 }
        val sealed = HistoryDelivery.seal(receiver.publicKey, from, to, chat, key, hash)
        assertEquals(115, sealed.size, "a sealed key and hash under 0x0001 is 115 bytes")
        val delivery = HistoryDelivery(from, to, chat, sealed, byteArrayOf(1, 2, 3), null)
        val parsed = assertNotNull(HistoryDelivery.parse(delivery.content()))
        assertContentEquals(byteArrayOf(1, 2, 3), parsed.bundle)
        val opened = assertNotNull(HistoryDelivery.open(receiver.privateKey, from, to, chat, parsed.sealed))
        assertContentEquals(key, opened.first)
        assertContentEquals(hash, opened.second)
        assertNull(HistoryDelivery.open(other.privateKey, from, to, chat, parsed.sealed), "sealed to another device")
        assertNull(HistoryDelivery.open(receiver.privateKey, from, from, chat, parsed.sealed), "bound to its receiver")
        assertNull(HistoryDelivery.parse(delivery.content().replace(",\"to\"", ", \"to\"")), "whitespace drops it")
        assertNull(HistoryDelivery.parse(delivery.content().replace("\"v\":1", "\"v\":2")))
        val blossom = HistoryDelivery(from, to, chat, sealed, null, listOf("https://blossom.invalid"))
        assertEquals(listOf("https://blossom.invalid"), HistoryDelivery.parse(blossom.content())?.blossom)
        assertNull(HistoryDelivery.parse(blossom.content().replace("https://blossom.invalid", "https://blossom.invalid?x=1")))
    }

    @Test
    fun aLongHistorySplitsIntoConsecutiveStretches() {
        val signer = NostrSignerInternal(KeyPair())
        val chat = "ee".repeat(16)
        val events =
            (0 until 60).map { i ->
                val rumor = RumorAssembler.assembleRumor<Event>(signer.pubKey, eventTemplate<Event>(kind = 9, description = "x".repeat(900) + i, createdAt = 1_000L + i) {})
                HistoryEvent(rumor, epoch = 1)
            }
        val bundles = HistoryBundles.split(chat, events)
        assertTrue(bundles.size > 1)
        val parsed = bundles.map { assertNotNull(HistoryBundles.parse(it, chat, now)) }
        assertTrue(bundles.all { it.encodeToByteArray().size <= HistoryBundles.INLINE_MAX_PLAINTEXT })
        for (i in 1 until parsed.size) assertEquals(parsed[i - 1].to, parsed[i].from)
        assertEquals(events.map { it.event.id }.toSet(), parsed.flatMap { b -> b.events.map { it.event.id } }.toSet())
        assertNull(HistoryBundles.parse(bundles.first(), "ff".repeat(16), now), "a bundle for another chat is dropped")
        assertNull(HistoryBundles.parse(bundles.first().replaceFirst("\"v\":1", "\"v\":1,\"v\":1"), chat, now), "a repeated member drops it")
        val tampered = bundles.first().replaceFirst("x", "y")
        assertTrue(HistoryBundles.parse(tampered, chat, now)!!.events.size < parsed.first().events.size, "an event whose id does not match is left out")
    }
}
