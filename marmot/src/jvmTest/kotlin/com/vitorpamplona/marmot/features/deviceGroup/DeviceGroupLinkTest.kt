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

import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.appComponents.DeviceRosterRules
import com.vitorpamplona.marmot.appComponents.DeviceRosterV1
import com.vitorpamplona.marmot.appComponents.DeviceTagV1
import com.vitorpamplona.marmot.client.SnapshotStateStore
import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.marmot.features.devicePairing.ExistingDevicePairing
import com.vitorpamplona.marmot.features.devicePairing.NewDevicePairing
import com.vitorpamplona.marmot.features.devicePairing.PairingDelivery
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.groups.MlsGroupManager
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two devices of one account link end to end, in process: the seven-emoji pairing over self-addressed
 * gift wraps, the device group's founding Add with the new device's roster entry (a roster diff that
 * only resolves through mls-kmp's `resolveAppDataUpdate`), the new device's join through its link's
 * Welcome, and its first Commit, which sets its tag key and tags its leaf (MDK
 * `cgka-engine/tests/account_devices/link_device.rs`, `device_group_welcome.rs`).
 */
class DeviceGroupLinkTest {
    private val now = 1_800_000_000L
    private val keys = KeyPair()
    private val laptopSlot = "1a".repeat(32)
    private val phoneSlot = "2b".repeat(32)

    private inner class Device(
        val slot: HexKeyAlias,
    ) {
        val signer = NostrSignerInternal(keys)
        val groups = MlsGroupManager(SnapshotStateStore(), CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS)
        val trust = InMemoryDeviceGroupTrustStore()
        val deviceGroups = MarmotDeviceGroupManager(signer, groups, trust, slot, listOf("wss://relay.invalid"))
    }

    private class Linked(
        val link: ConfirmedLink,
        val bundle: KeyPackageBundle,
    )

    /** The phone publishes a device-group-capable KeyPackage and pairs with the laptop. */
    private suspend fun pair(
        laptop: Device,
        phone: Device,
    ): Linked {
        val bundle = CurrentProfileGroupFactory.createKeyPackage(phone.signer, lastResort = false, supportedComponents = CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS)
        val kpRef = bundle.keyPackage.reference().toHexKey()
        val kpEvent = "e7".repeat(32)
        val account = phone.signer.pubKey
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, now)
        val existing = ExistingDevicePairing(account, laptop.slot)

        suspend fun hop(
            m: com.vitorpamplona.marmot.features.devicePairing.PairingMessage,
            from: Device,
            to: Device,
        ) = assertNotNull(PairingDelivery.unwrap(PairingDelivery.wrap(m, from.signer, now), to.signer)).message

        existing.receive(hop(newDevice.requestMessage, phone, laptop), now, now)
        val answer = existing.answer(newDevice.sessionId, ExistingDevicePairing.PublishedKeyPackage(kpEvent, kpRef), now)
        val reveal = assertIs<NewDevicePairing.Event.Reveal>(newDevice.receive(hop(answer, laptop, phone), now)).reveal
        existing.receive(hop(reveal, phone, laptop), now, now)
        val (groupId, signatureKey) = laptop.deviceGroups.confirmTarget()
        newDevice.receive(hop(existing.confirmLink(newDevice.sessionId, groupId, signatureKey, now), laptop, phone), now)
        val linked = assertIs<NewDevicePairing.Confirmation.Linked>(newDevice.confirmMatch(now))
        phone.deviceGroups.recordLink(linked.link, now)
        val done = assertIs<ExistingDevicePairing.Event.Linked>(existing.receive(hop(linked.confirm, phone, laptop), now, now))
        assertEquals(linked.link, done.link)
        return Linked(done.link, bundle)
    }

    @Test
    fun twoDevicesLinkAndAgreeOnTheRoster() =
        runBlocking<Unit> {
            val laptop = Device(laptopSlot)
            val phone = Device(phoneSlot)
            val linked = pair(laptop, phone)

            // The laptop trusts no device group yet: it creates one and adds the phone in the founding Add.
            val founding = laptop.deviceGroups.approve(linked.link, linked.bundle.keyPackage.toTlsBytes(), phoneSlot, "Phone", now)
            laptop.deviceGroups.applyStaged(founding)
            val nostrId = founding.nostrGroupId
            assertTrue(laptop.deviceGroups.isDeviceGroup(nostrId))

            assertEquals(nostrId, phone.deviceGroups.joinLinkWelcome(assertNotNull(founding.welcomeBytes), linked.bundle, now))
            assertNull(phone.deviceGroups.trust().pendingLink)
            // Until its first Commit the phone's entry has no tag key and its leaf is unclaimed.
            assertNull(
                phone.deviceGroups
                    .roster()!!
                    .device(phoneSlot)!!
                    .tagSignatureKey,
            )
            assertEquals(
                DeviceGroupTrust.Outcome.PENDING,
                laptop.deviceGroups
                    .trust()
                    .approvals
                    .single()
                    .outcome,
            )

            val first = phone.deviceGroups.stageFirstCommit()
            laptop.deviceGroups.processCommit(nostrId, first.framedCommitBytes)
            phone.deviceGroups.applyStaged(first)

            val laptopGroup = laptop.groups.getGroup(nostrId)!!
            val phoneGroup = phone.groups.getGroup(nostrId)!!
            assertEquals(laptopGroup.epoch, phoneGroup.epoch)
            assertContentEquals(laptopGroup.epochAuthenticator, phoneGroup.epochAuthenticator)
            val laptopBytes = AppDataDictionary.fromExtensionsOrEmpty(laptopGroup.view().extensions)[DeviceRosterV1.COMPONENT_ID]!!
            val phoneBytes = AppDataDictionary.fromExtensionsOrEmpty(phoneGroup.view().extensions)[DeviceRosterV1.COMPONENT_ID]!!
            assertContentEquals(laptopBytes, phoneBytes)

            val roster = DeviceRosterV1.decode(laptopBytes)
            assertEquals(listOf(laptopSlot, phoneSlot), roster.devices.map { it.slot })
            val laptopEntry = roster.device(laptopSlot)!!
            val phoneEntry = roster.device(phoneSlot)!!
            assertNull(laptopEntry.linkedBy)
            assertNotNull(laptopEntry.tagSignatureKey)
            assertEquals(laptopSlot, phoneEntry.linkedBy)
            assertEquals("Phone", phoneEntry.label)
            assertEquals(linked.link.keyPackageRef, phoneEntry.announcedKeyPackage)
            assertNotNull(phoneEntry.tagSignatureKey)
            assertTrue(phoneEntry.addToAllChats && phoneEntry.bringHistory && !phoneEntry.keepWhileInactive)

            // The link is made, and both devices read both leaves as whose they are.
            assertEquals(
                DeviceGroupTrust.Outcome.MADE,
                laptop.deviceGroups
                    .trust()
                    .approvals
                    .single()
                    .outcome,
            )
            for (device in listOf(laptop, phone)) {
                assertEquals(setOf(DeviceTagV1.Claim.Device(laptopSlot), DeviceTagV1.Claim.Device(phoneSlot)), device.deviceGroups.claims(nostrId).toSet())
            }
            assertEquals("hi", laptopGroup.decrypt(phoneGroup.encrypt("hi".encodeToByteArray())).content.decodeToString())
        }

    @Test
    fun aWelcomeFromAnotherLeafIsRefusedAndLeavesTheLinkWaiting() =
        runBlocking<Unit> {
            val laptop = Device(laptopSlot)
            val phone = Device(phoneSlot)
            val linked = pair(laptop, phone)

            // Someone holding the account key founds a device group under the same id from another leaf.
            val forger = Device("3c".repeat(32))
            forger.deviceGroups.confirmTarget()
            val forgedLink = linked.link.copy(deviceGroupId = forger.deviceGroups.confirmTarget().first, welcomeSenderKey = forger.deviceGroups.confirmTarget().second)
            val forged = forger.deviceGroups.approve(forgedLink, linked.bundle.keyPackage.toTlsBytes(), phoneSlot, "Phone", now)
            assertFails { phone.deviceGroups.joinLinkWelcome(forged.welcomeBytes!!, linked.bundle, now) }
            assertNull(phone.deviceGroups.trust().trustedGroupId)
            assertNotNull(phone.deviceGroups.trust().pendingLink)

            // The real one still joins, with the same KeyPackage.
            val real = laptop.deviceGroups.approve(linked.link, linked.bundle.keyPackage.toTlsBytes(), phoneSlot, "Phone", now)
            phone.deviceGroups.joinLinkWelcome(real.welcomeBytes!!, linked.bundle, now)
            assertEquals(linked.link.deviceGroupId, phone.deviceGroups.trust().trustedGroupId)
        }

    @Test
    fun aDeviceGroupIsNeverJoinedThroughAnOrdinaryWelcomeOrAfterTheWait() =
        runBlocking<Unit> {
            val laptop = Device(laptopSlot)
            val phone = Device(phoneSlot)
            val linked = pair(laptop, phone)
            val founding = laptop.deviceGroups.approve(linked.link, linked.bundle.keyPackage.toTlsBytes(), phoneSlot, "Phone", now)
            // Marmot's own policy, as a chat Welcome is joined, refuses a group that requires 0x800e.
            assertFails { MlsGroup.processWelcome(founding.welcomeBytes!!, linked.bundle, MarmotGroupPolicy) }
            // And the link's Welcome no longer joins once the wait is over.
            assertFails { phone.deviceGroups.joinLinkWelcome(founding.welcomeBytes!!, linked.bundle, now + MarmotDeviceGroupManager.LINK_WAIT_SECS) }
        }

    @Test
    fun aDeviceGroupKeepsItsRequirementAndOneAccount() =
        runBlocking<Unit> {
            val laptop = Device(laptopSlot)
            val phone = Device(phoneSlot)
            val linked = pair(laptop, phone)
            val founding = laptop.deviceGroups.approve(linked.link, linked.bundle.keyPackage.toTlsBytes(), phoneSlot, "Phone", now)
            laptop.deviceGroups.applyStaged(founding)
            val nostrId = founding.nostrGroupId

            // Another account's KeyPackage never joins a device group, even from its only admin.
            val stranger = NostrSignerInternal(KeyPair())
            val strangerKp = CurrentProfileGroupFactory.createKeyPackage(stranger, lastResort = false, supportedComponents = CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS)
            assertReason("one account") {
                laptop.groups.stageOwn(nostrId) {
                    it.proposeAdd(strangerKp.keyPackage.toTlsBytes())
                    it.commit()
                }
            }

            // The requirement is never dropped, and the roster is never removed.
            val required = ComponentsList.supportedOrRequired(laptop.groups.getGroup(nostrId)!!.appDataDictionary())
            assertReason("from its creation or never") {
                laptop.groups.stageOwn(nostrId) {
                    it.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required - DeviceRosterV1.COMPONENT_ID))
                    it.commit()
                }
            }
            assertFails {
                laptop.groups.stageOwn(nostrId) {
                    it.proposeAppDataRemoval(DeviceRosterV1.COMPONENT_ID)
                    it.commit()
                }
            }
            // An update that does not apply to the parent roster is refused.
            assertReason("device roster") {
                laptop.groups.stageOwn(nostrId) {
                    it.proposeAppDataUpdate(DeviceRosterV1.COMPONENT_ID, byteArrayOf(0))
                    it.commit()
                }
            }
        }

    @Test
    fun noChatEverStartsRequiringTheRosterOrTheTag() =
        runBlocking<Unit> {
            val signer = NostrSignerInternal(KeyPair())
            val groups = MlsGroupManager(SnapshotStateStore(), CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS)
            val chat = CurrentProfileGroupFactory.createGroup(signer, ByteArray(32) { 7 }, listOf("wss://relay.invalid"), supportedComponents = CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS)
            val id = "07".repeat(32)
            groups.adoptGroup(id, chat)
            val required = ComponentsList.supportedOrRequired(chat.appDataDictionary())
            for (extra in listOf(DeviceRosterV1.COMPONENT_ID, DeviceTagV1.COMPONENT_ID)) {
                assertReason(if (extra == DeviceTagV1.COMPONENT_ID) "0x800f" else "from its creation or never") {
                    groups.stageOwn(id) {
                        it.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required + extra))
                        it.commit()
                    }
                }
            }
        }

    @Test
    fun theTrustRecordRoundTrips() {
        val link = ConfirmedLink("01".repeat(32), "02".repeat(32), "03".repeat(32), "04".repeat(16), "05".repeat(32), laptopSlot)
        val trust =
            DeviceGroupTrust(
                ownSlot = phoneSlot,
                trustedGroupId = "04".repeat(16),
                trustedNostrGroupId = "06".repeat(32),
                tagSigningSeed = "07".repeat(32),
                pendingLink = DeviceGroupTrust.PendingLink(link, now + 600),
                approvals = listOf(DeviceGroupTrust.Approval("08".repeat(32), now, DeviceGroupTrust.Outcome.MADE)),
            )
        assertEquals(trust, DeviceGroupTrust.decode(trust.encode()))
        assertEquals(DeviceGroupTrust(phoneSlot), DeviceGroupTrust.decode(DeviceGroupTrust(phoneSlot).encode()))
        // Version 1's layout, frozen: version, slot, three absent options, no link, no approvals.
        assertEquals("01" + phoneSlot + "00000000" + "00", DeviceGroupTrust(phoneSlot).encode().toHexKey())
        assertFails { DeviceGroupTrust.decode(DeviceGroupTrust(phoneSlot).encode() + byteArrayOf(0)) }
    }

    @Test
    fun theRosterResolvesAsADiffOnlyInADeviceGroup() {
        val roster = DeviceRosterV1("33".repeat(32))
        val update = byteArrayOf(9, 9)
        // Before a group requires 0x800e its bytes replace whole, as for clients that do not support it.
        assertContentEquals(update, DeviceRosterRules.resolveUpdate(emptyList(), DeviceRosterV1.COMPONENT_ID, roster.encode(), update))
        assertContentEquals(update, MarmotGroupPolicy.resolveAppDataUpdate(emptyList(), 0x8001, null, update))
    }
}

private typealias HexKeyAlias = String

private suspend fun assertReason(
    fragment: String,
    block: suspend () -> Unit,
) {
    val e =
        try {
            block()
            null
        } catch (e: Exception) {
            e
        }
    assertNotNull(e, "expected a refusal mentioning '$fragment'")
    assertTrue(generateSequence<Throwable>(e) { it.cause }.any { it.message?.contains(fragment) == true }, "refused for another reason: ${e.message}")
}
