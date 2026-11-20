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

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.marmot.appComponents.AccountDevicesV1
import com.vitorpamplona.marmot.appComponents.AppComponentIds
import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.appComponents.MarmotProtocolProfile
import com.vitorpamplona.marmot.appComponents.accountIdentityProof.AccountIdentityProofV2
import com.vitorpamplona.marmot.features.devicePairing.MarmotDevicePairingKinds
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotCommitClass
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageFetcher
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageUtils
import com.vitorpamplona.marmot.mip00KeyPackages.buildCurrentProfileFrom
import com.vitorpamplona.marmot.mip01Groups.MlsCiphersuite
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentData
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.quartz.marmot.mip00KeyPackages.KeyPackageEvent
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSigner
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The receipt rules MDK applies on every send, ingest and convergence replay
 * that an audit of the account-devices work found missing or divergent: the
 * account identity proof of every leaf a commit introduces, admin SelfRemove,
 * the admin–leaf coupling, the account-devices requirement on the legacy
 * profile, and same-account commits that must carry nothing but their own
 * proposals.
 *
 * A hostile or buggy sender is played by a group restored under
 * [Unchecked], Marmot's policy with its local refusals switched off, so the
 * bytes it produces are exactly what such a client could publish.
 */
@OptIn(ExperimentalEncodingApi::class)
class MarmotReceiptRulesTest {
    private val nostrGroupId = "b".repeat(64)

    private class Device(
        keyPair: KeyPair = KeyPair(),
        supported: List<Int> = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS,
    ) {
        val signer = NostrSignerInternal(keyPair)
        val manager = MarmotManager(signer, SnapshotStateStore(), SnapshotMessageStore(), SnapshotBundleStore(), publisher = ACCEPTING_RELAY, supportedComponents = supported)
        val pubKey get() = signer.pubKey

        fun group(nostrGroupId: HexKey) = manager.groupManager.getGroup(nostrGroupId)!!

        /** A copy of this device's group under [policy], to build or receive bytes without touching the manager. */
        fun copy(
            nostrGroupId: HexKey,
            policy: MlsGroupPolicy = MarmotGroupPolicy,
        ) = MlsGroup.restore(group(nostrGroupId).saveState(), policy)
    }

    /** Marmot's rules minus the sender-side refusals a hostile client would skip. */
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

        override fun authorizeSelfRemove(group: GroupView) = Unit

        override fun authorizeProposal(
            group: GroupView,
            proposal: PendingProposal,
        ) = Unit
    }

    private val unsupported = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AccountDevicesV1.COMPONENT_ID

    private suspend fun found(
        creator: Device,
        invitees: List<Device>,
        admins: List<Device> = emptyList(),
    ) {
        creator.manager.createCurrentProfileGroup(
            nostrGroupId = nostrGroupId,
            relays = listOf("wss://relay.invalid"),
            profile = GroupProfileV1("receipt", ""),
            additionalAdmins = admins.map { it.pubKey.hexToByteArray() },
        )
        if (invitees.isEmpty()) return
        val (_, welcomes) = creator.manager.addMembers(nostrGroupId, invitees.map { it.manager.generateKeyPackageEvent(relays = emptyList()) }, emptyList())
        invitees.zip(welcomes).forEach { (device, welcome) -> assertIs<MarmotIngestResult.JoinedGroup>(device.manager.ingest(welcome.giftWrapEvent)) }
    }

    private suspend fun keyPackageBytes(device: Device): ByteArray = KeyPackageUtils.decodeKeyPackage(Base64.decode(device.manager.generateKeyPackageEvent(relays = emptyList()).content)).toTlsBytes()

    /**
     * A current-profile KeyPackage claiming [account], whose `0x8009` entry is
     * [proofBy]'s proof over the leaf key (null: no proof at all), with
     * [keyPackageEntries] in the KeyPackage-level dictionary.
     */
    private suspend fun keyPackageClaiming(
        account: HexKey,
        proofBy: NostrSigner?,
        keyPackageEntries: List<ComponentData> = emptyList(),
    ): KeyPackageBundle {
        val leafKeys = Ed25519.generateKeyPair()
        val entries =
            mutableListOf(
                ComponentData(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(CurrentProfileGroupFactory.SUPPORTED_COMPONENTS)),
                ComponentData(ComponentsList.SAFE_AAD_ID, ComponentsList.encode(emptyList())),
            )
        if (proofBy != null) {
            entries.add(ComponentData(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2, AccountIdentityProofV2.create(proofBy, MlsCiphersuite.DEFAULT, leafKeys.publicKey).encode()))
        }
        return MlsGroup.createKeyPackage(
            identity = account.hexToByteArray(),
            policy = MarmotGroupPolicy,
            leafSignatureKeyPair = leafKeys,
            leafExtensions = listOf(AppDataDictionary(entries).toExtension()),
            capabilities = MarmotCapabilities.currentProfileLeaf(),
            keyPackageExtensions = if (keyPackageEntries.isEmpty()) emptyList() else listOf(AppDataDictionary(keyPackageEntries).toExtension()),
        )
    }

    // --- the account identity proof (audit #1) ---

    @Test
    fun aNonAdminSameAccountAddWithAValidProofIsAccepted() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            found(alice, listOf(bobPhone, bobLaptop))

            val tablet = keyPackageBytes(Device(bobKeys))
            val commit = bobLaptop.copy(nostrGroupId).addMember(tablet)

            val received = alice.copy(nostrGroupId)
            received.processFramedCommit(commit.framedCommitBytes)
            assertEquals(2L, received.epoch)
            assertEquals(4, received.memberCount)
        }

    @Test
    fun aSameAccountAddWithoutAProofIsRefused() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            found(alice, listOf(bobPhone, bobLaptop))

            val rogue = keyPackageClaiming(bobLaptop.pubKey, proofBy = null)
            // Our own client refuses to build it...
            assertFailsWith<IllegalStateException> { bobLaptop.copy(nostrGroupId).addMember(rogue.keyPackage.toTlsBytes()) }
            // ...and every member refuses it from a client that did.
            val commit = bobLaptop.copy(nostrGroupId, Unchecked).addMember(rogue.keyPackage.toTlsBytes())
            val received = alice.copy(nostrGroupId)
            assertFailsWith<IllegalStateException> { received.processFramedCommit(commit.framedCommitBytes) }
            assertEquals(1L, received.epoch)
            assertEquals(3, received.memberCount)
        }

    @Test
    fun aSameAccountAddWithAForgedProofIsRefused() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            found(alice, listOf(bobPhone, bobLaptop))

            // Claims bob's account, but the proof is mallory's: whoever holds a
            // leaf's MLS key cannot sign for the account.
            val mallory = NostrSignerInternal(KeyPair())
            val rogue = keyPackageClaiming(bobLaptop.pubKey, proofBy = mallory)
            val commit = bobLaptop.copy(nostrGroupId, Unchecked).addMember(rogue.keyPackage.toTlsBytes())
            assertEquals(MarmotCommitClass.SAME_ACCOUNT, MarmotCommitClass.of(bobLaptop.group(nostrGroupId).view(), listOf(PendingProposal(Proposal.Add(rogue.keyPackage), bobLaptop.group(nostrGroupId).leafIndex)), bobLaptop.group(nostrGroupId).leafIndex, true))

            for (member in listOf(alice, bobPhone)) {
                val received = member.copy(nostrGroupId)
                assertFailsWith<IllegalStateException> { received.processFramedCommit(commit.framedCommitBytes) }
                assertEquals(1L, received.epoch)
            }
        }

    @Test
    fun anAdminsAddOfAForgedLeafIsRefusedToo() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))
            val carol = NostrSignerInternal(KeyPair())
            val rogue = keyPackageClaiming(carol.pubKey, proofBy = NostrSignerInternal(KeyPair()))
            val commit = alice.copy(nostrGroupId, Unchecked).addMember(rogue.keyPackage.toTlsBytes())
            assertFailsWith<IllegalStateException> { bob.copy(nostrGroupId).processFramedCommit(commit.framedCommitBytes) }
        }

    // --- account-devices data (audit #12) ---

    @Test
    fun aCommitCarrying0x800dDataIsRefusedOnReceipt() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))

            // An AppDataUpdate on 0x800d, from the admin.
            val hostile = alice.copy(nostrGroupId, Unchecked)
            hostile.proposeAppDataUpdate(AccountDevicesV1.COMPONENT_ID, byteArrayOf(1))
            val update = hostile.commit()
            assertFailsWith<IllegalStateException> { bob.copy(nostrGroupId).processFramedCommit(update.framedCommitBytes) }

            // A KeyPackage-level 0x800d entry on an Add.
            val carol = NostrSignerInternal(KeyPair())
            val carrying = keyPackageClaiming(carol.pubKey, proofBy = carol, keyPackageEntries = listOf(ComponentData(AccountDevicesV1.COMPONENT_ID, ByteArray(0))))
            val add = alice.copy(nostrGroupId, Unchecked).addMember(carrying.keyPackage.toTlsBytes())
            assertFailsWith<IllegalStateException> { bob.copy(nostrGroupId).processFramedCommit(add.framedCommitBytes) }
        }

    @Test
    fun aGroupInfoCarrying0x800dIsRefusedOnJoin() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))
            val extensions = alice.group(nostrGroupId).extensions
            val ids = listOf(alice.pubKey, bob.pubKey)
            val view = GroupView(extensions, ids.size, 1, { ids.getOrNull(it) }, { null }, { null })
            MarmotGroupPolicy.validateJoin(view, 0, emptyList())
            val groupInfo = listOf(AppDataDictionary(listOf(ComponentData(AccountDevicesV1.COMPONENT_ID, ByteArray(0)))).toExtension())
            assertFailsWith<IllegalStateException> { MarmotGroupPolicy.validateJoin(view, 0, groupInfo) }
        }

    // --- the legacy profile (audit #2) ---

    /** RFC 9420 `required_capabilities` requiring [extensionTypes]. */
    private fun requiredCapabilities(extensionTypes: List<Int>): Extension {
        val writer = TlsWriter()
        writer.putOpaqueVarInt(TlsWriter().apply { extensionTypes.forEach { putUint16(it) } }.toByteArray())
        writer.putOpaqueVarInt(ByteArray(0))
        writer.putOpaqueVarInt(TlsWriter().apply { putUint16(Credential.CREDENTIAL_TYPE_BASIC) }.toByteArray())
        return Extension(MlsGroup.REQUIRED_CAPABILITIES_EXTENSION_TYPE, writer.toByteArray())
    }

    private fun appComponents(ids: List<Int>) = AppDataDictionary(listOf(ComponentData(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(ids)))).toExtension()

    @Test
    fun accountDevicesInALegacyRequiredListChangesNothing() {
        val legacyProof = requiredCapabilities(listOf(AppDataDictionary.EXTENSION_TYPE, MarmotProtocolProfile.LEGACY_ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE))
        val current = requiredCapabilities(listOf(AppDataDictionary.EXTENSION_TYPE))

        // The current profile: 0x8009 required, no 0xf2f1.
        assertTrue(AccountDevicesV1.isRequired(listOf(current, appComponents(listOf(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2, AccountDevicesV1.COMPONENT_ID)))))
        // The legacy profile lists it: not required.
        assertFalse(AccountDevicesV1.isRequired(listOf(legacyProof, appComponents(listOf(AccountDevicesV1.COMPONENT_ID)))))
        // Both profiles at once, or neither: fail closed.
        assertFalse(AccountDevicesV1.isRequired(listOf(legacyProof, appComponents(listOf(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2, AccountDevicesV1.COMPONENT_ID)))))
        assertFalse(AccountDevicesV1.isRequired(listOf(current, appComponents(listOf(AccountDevicesV1.COMPONENT_ID)))))

        // So a non-admin's same-account Remove there needs an admin.
        val account = "e".repeat(64)
        val ids = listOf("a".repeat(64), account, account)
        val legacy = listOf(legacyProof, appComponents(listOf(AccountDevicesV1.COMPONENT_ID)))
        val view = GroupView(legacy, ids.size, 1, { ids.getOrNull(it) }, { null }, { null })
        assertEquals(MarmotCommitClass.ADMIN_REQUIRED, MarmotCommitClass.of(view, listOf(PendingProposal(Proposal.Remove(2), 1)), 1, true))
    }

    // --- same-account commits carry only their own proposals (audit #3) ---

    @Test
    fun removingOwnDevicesLeavesAPeersPooledSelfRemoveOut() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            val dave = Device()
            found(alice, listOf(bobPhone, bobLaptop, dave))

            val leaving = assertNotNull(dave.manager.leave(nostrGroupId).selfRemove)
            assertIs<MarmotIngestResult.ProposalStaged>(bobLaptop.manager.ingest(leaving.signedEvent))

            val phoneLeaf = bobPhone.group(nostrGroupId).leafIndex
            val commit = bobLaptop.manager.removeOwnAccountDevices(nostrGroupId, listOf(phoneLeaf))
            assertIs<MarmotIngestResult.Commit>(alice.manager.ingest(commit.signedEvent))
            assertEquals(2L, alice.manager.groupEpoch(nostrGroupId))
            // Bob's phone is gone; dave's departure waits for the next commit.
            assertEquals(3, alice.manager.memberCount(nostrGroupId))
            assertTrue(alice.manager.leafIndicesOf(nostrGroupId, dave.pubKey).isNotEmpty())
        }

    @Test
    fun theActivationCommitRemovesALingering0x800dEntry() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            val carol = Device(supported = unsupported)
            found(alice, listOf(bob, carol))
            assertFalse(alice.manager.requiresAccountDevices(nostrGroupId))

            // Before the group requires it, a 0x800d entry is an unknown component's data.
            val staged = alice.manager.groupManager.stageAppDataUpdate(nostrGroupId, AccountDevicesV1.COMPONENT_ID, byteArrayOf(9))
            alice.manager.groupManager.installState(nostrGroupId, staged.pendingState)
            alice.manager.removeAccount(nostrGroupId, carol.pubKey)
            assertTrue(alice.group(nostrGroupId).appDataDictionary().contains(AccountDevicesV1.COMPONENT_ID))

            assertNull(alice.manager.accountDevicesActivationBlocker(nostrGroupId))
            alice.manager.requireAccountDevices(nostrGroupId)
            assertTrue(alice.manager.requiresAccountDevices(nostrGroupId))
            assertFalse(alice.group(nostrGroupId).appDataDictionary().contains(AccountDevicesV1.COMPONENT_ID))
        }

    @Test
    fun aFoundingAddThatBreaksTheComponentsRulesIsRefused() =
        runBlocking<Unit> {
            // Every founder advertises 0x800d, so the group must require it; a
            // KeyPackage carrying 0x800d data then breaks its rules, and the
            // creation is refused rather than quietly not requiring it.
            val alice = Device()
            val carol = NostrSignerInternal(KeyPair())
            val bundle = keyPackageClaiming(carol.pubKey, proofBy = carol, keyPackageEntries = listOf(ComponentData(ComponentsList.LAST_RESORT_KEY_PACKAGE_ID, ByteArray(0)), ComponentData(AccountDevicesV1.COMPONENT_ID, ByteArray(0))))
            val event = carol.sign(KeyPackageEvent.buildCurrentProfileFrom(bundle.keyPackage, "f".repeat(64)))
            alice.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))
            assertFailsWith<IllegalStateException> { alice.manager.addMembers(nostrGroupId, listOf(event), emptyList()) }
            assertEquals(0L, alice.manager.groupEpoch(nostrGroupId))
        }

    // --- admin SelfRemove and the admin–leaf coupling (audit #4) ---

    @Test
    fun anAdminsSelfRemoveIsRefusedOnArrival() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            val carol = Device()
            found(alice, listOf(bob, carol), admins = listOf(carol))

            val (proposal, _) = carol.copy(nostrGroupId, Unchecked).buildSelfRemoveProposalMessage()
            val received = alice.copy(nostrGroupId)
            assertFailsWith<IllegalStateException> { received.processMessage(proposal) }
            assertFalse(received.hasPendingProposals())

            // And a commit that carries one is refused, whoever commits it.
            val view = alice.group(nostrGroupId).view()
            val carolLeaf = carol.group(nostrGroupId).leafIndex
            val bobLeaf = bob.group(nostrGroupId).leafIndex
            assertFailsWith<IllegalStateException> { MarmotGroupPolicy.authorizeCommit(view, listOf(PendingProposal(Proposal.SelfRemove(), carolLeaf)), bobLeaf) }
            // A non-admin's SelfRemove is still fine.
            MarmotGroupPolicy.authorizeCommit(view, listOf(PendingProposal(Proposal.SelfRemove(), bobLeaf)), carolLeaf)
        }

    @Test
    fun removingAnAdminsLastLeafMustDropItsAdminSeat() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            val carol = Device()
            found(alice, listOf(bob, carol), admins = listOf(carol))
            val carolLeaf = carol.group(nostrGroupId).leafIndex

            // A bare Remove of carol's only leaf leaves an admin without a leaf.
            assertFailsWith<IllegalStateException> { alice.manager.removeMember(nostrGroupId, carolLeaf) }
            val hostile = alice.copy(nostrGroupId, Unchecked).removeMember(carolLeaf)
            assertFailsWith<IllegalStateException> { bob.copy(nostrGroupId).processFramedCommit(hostile.framedCommitBytes) }

            // Removing the account drops the seat in the same commit.
            val commit = alice.manager.removeAccount(nostrGroupId, carol.pubKey)
            assertIs<MarmotIngestResult.Commit>(bob.manager.ingest(commit.signedEvent))
            assertEquals(listOf(alice.pubKey), bob.manager.groupView(nostrGroupId)!!.adminPubkeys)
        }

    // --- small API pieces ---

    @Test
    fun theOldInviteLookupConstructorStillBuilds() {
        @Suppress("DEPRECATION")
        val lookup = KeyPackageFetcher.InviteLookup(null, emptySet())
        assertTrue(lookup.keyPackages.isEmpty())
        assertNull(lookup.keyPackage)
    }

    @Test
    fun devicePairingKindsAreNamed() {
        assertEquals(452..456, MarmotDevicePairingKinds.ALL)
        assertTrue(MarmotDevicePairingKinds.isPairingKind(MarmotDevicePairingKinds.CANCEL))
        assertFalse(MarmotDevicePairingKinds.isPairingKind(457))
    }

    @Test
    fun aPolicyGetsACopyOfTheLeaf() =
        runBlocking<Unit> {
            val alice = Device()
            found(alice, listOf(Device()))
            val group = alice.group(nostrGroupId)
            val leaf = assertNotNull(group.view().leafNode(group.leafIndex))
            val key = leaf.signatureKey.copyOf()
            leaf.signatureKey.fill(0)
            assertContentEquals(key, assertNotNull(group.view().leafNode(group.leafIndex)).signatureKey)
        }
}
