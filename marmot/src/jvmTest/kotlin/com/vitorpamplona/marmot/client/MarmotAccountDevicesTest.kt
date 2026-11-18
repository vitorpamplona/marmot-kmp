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
import com.vitorpamplona.marmot.appComponents.accountIdentityProof.AccountIdentityProofV2
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotCommitClass
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.mip00KeyPackages.buildCurrentProfileFrom
import com.vitorpamplona.marmot.mip01Groups.MlsCiphersuite
import com.vitorpamplona.marmot.protocolCore.MlsCandidateStateEngine
import com.vitorpamplona.marmot.protocolCore.TipPriority
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentData
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.quartz.marmot.mip00KeyPackages.KeyPackageEvent
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * `marmot.group.account-devices.v1` (`0x800d`): what MDK 0.15+ puts into every
 * group whose founders all support it, and refuses to invite a KeyPackage into
 * without. Advertising it is only safe because every rule below is enforced:
 * a member that advertised it and then rejected a valid same-account commit
 * would fork the group.
 */
class MarmotAccountDevicesTest {
    private val nostrGroupId = "a".repeat(64)

    private class Device(
        keyPair: KeyPair = KeyPair(),
        supported: List<Int> = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS,
    ) {
        val signer = NostrSignerInternal(keyPair)
        val manager =
            MarmotManager(
                signer,
                SnapshotStateStore(),
                SnapshotMessageStore(),
                SnapshotBundleStore(),
                publisher = ACCEPTING_RELAY,
                supportedComponents = supported,
            )
        val pubKey get() = signer.pubKey
    }

    private val unsupported = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AccountDevicesV1.COMPONENT_ID

    /** [creator] founds the group with every device in [invitees] (one KeyPackage each); admins are [admins]. */
    private suspend fun found(
        creator: Device,
        invitees: List<Device>,
        admins: List<Device> = emptyList(),
    ) {
        creator.manager.createCurrentProfileGroup(
            nostrGroupId = nostrGroupId,
            relays = listOf("wss://relay.invalid"),
            profile = GroupProfileV1("devices", ""),
            additionalAdmins = admins.map { it.pubKey.hexToByteArray() },
        )
        if (invitees.isEmpty()) return
        val keyPackages = invitees.map { it.manager.generateKeyPackageEvent(relays = emptyList()) }
        val (commit, welcomes) = creator.manager.addMembers(nostrGroupId, keyPackages, emptyList())
        assertEquals(null, commit, "a founding Add publishes no commit")
        assertEquals(invitees.size, welcomes.size)
        invitees.zip(welcomes).forEach { (device, welcome) ->
            assertIs<MarmotIngestResult.JoinedGroup>(device.manager.ingest(welcome.giftWrapEvent))
        }
    }

    @Test
    fun ourLeavesAndKeyPackagesAdvertiseAccountDevices() =
        runBlocking<Unit> {
            val alice = Device()
            val kp = alice.manager.generateKeyPackageEvent(relays = emptyList())
            assertTrue(kp.tags.any { it.firstOrNull() == "app_components" && "0x800d" in it }, "the KeyPackage event must list 0x800d")
        }

    @Test
    fun aGroupWhoseFoundersAllSupportItRequiresIt() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))
            assertTrue(alice.manager.requiresAccountDevices(nostrGroupId))
            assertTrue(bob.manager.requiresAccountDevices(nostrGroupId))
            assertEquals(1L, bob.manager.groupEpoch(nostrGroupId))
        }

    @Test
    fun aFounderWithoutSupportKeepsTheGroupFromRequiringIt() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            val carol = Device(supported = unsupported)
            found(alice, listOf(bob, carol))
            assertFalse(alice.manager.requiresAccountDevices(nostrGroupId))
            assertFalse(carol.manager.requiresAccountDevices(nostrGroupId))
            assertEquals(3, carol.manager.memberCount(nostrGroupId))
        }

    @Test
    fun aKeyPackageWithoutSupportCannotJoinAGroupThatRequiresIt() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))
            val old = Device(supported = unsupported)
            val kp = old.manager.generateKeyPackageEvent(relays = emptyList())
            assertFailsWith<IllegalArgumentException> { alice.manager.addMember(nostrGroupId, kp, emptyList()) }
            assertEquals(1L, alice.manager.groupEpoch(nostrGroupId))
        }

    @Test
    fun aNonAdminRemovesAnotherDeviceOfItsOwnAccount() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            found(alice, listOf(bobPhone, bobLaptop))
            assertEquals(3, alice.manager.memberCount(nostrGroupId))
            assertEquals(2, alice.manager.accountCount(nostrGroupId))

            val phoneLeaf =
                bobPhone.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .leafIndex
            val commit = bobLaptop.manager.removeOwnAccountDevices(nostrGroupId, listOf(phoneLeaf))

            // Alice, the admin, and the removed phone both accept it.
            assertIs<MarmotIngestResult.Commit>(alice.manager.ingest(commit.signedEvent))
            assertEquals(2L, alice.manager.groupEpoch(nostrGroupId))
            assertEquals(2, alice.manager.memberCount(nostrGroupId))
            assertEquals(1, alice.manager.leafIndicesOf(nostrGroupId, bobLaptop.pubKey).size)
            bobPhone.manager.ingest(commit.signedEvent)
            assertFalse(bobPhone.manager.isMember(nostrGroupId))
        }

    @Test
    fun withoutTheRequirementASameAccountRemoveStaysAdminOnly() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys, unsupported)
            val bobLaptop = Device(bobKeys, unsupported)
            found(alice, listOf(bobPhone, bobLaptop))
            assertFalse(alice.manager.requiresAccountDevices(nostrGroupId))
            val phoneLeaf =
                bobPhone.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .leafIndex
            assertFailsWith<IllegalStateException> { bobLaptop.manager.removeOwnAccountDevices(nostrGroupId, listOf(phoneLeaf)) }
        }

    @Test
    fun aNonAdminCannotRemoveAnotherAccountEvenAlongsideItsOwnDevice() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            val carol = Device()
            found(alice, listOf(bobPhone, bobLaptop, carol))
            val group = bobLaptop.manager.groupManager.getGroup(nostrGroupId)!!
            val phoneLeaf =
                bobPhone.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .leafIndex
            val carolLeaf =
                carol.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .leafIndex
            assertEquals(MarmotCommitClass.ADMIN_REQUIRED, classifyRemoves(group, listOf(phoneLeaf, carolLeaf)))
            assertEquals(MarmotCommitClass.SAME_ACCOUNT, classifyRemoves(group, listOf(phoneLeaf)))
            assertFailsWith<IllegalStateException> {
                bobLaptop.manager.groupManager.stageRemoveMembers(nostrGroupId, listOf(phoneLeaf, carolLeaf))
            }
        }

    @Test
    fun theRequirementCanNeverBeDropped() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))
            val required =
                alice.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .appDataDictionary()
            val without = ComponentsList.supportedOrRequired(required) - AccountDevicesV1.COMPONENT_ID
            assertFailsWith<IllegalStateException> {
                alice.manager.groupManager.stageAppDataUpdate(nostrGroupId, ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(without))
            }
            // Nor written as data.
            assertFailsWith<IllegalStateException> {
                alice.manager.groupManager.stageAppDataUpdate(nostrGroupId, AccountDevicesV1.COMPONENT_ID, ByteArray(0))
            }
            assertTrue(alice.manager.requiresAccountDevices(nostrGroupId))
        }

    @Test
    fun noAccountMayHoldMoreThanTwentyLeaves() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobs = (1..AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT).map { Device(bobKeys) }
            // Twenty devices of one account: the founding still requires it.
            val keyPackages = bobs.map { it.manager.generateKeyPackageEvent(relays = emptyList()) }
            alice.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))
            alice.manager.addMembers(nostrGroupId, keyPackages, emptyList())
            assertTrue(alice.manager.requiresAccountDevices(nostrGroupId))
            assertEquals(AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT, alice.manager.leafIndicesOf(nostrGroupId, bobs.first().pubKey).size)

            // A twenty-first, even from the admin, breaks the resulting state.
            val extra = Device(bobKeys).manager.generateKeyPackageEvent(relays = emptyList())
            assertFailsWith<IllegalStateException> { alice.manager.addMember(nostrGroupId, extra, emptyList()) }
        }

    @Test
    fun removingAnAccountRemovesEveryDeviceAndItsAdminSeat() =
        runBlocking<Unit> {
            val alice = Device()
            val bobKeys = KeyPair()
            val bobPhone = Device(bobKeys)
            val bobLaptop = Device(bobKeys)
            val carol = Device()
            found(alice, listOf(bobPhone, bobLaptop, carol), admins = listOf(bobPhone))
            assertEquals(4, alice.manager.memberCount(nostrGroupId))

            val commit = alice.manager.removeAccount(nostrGroupId, bobPhone.pubKey)
            assertEquals(2, alice.manager.memberCount(nostrGroupId))
            assertEquals(
                listOf(alice.pubKey, carol.pubKey).sorted(),
                alice.manager
                    .memberAccounts(nostrGroupId)
                    .map { it.pubkey }
                    .sorted(),
            )
            assertEquals(listOf(alice.pubKey), alice.manager.groupView(nostrGroupId)!!.adminPubkeys)

            assertIs<MarmotIngestResult.Commit>(carol.manager.ingest(commit.signedEvent))
            assertEquals(2, carol.manager.accountCount(nostrGroupId))
            bobLaptop.manager.ingest(commit.signedEvent)
            assertFalse(bobLaptop.manager.isMember(nostrGroupId))
        }

    @Test
    fun anOrdinaryInviteNeverAddsADeviceOfOurOwnAccount() =
        runBlocking<Unit> {
            val aliceKeys = KeyPair()
            val alice = Device(aliceKeys)
            val bob = Device()
            found(alice, listOf(bob))
            val otherAliceDevice = Device(aliceKeys).manager.generateKeyPackageEvent(relays = emptyList())
            assertFailsWith<IllegalArgumentException> { alice.manager.addMember(nostrGroupId, otherAliceDevice, emptyList()) }
        }

    @Test
    fun activationNeedsEveryLeafToAdvertiseIt() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            val carol = Device(supported = unsupported)
            found(alice, listOf(bob, carol))
            assertFalse(alice.manager.requiresAccountDevices(nostrGroupId))
            assertTrue(alice.manager.accountDevicesActivationBlocker(nostrGroupId) != null)
            assertFailsWith<IllegalStateException> { alice.manager.requireAccountDevices(nostrGroupId) }
            assertEquals("only an admin can turn it on", bob.manager.accountDevicesActivationBlocker(nostrGroupId))
        }

    /**
     * `convergence.md`, `tip_priority`, and `account-devices-v1.md`, "Branch
     * priority": a same-account commit is ordinary even from an admin, an
     * admin's removal of another account is privileged, and a self-update (an
     * empty commit with a path) is ordinary. MDK's `commit_class.rs` reads the
     * same; a member that ranked these differently would pick another branch.
     */
    @Test
    fun branchPriorityFollowsTheCommitClassNotTheCommitter() =
        runBlocking<Unit> {
            val aliceKeys = KeyPair()
            val alicePhone = Device(aliceKeys)
            val aliceLaptop = Device(aliceKeys)
            val bob = Device()
            found(alicePhone, listOf(aliceLaptop, bob))
            val engine = MlsCandidateStateEngine()
            val groups = alicePhone.manager.groupManager
            val parent = groups.getGroup(nostrGroupId)!!.saveState()
            val laptopLeaf =
                aliceLaptop.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .leafIndex
            val bobLeaf =
                bob.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .leafIndex

            val ownDevice = groups.stageRemoveMembers(nostrGroupId, listOf(laptopLeaf)).result.framedCommitBytes
            assertEquals(TipPriority.ORDINARY, engine.tipPriority(parent, ownDevice), "an admin's same-account commit is ordinary")

            val otherAccount = groups.stageRemoveMembers(nostrGroupId, listOf(bobLeaf)).result.framedCommitBytes
            assertEquals(TipPriority.PRIVILEGED, engine.tipPriority(parent, otherAccount))

            val selfUpdate = groups.stageCommit(nostrGroupId).result.framedCommitBytes
            assertEquals(TipPriority.ORDINARY, engine.tipPriority(parent, selfUpdate), "an empty commit with a path is a self-update")

            // A non-admin's same-account commit is authorized, and ordinary.
            val bobView =
                bob.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .saveState()
            assertTrue(engine.isAuthorized(bobView, ownDevice))
        }

    /**
     * `joining.md`, receiving step 8: the Welcome's author must be an active
     * admin of the resulting state, or — only when that state requires
     * account-devices — a device of the joiner's own account.
     */
    @Test
    fun aWelcomeMustComeFromAnAdminOrFromOurOwnAccount() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))
            val required =
                alice.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .extensions
            val carol = "c".repeat(64)
            val dave = "d".repeat(64)
            // Leaves: 0 alice (admin), 1 bob, 2 carol (us), 3 carol's other device.
            val ids = listOf(alice.pubKey, bob.pubKey, carol, carol)

            fun join(
                extensions: List<Extension>,
                signer: Int,
            ) = MarmotGroupPolicy.validateJoin(GroupView(extensions, ids.size, 2, { ids.getOrNull(it) }, { null }, { null }), signer, emptyList())

            join(required, signer = 0)
            assertFailsWith<IllegalArgumentException> { join(required, signer = 1) }
            join(required, signer = 3)

            // Without the requirement, our own other device is not an inviter.
            val notRequired = Device()
            found(notRequired, listOf(Device(supported = unsupported)))
            val plain =
                notRequired.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .extensions
            val plainIds = listOf(notRequired.pubKey, dave, carol, carol)
            assertFailsWith<IllegalArgumentException> {
                MarmotGroupPolicy.validateJoin(GroupView(plain, plainIds.size, 2, { plainIds.getOrNull(it) }, { null }, { null }), 3, emptyList())
            }
            MarmotGroupPolicy.validateJoin(GroupView(plain, plainIds.size, 2, { plainIds.getOrNull(it) }, { null }, { null }), 0, emptyList())
        }

    /**
     * MDK 0.18's linked devices put a device-tag entry (`0x800f`) in every
     * LeafNode and KeyPackage dictionary. It is a component we do not know, so
     * its data is carried, never judged: the KeyPackage is invited, the member
     * joins and the group carries on.
     */
    @Test
    fun aDeviceTaggedKeyPackageIsInvitedAndJoins() =
        runBlocking<Unit> {
            val alice = Device()
            val bob = Device()
            found(alice, listOf(bob))

            val carolSigner = NostrSignerInternal(KeyPair())
            val leafKeys = Ed25519.generateKeyPair()
            val proof = AccountIdentityProofV2.create(carolSigner, MlsCiphersuite.DEFAULT, leafKeys.publicKey)
            val deviceTag = 0x800f
            val leaf =
                AppDataDictionary(
                    listOf(
                        ComponentData(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(CurrentProfileGroupFactory.SUPPORTED_COMPONENTS)),
                        ComponentData(ComponentsList.SAFE_AAD_ID, ComponentsList.encode(emptyList())),
                        ComponentData(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2, proof.encode()),
                        ComponentData(deviceTag, ByteArray(16) { 7 }),
                    ),
                )
            val bundle =
                MlsGroup.createKeyPackage(
                    identity = carolSigner.pubKey.hexToByteArray(),
                    policy = MarmotGroupPolicy,
                    leafSignatureKeyPair = leafKeys,
                    leafExtensions = listOf(leaf.toExtension()),
                    capabilities = MarmotCapabilities.currentProfileLeaf(),
                    keyPackageExtensions =
                        listOf(
                            AppDataDictionary(
                                listOf(ComponentData(ComponentsList.LAST_RESORT_KEY_PACKAGE_ID, ByteArray(0)), ComponentData(deviceTag, ByteArray(4) { 1 })),
                            ).toExtension(),
                        ),
                )
            val event = carolSigner.sign(KeyPackageEvent.buildCurrentProfileFrom(bundle.keyPackage, "f".repeat(64)))

            val (commit, welcome) = alice.manager.addMember(nostrGroupId, event, emptyList())
            assertIs<MarmotIngestResult.Commit>(bob.manager.ingest(commit!!.signedEvent))
            assertEquals(3, bob.manager.memberCount(nostrGroupId))
            assertTrue(bob.manager.requiresAccountDevices(nostrGroupId))
            assertNotNull(welcome)
        }

    private fun classifyRemoves(
        group: MlsGroup,
        leaves: List<Int>,
    ): MarmotCommitClass = MarmotCommitClass.of(group.view(), leaves.map { PendingProposal(Proposal.Remove(it), group.leafIndex) }, group.leafIndex, hasUpdatePath = true)
}
