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

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.marmot.appComponents.AccountDevicesV1
import com.vitorpamplona.marmot.appComponents.AdminPolicyV1
import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.appComponents.DeviceEntryV1
import com.vitorpamplona.marmot.appComponents.DeviceRosterRules
import com.vitorpamplona.marmot.appComponents.DeviceRosterUpdateV1
import com.vitorpamplona.marmot.appComponents.DeviceRosterV1
import com.vitorpamplona.marmot.appComponents.DeviceTagV1
import com.vitorpamplona.marmot.appComponents.GroupLifecycleV1
import com.vitorpamplona.marmot.appComponents.MarmotGroupState
import com.vitorpamplona.marmot.appComponents.NostrRoutingV1
import com.vitorpamplona.marmot.appComponents.RosterOperationV1
import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.groups.MlsGroupManager
import com.vitorpamplona.marmot.groups.currentNostrGroupId
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageUtils
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.signers.NostrSigner

/**
 * The device-group side of linking (`features/device-group.md` "Creating the device group",
 * "Approving", "Joining", "Matching leaves to devices"): an existing device names the group in its
 * Confirm, creates it if it trusts none, and adds exactly the confirmed KeyPackage together with the
 * new device's roster entry; the new device joins only its link's Welcome and makes its first Commit,
 * which sets its `tag_signature_key` and tags its leaf, the sign that the link is made.
 *
 * Every Commit here is staged ([MlsGroupManager.StagedCommit]): the caller publishes it, and only then
 * applies it with [applyStaged] (publish-before-apply). Transport (relays, publishing, the Welcome's
 * delivery to the new device) is the caller's, as for every other group.
 *
 * Device-group support stays opt-in: this class needs leaves that advertise
 * [CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS], which nothing creates by default.
 */
class MarmotDeviceGroupManager(
    private val signer: NostrSigner,
    private val groupManager: MlsGroupManager,
    private val trustStore: DeviceGroupTrustStore,
    /** This device's KeyPackage publication slot (its kind-30443 `d`). */
    private val ownSlot: HexKey,
    /** Where the device group's traffic goes, if this device creates it. */
    private val relays: List<String>,
) {
    /**
     * What the founding device needs between its Confirm and the founding Add: the group id it named,
     * the leaf whose signature key it named, the roster key and its tag key. Memory only: a restart
     * in between abandons the link, which the new device's 600 s wait then ends.
     */
    private class Founding(
        val groupId: ByteArray,
        val leaf: CurrentProfileGroupFactory.LeafIdentity,
        val leafTagKey: ByteArray,
        val tagSeed: ByteArray,
    )

    private var founding: Founding? = null

    suspend fun trust(): DeviceGroupTrust = trustStore.load() ?: DeviceGroupTrust(ownSlot)

    /** The Nostr routing id of the trusted device group, if any. */
    suspend fun deviceGroupNostrId(): HexKey? = trust().trustedNostrGroupId

    /** Whether [nostrGroupId] is this device's trusted device group, which no chat list shows. */
    suspend fun isDeviceGroup(nostrGroupId: HexKey): Boolean = trust().trustedNostrGroupId == nostrGroupId

    /** The trusted device group's roster. */
    suspend fun roster(): DeviceRosterV1? = trust().trustedNostrGroupId?.let { groupManager.getGroup(it) }?.let { DeviceRosterRules.rosterOf(it.view().extensions) }

    // ---- existing device ----

    /**
     * What this device's Confirm names: the trusted device group and its own leaf's signature key
     * there, or a fresh 16-byte group id and the key it will create the group with.
     */
    suspend fun confirmTarget(): Pair<HexKey, HexKey> {
        val t = trust()
        t.trustedNostrGroupId?.let { nostrId ->
            val group = checkNotNull(groupManager.getGroup(nostrId)) { "the trusted device group is not loaded" }
            val key = checkNotNull(group.view().leafNode(group.view().myLeafIndex)).signatureKey
            return group.groupId.toHexKey() to key.toHexKey()
        }
        val f =
            founding ?: run {
                val tagSeed = RandomInstance.bytes(32)
                Founding(
                    groupId = RandomInstance.bytes(16),
                    leaf = CurrentProfileGroupFactory.newLeafIdentity(signer, supportedComponents = CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS),
                    leafTagKey = RandomInstance.bytes(32),
                    tagSeed = tagSeed,
                ).also { founding = it }
            }
        return f.groupId.toHexKey() to
            f.leaf.signatureKeyPair.publicKey
                .toHexKey()
    }

    /** A staged device-group Commit and the Welcome it carries, if it added a device. */
    class Staged(
        val nostrGroupId: HexKey,
        val staged: MlsGroupManager.StagedCommit,
    ) {
        val welcomeBytes: ByteArray? get() = staged.result.welcomeBytes
        val framedCommitBytes: ByteArray get() = staged.result.framedCommitBytes
    }

    /**
     * After the new device's Confirm verified ([link]): add exactly the confirmed KeyPackage
     * ([keyPackageMessage], the publication's MLSMessage or KeyPackage bytes, whose slot is
     * [newDeviceSlot]) with its roster entry, creating the device group first if this device trusts
     * none. Publish the returned Commit and its Welcome, then [applyStaged].
     */
    suspend fun approve(
        link: ConfirmedLink,
        keyPackageMessage: ByteArray,
        newDeviceSlot: HexKey,
        label: String,
        now: Long,
        settings: Int = DeviceEntryV1.ADD_TO_ALL_CHATS or DeviceEntryV1.BRING_HISTORY,
        client: String = "",
        platform: String = "",
    ): Staged {
        val keyPackage = KeyPackageUtils.decodeKeyPackage(keyPackageMessage)
        check(keyPackage.reference().toHexKey() == link.keyPackageRef) { "A device group adds only the KeyPackage the link confirmed" }
        val t = trust()
        val nostrId = t.trustedNostrGroupId ?: create(link, now)
        val group = checkNotNull(groupManager.getGroup(nostrId))
        check(group.groupId.toHexKey() == link.deviceGroupId) { "The link names another group" }
        val roster = checkNotNull(DeviceRosterRules.rosterOf(group.view().extensions)) { "The device group has no roster" }
        check(roster.device(newDeviceSlot) == null && roster.rejectedSlot(newDeviceSlot) == null) { "The slot is already in the roster" }
        check(roster.devices.size < AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT) { "The account has as many devices as a roster holds" }

        val entry =
            DeviceEntryV1(
                slot = newDeviceSlot,
                label = label,
                renameId = RandomInstance.bytes(DeviceRosterV1.RENAME_ID_SIZE).toHexKey(),
                client = client,
                platform = platform,
                linkedAt = now,
                linkedBy = ownSlot,
                settings = settings,
                announcedKeyPackage = link.keyPackageRef,
            )
        val update = DeviceRosterUpdateV1(listOf(RosterOperationV1.SetDevice(entry))).encode()
        val isFounding = group.epoch == 0L
        val staged =
            groupManager.stageOwn(nostrId) { clone ->
                clone.proposeAdd(keyPackage.toTlsBytes())
                if (isFounding && keyPackageAdvertises(keyPackageMessage, AccountDevicesV1.COMPONENT_ID)) {
                    // The ordinary creation rule (`protocol-core/group-setup.md`): every founder supports 0x800d.
                    val required = ComponentsList.supportedOrRequired(clone.appDataDictionary()).toMutableSet()
                    required.add(AccountDevicesV1.COMPONENT_ID)
                    clone.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required))
                }
                clone.proposeAppDataUpdate(DeviceRosterV1.COMPONENT_ID, update)
                clone.commit()
            }
        trustStore.save(trust().let { it.copy(approvals = it.approvals.filterNot { a -> a.slot == newDeviceSlot } + DeviceGroupTrust.Approval(newDeviceSlot, now, DeviceGroupTrust.Outcome.PENDING)) })
        return Staged(nostrId, staged)
    }

    private fun keyPackageAdvertises(
        keyPackageMessage: ByteArray,
        componentId: Int,
    ): Boolean = componentId in AccountDevicesV1.advertised(KeyPackageUtils.decodeKeyPackage(keyPackageMessage).leafNode.extensions)

    /** The founding state: this account as sole admin, `0x800e` required, a roster of this device alone. */
    private suspend fun create(
        link: ConfirmedLink,
        now: Long,
    ): HexKey {
        val f = checkNotNull(founding) { "No Confirm named a group to create" }
        check(
            f.groupId.toHexKey() == link.deviceGroupId && f.leaf.signatureKeyPair.publicKey
                .toHexKey() == link.welcomeSenderKey,
        ) {
            "The link does not name the group this device offered to create"
        }
        val tagKey = Ed25519.keyPairFromSeed(f.tagSeed)
        val ownEntry =
            DeviceEntryV1(
                slot = ownSlot,
                renameId = RandomInstance.bytes(DeviceRosterV1.RENAME_ID_SIZE).toHexKey(),
                linkedAt = now,
                tagSignatureKey = tagKey.publicKey.toHexKey(),
            )
        val roster = DeviceRosterV1(f.leafTagKey.toHexKey(), listOf(ownEntry))
        val nostrId = RandomInstance.bytes(32)
        val dictionary =
            MarmotGroupState
                .buildDictionary(
                    adminPolicy = AdminPolicyV1.of(listOf(signer.pubKey.hexToByteArray())),
                    routing = NostrRoutingV1.of(nostrId, relays),
                    lifecycle = GroupLifecycleV1.ACTIVE,
                    extraRequiredComponents = listOf(DeviceRosterV1.COMPONENT_ID),
                ).with(DeviceRosterV1.COMPONENT_ID, roster.encode())
        val tag = DeviceTagV1.produce(f.leafTagKey, ownSlot.hexToByteArray(), f.leaf.signatureKeyPair.publicKey, f.tagSeed)
        val leafExtensions = withTag(f.leaf.leafExtensions, tag)
        val group =
            MlsGroup.create(
                identity = signer.pubKey.hexToByteArray(),
                signingKey = f.leaf.signatureKeyPair.privateKey,
                initialExtensions = listOf(dictionary.toExtension()),
                leafExtensions = leafExtensions,
                policy = MarmotGroupPolicy,
                capabilities = MarmotCapabilities.currentProfileLeaf(),
                requiredCapabilities = MarmotCapabilities.currentProfileRequired(),
                groupId = f.groupId,
            )
        val nostrHex = nostrId.toHexKey()
        groupManager.adoptGroup(nostrHex, group)
        trustStore.save(trust().copy(trustedGroupId = f.groupId.toHexKey(), trustedNostrGroupId = nostrHex, tagSigningSeed = f.tagSeed.toHexKey()))
        founding = null
        return nostrHex
    }

    // ---- new device ----

    /** After this device's Confirm went out: keep the link until its Welcome joins or 600 s pass. */
    suspend fun recordLink(
        link: ConfirmedLink,
        now: Long,
    ) {
        trustStore.save(trust().copy(pendingLink = DeviceGroupTrust.PendingLink(link, now + LINK_WAIT_SECS)))
    }

    /**
     * Joins [welcomeBytes] only if it is the pending link's: into the link's group, from the leaf the
     * link named, consuming the link's KeyPackage ([bundle]), into a group that requires `0x800e`. A
     * refused Welcome changes nothing and uses up neither the KeyPackage nor the group id.
     */
    suspend fun joinLinkWelcome(
        welcomeBytes: ByteArray,
        bundle: KeyPackageBundle,
        now: Long,
    ): HexKey {
        val t = trust()
        val pending = checkNotNull(t.pendingLink) { "No link waits for a Welcome" }
        check(now < pending.waitUntil) { "The link's wait has ended" }
        check(bundle.keyPackage.reference().toHexKey() == pending.link.keyPackageRef) { "The Welcome is not for the link's KeyPackage" }
        val joined = MlsGroup.processWelcome(welcomeBytes, bundle, DeviceGroupLinkJoinPolicy(pending.link))
        check(joined.groupId.toHexKey() == pending.link.deviceGroupId) { "The Welcome joins another group than the link's" }
        val nostrId = checkNotNull(joined.currentNostrGroupId()) { "The device group carries no routing" }
        groupManager.adoptGroup(nostrId, MlsGroup.restore(joined.saveState(), MarmotGroupPolicy))
        trustStore.save(
            t.copy(
                trustedGroupId = pending.link.deviceGroupId,
                trustedNostrGroupId = nostrId,
                tagSigningSeed = RandomInstance.bytes(32).toHexKey(),
                pendingLink = null,
            ),
        )
        return nostrId
    }

    /**
     * The new device's first Commit: its own roster entry with its `tag_signature_key`, and an
     * UpdatePath leaf tagged under that key. Publish, then [applyStaged].
     */
    suspend fun stageFirstCommit(): Staged {
        val t = trust()
        val nostrId = checkNotNull(t.trustedNostrGroupId) { "No device group is trusted" }
        val seed = checkNotNull(t.tagSigningSeed).hexToByteArray()
        val group = checkNotNull(groupManager.getGroup(nostrId))
        val view = group.view()
        val roster = checkNotNull(DeviceRosterRules.rosterOf(view.extensions))
        val entry = checkNotNull(roster.device(ownSlot)) { "The roster does not list this device" }
        val tagPublic = Ed25519.keyPairFromSeed(seed).publicKey.toHexKey()
        val leaf = checkNotNull(view.leafNode(view.myLeafIndex))
        val tag = DeviceTagV1.produce(roster.leafTagKey.hexToByteArray(), ownSlot.hexToByteArray(), leaf.signatureKey, seed)
        val update = DeviceRosterUpdateV1(listOf(RosterOperationV1.SetDevice(entry.copy(tagSignatureKey = tagPublic)))).encode()
        val staged =
            groupManager.stageOwn(nostrId) { clone ->
                val v = clone.view()
                clone.advertiseInNextCommit(checkNotNull(v.leafCapabilities(v.myLeafIndex)), withTag(leaf.extensions, tag))
                clone.proposeAppDataUpdate(DeviceRosterV1.COMPONENT_ID, update)
                clone.commit()
            }
        return Staged(nostrId, staged)
    }

    // ---- both ----

    /** Makes a published staged Commit canonical. */
    suspend fun applyStaged(staged: Staged) {
        groupManager.installState(staged.nostrGroupId, staged.staged.pendingState)
        refreshApprovals()
    }

    /** Applies an inbound device-group Commit, then updates the links this device approved. */
    suspend fun processCommit(
        nostrGroupId: HexKey,
        framedCommitBytes: ByteArray,
    ) {
        groupManager.processFramedCommit(nostrGroupId, framedCommitBytes)
        refreshApprovals()
    }

    /** A link is made once the roster lists the new device with its `tag_signature_key`. */
    private suspend fun refreshApprovals() {
        val t = trust()
        val roster = roster() ?: return
        val updated =
            t.approvals.map { a ->
                if (a.outcome == DeviceGroupTrust.Outcome.PENDING && roster.device(a.slot)?.tagSignatureKey != null) a.copy(outcome = DeviceGroupTrust.Outcome.MADE) else a
            }
        if (updated != t.approvals) trustStore.save(t.copy(approvals = updated))
    }

    /** Who holds each leaf of [nostrGroupId], as this device reads their tags against its roster. */
    suspend fun claims(nostrGroupId: HexKey): List<DeviceTagV1.Claim> {
        val roster = roster() ?: return emptyList()
        val view = groupManager.getGroup(nostrGroupId)?.view() ?: return emptyList()
        val own = signer.pubKey
        return (0 until view.leafCount).mapNotNull { i ->
            val leaf = view.leafNode(i) ?: return@mapNotNull null
            if (view.memberIdentityHex(i) != own) null else DeviceTagV1.read(leaf, roster)
        }
    }

    private fun withTag(
        leafExtensions: List<Extension>,
        tag: DeviceTagV1,
    ): List<Extension> {
        val dictionary = AppDataDictionary.fromExtensionsOrEmpty(leafExtensions).with(DeviceTagV1.COMPONENT_ID, tag.encode())
        return leafExtensions.filterNot { it.extensionType == AppDataDictionary.EXTENSION_TYPE } + dictionary.toExtension()
    }

    companion object {
        /** How long a new device waits for its link's Welcome after its Confirm. */
        const val LINK_WAIT_SECS = 600L

        /** How long the approver waits for the new device's first Commit after `linked_at`. */
        const val FIRST_COMMIT_DEADLINE_SECS = 3600L
    }
}
