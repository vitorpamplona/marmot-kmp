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
import com.vitorpamplona.marmot.OutboundGroupEvent
import com.vitorpamplona.marmot.WelcomeDelivery
import com.vitorpamplona.marmot.WelcomeResult
import com.vitorpamplona.marmot.appComponents.AccountDevicesV1
import com.vitorpamplona.marmot.appComponents.AdminPolicyV1
import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.appComponents.DeviceEntryV1
import com.vitorpamplona.marmot.appComponents.DeviceRosterRules
import com.vitorpamplona.marmot.appComponents.DeviceRosterUpdateV1
import com.vitorpamplona.marmot.appComponents.DeviceRosterV1
import com.vitorpamplona.marmot.appComponents.DeviceStatusV1
import com.vitorpamplona.marmot.appComponents.DeviceTagV1
import com.vitorpamplona.marmot.appComponents.GroupLifecycleV1
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.appComponents.MarmotGroupState
import com.vitorpamplona.marmot.appComponents.NostrRoutingV1
import com.vitorpamplona.marmot.appComponents.RejectedSlotV1
import com.vitorpamplona.marmot.appComponents.RejectionReasonV1
import com.vitorpamplona.marmot.appComponents.RosterOperationV1
import com.vitorpamplona.marmot.client.MarmotManager
import com.vitorpamplona.marmot.features.accountSync.AccountSyncState
import com.vitorpamplona.marmot.features.accountSync.AccountSyncStore
import com.vitorpamplona.marmot.features.accountSync.HistoryBundles
import com.vitorpamplona.marmot.features.accountSync.HistoryDelivery
import com.vitorpamplona.marmot.features.accountSync.HistoryEvent
import com.vitorpamplona.marmot.features.accountSync.HistoryKeys
import com.vitorpamplona.marmot.features.accountSync.InMemoryAccountSyncStore
import com.vitorpamplona.marmot.features.accountSync.InvitationGeneration
import com.vitorpamplona.marmot.features.accountSync.SmallStateItem
import com.vitorpamplona.marmot.features.accountSync.SmallStateMessages
import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.groups.MlsGroupManager
import com.vitorpamplona.marmot.groups.currentNostrGroupId
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageUtils
import com.vitorpamplona.marmot.mip01Groups.MlsCiphersuite
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentData
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.messages.KeyPackageBundleCodec
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNodeSource
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.signers.NostrSigner
import com.vitorpamplona.quartz.nip01Core.signers.eventTemplate
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import com.vitorpamplona.quartz.utils.Log
import com.vitorpamplona.quartz.utils.TimeUtils
import kotlinx.coroutines.CancellationException
import kotlin.concurrent.Volatile

/**
 * An account's device group (`features/device-group.md`): linking, the roster, private KeyPackages,
 * sibling Welcomes, gap filling, heartbeats, removal, sign-out and sign-ins.
 *
 * Built by `MarmotManager` when its `deviceGroupConfig` is set; that config is the one switch an app
 * flips. Every Commit here is staged ([MlsGroupManager.StagedCommit]): the caller publishes it, then
 * [applyStaged] (publish-before-apply). App events for siblings go out as [OutboundGroupEvent]s in the
 * device group: returned by the call that makes them, or, for answers to inbound traffic, queued in
 * [drainOutbox].
 */
class MarmotDeviceGroupManager internal constructor(
    private val signer: NostrSigner,
    private val groupManager: MlsGroupManager,
    private val trustStore: DeviceGroupTrustStore,
    private val keyPackageStore: PrivateKeyPackageStore,
    private var slot: HexKey?,
    private val relays: List<String>,
    private val manager: MarmotManager?,
    private val syncStore: AccountSyncStore = InMemoryAccountSyncStore(),
    private val relayProvider: (suspend () -> List<String>)? = null,
    private val client: String = "",
    private val platform: String = "",
) {
    /** The device group of [manager], as its config sets it up. Call [start] before use. */
    constructor(manager: MarmotManager, config: MarmotDeviceGroupConfig) :
        this(
            manager.signer,
            manager.groupManager,
            config.trustStore,
            config.privateKeyPackageStore,
            null,
            config.relays,
            manager,
            config.accountSyncStore,
            config.relayProvider,
            config.client,
            config.platform,
        )

    /** Linking only, over a bare [MlsGroupManager], with this device's slot given. */
    constructor(
        signer: NostrSigner,
        groupManager: MlsGroupManager,
        trustStore: DeviceGroupTrustStore,
        ownSlot: HexKey,
        relays: List<String>,
    ) : this(signer, groupManager, trustStore, InMemoryPrivateKeyPackageStore(), ownSlot, relays, null)

    private val ownSlot: HexKey get() = checkNotNull(slot) { "call start() first" }

    @Volatile
    private var cached: DeviceGroupTrust? = null

    private val outbox = ArrayList<OutboundGroupEvent>()

    /** Live gap-fill claims: (chat, target slot) to claimant slot to expiry. */
    private val claims = HashMap<Pair<HexKey, HexKey>, MutableMap<HexKey, Long>>()

    /** Post-link inventory pages this new device received: revision, total and the tokens. */
    private var inventory: Triple<Long, Long, MutableSet<HexKey>>? = null

    /**
     * Loads the trust record, resolves this device's slot (its primary KeyPackage `d`), and makes the
     * KeyPackages it mints carry its device tag.
     */
    suspend fun start() {
        val m = manager
        if (slot == null && m != null) slot = m.keyPackageRotationManager.getOrCreateSlotDTag(KeyPackageUtils.PRIMARY_SLOT)
        cached = trustStore.load() ?: DeviceGroupTrust(ownSlot)
        m?.keyPackageRotationManager?.leafComponents = { key -> ownTagComponents(key) }
    }

    suspend fun trust(): DeviceGroupTrust = cached ?: (trustStore.load() ?: DeviceGroupTrust(ownSlot)).also { cached = it }

    private suspend fun saveTrust(trust: DeviceGroupTrust) {
        trustStore.save(trust)
        cached = trust
    }

    private suspend fun keyPackages(): PrivateKeyPackages = keyPackageStore.load() ?: PrivateKeyPackages()

    /** Whether [nostrGroupId] is this device's trusted device group, which no chat list shows. */
    fun isTrustedDeviceGroup(nostrGroupId: HexKey): Boolean = cached?.let { !it.unlinked && it.trustedNostrGroupId == nostrGroupId } == true

    suspend fun deviceGroupNostrId(): HexKey? = trust().trustedNostrGroupId

    suspend fun isDeviceGroup(nostrGroupId: HexKey): Boolean = trust().trustedNostrGroupId == nostrGroupId

    private fun deviceGroup(): MlsGroup? = cached?.trustedNostrGroupId?.let { groupManager.getGroup(it) }

    suspend fun roster(): DeviceRosterV1? = trust().trustedNostrGroupId?.let { groupManager.getGroup(it) }?.let { DeviceRosterRules.rosterOf(it.view().extensions) }

    private fun cachedRoster(): DeviceRosterV1? = deviceGroup()?.let { DeviceRosterRules.rosterOf(it.view().extensions) }

    /** The answers queued for inbound traffic (hand-offs for requests): publish them in the device group. */
    fun drainOutbox(): List<OutboundGroupEvent> = outbox.toList().also { outbox.clear() }

    // =================================================================================================
    // Tags (device-tag-v1.md "Producing tags")
    // =================================================================================================

    /**
     * The `0x800f` entry for a new leaf with [signatureKey], once this device can tag: it trusts a
     * device group whose roster lists it with its `tag_signature_key`. Empty before that.
     */
    fun ownTagComponents(signatureKey: ByteArray): List<ComponentData> {
        val t = cached ?: return emptyList()
        val seed = t.tagSigningSeed ?: return emptyList()
        val roster = cachedRoster() ?: return emptyList()
        val tagKey = roster.device(t.ownSlot)?.tagSignatureKey ?: return emptyList()
        if (tagKey != Ed25519.keyPairFromSeed(seed.hexToByteArray()).publicKey.toHexKey()) return emptyList()
        val tag = DeviceTagV1.produce(roster.leafTagKey.hexToByteArray(), t.ownSlot.hexToByteArray(), signatureKey, seed.hexToByteArray())
        return listOf(ComponentData(DeviceTagV1.COMPONENT_ID, tag.encode()))
    }

    /** Who holds each of this account's leaves in [nostrGroupId], as this device reads their tags. */
    suspend fun claims(nostrGroupId: HexKey): List<DeviceTagV1.Claim> = leafClaims(nostrGroupId).map { it.second }

    private suspend fun leafClaims(nostrGroupId: HexKey): List<Pair<Int, DeviceTagV1.Claim>> {
        val roster = roster() ?: return emptyList()
        val view = groupManager.getGroup(nostrGroupId)?.view() ?: return emptyList()
        return (0 until view.leafCount).mapNotNull { i ->
            val leaf = view.leafNode(i) ?: return@mapNotNull null
            if (view.memberIdentityHex(i) != signer.pubKey) null else i to DeviceTagV1.read(leaf, roster)
        }
    }

    // =================================================================================================
    // Linking: existing device
    // =================================================================================================

    private class Founding(
        val groupId: ByteArray,
        val leaf: CurrentProfileGroupFactory.LeafIdentity,
        val leafTagKey: ByteArray,
        val tagSeed: ByteArray,
    )

    /** Memory only: a restart between the Confirm and the founding Add abandons the link. */
    private var founding: Founding? = null

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
                val leafTagKey = RandomInstance.bytes(32)
                val ownSlotBytes = ownSlot.hexToByteArray()
                Founding(
                    groupId = RandomInstance.bytes(16),
                    leaf =
                        CurrentProfileGroupFactory.newLeafIdentity(signer, MlsCiphersuite.DEFAULT, CurrentProfileGroupFactory.DEVICE_GROUP_SUPPORTED_COMPONENTS) { key ->
                            listOf(ComponentData(DeviceTagV1.COMPONENT_ID, DeviceTagV1.produce(leafTagKey, ownSlotBytes, key, tagSeed).encode()))
                        },
                    leafTagKey = leafTagKey,
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
        /** The founding Add of the device group: merged locally, nothing to publish. */
        val isFounding: Boolean = false,
        /** For an Add under a link: the KeyPackage event its kind 444 Welcome names. */
        val linkKeyPackageEventId: HexKey? = null,
    ) {
        val welcomeBytes: ByteArray? get() = staged.result.welcomeBytes
        val framedCommitBytes: ByteArray get() = staged.result.framedCommitBytes
    }

    /**
     * After the new device's Confirm verified ([link]): add exactly the confirmed KeyPackage
     * ([keyPackageMessage], whose publication slot is [newDeviceSlot]) with its roster entry, creating
     * the device group first if this device trusts none. Publish, then [applyStaged].
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
        /** This device's own label, when this approval founds the device group; ignored otherwise. */
        ownLabel: String = "",
    ): Staged {
        val keyPackage = KeyPackageUtils.decodeKeyPackage(keyPackageMessage)
        check(keyPackage.reference().toHexKey() == link.keyPackageRef) { "A device group adds only the KeyPackage the link confirmed" }
        val t = trust()
        check(t.pendingLink == null) { "A device waiting for its own link answers no request" }
        val nostrId = t.trustedNostrGroupId ?: create(link, now, ownLabel)
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
                if (isFounding && AccountDevicesV1.COMPONENT_ID in AccountDevicesV1.advertised(keyPackage.leafNode.extensions)) {
                    // The ordinary creation rule (`protocol-core/group-setup.md`): every founder supports 0x800d.
                    val required = ComponentsList.supportedOrRequired(clone.appDataDictionary()).toMutableSet()
                    required.add(AccountDevicesV1.COMPONENT_ID)
                    clone.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required))
                }
                clone.proposeAppDataUpdate(DeviceRosterV1.COMPONENT_ID, update)
                clone.commit()
            }
        val approval = DeviceGroupTrust.Approval(newDeviceSlot, now, DeviceGroupTrust.Outcome.PENDING, keyPackage.leafNode.signatureKey.toHexKey())
        saveTrust(trust().let { it.copy(approvals = it.approvals.filterNot { a -> a.slot == newDeviceSlot } + approval) })
        return Staged(nostrId, staged, isFounding = isFounding, linkKeyPackageEventId = link.keyPackageEventId)
    }

    /** Where a device group made now lives: the provider's relays, else the configured ones. */
    private suspend fun currentRelays(): List<String> =
        relayProvider
            ?.let { provider -> runCatching { provider() }.getOrNull() }
            ?.filter { runCatching { NostrRoutingV1.requireValidRelayUrl(it) }.isSuccess }
            ?.distinct()
            ?.take(NostrRoutingV1.MAX_RELAYS)
            ?.takeIf { it.isNotEmpty() }
            ?: relays

    @Deprecated("Kept for binary compatibility", level = DeprecationLevel.HIDDEN)
    suspend fun approve(
        link: ConfirmedLink,
        keyPackageMessage: ByteArray,
        newDeviceSlot: HexKey,
        label: String,
        now: Long,
        settings: Int,
        client: String,
        platform: String,
    ): Staged = approve(link, keyPackageMessage, newDeviceSlot, label, now, settings, client, platform, "")

    private suspend fun create(
        link: ConfirmedLink,
        now: Long,
        ownLabel: String,
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
                label = ownLabel,
                renameId = RandomInstance.bytes(DeviceRosterV1.RENAME_ID_SIZE).toHexKey(),
                client = client,
                platform = platform,
                linkedAt = now,
                tagSignatureKey = tagKey.publicKey.toHexKey(),
                historyKey = HistoryKeys.publicKeyHex(f.tagSeed),
            )
        val roster = DeviceRosterV1(f.leafTagKey.toHexKey(), listOf(ownEntry), ownRejectionsForRoster())
        val nostrId = RandomInstance.bytes(32)
        val dictionary =
            MarmotGroupState
                .buildDictionary(
                    adminPolicy = AdminPolicyV1.of(listOf(signer.pubKey.hexToByteArray())),
                    routing = NostrRoutingV1.of(nostrId, currentRelays()),
                    lifecycle = GroupLifecycleV1.ACTIVE,
                    extraRequiredComponents = listOf(DeviceRosterV1.COMPONENT_ID),
                ).with(DeviceRosterV1.COMPONENT_ID, roster.encode())
        val group =
            MlsGroup.create(
                identity = signer.pubKey.hexToByteArray(),
                signingKey = f.leaf.signatureKeyPair.privateKey,
                initialExtensions = listOf(dictionary.toExtension()),
                leafExtensions = f.leaf.leafExtensions,
                policy = MarmotGroupPolicy,
                capabilities = MarmotCapabilities.currentProfileLeaf(),
                requiredCapabilities = MarmotCapabilities.currentProfileRequired(),
                groupId = f.groupId,
            )
        val nostrHex = nostrId.toHexKey()
        if (manager != null) manager.adoptCreatedDeviceGroup(nostrHex, group) else groupManager.adoptGroup(nostrHex, group)
        saveTrust(trust().copy(trustedGroupId = f.groupId.toHexKey(), trustedNostrGroupId = nostrHex, tagSigningSeed = f.tagSeed.toHexKey(), ownRejections = emptyList()))
        founding = null
        return nostrHex
    }

    /** A founding roster carries the rejections this device kept while it had no device group. */
    private suspend fun ownRejectionsForRoster(): List<RejectedSlotV1> =
        trust()
            .ownRejections
            .filter { it.slot != ownSlot }
            .sortedBy { it.slot }
            .map { RejectedSlotV1(it.slot, RejectionReasonV1.NOT_ME, it.time) }

    // =================================================================================================
    // Linking: new device
    // =================================================================================================

    /** After this device's Confirm went out: keep the link until its Welcome joins or 600 s pass. */
    suspend fun recordLink(
        link: ConfirmedLink,
        now: Long,
    ) {
        saveTrust(trust().copy(pendingLink = DeviceGroupTrust.PendingLink(link, now + LINK_WAIT_SECS)))
    }

    /** A Cancel for the link's session withdraws the link, unless its Welcome already joined. */
    suspend fun cancelLink(sessionId: HexKey) {
        val t = trust()
        if (t.pendingLink?.link?.sessionId == sessionId) saveTrust(t.copy(pendingLink = null))
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
        val restored = MlsGroup.restore(joined.saveState(), MarmotGroupPolicy)
        if (manager != null) manager.adoptJoinedDeviceGroup(nostrId, restored) else groupManager.adoptGroup(nostrId, restored)
        saveTrust(
            t.copy(
                trustedGroupId = pending.link.deviceGroupId,
                trustedNostrGroupId = nostrId,
                tagSigningSeed = linkTagSeed(bundle).toHexKey(),
                pendingLink = null,
                linkedKeyPackageRef = pending.link.keyPackageRef,
                unlinked = false,
            ),
        )
        refresh()
        return nostrId
    }

    /**
     * The new device's tag signing key is the signature key of the leaf the link added, the
     * confirmed KeyPackage's: MDK takes a link as made only when the first Commit sets exactly
     * that key as `tag_signature_key` (`marmot-app` `link_verdict`), and finds the device's
     * pre-link leaves by it ("Adding the new device to chats"). The spec lets each device make
     * its own pair; reusing the leaf's is the choice both readings accept.
     */
    private fun linkTagSeed(bundle: KeyPackageBundle): ByteArray {
        val seed = bundle.signaturePrivateKey.copyOfRange(0, 32)
        return if (Ed25519.keyPairFromSeed(seed).publicKey.contentEquals(bundle.keyPackage.leafNode.signatureKey)) seed else RandomInstance.bytes(32)
    }

    /** Whether [keyPackageEventId] is the KeyPackage this device's pending link reserved. */
    fun isReservedForLink(keyPackageEventId: HexKey?): Boolean = keyPackageEventId != null && cached?.pendingLink?.link?.keyPackageEventId == keyPackageEventId

    /** [joinLinkWelcome] for a kind 444 that names the link's KeyPackage, with the bundle this device holds for it. */
    suspend fun joinLinkWelcome(welcomeBytes: ByteArray): HexKey {
        val m = checkNotNull(manager)
        val ref = checkNotNull(trust().pendingLink) { "No link waits for a Welcome" }.link.keyPackageRef
        val bundle = checkNotNull(m.keyPackageRotationManager.findBundleByRef(ref.hexToByteArray())) { "The link's KeyPackage is not held" }
        val id = joinLinkWelcome(welcomeBytes, bundle, TimeUtils.now())
        m.keyPackageRotationManager.markConsumedByRef(bundle.keyPackage.reference())
        return id
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
        val update = DeviceRosterUpdateV1(listOf(RosterOperationV1.SetDevice(withOwnFields(entry, seed).copy(tagSignatureKey = tagPublic)))).encode()
        val staged =
            groupManager.stageOwn(nostrId) { clone ->
                val v = clone.view()
                clone.advertiseInNextCommit(checkNotNull(v.leafCapabilities(v.myLeafIndex)), withTag(leaf.extensions, tag))
                clone.proposeAppDataUpdate(DeviceRosterV1.COMPONENT_ID, update)
                clone.commit()
            }
        return Staged(nostrId, staged)
    }

    // =================================================================================================
    // Roster commits: link failure, slot announcements, removal, sign-out, rejections
    // =================================================================================================

    private suspend fun stageRosterUpdate(
        removeLeaves: List<Int>,
        ops: List<RosterOperationV1>,
    ): Staged {
        val nostrId = checkNotNull(trust().trustedNostrGroupId) { "No device group is trusted" }
        val update = DeviceRosterUpdateV1.of(ops).encode()
        val staged =
            groupManager.stageOwn(nostrId) { clone ->
                removeLeaves.sorted().forEach { clone.proposeRemove(it) }
                clone.proposeAppDataUpdate(DeviceRosterV1.COMPONENT_ID, update)
                clone.commit()
            }
        return Staged(nostrId, staged)
    }

    /**
     * `A link that is not taken up`: each link this device approved whose new device has not made its
     * first Commit 3600 s after `linked_at` fails, and this device undoes it with one Commit that
     * removes the new device's leaf and, with `remove_device` alone, its entry. Publish, then
     * [applyStaged]. Null when nothing is due.
     */
    suspend fun checkLinkDeadlines(now: Long): Staged? {
        val t = trust()
        val roster = roster() ?: return null
        val due = t.approvals.filter { it.outcome == DeviceGroupTrust.Outcome.PENDING && now >= it.linkedAt + FIRST_COMMIT_DEADLINE_SECS }
        val failed = t.approvals.filter { it.outcome == DeviceGroupTrust.Outcome.FAILED } + due.map { it.copy(outcome = DeviceGroupTrust.Outcome.FAILED) }
        if (due.isNotEmpty()) saveTrust(t.copy(approvals = t.approvals.map { a -> if (a in due) a.copy(outcome = DeviceGroupTrust.Outcome.FAILED) else a }))
        val undo = failed.filter { roster.device(it.slot)?.linkedBy == ownSlot }
        if (undo.isEmpty()) return null
        val view = checkNotNull(deviceGroup()).view()
        val leaves = undo.mapNotNull { a -> (0 until view.leafCount).firstOrNull { view.leafNode(it)?.signatureKey?.toHexKey() == a.leafSignatureKey } }
        return stageRosterUpdate(leaves, undo.map { RosterOperationV1.RemoveDevice(it.slot) })
    }

    /** Whether this device must announce [keyPackageRef] in its roster entry before publishing it. */
    suspend fun announcementNeeded(keyPackageRef: HexKey): Boolean {
        val roster = roster() ?: return false
        return roster.device(ownSlot)?.announcedKeyPackage != keyPackageRef
    }

    /**
     * `Slot announcements`: the Commit that names [keyPackageRef] in this device's own entry, every
     * other field unchanged. The device publishes that KeyPackage only once this Commit is applied.
     */
    suspend fun stageAnnouncement(keyPackageRef: HexKey): Staged {
        val entry = checkNotNull(roster()?.device(ownSlot)) { "The roster does not list this device" }
        return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetDevice(withOwnFields(entry).copy(announcedKeyPackage = keyPackageRef))))
    }

    /**
     * This device's own entry with its current `client`, `platform` and history key; every other
     * field, `label`, `settings` and `rename_id` included, as the roster holds it.
     */
    private suspend fun withOwnFields(
        entry: DeviceEntryV1,
        seed: ByteArray? = null,
    ): DeviceEntryV1 {
        val tagSeed = seed ?: trust().tagSigningSeed?.hexToByteArray()
        return entry.copy(
            client = client,
            platform = platform,
            historyKey = tagSeed?.let { HistoryKeys.publicKeyHex(it) } ?: entry.historyKey,
        )
    }

    /**
     * The update of this device's own entry when its `client`, `platform` or history key is not what
     * the roster holds (`account-sync.md` "History keys": a device whose entry has none writes its
     * own). Null when the entry is current, untagged yet, or no device group is trusted. A KeyPackage
     * announcement ([stageAnnouncement]) carries the same fields, so this is only for a device that
     * announces nothing for a while.
     */
    suspend fun stageOwnEntryRefresh(): Staged? {
        val entry = roster()?.device(ownSlot) ?: return null
        if (entry.tagSignatureKey == null) return null
        val current = withOwnFields(entry)
        if (current == entry) return null
        return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetDevice(current)))
    }

    /**
     * A user's rename of [slot], its own entry included (`Labels, clients and platforms`): the Commit
     * that sets the entry's `label` and a fresh `rename_id`, every other field as the roster holds it.
     * Null when the label is already [label]. Publish, then [applyStaged].
     */
    suspend fun stageRename(
        slot: HexKey,
        label: String,
    ): Staged? {
        val entry = checkNotNull(roster()?.device(slot)) { "The roster does not list that device" }
        if (entry.label == label) return null
        val renamed = entry.copy(label = label, renameId = RandomInstance.bytes(DeviceRosterV1.RENAME_ID_SIZE).toHexKey())
        return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetDevice(renamed)))
    }

    /**
     * The account's relays changed: the Commit that moves the trusted device group's routing to
     * [relays] (sorted, at most 16), its `nostr_group_id` kept. Null when it already lists exactly
     * those, when none is valid, or when no device group is trusted. Publish (to the relays the
     * siblings listen on now), then [applyStaged]; the group's traffic follows the new routing.
     */
    suspend fun stageRelays(relays: Collection<String>): Staged? {
        val nostrId = trust().trustedNostrGroupId ?: return null
        val group = groupManager.getGroup(nostrId) ?: return null
        val current = AppDataDictionary.fromExtensionsOrEmpty(group.view().extensions)[NostrRoutingV1.COMPONENT_ID]?.let { NostrRoutingV1.decode(it) } ?: return null
        val wanted =
            relays
                .filter { runCatching { NostrRoutingV1.requireValidRelayUrl(it) }.isSuccess }
                .distinct()
                .sorted()
                .take(NostrRoutingV1.MAX_RELAYS)
        if (wanted.isEmpty() || wanted == current.relays) return null
        val routing = NostrRoutingV1(current.nostrGroupId, wanted)
        val staged =
            groupManager.stageOwn(nostrId) { clone ->
                clone.proposeAppDataUpdate(NostrRoutingV1.COMPONENT_ID, routing.encode())
                clone.commit()
            }
        return Staged(nostrId, staged)
    }

    /**
     * `The removal Commit`: the sibling's tagged leaf out, `remove_device`, then a `removed` record with
     * the decision's time and the entry's key. The decision is kept until the roster no longer lists the
     * slot. Publish, then [applyStaged], then [removeGoneDevicesFromChats].
     */
    suspend fun stageRemoveDevice(
        slot: HexKey,
        now: Long,
    ): Staged {
        check(slot != ownSlot) { "A device never removes itself: it signs out" }
        val nostrId = checkNotNull(trust().trustedNostrGroupId)
        val roster = checkNotNull(roster())
        val entry = checkNotNull(roster.device(slot)) { "The roster does not list that device" }
        val tagKey = checkNotNull(entry.tagSignatureKey) { "A device whose link may still fail is not removed" }
        val t = trust()
        val decidedAt = t.removalDecisions.firstOrNull { it.slot == slot }?.time ?: now
        saveTrust(t.copy(removalDecisions = t.removalDecisions.filterNot { it.slot == slot } + DeviceGroupTrust.SlotTime(slot, decidedAt)))
        val leaf = leafClaims(nostrId).firstOrNull { it.second == DeviceTagV1.Claim.Device(slot) }?.first
        return stageRosterUpdate(
            listOfNotNull(leaf),
            listOf(RosterOperationV1.RemoveDevice(slot), RosterOperationV1.SetRejectedSlot(RejectedSlotV1(slot, RejectionReasonV1.REMOVED, decidedAt, tagKey))),
        )
    }

    /**
     * `device-roster-v1.md` "State": a `removed` record goes once 30 days have passed since its
     * `rejected_at`. The Commit that drops every such record, or null when none is due.
     */
    suspend fun expireRemovedRecords(now: Long): Staged? {
        val due = roster()?.rejectedSlots.orEmpty().filter { it.reason == RejectionReasonV1.REMOVED && now >= it.rejectedAt + REMOVED_RECORD_SECS }
        if (due.isEmpty()) return null
        return stageRosterUpdate(emptyList(), due.map { RosterOperationV1.RemoveRejectedSlot(it.slot) })
    }

    /** `Signing out` through siblings: this device's own entry set to `leaving`. Publish, then [applyStaged]. */
    suspend fun stageSignOut(): Staged {
        val entry = checkNotNull(roster()?.device(ownSlot)) { "The roster does not list this device" }
        checkNotNull(entry.tagSignatureKey) { "A device without its tag key signs out on its own" }
        return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetDevice(entry.copy(status = DeviceStatusV1.LEAVING))))
    }

    /** Siblings the roster lists as `leaving` with their key: each is removed as if the user decided to. */
    suspend fun pendingDepartures(): List<HexKey> =
        roster()
            ?.devices
            .orEmpty()
            .filter { it.slot != ownSlot && it.status == DeviceStatusV1.LEAVING && it.tagSignatureKey != null }
            .map { it.slot }

    // =================================================================================================
    // Applying device-group Commits
    // =================================================================================================

    /** What [applyStaged] did: the Commit published, and the Welcome of a linked device's Add. */
    class Applied(
        /** The device-group Commit, already published; null for the founding Add or without a confirming relay. */
        val event: OutboundGroupEvent?,
        /** The kind 444 to this account for the new device; deliver after the Commit is canonical. */
        val welcome: WelcomeDelivery?,
    )

    /**
     * Publishes [staged] and makes it canonical (publish-before-apply, through `MarmotManager`'s
     * publish gate, so the device group forks and settles like any group), or merges the founding Add
     * locally. Without a `MarmotManager`, only installs it.
     */
    suspend fun applyStaged(staged: Staged): Applied {
        val m = manager
        var event: OutboundGroupEvent? = null
        var canonical = true
        when {
            m == null -> groupManager.installState(staged.nostrGroupId, staged.staged.pendingState)
            staged.isFounding -> m.installDeviceGroupFounding(staged.nostrGroupId, staged.staged)
            else -> {
                event = m.publishDeviceGroupCommit(staged.nostrGroupId, staged.staged)
                canonical = event != null
            }
        }
        val welcome =
            if (m != null && canonical && staged.linkKeyPackageEventId != null) {
                staged.welcomeBytes?.let { m.wrapDeviceGroupWelcome(staged.nostrGroupId, it, staged.linkKeyPackageEventId) }
            } else {
                null
            }
        refresh()
        return Applied(event, welcome)
    }

    /** Applies an inbound device-group Commit, then everything that follows from the roster it leaves. */
    suspend fun processCommit(
        nostrGroupId: HexKey,
        framedCommitBytes: ByteArray,
    ) {
        groupManager.processFramedCommit(nostrGroupId, framedCommitBytes)
        refresh()
    }

    /** Per-epoch sender claims of the device group, so app events from an older epoch read their sender then. */
    private val epochClaims = LinkedHashMap<Long, Map<Int, HexKey>>()

    /**
     * Brings everything that follows from the device group's current state up to date: links made,
     * removed slots, a removal of this device. `MarmotManager.ingest` calls it after every group event;
     * call it after anything else that may move the device group (a convergence pass).
     */
    suspend fun refresh() {
        if (cached == null) start()
        recordEpochClaims()
        afterRosterChange()
        // A delivery read before its chat's Welcome imports once the chat is held.
        if (keptDeliveries.isNotEmpty()) importKeptHistory(TimeUtils.now(), fetch = false)
    }

    private suspend fun recordEpochClaims() {
        val group = deviceGroup() ?: return
        if (!group.isLocalMember()) return
        val roster = DeviceRosterRules.rosterOf(group.view().extensions) ?: return
        val view = group.view()
        val map = HashMap<Int, HexKey>()
        for (i in 0 until view.leafCount) {
            val leaf = view.leafNode(i) ?: continue
            (DeviceTagV1.read(leaf, roster) as? DeviceTagV1.Claim.Device)?.let { map[i] = it.slot }
        }
        epochClaims[group.epoch] = map
        while (epochClaims.size > EPOCH_CLAIMS_KEPT) epochClaims.remove(epochClaims.keys.first())
    }

    private suspend fun afterRosterChange() {
        val t = trust()
        val nostrId = t.trustedNostrGroupId ?: return
        val group = groupManager.getGroup(nostrId) ?: return
        if (!group.isLocalMember()) {
            onRemovedFromDeviceGroup(t, group)
            return
        }
        val roster = DeviceRosterRules.rosterOf(group.view().extensions) ?: return
        // Links made: the roster lists the new device with its key.
        val approvals =
            t.approvals.map { a ->
                if (a.outcome == DeviceGroupTrust.Outcome.PENDING && roster.device(a.slot)?.tagSignatureKey != null) a.copy(outcome = DeviceGroupTrust.Outcome.MADE) else a
            }
        // Every slot a roster this device applied holds as removed, for sign-ins (MDK 2d509151).
        val removed = t.removedSlots.associateBy { it.slot }.toMutableMap()
        roster.rejectedSlots.filter { it.reason == RejectionReasonV1.REMOVED }.forEach { r -> removed[r.slot] = DeviceGroupTrust.SlotTime(r.slot, maxOf(removed[r.slot]?.time ?: 0, r.rejectedAt)) }
        val decisions = t.removalDecisions.filter { roster.device(it.slot) != null }
        // A rejection is forgotten once the roster holds the slot as a device.
        val rejections = t.ownRejections.filter { roster.device(it.slot) == null }
        val next = t.copy(approvals = approvals, removedSlots = removed.values.sortedBy { it.slot }, removalDecisions = decisions, ownRejections = rejections)
        if (next != t) saveTrust(next)
        dropKeyPackagesOfGoneSlots(roster)
    }

    /**
     * `On the removed device` / `A link that is not taken up`: removed with no entry left for its slot
     * and having joined rather than created the group, the link failed; otherwise the user removed it
     * and the device is unlinked, acting for the account no more. Either way its copy is discarded.
     */
    private suspend fun onRemovedFromDeviceGroup(
        t: DeviceGroupTrust,
        group: MlsGroup,
    ) {
        val roster = DeviceRosterRules.rosterOf(group.view().extensions)
        val linkFailed = roster != null && roster.device(t.ownSlot) == null && roster.rejectedSlot(t.ownSlot) == null && t.linkedKeyPackageRef != null
        t.trustedNostrGroupId?.let { discard(it) }
        val reset = DeviceGroupTrust(ownSlot = t.ownSlot, unlinked = !linkFailed, ownRejections = t.ownRejections, firstCheckSlots = t.firstCheckSlots)
        saveTrust(reset)
        keyPackageStore.save(PrivateKeyPackages())
        Log.w(TAG) { if (linkFailed) "linking this device failed" else "this device was unlinked from its account" }
    }

    /**
     * `Explicit local reset`: discards this device's copy of its device group and the link-bound state,
     * keeping its chats and account. A later link is a fresh join.
     */
    suspend fun resetLocalCopy() {
        val t = trust()
        t.trustedNostrGroupId?.let { discard(it) }
        saveTrust(DeviceGroupTrust(ownSlot = t.ownSlot, ownRejections = t.ownRejections, firstCheckSlots = t.firstCheckSlots))
        keyPackageStore.save(PrivateKeyPackages())
        founding = null
    }

    private suspend fun discard(nostrGroupId: HexKey) {
        val m = manager
        if (m != null) m.discardDeviceGroup(nostrGroupId) else groupManager.removeGroupState(nostrGroupId)
        epochClaims.clear()
    }

    /** `Removing it from chats`: this account's leaves of gone slots, out of every chat requiring `0x800d`. */
    suspend fun removeGoneDevicesFromChats(): List<OutboundGroupEvent> {
        val m = manager ?: return emptyList()
        val deviceGroupId = trust().trustedNostrGroupId ?: return emptyList()
        val out = ArrayList<OutboundGroupEvent>()
        for (chat in groupManager.activeGroupIds()) {
            if (chat == deviceGroupId) continue
            val group = groupManager.getGroup(chat) ?: continue
            if (!AccountDevicesV1.isRequired(group.view().extensions)) continue
            val gone = leafClaims(chat).filter { it.second is DeviceTagV1.Claim.RemovedSlot }.map { it.first }
            if (gone.isEmpty()) continue
            try {
                out.add(m.removeOwnAccountDevices(chat, gone))
            } catch (e: Exception) {
                Log.w(TAG, "could not remove a gone device's leaves from $chat", e)
            }
        }
        return out
    }

    private suspend fun dropKeyPackagesOfGoneSlots(roster: DeviceRosterV1) {
        val kps = keyPackages()
        val live: (HexKey) -> Boolean = { roster.device(it) != null }
        val kept = kps.copy(issued = kps.issued.filter { live(it.toSlot) }, held = kps.held.filter { live(it.fromSlot) })
        if (kept.issued.size != kps.issued.size || kept.held.size != kps.held.size) keyPackageStore.save(kept)
    }

    // =================================================================================================
    // Device-group app events
    // =================================================================================================

    private suspend fun deviceGroupEvent(
        kind: Int,
        content: String,
        now: Long,
    ): OutboundGroupEvent {
        val m = checkNotNull(manager) { "app events need a MarmotManager" }
        val nostrId = checkNotNull(trust().trustedNostrGroupId)
        val rumor = RumorAssembler.assembleRumor<Event>(signer.pubKey, eventTemplate<Event>(kind = kind, description = content, createdAt = now) {})
        return m.buildGroupMessage(nostrId, rumor)
    }

    /** Whether this device's own leaf in its device group carries a tag that reads as its slot. */
    private suspend fun ownLeafTagged(): Boolean {
        val nostrId = trust().trustedNostrGroupId ?: return false
        val view = groupManager.getGroup(nostrId)?.view() ?: return false
        val leaf = view.leafNode(view.myLeafIndex) ?: return false
        return roster()?.let { DeviceTagV1.read(leaf, it) } == DeviceTagV1.Claim.Device(ownSlot)
    }

    /**
     * Routes one decrypted app event of the trusted device group. The sending leaf, in the epoch the
     * device holds, must carry a tag that reads as a device in the roster; anything else is dropped.
     */
    suspend fun onAppEvent(
        nostrGroupId: HexKey,
        innerEventJson: String,
        senderLeafIndex: Int,
        epoch: Long,
        now: Long = TimeUtils.now(),
    ) {
        if (!isTrustedDeviceGroup(nostrGroupId)) return
        val event = Event.fromJsonOrNull(innerEventJson) ?: return
        val group = groupManager.getGroup(nostrGroupId) ?: return
        val roster = DeviceRosterRules.rosterOf(group.view().extensions) ?: return
        // The sending leaf as it was in the epoch the message was sent in (`Receiving`): the current
        // tree for the current epoch, the claims recorded while an older epoch was current otherwise.
        // A heartbeat counts only from the epoch the device holds (`Heartbeats`).
        val sender =
            if (epoch == group.epoch) {
                val leaf = group.view().leafNode(senderLeafIndex) ?: return
                (DeviceTagV1.read(leaf, roster) as? DeviceTagV1.Claim.Device)?.slot ?: return
            } else {
                if (event.kind == MarmotDeviceGroupKinds.HEARTBEAT) return
                epochClaims[epoch]?.get(senderLeafIndex) ?: return
            }
        if (sender == ownSlot) return
        // A sender the current roster no longer lists as a device is dropped whatever its old tag said.
        if (roster.device(sender) == null) return
        when (event.kind) {
            MarmotDeviceGroupKinds.HEARTBEAT -> onHeartbeat(sender, roster, event.createdAt, now)
            MarmotDeviceGroupKinds.GAP_FILL_CLAIM -> onClaim(sender, event, now)
            MarmotDeviceGroupKinds.PRIVATE_KEY_PACKAGE_REQUEST -> onKeyPackageRequest(sender, event, now)
            MarmotDeviceGroupKinds.PRIVATE_KEY_PACKAGE_HAND_OFF -> onHandOff(sender, event, now)
            MarmotDeviceGroupKinds.SIBLING_WELCOME -> onSiblingWelcome(sender, event)
            MarmotDeviceGroupKinds.LINK_CHAT_INVENTORY -> onInventory(sender, roster, event, now)
            SmallStateMessages.UPDATE_KIND -> onSmallStateUpdate(event)
            SmallStateMessages.BROADCAST_REQUEST_KIND -> onBroadcastRequest(now)
            HistoryDelivery.KIND -> onHistoryDelivery(sender, event, now)
            else -> {}
        }
    }

    // ---- heartbeats ----------------------------------------------------------------------------------

    /** A heartbeat to send when the last one is an hour old and this device's leaf is tagged. */
    suspend fun heartbeatDue(now: Long): OutboundGroupEvent? {
        val t = trust()
        if (!t.trustsDeviceGroup || now - t.lastHeartbeatSent < DeviceHeartbeat.INTERVAL_SECS || !ownLeafTagged()) return null
        return deviceGroupEvent(DeviceHeartbeat.KIND, DeviceHeartbeat.CONTENT, now)
    }

    /** A relay accepted the heartbeat sent at [sentAt]. */
    suspend fun heartbeatSent(sentAt: Long) {
        saveTrust(trust().copy(lastHeartbeatSent = sentAt))
    }

    private suspend fun onHeartbeat(
        sender: HexKey,
        roster: DeviceRosterV1,
        createdAt: Long,
        now: Long,
    ) {
        val linkedAt = roster.device(sender)?.linkedAt ?: return
        val seen = minOf(createdAt, now)
        val t = trust()
        val prior = t.activity.firstOrNull { it.slot == sender && it.linkedAt == linkedAt }?.lastActivity ?: 0
        if (seen <= prior) return
        saveTrust(t.copy(activity = t.activity.filterNot { it.slot == sender } + DeviceGroupTrust.Activity(sender, linkedAt, seen)))
    }

    /** A sibling's last activity, for its current roster entry. */
    suspend fun lastActivity(slot: HexKey): Long? {
        val linkedAt = roster()?.device(slot)?.linkedAt ?: return null
        return trust().activity.firstOrNull { it.slot == slot && it.linkedAt == linkedAt }?.lastActivity
    }

    // ---- private KeyPackages -------------------------------------------------------------------------

    private suspend fun issue(
        toSlot: HexKey,
        count: Int,
        now: Long,
    ): List<ByteArray> {
        val m = checkNotNull(manager)
        val kps = keyPackages()
        val room = MAX_PRIVATE_PER_SIBLING - kps.issued.count { it.toSlot == toSlot && now < it.notAfter }
        val n = minOf(count, room)
        if (n <= 0) return emptyList()
        val issued = ArrayList<PrivateKeyPackages.Issued>()
        val messages = ArrayList<ByteArray>()
        repeat(n) {
            val bundle = CurrentProfileGroupFactory.createKeyPackage(signer, false, MlsCiphersuite.DEFAULT, m.supportedComponents) { key -> ownTagComponents(key) }
            check(DeviceTagV1.entryOf(bundle.keyPackage.leafNode) != null) { "a private KeyPackage carries the issuer's tag" }
            val lifetime = checkNotNull(bundle.keyPackage.leafNode.lifetime)
            issued.add(PrivateKeyPackages.Issued(toSlot, bundle.keyPackage.reference().toHexKey(), lifetime.notBefore, lifetime.notAfter, now, KeyPackageBundleCodec.encode(bundle)))
            messages.add(mlsMessage(bundle.keyPackage.toTlsBytes()))
        }
        keyPackageStore.save(kps.copy(issued = kps.issued + issued))
        return messages
    }

    private fun mlsMessage(keyPackage: ByteArray): ByteArray =
        TlsWriter()
            .also { MlsMessage(wireFormat = WireFormat.KEY_PACKAGE, payload = keyPackage).encodeTls(it) }
            .toByteArray()

    private suspend fun handOff(
        toSlot: HexKey,
        packages: List<ByteArray>,
        now: Long,
    ): List<OutboundGroupEvent> =
        packages.chunked(PrivateKeyPackageHandOff.MAX_KEY_PACKAGES).map {
            deviceGroupEvent(PrivateKeyPackageHandOff.KIND, PrivateKeyPackageHandOff(ownSlot, toSlot, it).content(), now)
        }

    /** Asks [fromSlot] for [want] private KeyPackages (459). */
    suspend fun requestKeyPackages(
        fromSlot: HexKey,
        want: Int,
        now: Long,
    ): OutboundGroupEvent = deviceGroupEvent(PrivateKeyPackageRequest.KIND, PrivateKeyPackageRequest(ownSlot, fromSlot, want).content(), now)

    /**
     * "Issuing": for each sibling whose stock (handed, unconsumed, before halfway) is below 5, issue
     * enough to bring it to 10 and hand them over. Returns the hand-offs to publish.
     */
    suspend fun topUpSiblings(now: Long): List<OutboundGroupEvent> {
        if (!ownLeafTagged()) return emptyList()
        val roster = roster() ?: return emptyList()
        val out = ArrayList<OutboundGroupEvent>()
        for (device in roster.devices) {
            if (device.slot == ownSlot || device.tagSignatureKey == null) continue
            val stock = keyPackages().issued.count { it.toSlot == device.slot && now < it.halfway }
            if (stock >= STOCK_LOW) continue
            val packages = issue(device.slot, STOCK_TARGET - stock, now)
            if (packages.isNotEmpty()) out.addAll(handOff(device.slot, packages, now))
        }
        return out
    }

    private suspend fun onKeyPackageRequest(
        sender: HexKey,
        event: Event,
        now: Long,
    ) {
        val request = PrivateKeyPackageRequest.parse(event.content) ?: return
        if (request.to != ownSlot || request.from != sender) return
        val kps = keyPackages()
        if (event.id in kps.answeredRequests) return
        keyPackageStore.save(kps.copy(answeredRequests = (kps.answeredRequests + event.id).takeLast(MAX_ANSWERED)))
        val packages = issue(sender, request.want, now)
        if (packages.isNotEmpty()) outbox.addAll(handOff(sender, packages, now))
    }

    private suspend fun onHandOff(
        sender: HexKey,
        event: Event,
        now: Long,
    ) {
        val handOff = PrivateKeyPackageHandOff.parse(event.content) ?: return
        if (handOff.to != ownSlot || handOff.from != sender) return
        val roster = roster() ?: return
        val kps = keyPackages()
        val accepted = ArrayList<PrivateKeyPackages.Held>()
        for (bytes in handOff.keyPackages) {
            val kp =
                try {
                    KeyPackageUtils.decodeKeyPackage(bytes)
                } catch (e: Exception) {
                    return
                }
            val credential = kp.leafNode.credential
            val lifetime = kp.leafNode.lifetime ?: return
            // The whole hand-off is dropped unless every KeyPackage is the account's, live, not
            // last-resort, and tagged as the sender's.
            if (credential !is Credential.Basic || credential.identity.toHexKey() != signer.pubKey) return
            if (kp.isLastResort() || now >= lifetime.notAfter || now < lifetime.notBefore) return
            if (DeviceTagV1.read(kp.leafNode, roster) != DeviceTagV1.Claim.Device(sender)) return
            val ref = kp.reference().toHexKey()
            if (kps.used.any { it.ref == ref } || kps.held.any { it.ref == ref }) continue
            accepted.add(PrivateKeyPackages.Held(sender, ref, lifetime.notBefore, lifetime.notAfter, bytes))
        }
        if (accepted.isNotEmpty()) keyPackageStore.save(kps.copy(held = kps.held + accepted))
    }

    /** Private KeyPackages [slot] handed this device that it can still use. */
    suspend fun heldFrom(
        slot: HexKey,
        now: Long,
    ): Int = keyPackages().held.count { it.fromSlot == slot && now < it.notAfter }

    private suspend fun takeHeld(
        slot: HexKey,
        now: Long,
    ): PrivateKeyPackages.Held? {
        val kps = keyPackages()
        val pick = kps.held.filter { it.fromSlot == slot && now < it.notAfter }.minByOrNull { it.notAfter } ?: return null
        keyPackageStore.save(kps.copy(held = kps.held.filterNot { it.ref == pick.ref }, used = kps.used.filter { now < it.notAfter } + PrivateKeyPackages.Ref(pick.ref, pick.notAfter)))
        return pick
    }

    // ---- sibling Welcomes ----------------------------------------------------------------------------

    /** Siblings a chat may include: listed `active`/`inactive`, with a tag key, not this device. */
    private suspend fun eligibleSiblings(requireAddToAll: Boolean): List<DeviceEntryV1> {
        val roster = roster() ?: return emptyList()
        val t = trust()
        return roster.devices.filter { d ->
            d.slot != ownSlot &&
                d.tagSignatureKey != null &&
                (d.status == DeviceStatusV1.ACTIVE || d.status == DeviceStatusV1.INACTIVE) &&
                (!requireAddToAll || d.addToAllChats) &&
                t.approvals.none { it.slot == d.slot && it.outcome != DeviceGroupTrust.Outcome.MADE }
        }
    }

    /** What [createChat] and [addSiblingToChat] did. */
    class SiblingAdd(
        val result: MarmotManager.SiblingAddResult,
        /** The sibling Welcomes to publish in the device group. */
        val deviceGroupEvents: List<OutboundGroupEvent>,
        /** Siblings left out for lack of a private KeyPackage: ask them ([requestKeyPackages]). */
        val missing: List<HexKey>,
    )

    /**
     * `Creating a chat`: a chat whose founding Add holds [invites] (other accounts' published
     * KeyPackages) and each linked sibling with a private KeyPackage it handed this device. A sibling
     * without one is omitted. Each included sibling gets a sibling Welcome in the device group.
     */
    suspend fun createChat(
        nostrGroupId: HexKey,
        chatRelays: List<String>,
        profile: GroupProfileV1?,
        invites: List<MarmotManager.MemberInvite>,
        now: Long,
    ): SiblingAdd {
        val m = checkNotNull(manager)
        m.createCurrentProfileGroup(nostrGroupId, chatRelays, profile)
        val included = ArrayList<Pair<HexKey, PrivateKeyPackages.Held>>()
        val missing = ArrayList<HexKey>()
        if (ownLeafTagged()) {
            for (sibling in eligibleSiblings(requireAddToAll = false)) {
                val held = takeHeld(sibling.slot, now)
                if (held == null) missing.add(sibling.slot) else included.add(sibling.slot to held)
            }
        }
        val normalized = m.groupRelays(nostrGroupId)
        val result = m.addWithSiblings(nostrGroupId, invites, included.map { it.second.keyPackage }, normalized)
        val events = siblingWelcomes(nostrGroupId, result.siblingWelcome, included, chatRelays, now)
        return SiblingAdd(result, events, missing)
    }

    /**
     * Adds [slot] to [nostrGroupId] with one of its private KeyPackages (the approver's post-link Add, or
     * a gap fill), unless a leaf already reads as it. Null when it cannot now.
     */
    suspend fun addSiblingToChat(
        nostrGroupId: HexKey,
        slot: HexKey,
        now: Long,
    ): SiblingAdd? {
        val m = checkNotNull(manager)
        if (!ownLeafTagged()) return null
        val group = groupManager.getGroup(nostrGroupId) ?: return null
        if (!AccountDevicesV1.isRequired(group.view().extensions)) return null
        if (leafClaims(nostrGroupId).any { it.second == DeviceTagV1.Claim.Device(slot) }) return null
        // A winning decline for this copy's admission holds every automatic sibling Add from it.
        if (declined(group.groupId.toHexKey())) return null
        val held = takeHeld(slot, now) ?: return SiblingAdd(MarmotManager.SiblingAddResult(null, emptyList(), null), emptyList(), listOf(slot))
        val relayUrls = AppDataDictionary.fromExtensionsOrEmpty(group.view().extensions)[NostrRoutingV1.COMPONENT_ID]?.let { NostrRoutingV1.decode(it).relays }.orEmpty()
        val result = m.addWithSiblings(nostrGroupId, emptyList(), listOf(held.keyPackage), m.groupRelays(nostrGroupId))
        // The Commit's publication succeeded: this device owes the sibling the chat's history.
        if (result.siblingWelcome != null) owedHistories.add(OwedHistory(nostrGroupId, slot, now))
        return SiblingAdd(result, siblingWelcomes(nostrGroupId, result.siblingWelcome, listOf(slot to held), relayUrls, now), emptyList())
    }

    /**
     * `Adding the new device to chats`: once a link this device approved is made, and while the new
     * device is active with "add to all my chats" on, add it to every chat this device is in that can
     * take a same-account Add. Chats it cannot take now (no private KeyPackage yet) are left for a later
     * pass or a sibling's gap fill.
     */
    suspend fun addNewDeviceToChats(
        slot: HexKey,
        now: Long,
    ): List<SiblingAdd> {
        val t = trust()
        if (t.approvals.none { it.slot == slot && it.outcome == DeviceGroupTrust.Outcome.MADE }) return emptyList()
        val entry = roster()?.device(slot) ?: return emptyList()
        if (entry.status != DeviceStatusV1.ACTIVE || !entry.addToAllChats) return emptyList()
        val deviceGroupId = t.trustedNostrGroupId
        return groupManager.activeGroupIds().filter { it != deviceGroupId }.mapNotNull { chat -> addSiblingToChat(chat, slot, now)?.takeIf { it.missing.isEmpty() } }
    }

    private suspend fun siblingWelcomes(
        chat: HexKey,
        welcome: ByteArray?,
        included: List<Pair<HexKey, PrivateKeyPackages.Held>>,
        chatRelays: List<String>,
        now: Long,
    ): List<OutboundGroupEvent> {
        if (welcome == null || included.isEmpty()) return emptyList()
        // The copy's original generation travels with the Add (version 2); a copy with none, which this
        // client's user joined, is forwarded as confirmed (version 3, `device-group.md` "Choosing the version").
        val generation =
            groupManager
                .getGroup(chat)
                ?.groupId
                ?.toHexKey()
                ?.let { sync().generations[it] }
        val confirmed = generation == null
        val version = SiblingWelcome.choose(generation, null, confirmed)
        val relays = chatRelays.distinct().take(SiblingWelcome.MAX_RELAYS)
        val repairs = ArrayList<PrivateKeyPackages.Repair>()
        val events =
            included.map { (slot, held) ->
                val content = SiblingWelcome(version, ownSlot, slot, generation, null, confirmed, held.ref, welcome, relays).content()
                repairs.add(PrivateKeyPackages.Repair(slot, chat, held.ref, held.notAfter, now, content))
                deviceGroupEvent(SiblingWelcome.KIND, content, now)
            }
        val kps = keyPackages()
        keyPackageStore.save(kps.copy(repairs = kps.repairs.filter { now < it.notAfter } + repairs))
        return events
    }

    /**
     * `Resending a published sibling Welcome`: a retained Welcome is due again once its target's last
     * activity is at least 600 s after the carrier went out; it is sent again in a fresh carrier unless
     * the chat's tree shows the target's leaf has advanced past its KeyPackage (an Update or a Commit),
     * which completes repair. Returns the carriers to publish.
     */
    suspend fun siblingWelcomeRepairs(now: Long): List<OutboundGroupEvent> {
        if (!ownLeafTagged()) return emptyList()
        val roster = roster() ?: return emptyList()
        val kps = keyPackages()
        val kept = ArrayList<PrivateKeyPackages.Repair>()
        val out = ArrayList<OutboundGroupEvent>()
        for (r in kps.repairs) {
            if (now >= r.notAfter) continue
            val target = roster.device(r.toSlot)
            if (target == null || target.status == DeviceStatusV1.LEAVING || target.status == DeviceStatusV1.MOVED) continue
            val leaf =
                groupManager.getGroup(r.chat)?.view()?.let { v ->
                    (0 until v.leafCount).mapNotNull { v.leafNode(it) }.firstOrNull { DeviceTagV1.read(it, roster) == DeviceTagV1.Claim.Device(r.toSlot) }
                }
            if (leaf != null && leaf.leafNodeSource != LeafNodeSource.KEY_PACKAGE) continue
            val activity = lastActivity(r.toSlot)
            if (activity == null || activity < r.publishedAt + REPAIR_AFTER_SECS || now <= r.publishedAt) {
                kept.add(r)
                continue
            }
            out.add(deviceGroupEvent(SiblingWelcome.KIND, r.content, now))
            kept.add(r.copy(publishedAt = now))
        }
        keyPackageStore.save(keyPackages().copy(repairs = kept))
        return out
    }

    /**
     * `Producing tags`: once this device can tag, a self-update in each chat where its own leaf carries
     * no tag reading as its slot, so its siblings can tell its leaf apart. Returns the Commits, already
     * published. The caller spreads these out over time (the spec's delay for stale leaves).
     */
    suspend fun retagOwnLeaves(): List<OutboundGroupEvent> {
        val m = manager ?: return emptyList()
        if (!ownLeafTagged()) return emptyList()
        val deviceGroupId = trust().trustedNostrGroupId
        val roster = roster() ?: return emptyList()
        val out = ArrayList<OutboundGroupEvent>()
        for (chat in groupManager.activeGroupIds()) {
            if (chat == deviceGroupId) continue
            val group = groupManager.getGroup(chat) ?: continue
            if (!group.isLocalMember()) continue
            val view = group.view()
            val leaf = view.leafNode(view.myLeafIndex) ?: continue
            if (DeviceTagV1.read(leaf, roster) == DeviceTagV1.Claim.Device(ownSlot)) continue
            val tag = ownTagComponents(leaf.signatureKey).singleOrNull() ?: continue
            val caps = view.leafCapabilities(view.myLeafIndex) ?: continue
            val dictionary = AppDataDictionary.fromExtensionsOrEmpty(leaf.extensions).with(tag.componentId, tag.data)
            val extensions = leaf.extensions.filterNot { it.extensionType == AppDataDictionary.EXTENSION_TYPE } + dictionary.toExtension()
            try {
                val staged =
                    groupManager.stageOwn(chat) { clone ->
                        clone.advertiseInNextCommit(caps, extensions)
                        clone.commit()
                    }
                m.publishDeviceGroupCommit(chat, staged)?.let { out.add(it) }
            } catch (e: Exception) {
                Log.w(TAG, "could not retag this device's leaf in $chat", e)
            }
        }
        return out
    }

    /**
     * `Marking and removing inactive devices`, simplified to the clock this device keeps: a sibling
     * whose last activity (or `linked_at`, before any) is 30 days old is set `inactive`; one still
     * `inactive` at 90 days with "keep while inactive" off is removed with the ordinary removal Commit
     * (no decision kept, its slot not deleted). This device sets its own entry back to `active` once
     * its leaf is tagged and it has sent a heartbeat. Null when nothing is due.
     */
    suspend fun stageInactivity(now: Long): Staged? {
        val roster = roster() ?: return null
        val t = trust()
        roster.device(ownSlot)?.let { own ->
            if (own.status == DeviceStatusV1.INACTIVE && t.lastHeartbeatSent > 0 && ownLeafTagged()) {
                return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetDevice(own.copy(status = DeviceStatusV1.ACTIVE))))
            }
        }
        for (d in roster.devices) {
            if (d.slot == ownSlot || d.tagSignatureKey == null) continue
            val since = maxOf(d.linkedAt, lastActivity(d.slot) ?: 0)
            if (d.status == DeviceStatusV1.ACTIVE && now - since >= INACTIVE_AFTER_SECS) {
                return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetDevice(d.copy(status = DeviceStatusV1.INACTIVE))))
            }
            if (d.status == DeviceStatusV1.INACTIVE && !d.keepWhileInactive && now - since >= REMOVE_INACTIVE_AFTER_SECS) {
                val nostrId = checkNotNull(t.trustedNostrGroupId)
                val leaf = leafClaims(nostrId).firstOrNull { it.second == DeviceTagV1.Claim.Device(d.slot) }?.first
                return stageRosterUpdate(listOfNotNull(leaf), listOf(RosterOperationV1.RemoveDevice(d.slot), RosterOperationV1.SetRejectedSlot(RejectedSlotV1(d.slot, RejectionReasonV1.REMOVED, now, d.tagSignatureKey))))
            }
        }
        return null
    }

    private suspend fun onSiblingWelcome(
        sender: HexKey,
        event: Event,
    ) {
        val m = manager ?: return
        val sw = SiblingWelcome.parse(event.content) ?: return
        if (sw.to != ownSlot || sw.from != sender) return
        val kps = keyPackages()
        val issued = kps.issued.firstOrNull { it.ref == sw.keyPackageRef && it.toSlot == sender } ?: return
        val bundle = KeyPackageBundleCodec.decode(issued.bundle)
        when (val result = m.joinSiblingWelcome(sw.welcome, bundle)) {
            is WelcomeResult.Joined -> {
                keyPackageStore.save(keyPackages().let { it.copy(issued = it.issued.filterNot { i -> i.ref == issued.ref }) })
                // The sibling's original generation, never one derived from this later Add.
                sw.invitationGeneration?.let { onChatAdmitted(result.nostrGroupId, inheritedGeneration = it, founded = false) }
            }
            else -> Log.w(TAG) { "sibling Welcome from ${sender.take(8)} did not join: $result" }
        }
    }

    // ---- account sync (account-sync.md) ----------------------------------------------------------------

    private suspend fun sync(): AccountSyncState = syncStore.load() ?: AccountSyncState()

    /** This account's small state: every winning item and each local copy's invitation generation. */
    suspend fun smallState(): AccountSyncState = sync()

    private fun nostrIdOf(mlsGroupId: HexKey): HexKey? = groupManager.activeGroupIds().firstOrNull { groupManager.getGroup(it)?.groupId?.toHexKey() == mlsGroupId }

    private suspend fun declined(mlsGroupId: HexKey): Boolean {
        val s = sync()
        val gen = s.generations[mlsGroupId] ?: return false
        return (s.held("$mlsGroupId/invite/$gen") as? SmallStateItem.Invite)?.accept == false
    }

    /**
     * Records the invitation generation of a newly admitted copy (`Invitation decisions`): derived from
     * its post-admission GroupContext, or [inheritedGeneration] from a sibling Welcome. A copy this
     * device founded holds an implicit acceptance at version 1 unless a decision is already held. A
     * decline already held for the generation is applied at once. `MarmotManager` calls this for every
     * join and founding; a client without a device group keeps the generations too, for later.
     */
    suspend fun onChatAdmitted(
        nostrGroupId: HexKey,
        inheritedGeneration: HexKey? = null,
        founded: Boolean,
    ) {
        if (cached == null) start()
        if (nostrGroupId == trust().trustedNostrGroupId) return
        val group = groupManager.getGroup(nostrGroupId) ?: return
        val mlsId = group.groupId.toHexKey()
        if (mlsId.length !in 2..512) return
        val gen = inheritedGeneration ?: InvitationGeneration.compute(signer.pubKey.hexToByteArray(), group.saveState().groupContext.toTlsBytes()).toHexKey()
        var s = sync().let { it.copy(generations = it.generations + (mlsId to gen)) }
        if (founded && s.held("$mlsId/invite/$gen") == null) s = s.merge(SmallStateItem.Invite(mlsId, gen, accept = true, version = 1)).first
        syncStore.save(s)
        if (declined(mlsId)) applyDecline(nostrGroupId)
    }

    /**
     * `Leaving`: before this device's user leaves a chat, record a decline for its copy's generation as
     * a local change (one version above the held one). Returns the updates to publish in the device
     * group; the caller then leaves the chat as usual (`MarmotManager.leave`). A copy with no generation,
     * or a device that trusts no device group, records nothing.
     */
    suspend fun recordLeave(
        nostrGroupId: HexKey,
        now: Long,
    ): List<OutboundGroupEvent> {
        val group = groupManager.getGroup(nostrGroupId) ?: return emptyList()
        val mlsId = group.groupId.toHexKey()
        val s = sync()
        val gen = s.generations[mlsId] ?: return emptyList()
        val held = s.held("$mlsId/invite/$gen") as? SmallStateItem.Invite
        val version = (held?.version ?: 0) + 1
        if (version > SmallStateItem.MAX_NUMBER) return emptyList()
        val item = SmallStateItem.Invite(mlsId, gen, accept = false, version = version)
        syncStore.save(s.merge(item).first)
        return sendItems(listOf(item), now)
    }

    /** A user change of `pin`, `mute` or `archive` ([value]: `true`, `false` or a mute time). */
    suspend fun changeSetting(
        nostrGroupId: HexKey,
        name: String,
        value: String,
        now: Long,
    ): List<OutboundGroupEvent> {
        require(name == "pin" || name == "mute" || name == "archive")
        val mlsId = checkNotNull(groupManager.getGroup(nostrGroupId)).groupId.toHexKey()
        val s = sync()
        val held = s.held("$mlsId/$name") as? SmallStateItem.Versioned
        val item = SmallStateItem.Versioned(mlsId, name, value, (held?.version ?: 0) + 1, RandomInstance.bytes(16).toHexKey())
        syncStore.save(s.merge(item).first)
        return sendItems(listOf(item), now)
    }

    /** The user read up to the message sent in [epoch] at [createdAt] with [eventId]; positions only move forward. */
    suspend fun markRead(
        nostrGroupId: HexKey,
        epoch: Long,
        createdAt: Long,
        eventId: HexKey,
        now: Long,
    ): List<OutboundGroupEvent> {
        val mlsId = checkNotNull(groupManager.getGroup(nostrGroupId)).groupId.toHexKey()
        val item = SmallStateItem.Read(mlsId, epoch, createdAt, eventId)
        val (next, won) = sync().merge(item)
        if (!won) return emptyList()
        syncStore.save(next)
        return sendItems(listOf(item), now)
    }

    private suspend fun sendItems(
        items: List<SmallStateItem>,
        now: Long,
    ): List<OutboundGroupEvent> {
        if (!trust().trustsDeviceGroup || items.isEmpty()) return emptyList()
        return SmallStateMessages.updates(items).map { deviceGroupEvent(SmallStateMessages.UPDATE_KIND, it, now) }
    }

    /**
     * `Broadcasts`: every item this device holds, when it starts ([start] = true: plus a broadcast
     * request) or once 24 hours have passed since its last broadcast. Returns the events to publish.
     */
    suspend fun broadcastDue(
        now: Long,
        start: Boolean = false,
    ): List<OutboundGroupEvent> {
        if (!trust().trustsDeviceGroup) return emptyList()
        val s = sync()
        if (!start && now - s.lastBroadcast < BROADCAST_INTERVAL_SECS) return emptyList()
        syncStore.save(s.copy(lastBroadcast = now))
        val out = ArrayList(sendItems(s.items, now))
        if (start) out.add(deviceGroupEvent(SmallStateMessages.BROADCAST_REQUEST_KIND, SmallStateMessages.BROADCAST_REQUEST, now))
        return out
    }

    /**
     * Convergence rewound the device group onto another branch: an update this device encrypted on the
     * withdrawn branch may never reach a sibling, and branch selection parks it rather than withdrawing it.
     * Every item, invitation answers included, is owed again and queued on [drainOutbox]; receivers merge by
     * version, so an update that does arrive later costs only a duplicate (MDK 0.19.0, mdk#3594).
     */
    suspend fun onDeviceGroupRewound(
        nostrGroupId: HexKey,
        now: Long = TimeUtils.now(),
    ) {
        if (!isTrustedDeviceGroup(nostrGroupId)) return
        outbox.addAll(sendItems(sync().items, now))
    }

    private suspend fun onBroadcastRequest(now: Long) {
        val s = sync()
        // At most one answering broadcast an hour.
        if (now - s.lastRequestAnswered < REQUEST_ANSWER_INTERVAL_SECS) return
        syncStore.save(s.copy(lastRequestAnswered = now, lastBroadcast = now))
        outbox.addAll(sendItems(s.items, now))
    }

    private suspend fun onSmallStateUpdate(event: Event) {
        val items = SmallStateMessages.parse(event.content) ?: return
        var s = sync()
        val declines = ArrayList<SmallStateItem.Invite>()
        for (item in items) {
            val (next, won) = s.merge(item)
            s = next
            if (won && item is SmallStateItem.Invite && !item.accept) declines.add(item)
        }
        syncStore.save(s)
        // `Applying`: a winning decline requests Leave for the local copy of exactly that generation.
        for (d in declines) {
            if (s.generations[d.chat] != d.generation) continue
            nostrIdOf(d.chat)?.let { applyDecline(it) }
        }
    }

    private suspend fun applyDecline(nostrGroupId: HexKey) {
        val m = manager ?: return
        if (!groupManager.isMember(nostrGroupId)) return
        try {
            outbox.add(m.leaveGroup(nostrGroupId))
        } catch (e: Exception) {
            Log.w(TAG, "could not leave $nostrGroupId after a sibling's decline", e)
        }
    }

    // ---- gap fill ------------------------------------------------------------------------------------

    private suspend fun onClaim(
        sender: HexKey,
        event: Event,
        now: Long,
    ) {
        val claim = GapFillClaim.parse(event.content) ?: return
        if (claim.from != sender || !GapFillClaim.isLive(event.createdAt, now)) return
        val roster = roster() ?: return
        if (roster.device(claim.to) == null) return
        val map = claims.getOrPut(claim.chat to claim.to) { HashMap() }
        map[sender] = maxOf(map[sender] ?: 0, event.createdAt + GapFillClaim.LIFETIME_SECS)
    }

    /** What [fillMissingChats] produced: claims to publish now, and the Adds it made. */
    class GapFill(
        val claims: List<OutboundGroupEvent>,
        val adds: List<SiblingAdd>,
    )

    /**
     * `Filling a missing chat`: for each chat requiring `0x800d` that lacks a sibling with "add to all
     * my chats" on, claim it first (458); on a later pass, if this device's live claim is the lowest
     * slot among the live ones, make the Add.
     */
    suspend fun fillMissingChats(now: Long): GapFill {
        val deviceGroupId = trust().trustedNostrGroupId ?: return GapFill(emptyList(), emptyList())
        if (!ownLeafTagged()) return GapFill(emptyList(), emptyList())
        val siblings = eligibleSiblings(requireAddToAll = true)
        val outClaims = ArrayList<OutboundGroupEvent>()
        val adds = ArrayList<SiblingAdd>()
        for (chat in groupManager.activeGroupIds()) {
            if (chat == deviceGroupId) continue
            val group = groupManager.getGroup(chat) ?: continue
            if (!AccountDevicesV1.isRequired(group.view().extensions)) continue
            val present = leafClaims(chat).map { it.second }.toSet()
            val mlsId = group.groupId.toHexKey()
            for (sibling in siblings) {
                if (DeviceTagV1.Claim.Device(sibling.slot) in present) continue
                if (heldFrom(sibling.slot, now) == 0) continue
                val live = claims.getOrPut(mlsId to sibling.slot) { HashMap() }
                live.entries.removeAll { now >= it.value }
                if (ownSlot !in live) {
                    outClaims.add(deviceGroupEvent(GapFillClaim.KIND, GapFillClaim(ownSlot, sibling.slot, mlsId).content(), now))
                    live[ownSlot] = now + GapFillClaim.LIFETIME_SECS
                    continue
                }
                if (live.keys.minOrNull() != ownSlot) continue
                addSiblingToChat(chat, sibling.slot, now)?.let { adds.add(it) }
            }
        }
        return GapFill(outClaims, adds)
    }

    // ---- post-link inventory -------------------------------------------------------------------------

    /**
     * The approver's report to the new device [slot] of the chats it can expect (477), for a link it
     * approved: every chat requiring `0x800d`, as tokens of the link's KeyPackageRef and the group id.
     */
    suspend fun chatInventory(
        slot: HexKey,
        revision: Long,
        now: Long,
    ): List<OutboundGroupEvent> {
        val roster = roster() ?: return emptyList()
        val entry = roster.device(slot) ?: return emptyList()
        if (entry.linkedBy != ownSlot) return emptyList()
        val ref = entry.announcedKeyPackage ?: return emptyList()
        val deviceGroupId = trust().trustedNostrGroupId
        val tokens =
            groupManager
                .activeGroupIds()
                .filter { it != deviceGroupId }
                .mapNotNull { groupManager.getGroup(it) }
                .filter { AccountDevicesV1.isRequired(it.view().extensions) }
                .map { LinkChatInventory.token(ref.hexToByteArray(), it.groupId).toHexKey() }
                .sorted()
        val pages = if (tokens.isEmpty()) listOf(emptyList()) else tokens.chunked(LinkChatInventory.PAGE_SIZE)
        return pages.mapIndexed { i, page ->
            deviceGroupEvent(LinkChatInventory.KIND, LinkChatInventory(slot, ref, revision, now + INVENTORY_LIFETIME_SECS, tokens.size.toLong(), i.toLong(), page).content(), now)
        }
    }

    private suspend fun onInventory(
        sender: HexKey,
        roster: DeviceRosterV1,
        event: Event,
        now: Long,
    ) {
        val page = LinkChatInventory.parse(event.content) ?: return
        val t = trust()
        if (page.to != ownSlot || page.link != t.linkedKeyPackageRef || roster.device(ownSlot)?.linkedBy != sender) return
        if (now >= page.expiresAt) return
        val current = inventory
        if (current == null || page.revision > current.first) {
            inventory = Triple(page.revision, page.total, page.chats.toMutableSet())
        } else if (page.revision == current.first) {
            current.third.addAll(page.chats)
        }
    }

    /** How many chats the approver reported that this new device has not joined yet; null without a report. */
    suspend fun remainingExpectedChats(): Long? {
        val inv = inventory ?: return null
        val ref = trust().linkedKeyPackageRef ?: return null
        val joined =
            groupManager
                .activeGroupIds()
                .mapNotNull { groupManager.getGroup(it) }
                .map { LinkChatInventory.token(ref.hexToByteArray(), it.groupId).toHexKey() }
                .count { it in inv.third }
        return inv.second - joined
    }

    // ---- history deliveries (account-sync.md "History deliveries") ------------------------------------

    private class OwedHistory(
        val chat: HexKey,
        val slot: HexKey,
        val owedAt: Long,
    )

    /**
     * Histories this device owes the siblings its own Commits added to chats. Memory only: a restart
     * before [historyDeliveries] runs forgets them (the spec's limits already allow a lost history).
     */
    private val owedHistories = ArrayList<OwedHistory>()

    private class KeptDelivery(
        val delivery: HistoryDelivery,
        val key: ByteArray,
        val hash: ByteArray,
        val readAt: Long,
        var ciphertext: ByteArray?,
    )

    /** Deliveries read that cannot be imported yet: their chat is not held, or their blob not fetched. Memory only. */
    private val keptDeliveries = ArrayList<KeptDelivery>()

    /** Events a history delivery brought into [nostrGroupId], already in the message store. */
    class ImportedHistory(
        val nostrGroupId: HexKey,
        val events: List<Event>,
        /** Each event's id to the MLS epoch its bundle gave it. */
        val epochs: Map<HexKey, Long> = emptyMap(),
    )

    private val imported = ArrayList<ImportedHistory>()

    /**
     * Fetches a Blossom blob by its URL, reading at most `maxBytes`; null when it cannot now. Set by an
     * app that lets this device contact the servers a delivery names; without it a Blossom delivery
     * is kept until it expires, and only inline ones import.
     */
    @Volatile
    var historyBlobFetcher: (suspend (url: String, maxBytes: Long) -> ByteArray?)? = null

    /** The histories imported since the last call, for the app to show. */
    fun drainImportedHistory(): List<ImportedHistory> = imported.toList().also { imported.clear() }

    /** How many histories this device still owes ([historyDeliveries] sends them). */
    fun owedHistoryCount(): Int = owedHistories.size

    /** How many deliveries wait for their chat or their blob. */
    fun keptHistoryCount(): Int = keptDeliveries.size

    /**
     * `Sending`: the deliveries of every history this device owes, while its own leaf is tagged: each
     * sibling still in the roster with "bring chat history" on and a history key gets the chat as this
     * device holds it, in inline bundles, the newest [MAX_HISTORY_BUNDLES] when it needs more. Returns
     * the events to publish in the device group; a history is forgotten once its deliveries are built.
     */
    suspend fun historyDeliveries(now: Long): List<OutboundGroupEvent> {
        owedHistories.removeAll { now >= it.owedAt + HistoryDelivery.LIFETIME_SECS }
        if (owedHistories.isEmpty() || !ownLeafTagged()) return emptyList()
        val roster = roster() ?: return emptyList()
        val out = ArrayList<OutboundGroupEvent>()
        for (owed in owedHistories.toList()) {
            owedHistories.remove(owed)
            try {
                out.addAll(deliveriesFor(owed, roster, now))
            } catch (e: Exception) {
                Log.w(TAG, "could not build the history of ${owed.chat.take(8)} for ${owed.slot.take(8)}", e)
            }
        }
        return out
    }

    private suspend fun deliveriesFor(
        owed: OwedHistory,
        roster: DeviceRosterV1,
        now: Long,
    ): List<OutboundGroupEvent> {
        val entry = roster.device(owed.slot) ?: return emptyList()
        if (!entry.bringHistory) return emptyList()
        val historyKey = entry.historyKey?.takeIf { it.length == 64 }?.hexToByteArray() ?: return emptyList()
        val group = groupManager.getGroup(owed.chat) ?: return emptyList()
        val chat = group.groupId.toHexKey()
        if (!HistoryBundles.isChat(chat)) return emptyList()
        val bundles = HistoryBundles.split(chat, historyOf(owed.chat, now)).takeLast(MAX_HISTORY_BUNDLES)
        return bundles.mapNotNull { plaintext ->
            val (key, ciphertext) = HistoryBundles.encrypt(plaintext.encodeToByteArray())
            val sealed = HistoryDelivery.seal(historyKey, ownSlot, owed.slot, chat, key, HistoryDelivery.hash(ciphertext))
            val content = HistoryDelivery(ownSlot, owed.slot, chat, sealed, ciphertext, null).content()
            if (content.encodeToByteArray().size > HistoryDelivery.MAX_CONTENT_BYTES) null else deviceGroupEvent(HistoryDelivery.KIND, content, now)
        }
    }

    /** Every app event of the chat this device holds with its epoch, unexpired, in chat order. */
    private suspend fun historyOf(
        nostrGroupId: HexKey,
        now: Long,
    ): List<HistoryEvent> {
        val m = manager ?: return emptyList()
        val epochs = m.storedEpochs(nostrGroupId)
        val expiries = m.messageExpiries(nostrGroupId)
        return m
            .loadStoredMessages(nostrGroupId)
            .mapNotNull { json ->
                val event = Event.fromJsonOrNull(json) ?: return@mapNotNull null
                val epoch = epochs[event.id] ?: return@mapNotNull null
                if (MarmotDeviceGroupKinds.isDeviceGroupKind(event.kind)) return@mapNotNull null
                val expiry = expiries[event.id]
                if (expiry != null && expiry <= now) return@mapNotNull null
                HistoryEvent(event, epoch, expiry?.let { (it - event.createdAt).coerceAtLeast(1) })
            }.distinctBy { it.event.id }
            .sortedBy { it.position }
    }

    private suspend fun onHistoryDelivery(
        sender: HexKey,
        event: Event,
        now: Long,
    ) {
        val delivery = HistoryDelivery.parse(event.content) ?: return
        if (delivery.to != ownSlot || delivery.from != sender) return
        val seed = trust().tagSigningSeed?.hexToByteArray() ?: return
        val (key, hash) = HistoryDelivery.open(HistoryKeys.keyPair(seed).privateKey, delivery.from, delivery.to, delivery.chat, delivery.sealed) ?: return
        if (keptDeliveries.size >= MAX_KEPT_DELIVERIES) keptDeliveries.removeAt(0)
        keptDeliveries.add(KeptDelivery(delivery, key, hash, now, delivery.bundle))
        importKeptHistory(now, fetch = false)
    }

    /**
     * Imports every kept delivery that can be now: its chat is held and its ciphertext is at hand,
     * fetched from one of its Blossom servers with [fetch] and a [historyBlobFetcher]. Deliveries a
     * week old, or whose sender left the roster, are dropped. The app calls this on its timer.
     */
    suspend fun importKeptHistory(
        now: Long,
        fetch: Boolean = true,
    ) {
        keptDeliveries.removeAll { now >= it.readAt + HistoryDelivery.LIFETIME_SECS }
        if (keptDeliveries.isEmpty()) return
        val roster = roster()
        for (kept in keptDeliveries.toList()) {
            if (roster?.device(kept.delivery.from) == null) {
                keptDeliveries.remove(kept)
                continue
            }
            val nostrId = nostrIdOf(kept.delivery.chat) ?: continue
            val ciphertext = kept.ciphertext ?: (if (fetch) fetchBlob(kept) else null) ?: continue
            if (!HistoryDelivery.hash(ciphertext).contentEquals(kept.hash)) {
                // Other bytes than the sealed hash: an inline one is dropped, a fetched one is tried again.
                if (kept.delivery.bundle != null) keptDeliveries.remove(kept) else kept.ciphertext = null
                continue
            }
            keptDeliveries.remove(kept)
            val plaintext = HistoryBundles.decrypt(ciphertext, kept.key) ?: continue
            val bundle = HistoryBundles.parse(plaintext.decodeToString(), kept.delivery.chat, now) ?: continue
            importBundle(nostrId, bundle)
        }
    }

    private suspend fun fetchBlob(kept: KeptDelivery): ByteArray? {
        val fetcher = historyBlobFetcher ?: return null
        for (server in kept.delivery.blossom.orEmpty()) {
            val bytes =
                try {
                    fetcher(HistoryDelivery.blobUrl(server, kept.hash), MAX_BUNDLE_CIPHERTEXT.toLong())
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    null
                }
            if (bytes != null && bytes.size <= MAX_BUNDLE_CIPHERTEXT && HistoryDelivery.hash(bytes).contentEquals(kept.hash)) return bytes
        }
        return null
    }

    /** Adds the events of [bundle] this device does not hold yet; never touches the ones it holds. */
    private suspend fun importBundle(
        nostrGroupId: HexKey,
        bundle: HistoryBundles.Parsed,
    ) {
        val m = manager ?: return
        val held = HashSet<HexKey>(m.storedEpochs(nostrGroupId).keys)
        m.loadStoredMessages(nostrGroupId).forEach { json -> Event.fromJsonOrNull(json)?.let { held.add(it.id) } }
        val fresh = bundle.events.filter { held.add(it.event.id) }
        if (fresh.isEmpty()) return
        fresh.forEach { m.persistDecryptedMessage(nostrGroupId, it.event.toJson(), it.epoch) }
        imported.add(ImportedHistory(nostrGroupId, fresh.map { it.event }, fresh.associate { it.event.id to it.epoch }))
        Log.d(TAG) { "imported ${fresh.size} event(s) of history into ${nostrGroupId.take(8)}" }
    }

    // ---- sign-ins ------------------------------------------------------------------------------------

    /** A KeyPackage publication of this account: its slot and `created_at`. */
    data class Publication(
        val slot: HexKey,
        val createdAt: Long,
    )

    enum class SignInClass {
        /** This device's own slot. */
        OWN,

        /** A device in the trusted roster. */
        LINKED,

        /** Rejected in the roster or by this device. */
        REJECTED,

        /** Published no later than a removal this device saw: no sign-in (MDK `2d509151`). */
        REMOVED,

        /** Returned by the first check: signed in before this device. */
        ALREADY_SIGNED_IN,

        /** Appeared after the first check: ask the user whether it was them. */
        NEW_SIGN_IN,
    }

    /**
     * `New sign-ins`: classifies the account's current publications. The first call records the slots
     * it saw as the first check ([recordFirstCheck]); a slot that check returned is "already signed
     * in", any other unrecognized slot is new. A slot a roster held as `removed` raises nothing for a
     * publication no later than that removal plus [DIRECTORY_SKEW_SECS].
     */
    suspend fun classifySignIns(publications: List<Publication>): Map<HexKey, SignInClass> {
        val t = trust()
        val roster = roster()
        val first = t.firstCheckSlots?.toSet()
        val latest = publications.groupBy { it.slot }.mapValues { (_, p) -> p.maxOf { it.createdAt } }
        return latest.mapValues { (slot, createdAt) ->
            when {
                slot == ownSlot -> SignInClass.OWN
                roster?.device(slot) != null -> SignInClass.LINKED
                roster?.rejectedSlot(slot)?.reason == RejectionReasonV1.NOT_ME || t.ownRejections.any { it.slot == slot } -> SignInClass.REJECTED
                roster?.rejectedSlot(slot)?.reason == RejectionReasonV1.REMOVED -> SignInClass.REMOVED
                t.removedSlots.any { it.slot == slot } ->
                    // A removed device comes back only in a new slot: a later publication in the old
                    // one is a new sign-in, whatever the first check saw.
                    if (t.removedSlots.any { it.slot == slot && createdAt <= it.time + DIRECTORY_SKEW_SECS }) SignInClass.REMOVED else SignInClass.NEW_SIGN_IN
                first != null && slot in first -> SignInClass.ALREADY_SIGNED_IN
                else -> SignInClass.NEW_SIGN_IN
            }
        }
    }

    /** Records the first complete read's slots, once; later calls change nothing. */
    suspend fun recordFirstCheck(slots: Collection<HexKey>) {
        val t = trust()
        if (t.firstCheckSlots == null) saveTrust(t.copy(firstCheckSlots = slots.distinct().sorted()))
    }

    /**
     * "This wasn't me": keeps the rejection and, in the trusted device group while the roster has no
     * entry for the slot, returns the Commit that records a `not_me` rejected slot.
     */
    suspend fun rejectSignIn(
        slot: HexKey,
        now: Long,
    ): Staged? {
        val t = trust()
        if (t.ownRejections.none { it.slot == slot }) saveTrust(t.copy(ownRejections = t.ownRejections + DeviceGroupTrust.SlotTime(slot, now)))
        val roster = roster() ?: return null
        if (roster.device(slot) != null || roster.rejectedSlot(slot) != null) return null
        return stageRosterUpdate(emptyList(), listOf(RosterOperationV1.SetRejectedSlot(RejectedSlotV1(slot, RejectionReasonV1.NOT_ME, now))))
    }

    // =================================================================================================

    private fun withTag(
        leafExtensions: List<Extension>,
        tag: DeviceTagV1,
    ): List<Extension> {
        val dictionary = AppDataDictionary.fromExtensionsOrEmpty(leafExtensions).with(DeviceTagV1.COMPONENT_ID, tag.encode())
        return leafExtensions.filterNot { it.extensionType == AppDataDictionary.EXTENSION_TYPE } + dictionary.toExtension()
    }

    companion object {
        private const val TAG = "MarmotDeviceGroup"

        /** How long a new device waits for its link's Welcome after its Confirm. */
        const val LINK_WAIT_SECS = 600L

        /** How long the approver waits for the new device's first Commit after `linked_at`. */
        const val FIRST_COMMIT_DEADLINE_SECS = 3600L

        /** "Issuing": top up below 5, to 10; keep at most 300 per sibling. */
        const val STOCK_LOW = 5
        const val STOCK_TARGET = 10
        const val MAX_PRIVATE_PER_SIBLING = 300

        private const val MAX_ANSWERED = 512

        const val BROADCAST_INTERVAL_SECS = 24 * 3600L
        const val REQUEST_ANSWER_INTERVAL_SECS = 3600L

        /** A sibling Welcome is due again once its target ran this long after the carrier went out. */
        const val REPAIR_AFTER_SECS = 600L

        const val INACTIVE_AFTER_SECS = 30 * 24 * 3600L
        const val REMOVE_INACTIVE_AFTER_SECS = 90 * 24 * 3600L

        /** Epochs whose sender claims are kept for late app events, as many as past epochs are retained. */
        private const val EPOCH_CLAIMS_KEPT = 16

        /** Version 1 inventory senders use at most a seven-day report lifetime. */
        const val INVENTORY_LIFETIME_SECS = 7 * 24 * 3600L

        /** A device sends at most this many deliveries for one history: its newest bundles. */
        const val MAX_HISTORY_BUNDLES = 8

        /** Deliveries a device keeps while it waits for their chat or blob. */
        const val MAX_KEPT_DELIVERIES = 256

        /** The longest bundle's ciphertext: 8 MiB and its 16-byte tag. */
        const val MAX_BUNDLE_CIPHERTEXT = HistoryBundles.MAX_BYTES + 16

        /** A `removed` record lasts this long after its `rejected_at`. */
        const val REMOVED_RECORD_SECS = 30 * 24 * 3600L

        /** How far ahead a removed device's clock may run, for the removed-slot sign-in cutoff. */
        const val DIRECTORY_SKEW_SECS = 600L
    }
}
