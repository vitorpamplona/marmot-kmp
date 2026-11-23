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
package com.vitorpamplona.marmot.groups

import com.vitorpamplona.marmot.appComponents.AccountDevicesV1
import com.vitorpamplona.marmot.appComponents.AdminPolicyV1
import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.appComponents.GroupLifecycleV1
import com.vitorpamplona.marmot.appComponents.MarmotProtocolProfile
import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamQuicPolicyV1
import com.vitorpamplona.marmot.groups.MlsGroupManager.Companion.EPOCH_RETENTION_WINDOW
import com.vitorpamplona.marmot.groups.currentAdminIdentities
import com.vitorpamplona.marmot.groups.currentNostrGroupId
import com.vitorpamplona.marmot.groups.isLocalAdmin
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.PrivateMessage
import com.vitorpamplona.mls.framing.PublicMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.DecryptedMessage
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupState
import com.vitorpamplona.mls.group.OwnSenderRatchet
import com.vitorpamplona.mls.group.RetainedEpochSecrets
import com.vitorpamplona.mls.messages.CommitResult
import com.vitorpamplona.mls.messages.ExternalJoinResult
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.schedule.KeySchedule
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.mls.tree.RatchetTree
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.utils.Log
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * High-level coordinator for MLS group lifecycle and state management.
 *
 * This is the primary entry point for the Marmot MLS integration. It bridges
 * the low-level MLS engine ([MlsGroup]) with the Nostr application layer,
 * managing multiple concurrent groups and ensuring state survives app restarts.
 *
 * ## Responsibilities
 *
 * - **Group lifecycle**: Create, join (via Welcome or external commit), and leave groups
 * - **State persistence**: Save/restore group state through [MlsGroupStateStore]
 * - **Epoch retention**: Keep recent epochs' exporter secrets for late-arriving messages
 * - **Key hygiene**: Secure deletion of consumed init_keys after Welcome processing
 * - **KeyPackage rotation**: Schedule self-updates within 24h of joining (MIP-00)
 *
 * ## Typical Usage
 *
 * ```kotlin
 * val store: MlsGroupStateStore = ... // platform-specific encrypted storage
 * val manager = MlsGroupManager(store)
 *
 * // On app startup
 * manager.restoreAll()
 *
 * // Create a new group
 * val group = manager.createGroup(nostrGroupId, myIdentity)
 *
 * // Add a member (from their published KeyPackage)
 * val result = manager.addMember(nostrGroupId, keyPackageBytes)
 * // Send result.commitBytes as kind 445 GroupEvent
 * // Send result.welcomeBytes as kind 444 WelcomeEvent (NIP-59 wrapped)
 *
 * // Join via Welcome
 * manager.processWelcome(nostrGroupId, welcomeBytes, myKeyPackageBundle)
 *
 * // Encrypt/decrypt messages
 * val ciphertext = manager.encrypt(nostrGroupId, plaintext)
 * val decrypted = manager.decrypt(nostrGroupId, ciphertext)
 *
 * // Derive outer encryption key for GroupEvents (MIP-03)
 * val key = manager.exporterSecret(nostrGroupId)
 * ```
 *
 * ## Cross-Implementation Notes
 *
 * This manager uses ciphersuite 0x0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
 * The exporter retention window is [EPOCH_RETENTION_WINDOW] = 5, matching the
 * `DEFAULT_EPOCH_LOOKBACK` used by the MDK reference implementation so that late-
 * arriving MIP-03 GroupEvents whose outer ChaCha20-Poly1305 key was derived from a
 * prior epoch's exporter secret can still be peeled after a Commit advances the
 * group. The MLS application message inside opens through mls-kmp's own retained
 * receiver data ([MlsGroup.decryptFormerEpoch], [MlsGroup.RETAIN_EPOCHS] epochs),
 * which verifies it against the tree of the epoch it was sent in.
 *
 * Thread safety: All suspending mutation methods are guarded by a [Mutex]
 * to prevent concurrent state corruption. Non-suspending read methods
 * ([getGroup], [isMember], [activeGroupIds], [encrypt], [decrypt],
 * [decryptOrNull], [exporterSecret]) must be called from the same
 * coroutine context that owns this manager (e.g., the Account's scope).
 *
 * @see MlsGroup The low-level MLS state machine
 * @see MlsGroupStateStore Storage abstraction for group state persistence
 */
class MlsGroupManager(
    private val store: MlsGroupStateStore,
    /**
     * The component ids this client supports, which its leaves advertise. The
     * default is [CurrentProfileGroupFactory.SUPPORTED_COMPONENTS]; a test
     * models an older client by passing fewer.
     */
    val supportedComponents: List<Int> = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS,
) {
    /** The 2.x constructor, kept so code compiled against it still links. */
    @Deprecated("Use the constructor with supportedComponents. Removed in 3.0.0.", level = DeprecationLevel.HIDDEN)
    constructor(store: MlsGroupStateStore) : this(store, CurrentProfileGroupFactory.SUPPORTED_COMPONENTS)

    private val mutex = Mutex()
    private val groups = mutableMapOf<HexKey, MlsGroup>()
    private val retainedEpochs = mutableMapOf<HexKey, MutableList<RetainedEpochSecrets>>()

    /**
     * Bumped whenever a group's retained-epoch window changes, and compared
     * against what was last written in [persistGroup].
     *
     * The window only moves when an epoch advances, but [persistGroup] runs on
     * every application message too — sending one advances the sender's ratchet
     * and that has to be durable. Re-encoding and rewriting an unchanged
     * retention window on each of those was measurable: it is one TlsWriter and
     * one byte array per retained epoch, plus a store write, for bytes
     * identical to the ones already there.
     */
    private val retainedEpochRevision = mutableMapOf<HexKey, Long>()
    private val retainedEpochPersisted = mutableMapOf<HexKey, Long>()

    /** Application messages opened per group since its state was last written: see [noteReceived]. */
    private val receivedSinceSave = mutableMapOf<HexKey, Int>()

    /**
     * Restore all groups from persistent storage on startup.
     * Call this once during Account initialization.
     */
    suspend fun restoreAll() =
        mutex.withLock {
            val groupIds = store.listGroups()
            Log.d(TAG) { "restoreAll(): store reports ${groupIds.size} groups: $groupIds" }
            for (nostrGroupId in groupIds) {
                try {
                    val stateBytes = store.load(nostrGroupId)
                    if (stateBytes == null) {
                        Log.w(TAG) { "restoreAll(): load returned null for $nostrGroupId, skipping" }
                        continue
                    }
                    val state = MlsGroupState.decodeTls(stateBytes)
                    // main needs the local binding for the sender-ratchet
                    // restore below; this branch supplies Marmot's policy.
                    val group = MlsGroup.restore(state, MarmotGroupPolicy)
                    groups[nostrGroupId] = group
                    Log.d(TAG) { "restoreAll(): restored group $nostrGroupId (${stateBytes.size} bytes)" }

                    // Sends since the last full write left their position here
                    // rather than rewriting the whole state. Applying it can
                    // only move the ratchet forward (see
                    // [MlsGroup.restoreOwnSenderRatchet]); skipping it would
                    // reuse generations this leaf has already published.
                    store.loadSenderRatchet(nostrGroupId)?.let { bytes ->
                        OwnSenderRatchet.decodeTlsOrNull(bytes)?.let { record ->
                            if (group.restoreOwnSenderRatchet(record)) {
                                Log.d(TAG) {
                                    "restoreAll(): advanced $nostrGroupId sender ratchet to " +
                                        "app gen ${record.applicationGeneration} from its standalone record"
                                }
                            }
                        }
                    }

                    // Restore the retained exporter secrets. Records written
                    // before 3.3.0 also carry the epoch's sender-data and
                    // encryption secrets, which nothing reads any more (a
                    // former epoch's messages open through mls-kmp's own
                    // retained receiver data): drop them and rewrite the
                    // record now, so they do not stay at rest.
                    val retained = store.loadRetainedEpochs(nostrGroupId)
                    if (retained.isNotEmpty()) {
                        val decoded = retained.map { RetainedEpochSecrets.decodeTls(TlsReader(it)) }
                        retainedEpochs[nostrGroupId] = decoded.map { it.exporterOnly() }.toMutableList()
                        if (decoded.any { it.senderDataSecret.isNotEmpty() || it.encryptionSecret.isNotEmpty() }) {
                            store.saveRetainedEpochs(nostrGroupId, encodeRetained(retainedEpochs[nostrGroupId].orEmpty()))
                        }
                        // What was just loaded is by definition what is on
                        // disk, so the first persist has nothing to rewrite.
                        retainedEpochPersisted[nostrGroupId] = retainedEpochRevision[nostrGroupId] ?: 0L
                        Log.d(TAG) { "restoreAll(): restored ${retained.size} retained epochs for $nostrGroupId" }
                    }
                } catch (e: Exception) {
                    currentCoroutineContext().ensureActive()
                    // Could be genuinely corrupted state, or a transient bug
                    // (e.g. wrong cipher param spec). Skip but DO NOT delete —
                    // a future restart after a fix should still be able to
                    // recover the group. If it really is corrupted the user
                    // can explicitly leave/delete the group from the UI.
                    Log.e(
                        TAG,
                        "restoreAll(): failed to restore group $nostrGroupId, skipping (file preserved): ${e.message}",
                        e,
                    )
                }
            }
            Log.d(TAG) { "restoreAll(): finished with ${groups.size} active groups in memory" }
        }

    /**
     * Get an active group by its Nostr group ID.
     */
    fun getGroup(nostrGroupId: HexKey): MlsGroup? = groups[nostrGroupId]

    /**
     * A snapshot of a group's current state, WITHOUT persisting anything.
     *
     * Convergence keeps a bounded window of these so a commit that lost a
     * same-epoch race still has a parent to replay against later. Taking the
     * snapshot must not touch storage: it happens on every applied commit,
     * and the state that matters is already persisted by the apply itself.
     */
    fun snapshot(nostrGroupId: HexKey): MlsGroupState? = groups[nostrGroupId]?.saveState()

    /**
     * Replace a group's state wholesale — the convergence rewind primitive.
     *
     * Used when branch selection picks a candidate branch over what was
     * canonical. The outgoing epoch's secrets are pushed into the retention
     * window first, so application messages already sent on the abandoned
     * branch still decrypt for as long as any other past epoch would.
     *
     * This deliberately takes a whole state rather than a commit: the state was
     * produced by replaying MLS bytes during graph construction, and replaying
     * them a second time here would risk the two answers differing.
     */
    suspend fun installState(
        nostrGroupId: HexKey,
        state: MlsGroupState,
    ) = mutex.withLock {
        val current = groups[nostrGroupId]
        val changed =
            current == null ||
                !current
                    .saveState()
                    .groupContext
                    .toTlsBytes()
                    .contentEquals(state.groupContext.toTlsBytes())
        if (!changed) return@withLock

        val outgoing = current?.retainedSecrets()
        groups[nostrGroupId] = MlsGroup.restore(state, MarmotGroupPolicy)
        // Retain by outgoing epoch even when the epoch NUMBER is unchanged: a
        // same-epoch rewind swaps one epoch-N state for a different one, and
        // the abandoned N still has traffic addressed to it.
        if (outgoing != null) pushRetainedEpoch(nostrGroupId, outgoing)
        persistGroup(nostrGroupId)
    }

    /**
     * Register and persist a group built elsewhere, e.g. by
     * `CurrentProfileGroupFactory`.
     *
     * Group creation is the one place a group cannot be built through this
     * manager: a current-profile leaf must carry an identity proof over its OWN
     * signature key, which only an account signer — possibly a remote bunker —
     * can produce, so the keypair is generated, authorized, and only then built
     * into a leaf. The manager takes ownership of the finished group here.
     */
    suspend fun adoptGroup(
        nostrGroupId: HexKey,
        group: MlsGroup,
    ) = mutex.withLock {
        require(!groups.containsKey(nostrGroupId)) { "Group $nostrGroupId already exists" }
        groups[nostrGroupId] = group
        persistGroup(nostrGroupId)
    }

    /**
     * List all active Nostr group IDs.
     */
    fun activeGroupIds(): Set<HexKey> = groups.keys.toSet()

    /**
     * Check if we are a (live) member of the given group.
     *
     * After processing a commit that removes us, the group entry stays in
     * [groups] so callers can still inspect the post-Remove tree, but our
     * own leaf has been set to null and the leaf count may have shrunk
     * past `myLeafIndex`. Either condition means we cannot encrypt any
     * more messages, propose anything, or decrypt future epochs — i.e.
     * we are functionally not a member, and surface as such here so
     * callers (`amy marmot group show`, the inbound processor) get a
     * clean `not_member` answer instead of a misleading `true`.
     */
    fun isMember(nostrGroupId: HexKey): Boolean = groups[nostrGroupId]?.isLocalMember() ?: false

    // --- Group Creation ---

    /**
     * Create a new MLS group and persist it.
     *
     * @param nostrGroupId hex-encoded Nostr routing ID for the group
     * @param identity the creator's identity bytes (typically Nostr pubkey)
     * @param signingKey optional Ed25519 signing key (generated if null)
     * @return the new [MlsGroup]
     */
    suspend fun createGroup(
        nostrGroupId: HexKey,
        identity: ByteArray,
        signingKey: ByteArray? = null,
        initialExtensions: List<com.vitorpamplona.mls.tree.Extension> = emptyList(),
    ): MlsGroup =
        mutex.withLock {
            Log.d(TAG) { "createGroup($nostrGroupId): creating new MLS group" }
            val group = MlsGroup.create(identity, signingKey, initialExtensions, policy = MarmotGroupPolicy)
            groups[nostrGroupId] = group
            persistGroup(nostrGroupId)
            Log.d(TAG) { "createGroup($nostrGroupId): done, in-memory group count=${groups.size}" }
            group
        }

    // --- Joining ---

    /**
     * Join a group by processing a Welcome message.
     *
     * After processing:
     * 1. The init_key from the KeyPackageBundle is securely deleted
     *    (the bundle should be discarded by the caller after this returns)
     * 2. Group state is persisted
     * 3. A KeyPackage rotation should be triggered (see [needsKeyPackageRotation])
     *
     * @param welcomeBytes TLS-serialized Welcome message
     * @param bundle the KeyPackageBundle that was used for the invitation
     * @param hintNostrGroupId optional nostrGroupId from the Welcome event's "h" tag;
     *   if provided and non-null, validated against the GroupContext's NostrGroupData extension.
     *   If absent (sender did not include an "h" tag), the ID is derived from the MLS content.
     * @return pair of (joined group, derived nostrGroupId)
     */
    suspend fun processWelcome(
        welcomeBytes: ByteArray,
        bundle: KeyPackageBundle,
        hintNostrGroupId: HexKey? = null,
    ): Pair<MlsGroup, HexKey> =
        mutex.withLock {
            val group = MlsGroup.processWelcome(welcomeBytes, bundle, MarmotGroupPolicy)

            val derivedId =
                group.currentNostrGroupId()
                    ?: throw IllegalArgumentException(
                        "Welcome GroupContext carries no nostr routing: neither the current profile's " +
                            "0x8004 component nor the legacy 0xF2EE extension — cannot derive nostrGroupId",
                    )

            if (hintNostrGroupId != null && hintNostrGroupId != derivedId) {
                throw IllegalArgumentException(
                    "nostrGroupId mismatch: h-tag=$hintNostrGroupId, GroupContext=$derivedId",
                )
            }

            // Checked on the decoded group, not on a hint: a Welcome without an
            // h tag (or re-wrapped by anyone who saw it) whose KeyPackage is
            // still held — a last-resort one is — would otherwise replace the
            // live group with its join epoch, and persist that. A group this
            // device was removed from is no live member state, so a re-invite
            // still joins.
            if (groups[derivedId]?.isLocalMember() == true) throw MarmotAlreadyMemberException(derivedId)

            groups[derivedId] = group

            // init_key is consumed — the bundle's initPrivateKey should not be
            // reused. Caller must discard the bundle and rotate KeyPackages.

            persistGroup(derivedId)
            Pair(group, derivedId)
        }

    /**
     * Join a group via external commit.
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     * @param groupInfoBytes TLS-serialized GroupInfo
     * @param identity the joiner's identity bytes
     * @param signingKey optional signing key
     * @return pair of (joined group, commit bytes to publish)
     */
    suspend fun externalJoin(
        nostrGroupId: HexKey,
        groupInfoBytes: ByteArray,
        identity: ByteArray,
        signingKey: ByteArray? = null,
    ): ExternalJoinResult =
        mutex.withLock {
            val result = MlsGroup.externalJoin(groupInfoBytes, identity, signingKey, policy = MarmotGroupPolicy)
            groups[nostrGroupId] = result.group
            persistGroup(nostrGroupId)
            result
        }

    // --- Epoch Transitions ---

    /**
     * Create and apply a Commit, advancing the epoch.
     *
     * Retains the outgoing epoch's decryption secrets and persists
     * the new state before returning.
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     * @return the [CommitResult] to publish
     */
    suspend fun commit(nostrGroupId: HexKey): CommitResult =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            val retainedBefore = group.retainedSecrets()
            val result = group.commit()
            pushRetainedEpoch(nostrGroupId, retainedBefore)
            persistGroup(nostrGroupId)
            result
        }

    /**
     * A locally prepared Commit that has NOT been applied.
     *
     * `protocol-core/publish-lifecycle.md` requires publish-before-apply: a
     * locally generated group-state change must not become canonical until its
     * publish obligation is confirmed. Applying first and rolling back on
     * failure is not equivalent — between the two there is a window in which
     * this client is forked from every peer, and a crash inside that window
     * makes the fork permanent.
     *
     * So the commit is prepared on a CLONE restored from [priorState]. The live
     * group is untouched, keeps its pending proposals (which is exactly the
     * "proposal stays available for retry" rule on failure), and [pendingState]
     * becomes canonical only via [installState] once publication is confirmed.
     */
    class StagedCommit(
        val result: CommitResult,
        /** Canonical state the commit was generated from. */
        val priorState: MlsGroupState,
        /** What becomes canonical once the publish obligation succeeds. */
        val pendingState: MlsGroupState,
    )

    /**
     * Prepare a Commit without applying it, by running [prepare] on a clone.
     *
     * The clone's pre-commit exporter secret equals the live group's, so the
     * outbound kind:445 is outer-encrypted with the same epoch-N key it would
     * have been either way.
     *
     * The clone commits the pending proposal pool along with whatever
     * [prepare] proposes, unless [sweepPool] is false: a same-account Commit
     * and the account-devices activation must carry exactly their own
     * proposals (MDK's builders never read the proposal store), and a peer's
     * pooled SelfRemove swept into either would make it admin-required. Only
     * the clone loses the pool; the live group keeps it until the epoch moves.
     */
    private suspend fun stage(
        nostrGroupId: HexKey,
        sweepPool: Boolean = true,
        prepare: (MlsGroup) -> CommitResult,
    ): StagedCommit =
        mutex.withLock {
            val live = requireGroup(nostrGroupId)
            val priorState = live.saveState()
            val clone = MlsGroup.restore(stagingState(live, priorState, sweepPool), MarmotGroupPolicy)
            val result = prepare(clone)
            StagedCommit(result, priorState, clone.saveState())
        }

    /**
     * The state a commit is staged on: [priorState] without the pool when
     * [sweepPool] is false, and otherwise without any pooled peer proposal the
     * policy now refuses. A proposal pooled before a receipt rule existed (an
     * admin's SelfRemove, say) would make every commit that swept it fail, and
     * MLS lets a committer leave out a proposal it cannot validly commit.
     */
    private fun stagingState(
        live: MlsGroup,
        priorState: MlsGroupState,
        sweepPool: Boolean,
    ): MlsGroupState {
        if (priorState.pendingProposals.isEmpty()) return priorState
        if (!sweepPool) return priorState.copy(pendingProposals = emptyList())
        val view = live.view()
        val kept =
            priorState.pendingProposals.filter { pending ->
                pending.isFrom(live.leafIndex) || runCatching { MarmotGroupPolicy.authorizeProposal(view, pending) }.isSuccess
            }
        return if (kept.size == priorState.pendingProposals.size) priorState else priorState.copy(pendingProposals = kept)
    }

    /** Stage an Add. See [StagedCommit] for why this does not apply. */
    suspend fun stageAddMember(
        nostrGroupId: HexKey,
        keyPackageBytes: ByteArray,
    ): StagedCommit = stageAddMembers(nostrGroupId, listOf(keyPackageBytes))

    /** Stage several Adds as ONE commit. See [MlsGroup.addMembers]. */
    suspend fun stageAddMembers(
        nostrGroupId: HexKey,
        keyPackagesBytes: List<ByteArray>,
    ): StagedCommit = stage(nostrGroupId) { it.addMembers(keyPackagesBytes) }

    /**
     * Stage the founding Add Commit, and — when [requireAccountDevices] — make
     * the group require `marmot.group.account-devices.v1` in that same commit
     * (`protocol-core/group-setup.md`: a supporting creator MUST require it
     * when its own leaf and every founding KeyPackage advertise it).
     *
     * Epoch 0 never leaves this device — the founding Add has an empty publish
     * obligation, and joiners learn epoch 1 from the Welcome — so requiring the
     * component here is indistinguishable, to every peer, from a group created
     * requiring it. The activation runs the engine's every-leaf check and the
     * component's own resulting-state rules like any other.
     */
    suspend fun stageFoundingAdd(
        nostrGroupId: HexKey,
        keyPackagesBytes: List<ByteArray>,
        requireAccountDevices: Boolean,
    ): StagedCommit =
        stage(nostrGroupId) { clone ->
            keyPackagesBytes.forEach { clone.proposeAdd(it) }
            if (requireAccountDevices) {
                val required = ComponentsList.supportedOrRequired(clone.appDataDictionary()).toMutableSet()
                required.add(AccountDevicesV1.COMPONENT_ID)
                clone.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required))
            }
            clone.commit()
        }

    /**
     * Stage a Commit that [prepare] builds on a clone carrying exactly its own proposals, for the
     * device-group flows whose Commits combine proposals no other helper does (the founding Add with
     * its roster entry, a new device's first Commit). See [StagedCommit].
     */
    internal suspend fun stageOwn(
        nostrGroupId: HexKey,
        prepare: (MlsGroup) -> CommitResult,
    ): StagedCommit = stage(nostrGroupId, sweepPool = false, prepare)

    /** Stage a Remove. See [StagedCommit] for why this does not apply. */
    suspend fun stageRemoveMember(
        nostrGroupId: HexKey,
        targetLeafIndex: Int,
    ): StagedCommit = stage(nostrGroupId) { it.removeMember(targetLeafIndex) }

    /**
     * Stage ONE Commit that removes every leaf in [targetLeafIndices], and,
     * when [admins] is not null, replaces the admin policy with it in the same
     * commit (the coupling rule in `app-components/admin-policy-v1.md`: a
     * commit that removes an admin account's last leaf removes its key from
     * `admins` too).
     */
    suspend fun stageRemoveMembers(
        nostrGroupId: HexKey,
        targetLeafIndices: Collection<Int>,
        admins: List<HexKey>? = null,
    ): StagedCommit = stageLeafRemovals(nostrGroupId, targetLeafIndices, admins, sweepPool = true)

    /**
     * Stage ONE same-account Commit that removes [targetLeafIndices], other
     * leaves of our own account, and nothing else
     * (`app-components/account-devices-v1.md`): the pending pool stays out of
     * it, so a peer's pooled SelfRemove cannot turn it admin-required.
     */
    suspend fun stageRemoveOwnAccountDevices(
        nostrGroupId: HexKey,
        targetLeafIndices: Collection<Int>,
    ): StagedCommit = stageLeafRemovals(nostrGroupId, targetLeafIndices, admins = null, sweepPool = false)

    private suspend fun stageLeafRemovals(
        nostrGroupId: HexKey,
        targetLeafIndices: Collection<Int>,
        admins: List<HexKey>?,
        sweepPool: Boolean,
    ): StagedCommit {
        require(targetLeafIndices.isNotEmpty()) { "stageRemoveMembers needs at least one leaf" }
        return stage(nostrGroupId, sweepPool) { clone ->
            targetLeafIndices.distinct().sorted().forEach { clone.proposeRemove(it) }
            if (admins != null) clone.proposeAppDataUpdate(AdminPolicyV1.COMPONENT_ID, AdminPolicyV1.ofHex(admins).encode())
            clone.commit()
        }
    }

    /**
     * Stage the activation Commit that makes the group require
     * `marmot.group.account-devices.v1` (`account-devices-v1.md`, "Activation
     * in an existing group"): it adds `0x800d` to the required list and, when
     * the GroupContext still carries a `0x800d` entry only an earlier client
     * could have left there, removes it in the same commit ("Data"), as MDK
     * does. Nothing else: the pending pool stays out of it. Only an active
     * admin may commit it; [accountDevicesActivationBlocker] says why a group
     * cannot take it yet.
     */
    suspend fun stageRequireAccountDevices(nostrGroupId: HexKey): StagedCommit {
        requireAdminForExtensionChange(requireGroup(nostrGroupId))
        val blocker = accountDevicesActivationBlocker(nostrGroupId)
        check(blocker == null) { "Cannot require account-devices: $blocker" }
        return stage(nostrGroupId, sweepPool = false) { clone ->
            val required = ComponentsList.supportedOrRequired(clone.appDataDictionary()).toMutableSet()
            required.add(AccountDevicesV1.COMPONENT_ID)
            clone.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required))
            if (clone.appDataDictionary().contains(AccountDevicesV1.COMPONENT_ID)) clone.proposeAppDataRemoval(AccountDevicesV1.COMPONENT_ID)
            clone.commit()
        }
    }

    /**
     * Why [nostrGroupId] cannot activate account-devices now, or null when it
     * can: it already requires it, it is not a current-profile group, a leaf
     * does not advertise it or carries a `0x800d` entry, or an account holds
     * more leaves than the limit. A GroupContext `0x800d` entry is no blocker:
     * the activation commit removes it. Describes
     * the group as a whole, never which member holds it back.
     */
    fun accountDevicesActivationBlocker(nostrGroupId: HexKey): String? {
        val group = requireGroup(nostrGroupId)
        val view = group.view()
        if (AccountDevicesV1.isRequired(view.extensions)) return "the group already requires it"
        if (!MarmotProtocolProfile.isCurrent(view.extensions)) return "the group is not on the current profile"
        val perAccount = mutableMapOf<HexKey, Int>()
        for ((_, leaf) in group.members()) {
            if (!AccountDevicesV1.isAdvertisedBy(leaf)) return "a member does not advertise it"
            if (AppDataDictionary.fromExtensionsOrEmpty(leaf.extensions).contains(AccountDevicesV1.COMPONENT_ID)) return "a member's leaf carries 0x800d data"
            val account = AccountDevicesV1.accountOf(leaf) ?: continue
            perAccount[account] = (perAccount[account] ?: 0) + 1
        }
        if (perAccount.values.any { it > AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT }) return "an account has more than ${AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT} devices in it"
        return null
    }

    /**
     * Refuse a GroupContextExtensions change from a non-admin.
     *
     * The admin set is read profile-agnostically: a current-profile group
     * keeps it in the `0x8003` admin-policy component, a legacy group inside
     * the `0xF2EE` extension. Reading only the legacy one made
     * `adminsConfigured` false for every current-profile group, which skipped
     * the gate entirely rather than failing closed — the group would then
     * refuse the commit on arrival at every peer, so the only thing the
     * missing check bought was a locally-diverged copy.
     *
     * A group with NO admin set at all is still open: that is the MIP-01
     * bootstrap state, before any admin policy has been installed.
     */
    private fun requireAdminForExtensionChange(group: MlsGroup) {
        val admins = group.currentAdminIdentities()
        check(admins.isEmpty() || group.isLocalAdmin()) {
            "MIP-01: only admins may update group extensions"
        }
    }

    /** Stage a GroupContextExtensions change. See [StagedCommit]. */
    suspend fun stageUpdateGroupExtensions(
        nostrGroupId: HexKey,
        extensions: List<Extension>,
    ): StagedCommit {
        val live = requireGroup(nostrGroupId)
        requireAdminForExtensionChange(live)
        return stage(nostrGroupId) { clone ->
            clone.proposeGroupContextExtensions(extensions)
            clone.commit()
        }
    }

    /**
     * Stage an `app_data_update` proposal + Commit for one component.
     *
     * The current profile's carrier for group metadata. A GroupContextExtensions
     * change rewrites the WHOLE extension set, which is what MIP-01 had to do
     * with its single monolithic blob; `app_data_update` names one component
     * id, so two admins changing different components do not clobber each
     * other's work just by racing.
     *
     * Passing null [data] removes the component.
     *
     * Refuses to replace the state of the retired agent text stream component
     * `0x8006` or to add it to the required `app_components`
     * (`agent-text-stream-quic-v1.md`, "What clients stop doing"). Its removal
     * stays possible, for an admin whose user asks for it ("Removing the
     * component from a group").
     */
    suspend fun stageAppDataUpdate(
        nostrGroupId: HexKey,
        componentId: Int,
        data: ByteArray?,
    ): StagedCommit {
        val group = requireGroup(nostrGroupId)
        requireAdminForExtensionChange(group)
        require(componentId != AgentTextStreamQuicPolicyV1.COMPONENT_ID || data == null) {
            "the agent text stream component 0x8006 is retired: its state is never replaced"
        }
        if (componentId == ComponentsList.APP_COMPONENTS_ID && data != null) {
            val retired = AgentTextStreamQuicPolicyV1.COMPONENT_ID
            require(retired !in ComponentsList.decode(data) || retired in ComponentsList.supportedOrRequired(group.appDataDictionary())) {
                "the agent text stream component 0x8006 is retired: it is never added to the required components"
            }
        }
        return stage(nostrGroupId) { clone ->
            if (data == null) clone.proposeAppDataRemoval(componentId) else clone.proposeAppDataUpdate(componentId, data)
            clone.commit()
        }
    }

    /**
     * Stage the enablement Commit that makes `marmot.group.lifecycle.v1`
     * (`0x800c`) required, per `app-components/group-lifecycle-v1.md`
     * ("Enablement for existing groups").
     *
     * One Commit that adds the `active` state when it is absent and adds
     * `0x800c` to the required `app_components` list, and carries nothing else
     * — a peer validates the enablement shape and rejects a Commit that folds
     * unrelated proposals into it. Enablement does not disband the group.
     *
     * A group that already requires the component needs no enablement; callers
     * check [MarmotGroupState.requires] first rather than committing a no-op
     * epoch.
     */
    suspend fun stageEnableDisbanding(nostrGroupId: HexKey): StagedCommit {
        requireAdminForExtensionChange(requireGroup(nostrGroupId))
        // `app-components/README.md` ("Activation"): valid only when every leaf
        // in the resulting state advertises the id. Checked again here, right
        // before committing, so an activation another member cannot accept is
        // never published.
        val blockers = componentSupportBlockers(nostrGroupId, GroupLifecycleV1.COMPONENT_ID)
        check(blockers.isEmpty()) {
            "Cannot enable disbanding: ${blockers.size} member(s) do not advertise marmot.group.lifecycle.v1 yet"
        }
        return stage(nostrGroupId) { clone ->
            val dictionary = clone.appDataDictionary()
            val required = ComponentsList.supportedOrRequired(dictionary).toMutableSet()
            required.add(GroupLifecycleV1.COMPONENT_ID)
            clone.proposeAppDataUpdate(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required))
            if (dictionary[GroupLifecycleV1.COMPONENT_ID] == null) {
                clone.proposeAppDataUpdate(GroupLifecycleV1.COMPONENT_ID, GroupLifecycleV1.ACTIVE.encode())
            }
            clone.commit()
        }
    }

    /**
     * The members (account identity hex, deduplicated) whose leaf in
     * [nostrGroupId] does not advertise [componentId] in its `app_components`
     * list. Empty means the group is eligible to require it
     * (`app-components/README.md`, "Eligibility").
     */
    fun componentSupportBlockers(
        nostrGroupId: HexKey,
        componentId: Int,
    ): List<HexKey> {
        val group = requireGroup(nostrGroupId)
        val blockers = LinkedHashSet<HexKey>()
        for ((leafIndex, leaf) in group.members()) {
            if (componentId !in leafSupportedComponents(leaf)) {
                group.memberIdentityHex(leafIndex)?.let { blockers.add(it) }
            }
        }
        return blockers.toList()
    }

    /**
     * Component ids this client supports that its own leaf in [nostrGroupId]
     * does not advertise, for a current-profile group; empty otherwise.
     *
     * A leaf's advertisement is fixed when it is created, so a member that
     * joined before this release supported a component keeps hiding that
     * support from the group until it replaces its leaf.
     */
    fun ownLeafMissingComponents(nostrGroupId: HexKey): Set<Int> {
        val group = groups[nostrGroupId] ?: return emptySet()
        if (!group.currentGroupState().isCurrentProfile) return emptySet()
        val mine = group.members().firstOrNull { it.first == group.leafIndex }?.second ?: return emptySet()
        val advertised = leafSupportedComponents(mine)
        return supportedComponents.filterNot { it in advertised }.toSet()
    }

    /**
     * Stage a self-update Commit whose UpdatePath leaf advertises every
     * component this client supports (`app-components/README.md`, "Advertising
     * support"). Everything else on the leaf, the account identity proof
     * included, is kept: the proof is bound to the leaf's signature key, which
     * this commit does not rotate.
     */
    suspend fun stageLeafRefresh(nostrGroupId: HexKey): StagedCommit =
        stage(nostrGroupId) { clone ->
            val mine =
                clone.members().firstOrNull { it.first == clone.leafIndex }?.second
                    ?: throw IllegalStateException("Group $nostrGroupId has no local leaf")
            val dictionary = AppDataDictionary.fromExtensionsOrEmpty(mine.extensions)
            // Added to what the leaf already advertises, as MDK's refresh does: a refresh must never
            // withdraw support the group may require, or the downgrade check refuses it every time.
            val refreshed =
                dictionary.with(
                    ComponentsList.APP_COMPONENTS_ID,
                    ComponentsList.encode((leafSupportedComponents(mine) + supportedComponents).toList()),
                )
            val extensions =
                mine.extensions.filterNot { it.extensionType == AppDataDictionary.EXTENSION_TYPE } + refreshed.toExtension()
            clone.advertiseInNextCommit(MarmotCapabilities.currentProfileLeaf(), extensions)
            clone.commit()
        }

    private fun leafSupportedComponents(leaf: LeafNode): Set<Int> =
        AppDataDictionary
            .fromExtensions(leaf.extensions)
            ?.let { ComponentsList.supportedOrRequired(it) }
            .orEmpty()
            .toSet()

    /**
     * Stage the terminal disband Commit, in the exact shape
     * `app-components/group-lifecycle-v1.md` ("Disband update and Commit
     * shape") requires:
     *
     * - exactly one lifecycle update, to `disbanded`;
     * - exactly one admin-policy replacement naming ONLY the committer's
     *   account — carried even when the committer was already the sole admin;
     * - a Remove for every candidate-parent leaf except the committing leaf,
     *   including the committer's own other devices; and
     * - nothing else, all inline.
     *
     * A peer validates the whole set, so a Commit that carries only the
     * lifecycle update — which is what this used to stage — is rejected
     * outright as an unsupported lifecycle transition. The group would stay
     * live for every other member while reading as ended here, which is the
     * one outcome a terminal state must never produce.
     *
     * A single-leaf group therefore still produces a valid disband Commit,
     * with no Remove proposals at all.
     */
    suspend fun stageDisband(nostrGroupId: HexKey): StagedCommit {
        requireAdminForExtensionChange(requireGroup(nostrGroupId))
        return stage(nostrGroupId) { clone ->
            val committer =
                clone.memberIdentity(clone.leafIndex)
                    ?: throw IllegalStateException("Group $nostrGroupId has no identity for the local leaf")
            clone.proposeAppDataUpdate(GroupLifecycleV1.COMPONENT_ID, GroupLifecycleV1.DISBANDED.encode())
            clone.proposeAppDataUpdate(AdminPolicyV1.COMPONENT_ID, AdminPolicyV1(listOf(committer)).encode())
            // Every other leaf, not every other ACCOUNT: the spec removes the
            // committer's own remaining devices too, so the final tree holds
            // the one committing leaf and nothing else.
            for ((leafIndex, _) in clone.members()) {
                if (leafIndex != clone.leafIndex) clone.proposeRemove(leafIndex)
            }
            clone.commit()
        }
    }

    /**
     * Stage a peer's standalone proposal and PERSIST the group.
     *
     * Staging alone only mutates memory, and a staged proposal is an
     * obligation rather than a message: a departing member's `SelfRemove` sits
     * in the pool until someone commits it. Losing it to a restart leaves the
     * leaver in the tree, still holding the group's keys, with nobody holding
     * the proposal that would evict them — so this writes through the same way
     * an epoch change does.
     */
    suspend fun receiveStandaloneProposal(
        nostrGroupId: HexKey,
        pubMsg: PublicMessage,
    ) = mutex.withLock {
        requireGroup(nostrGroupId).receivePublicMessageProposal(pubMsg)
        persistGroup(nostrGroupId)
    }

    /** Whether [nostrGroupId] has a staged proposal waiting for a Commit. */
    fun hasPendingProposals(nostrGroupId: HexKey): Boolean = groups[nostrGroupId]?.hasPendingProposals() == true

    /**
     * Stage a Commit over whatever proposals are already staged.
     *
     * Unlike every other `stage*` entry point this one has nothing of its own
     * to propose — the proposals are already in the LIVE group's pool, put
     * there by ingesting a peer's standalone proposal. That pool travels with
     * [MlsGroup.saveState], so the clone inherits it; when it did not, this
     * committed an empty proposal list, advanced the epoch, and dropped the
     * very proposal it was called to apply.
     */
    suspend fun stageCommit(nostrGroupId: HexKey): StagedCommit = stage(nostrGroupId) { it.commit() }

    /**
     * Process a received Commit, advancing the epoch.
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     * @param commitBytes TLS-serialized Commit
     * @param senderLeafIndex sender's leaf index
     * @param confirmationTag optional confirmation tag for verification
     */
    suspend fun processCommit(
        nostrGroupId: HexKey,
        commitBytes: ByteArray,
        senderLeafIndex: Int,
        confirmationTag: ByteArray,
        signature: ByteArray = ByteArray(0),
        wireFormat: com.vitorpamplona.mls.framing.WireFormat = com.vitorpamplona.mls.framing.WireFormat.PUBLIC_MESSAGE,
    ) = mutex.withLock {
        val group = requireGroup(nostrGroupId)

        // Capture the outgoing epoch's secrets BEFORE advancing, but only
        // commit them to the retention window once processCommit succeeds —
        // otherwise a failed commit (e.g. "Duplicate encryption key" on an
        // add-me relay echo) would pollute the window with a duplicate of
        // the current epoch key, wasting the finite retention slots.
        val retainedBefore = group.retainedSecrets()

        group.processCommit(commitBytes, senderLeafIndex, confirmationTag, signature, wireFormat)

        pushRetainedEpoch(nostrGroupId, retainedBefore)
        persistGroup(nostrGroupId)
    }

    /**
     * Process a fully-framed `MlsMessage(PublicMessage(Commit))` — the wire shape
     * returned in [CommitResult.framedCommitBytes]. Delegates to
     * [MlsGroup.processFramedCommit] which extracts the sender leaf index,
     * confirmation_tag, and FramedContentTBS signature from the envelope, then
     * calls [MlsGroup.processCommit] with all fields properly populated.
     *
     * Intended for callers that hold the framed bytes directly (tests driving
     * peer managers, CLI interop harnesses). Production inbound goes through
     * `MarmotInboundProcessor`, which unwraps the outer ChaCha20 layer first
     * and then calls [processCommit] with the already-decoded PublicMessage
     * fields.
     */
    suspend fun processFramedCommit(
        nostrGroupId: HexKey,
        framedCommitBytes: ByteArray,
    ) = mutex.withLock {
        val group = requireGroup(nostrGroupId)
        val retainedBefore = group.retainedSecrets()

        group.processFramedCommit(framedCommitBytes)

        pushRetainedEpoch(nostrGroupId, retainedBefore)
        persistGroup(nostrGroupId)
    }

    // --- Message Encryption/Decryption ---

    /**
     * Encrypt an application message.
     * Synchronized to prevent nonce reuse from concurrent encryption.
     *
     * The ratchet position is persisted after every send. Encrypting advances
     * the SecretTree ratchet (RFC 9420 §9) but does not change the epoch, so
     * without this save a restart between two messages would reload the
     * pre-send ratchet position and re-emit an already-used generation —
     * reusing the AEAD key+nonce and getting rejected by strict receivers.
     *
     * What is written is the ~72-byte [OwnSenderRatchet] record, not the whole
     * group state: the advance touches this leaf's SecretTree entry and
     * nothing else, so re-encrypting the tree, the context and the epoch
     * secrets alongside it was pure overhead on the send path. A store that
     * has not adopted the split falls back to the full write, so the guarantee
     * does not depend on the optimisation.
     */
    suspend fun encrypt(
        nostrGroupId: HexKey,
        plaintext: ByteArray,
    ): ByteArray =
        mutex.withLock {
            val ciphertext = requireGroup(nostrGroupId).encrypt(plaintext)
            persistSenderRatchet(nostrGroupId)
            ciphertext
        }

    /**
     * Runs [read] on the group under the lock commits are applied under, so it never sees one
     * half-applied: a commit rewrites the extensions before it moves the epoch.
     */
    suspend fun <T> readGroup(
        nostrGroupId: HexKey,
        read: (MlsGroup) -> T,
    ): T? = mutex.withLock { groups[nostrGroupId]?.let(read) }

    /**
     * [encrypt], with the epoch the ciphertext was made in and that epoch's group-event key, read
     * under the same lock. Read apart, a commit merging in between would label the message with one
     * epoch and seal its outer layer with another's key.
     */
    suspend fun encryptForSend(
        nostrGroupId: HexKey,
        plaintext: ByteArray,
        /**
         * The epoch the message must go out in, or null for whichever is current. Checked under
         * the lock that encrypts: a message carrying media encrypted under one epoch's key must not
         * be sent in another, where no receiver derives that key.
         */
        expectedEpoch: Long? = null,
    ): SealedApplicationMessage =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            if (expectedEpoch != null && group.epoch != expectedEpoch) throw MarmotEpochMovedException(expectedEpoch, group.epoch)
            val ciphertext = group.encrypt(plaintext)
            persistSenderRatchet(nostrGroupId)
            SealedApplicationMessage(ciphertext, group.epoch, exporterSecret(nostrGroupId))
        }

    /**
     * Decrypt a PrivateMessage of this group.
     *
     * Tries the current epoch first. A former epoch's APPLICATION message then
     * goes to [MlsGroup.decryptFormerEpoch], which checks it exactly as the
     * current epoch would (group id, sender leaf, the FramedContentTBS
     * signature against that epoch's tree and GroupContext) and writes the
     * epoch's ratchet back so a generation opens once. mls-kmp retains
     * [MlsGroup.RETAIN_EPOCHS] former epochs for this.
     *
     * The returned sender leaf is a leaf of the epoch the message was sent in:
     * attribute it with [decryptAndAttribute], not with [memberIdentityHex],
     * which reads the current tree.
     */
    suspend fun decrypt(
        nostrGroupId: HexKey,
        messageBytes: ByteArray,
    ): DecryptedMessage = mutex.withLock { decryptLocked(nostrGroupId, messageBytes).message }

    /**
     * [decrypt], plus the account identity the sender leaf held in the epoch
     * the message was sent in, read under the same lock.
     */
    suspend fun decryptAndAttribute(
        nostrGroupId: HexKey,
        messageBytes: ByteArray,
    ): AttributedMessage = mutex.withLock { decryptLocked(nostrGroupId, messageBytes) }

    private suspend fun decryptLocked(
        nostrGroupId: HexKey,
        messageBytes: ByteArray,
    ): AttributedMessage {
        val group = requireGroup(nostrGroupId)

        // Try current epoch. If we hit an exception here we MUST surface
        // it — the real cause (a bad signature, a missing proposal) is what a
        // caller needs, not a later "epoch mismatch".
        val retainedBefore = group.retainedSecrets()
        val preEpoch = group.epoch
        val currentFailure: Exception =
            try {
                val result = group.decrypt(messageBytes)
                // PrivateMessage commits apply inline through
                // `MlsGroup.decrypt` → `processCommit`; the epoch advances
                // in memory but the CLI reopens a fresh Context on every
                // command, so we MUST persist here or reloaded state
                // silently reverts to the pre-commit extensions (including
                // admin list).
                if (result.contentType == ContentType.COMMIT && group.epoch != preEpoch) {
                    pushRetainedEpoch(nostrGroupId, retainedBefore)
                    persistGroup(nostrGroupId)
                } else if (result.contentType == ContentType.APPLICATION) {
                    noteReceived(nostrGroupId)
                }
                return AttributedMessage(result, group.memberIdentityHex(result.senderLeafIndex))
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                e
            }

        val epoch = privateMessageEpoch(messageBytes)
        if (epoch == null || epoch >= group.epoch) throw currentFailure
        val result = group.decryptFormerEpoch(messageBytes)
        noteReceived(nostrGroupId)
        return AttributedMessage(result, formerMemberIdentityHex(nostrGroupId, group, result.epoch, result.senderLeafIndex))
    }

    /**
     * Decrypt with null return on failure.
     */
    suspend fun decryptOrNull(
        nostrGroupId: HexKey,
        messageBytes: ByteArray,
    ): DecryptedMessage? =
        try {
            decrypt(nostrGroupId, messageBytes)
        } catch (_: Exception) {
            null
        }

    // --- Member Management ---

    /**
     * Add a member and create a Commit.
     *
     * The returned [CommitResult.preCommitExporterSecret] is the key the
     * outbound kind:445 MUST be outer-encrypted with (RFC 9420 §12.4 + MDK
     * parity). The local group state advances to the new epoch before this
     * function returns; publishers get one shot at the correct pre-commit
     * key via the [CommitResult] payload.
     */
    suspend fun addMember(
        nostrGroupId: HexKey,
        keyPackageBytes: ByteArray,
    ): CommitResult =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            val retainedBefore = group.retainedSecrets()
            val result = group.addMember(keyPackageBytes)
            pushRetainedEpoch(nostrGroupId, retainedBefore)
            persistGroup(nostrGroupId)
            result
        }

    /**
     * Remove a member and create a Commit. See [addMember] for the
     * pre-commit exporter key contract on the returned [CommitResult].
     */
    suspend fun removeMember(
        nostrGroupId: HexKey,
        targetLeafIndex: Int,
    ): CommitResult =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            val retainedBefore = group.retainedSecrets()
            val result = group.removeMember(targetLeafIndex)
            pushRetainedEpoch(nostrGroupId, retainedBefore)
            persistGroup(nostrGroupId)
            result
        }

    /**
     * Rotate the signing key within a group and commit.
     *
     * Per MIP-00, members SHOULD self-update within 24 hours of joining.
     * See [addMember] for the pre-commit exporter key contract.
     */
    suspend fun rotateSigningKey(nostrGroupId: HexKey): CommitResult =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            val retainedBefore = group.retainedSecrets()
            group.proposeSigningKeyRotation()
            val result = group.commit()
            pushRetainedEpoch(nostrGroupId, retainedBefore)
            persistGroup(nostrGroupId)
            result
        }

    /**
     * Update group extensions (e.g., MIP-01 metadata) via a GroupContextExtensions proposal.
     * See [addMember] for the pre-commit exporter key contract.
     */
    suspend fun updateGroupExtensions(
        nostrGroupId: HexKey,
        extensions: List<Extension>,
    ): CommitResult =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            requireAdminForExtensionChange(group)
            val retainedBefore = group.retainedSecrets()
            group.proposeGroupContextExtensions(extensions)
            val result = group.commit()
            pushRetainedEpoch(nostrGroupId, retainedBefore)
            persistGroup(nostrGroupId)
            result
        }

    /**
     * Leave a group by publishing a standalone PublicMessage SelfRemove
     * proposal (draft-ietf-mls-extensions). Admin receivers auto-commit
     * the pending proposal; the caller publishes the framed bytes as the
     * kind:445 content, outer-encrypted with the returned exporter key.
     */
    suspend fun leaveGroup(nostrGroupId: HexKey): Pair<ByteArray, ByteArray> =
        mutex.withLock {
            val group = requireGroup(nostrGroupId)
            val result = group.buildSelfRemoveProposalMessage()
            removeGroupStateUnlocked(nostrGroupId)
            result
        }

    /**
     * Remove all local state for a group without sending any proposals.
     * Used after the leave event has already been built.
     */
    suspend fun removeGroupState(nostrGroupId: HexKey) =
        mutex.withLock {
            removeGroupStateUnlocked(nostrGroupId)
        }

    private suspend fun removeGroupStateUnlocked(nostrGroupId: HexKey) {
        groups.remove(nostrGroupId)
        retainedEpochs.remove(nostrGroupId)
        receivedSinceSave.remove(nostrGroupId)
        formerTrees.remove(nostrGroupId)
        retainedEpochRevision.remove(nostrGroupId)
        retainedEpochPersisted.remove(nostrGroupId)
        store.delete(nostrGroupId)
    }

    /**
     * Wipe all MLS group state, both in-memory and on-disk. Intended as a
     * user-initiated "nuclear" reset for the Marmot subsystem — does NOT
     * publish any SelfRemove/leave events, because the reset path is meant
     * to recover from unusable local state where graceful leave may not
     * even be possible.
     *
     * The union of in-memory group IDs and [MlsGroupStateStore.listGroups]
     * is used so any orphaned on-disk state (e.g. a prior restore that
     * failed to decode into memory) is also removed. Returns the ids it wiped.
     */
    suspend fun clearAllState(): List<String> =
        mutex.withLock {
            val ids = (groups.keys + store.listGroups().toSet()).toList()
            Log.d(TAG) { "clearAllState(): wiping ${ids.size} group(s): $ids" }
            for (id in ids) {
                try {
                    removeGroupStateUnlocked(id)
                } catch (e: Exception) {
                    Log.w(TAG) { "clearAllState(): failed to wipe $id: ${e.message}" }
                }
            }
            groups.clear()
            retainedEpochs.clear()
            retainedEpochRevision.clear()
            retainedEpochPersisted.clear()
            receivedSinceSave.clear()
            formerTrees.clear()
            ids
        }

    // --- Key Export ---

    /**
     * Hex-encoded BasicCredential identity of the member at [leafIndex] in
     * the given group, or null if the group is unknown or the leaf is blank /
     * not a Basic credential.
     *
     * Used by MIP-03 inner-event sender verification to confirm that the
     * `pubkey` in a decrypted application message matches the MLS sender's
     * credential identity.
     */
    fun memberIdentityHex(
        nostrGroupId: HexKey,
        leafIndex: Int,
    ): String? = groups[nostrGroupId]?.memberIdentityHex(leafIndex)

    /**
     * Export the Marmot outer encryption key for GroupEvent wrapping.
     * MLS-Exporter("marmot", "group-event", 32)
     */
    fun exporterSecret(nostrGroupId: HexKey): ByteArray =
        requireGroup(nostrGroupId).exporterSecret(
            "marmot",
            "group-event".encodeToByteArray(),
            32,
        )

    /**
     * Export the MIP-04 encrypted media key for a group.
     * MLS-Exporter("marmot", "encrypted-media", 32)
     */
    fun mediaExporterSecret(nostrGroupId: HexKey): ByteArray =
        requireGroup(nostrGroupId).exporterSecret(
            "marmot",
            "encrypted-media".encodeToByteArray(),
            32,
        )

    /**
     * The encrypted-media key of [epoch], or null when this device no longer
     * holds that epoch.
     *
     * `features/encrypted-media.md` derives an attachment's key from the epoch
     * of the message that carries it, not from the group's current epoch, so a
     * file sent before a later commit opens only under its own epoch's secret.
     * The current epoch and the retained ones are the only epochs whose
     * exporter secret is still known; a caller that needs an older one must
     * have captured it while that epoch was live.
     */
    fun mediaExporterSecretAt(
        nostrGroupId: HexKey,
        epoch: Long,
    ): ByteArray? {
        val group = groups[nostrGroupId] ?: return null
        if (group.epoch == epoch) return mediaExporterSecret(nostrGroupId)
        val retained =
            retainedEpochs[nostrGroupId]
                ?.firstOrNull { it.epoch == epoch && it.exporterSecret.isNotEmpty() }
                ?: return null
        return KeySchedule.mlsExporter(
            retained.exporterSecret,
            "marmot",
            "encrypted-media".encodeToByteArray(),
            32,
        )
    }

    /**
     * Return exporter secrets from retained epochs for a group.
     *
     * Used by the inbound processor to attempt outer decryption with
     * previous epoch keys when the current epoch's key fails (e.g.,
     * after a commit has advanced the epoch but late-arriving messages
     * still use the old exporter key).
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     * @return list of retained exporter secrets (most recent first), each
     *         derived via MLS-Exporter("marmot", "group-event", 32)
     */
    fun retainedExporterSecrets(nostrGroupId: HexKey): List<ByteArray> {
        val retained = retainedEpochs[nostrGroupId] ?: return emptyList()
        return retained
            .filter { it.exporterSecret.isNotEmpty() }
            .sortedByDescending { it.epoch }
            .map { epochSecrets ->
                KeySchedule.mlsExporter(
                    epochSecrets.exporterSecret,
                    "marmot",
                    "group-event".encodeToByteArray(),
                    32,
                )
            }
    }

    // --- Private Helpers ---

    private fun requireGroup(nostrGroupId: HexKey): MlsGroup =
        groups[nostrGroupId]
            ?: throw IllegalStateException("Not a member of group $nostrGroupId")

    /**
     * Persist where our sender ratchet got to, without rewriting the group.
     *
     * Falls back to a full [persistGroup] when the store does not implement the
     * split, or when the group has no ratchet entry to record yet. Both are
     * correct-but-slower, never correct-but-lossy: the position must be on disk
     * before the ciphertext it produced can be published.
     */
    private suspend fun persistSenderRatchet(nostrGroupId: HexKey) {
        val group = groups[nostrGroupId]
        if (group == null) {
            Log.w(TAG) { "persistSenderRatchet($nostrGroupId): group not in memory, skipping" }
            return
        }
        val record = group.exportOwnSenderRatchet()
        if (record == null || !store.saveSenderRatchet(nostrGroupId, record.encodeTls())) {
            persistGroup(nostrGroupId)
        }
    }

    private suspend fun persistGroup(nostrGroupId: HexKey) {
        val group = groups[nostrGroupId]
        if (group == null) {
            Log.w(TAG) { "persistGroup($nostrGroupId): group not in memory, skipping" }
            return
        }
        try {
            val state = group.saveState()
            val encoded = state.encodeTls()
            Log.d(TAG) { "persistGroup($nostrGroupId): serialized ${encoded.size} bytes, calling store.save" }
            store.save(nostrGroupId, encoded)
            receivedSinceSave.remove(nostrGroupId)

            // The standalone record now describes a position this state already
            // contains, and after an epoch change it describes a ratchet that no
            // longer exists. Rewriting it keeps the two in step; a restore would
            // reject a stale one on its epoch anyway, but leaving one behind
            // makes every restore reason about a record it must then discard.
            group.exportOwnSenderRatchet()?.let { store.saveSenderRatchet(nostrGroupId, it.encodeTls()) }

            // Also persist retained epochs — but only when the window actually
            // moved. See [retainedEpochRevision].
            val retained = retainedEpochs[nostrGroupId]
            val revision = retainedEpochRevision[nostrGroupId] ?: 0L
            if (retained != null && retainedEpochPersisted[nostrGroupId] != revision) {
                val retainedBytes = encodeRetained(retained)
                store.saveRetainedEpochs(nostrGroupId, retainedBytes)
                retainedEpochPersisted[nostrGroupId] = revision
                Log.d(TAG) { "persistGroup($nostrGroupId): persisted ${retainedBytes.size} retained epochs" }
            }
        } catch (e: Exception) {
            Log.e(TAG, "persistGroup($nostrGroupId) FAILED: ${e.message}", e)
            throw e
        }
    }

    /**
     * Push a previously-captured [RetainedEpochSecrets] into the bounded
     * retention window. Call after the epoch advance has been applied
     * successfully so that failed commits don't pollute the window with
     * duplicate current-epoch keys.
     */
    private fun pushRetainedEpoch(
        nostrGroupId: HexKey,
        retainedBefore: RetainedEpochSecrets,
    ) {
        val retained = retainedEpochs.getOrPut(nostrGroupId) { mutableListOf() }
        retained.add(retainedBefore.exporterOnly())

        // Trim to retention window (keep only the most recent N-1 epochs)
        while (retained.size > EPOCH_RETENTION_WINDOW) {
            retained.removeAt(0)
        }
        retainedEpochRevision[nostrGroupId] = (retainedEpochRevision[nostrGroupId] ?: 0L) + 1
    }

    private fun encodeRetained(retained: List<RetainedEpochSecrets>): List<ByteArray> =
        retained.map { epoch ->
            val writer = TlsWriter()
            epoch.encodeTls(writer)
            writer.toByteArray()
        }

    /**
     * The epoch number of a PrivateMessage, or null for anything else. Read from the clear header,
     * so it costs a parse and no key.
     */
    private fun privateMessageEpoch(messageBytes: ByteArray): Long? =
        try {
            val mlsMessage = MlsMessage.decodeTls(TlsReader(messageBytes))
            if (mlsMessage.wireFormat != WireFormat.PRIVATE_MESSAGE) null else PrivateMessage.decodeTls(TlsReader(mlsMessage.payload)).epoch
        } catch (_: Exception) {
            null
        }

    /** Decoded trees of retained epochs, by group and epoch, checked against the record's own bytes. */
    private val formerTrees = mutableMapOf<HexKey, MutableMap<Long, Pair<ByteArray, RatchetTree>>>()

    /**
     * The BasicCredential identity [leafIndex] held in [epoch], a former epoch [group] still
     * retains: the tree a late message is attributed in, not today's, where the slot may now hold
     * someone else.
     */
    private fun formerMemberIdentityHex(
        nostrGroupId: HexKey,
        group: MlsGroup,
        epoch: Long,
        leafIndex: Int,
    ): HexKey? {
        val retained = group.retainedEpochs()
        val record = retained.firstOrNull { it.epoch == epoch } ?: return null
        val byEpoch = formerTrees.getOrPut(nostrGroupId) { mutableMapOf() }
        val tree =
            byEpoch[epoch]?.takeIf { it.first === record.treeBytes }?.second
                ?: RatchetTree.decodeTls(TlsReader(record.treeBytes)).also { decoded ->
                    byEpoch.keys.retainAll(retained.mapTo(HashSet()) { it.epoch })
                    byEpoch[epoch] = record.treeBytes to decoded
                }
        if (leafIndex !in 0 until tree.leafCount) return null
        return (tree.getLeaf(leafIndex)?.credential as? Credential.Basic)?.identity?.toHexKey()
    }

    /**
     * Counts an application message opened in [nostrGroupId] and writes the group once
     * [RECEIVED_PERSIST_BATCH] of them are pending. Opening one moves a receive ratchet and deletes
     * the key it used; until the state is written, a restart brings that key back.
     */
    private suspend fun noteReceived(nostrGroupId: HexKey) {
        val count = (receivedSinceSave[nostrGroupId] ?: 0) + 1
        if (count >= RECEIVED_PERSIST_BATCH) persistGroup(nostrGroupId) else receivedSinceSave[nostrGroupId] = count
    }

    /**
     * Writes every group whose receive ratchets moved since it was last written. A front end calls
     * it after a batch of inbound events and when it goes to the background; [MarmotSyncPolicy] calls
     * it after each catch-up. Until then up to [RECEIVED_PERSIST_BATCH] opened messages per group
     * would open again after a restart, and their keys stay on disk.
     */
    suspend fun flushReceivedState() =
        mutex.withLock {
            for (nostrGroupId in receivedSinceSave.keys.toList()) {
                if (groups.containsKey(nostrGroupId)) persistGroup(nostrGroupId) else receivedSinceSave.remove(nostrGroupId)
            }
        }

    companion object {
        private const val TAG = "MlsGroupManager"

        /**
         * Number of past epochs whose exporter secret is retained, for the
         * outer layer and the media key of late-arriving messages. Matches
         * MDK's `DEFAULT_EPOCH_LOOKBACK` so a message encrypted under the prior
         * N epochs' exporter secrets can still be peeled after a Commit
         * advances the group. Capped for forward-secrecy reasons.
         */
        const val EPOCH_RETENTION_WINDOW = 5

        /** Application messages opened in a group before its state is written again: see [noteReceived]. */
        const val RECEIVED_PERSIST_BATCH = 32
    }
}

/**
 * A message [MlsGroupManager.decryptAndAttribute] opened, and the BasicCredential identity (hex) its
 * sender leaf held in the epoch it was sent in; null when that leaf has no Basic credential.
 */
class AttributedMessage(
    val message: DecryptedMessage,
    val senderIdentityHex: HexKey?,
)

/**
 * A Welcome named a group this device is still a live member of, so it was not applied: joining
 * again would put the group back at the Welcome's epoch. A relay redelivering the Welcome after a
 * restart is the usual cause.
 */
class MarmotAlreadyMemberException(
    val nostrGroupId: HexKey,
) : IllegalStateException("Already a member of group $nostrGroupId; the Welcome was not applied")

/**
 * The exporter secret alone: a former epoch's messages open through mls-kmp's own receiver data, so
 * the manager keeps nothing else of the epoch. The TLS layout is unchanged, with empty secrets.
 */
internal fun RetainedEpochSecrets.exporterOnly(): RetainedEpochSecrets = if (senderDataSecret.isEmpty() && encryptionSecret.isEmpty()) this else copy(senderDataSecret = ByteArray(0), encryptionSecret = ByteArray(0))

/** An application message encrypted for sending: see [MlsGroupManager.encryptForSend]. */
class SealedApplicationMessage(
    val mlsCiphertext: ByteArray,
    val epoch: Long,
    val groupEventKey: ByteArray,
)

/**
 * A send pinned to [expected] found the group at [current]: whatever the message carries that was
 * encrypted under [expected]'s media key is unreadable in [current], so it must be encrypted again.
 */
class MarmotEpochMovedException(
    val expected: Long,
    val current: Long,
) : IllegalStateException("The group moved from epoch $expected to $current; encrypt the media again")
