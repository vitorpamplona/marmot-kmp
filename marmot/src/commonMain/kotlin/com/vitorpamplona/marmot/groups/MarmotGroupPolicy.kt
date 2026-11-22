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
import com.vitorpamplona.marmot.appComponents.AppComponentIds
import com.vitorpamplona.marmot.appComponents.MarmotProtocolProfile
import com.vitorpamplona.marmot.appComponents.accountIdentityProof.AccountIdentityProofV2
import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamQuicPolicyV1
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupData
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsExporterLabel
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.tree.Capabilities
import com.vitorpamplona.mls.tree.Extension

/**
 * Marmot's authorization rules (MIP-01 and MIP-03), as an [MlsGroupPolicy].
 *
 * These used to live inside `MlsGroup`, which meant the RFC 9420 engine knew
 * the word "admin" — a concept RFC 9420 does not have. They are unchanged
 * here; only where they run has moved.
 *
 * Stateless, so one instance serves every group.
 */
object MarmotGroupPolicy : MlsGroupPolicy {
    /**
     * The MIP-era leaf set. A current-profile group names
     * [MarmotCapabilities.currentProfileLeaf] explicitly instead: the two
     * profiles differ in what they advertise but share these authorization
     * rules, so the policy carries the older default and the factory that
     * knows it is building a current-profile group overrides it.
     */
    override val defaultLeafCapabilities: Capabilities get() = MarmotCapabilities.mipLeaf()

    override val defaultRequiredCapabilities: Extension get() = MarmotCapabilities.mipRequired()

    /**
     * No GREASE values in our capabilities. Every KeyPackage's capability lists
     * are republished verbatim in its `mls_extensions` and `mls_proposals`
     * tags, and the reference client (MDK, on OpenMLS, which only adds GREASE
     * when asked) neither sends them nor has been tested against KeyPackages
     * that carry them. Our KeyPackages stay the shape MDK expects.
     */
    override val greaseCapabilities: Boolean get() = false

    /**
     * Marmot's two group-context extension types, exempted from the §13.4
     * all-members-support check.
     *
     * Both are advertised by [MarmotCapabilities.mipLeaf] and by the current
     * profile, so a group built entirely by this client passes the check on
     * capabilities alone. The exemption is for the groups that are already out
     * there, whose older leaves predate the advertisement - dropping it would
     * make this client refuse to apply a GroupContextExtensions proposal in a
     * group it is happily a member of.
     */
    override val knownExtensionTypes: Set<Int> =
        setOf(MarmotCapabilities.MARMOT_GROUP_DATA_EXTENSION_TYPE, AppDataDictionary.EXTENSION_TYPE)

    /**
     * `MLS-Exporter("marmot", "group-event", 32)` — the outer
     * ChaCha20-Poly1305 key for a kind:445 GroupEvent. A commit must be sealed
     * under the PRE-commit epoch so members still at epoch N can open it.
     */
    override val commitExporter: MlsExporterLabel
        get() = MlsExporterLabel("marmot", "group-event".encodeToByteArray(), 32)

    override fun authorizeCommit(
        group: GroupView,
        proposals: List<PendingProposal>,
        committerLeafIndex: Int,
    ) {
        AccountDevicesV1.validateProposals(group, proposals)
        rejectAdminSelfRemoves(group, proposals)
        enforceAuthorizedProposalSet(group, proposals, committerLeafIndex)
        enforceNoAdminDepletion(group, proposals)
    }

    /**
     * The rules on what a commit produces. They run for every commit, an
     * admin's included, because they are about the state, not about who made
     * it:
     *
     * - `marmot.group.account-devices.v1` (never un-required, every leaf
     *   advertises it, at most 20 leaves per account, no `0x800d` data);
     * - the account identity proof (`0x8009`) of every leaf the commit
     *   introduces, in a current-profile group, and that the group stays on
     *   that profile;
     * - the admin–leaf coupling of `app-components/admin-policy-v1.md`: every
     *   admin the resulting state names still holds a leaf;
     * - the retired agent text stream's `0x8006` state, when the group still
     *   carries it, is valid (`agent-text-stream-quic-v1.md`, "Validation").
     */
    override fun validateResultingState(
        parentExtensions: List<Extension>,
        proposals: List<PendingProposal>,
        committerLeafIndex: Int,
        resulting: GroupView,
    ) {
        AccountDevicesV1.validateResultingState(parentExtensions, proposals, resulting)
        validateIntroducedLeafProofs(parentExtensions, proposals, committerLeafIndex, resulting)
        validateAdminLeafCoupling(parentExtensions, resulting)
        validateAgentTextStreamState(resulting)
    }

    /**
     * `agent-text-stream-quic-v1.md`, "What clients keep doing": a client that
     * advertises `0x8006` validates its state on every Commit, so an older
     * client's update is accepted only when valid. MDK checks the same bytes on
     * every update it receives. The member-role half of "Validation" is checked
     * at join ([requireAgentTextStreamRoles]); like MDK, not on received Commits.
     */
    private fun validateAgentTextStreamState(resulting: GroupView) {
        AppDataDictionary.fromExtensionsOrEmpty(resulting.extensions)[AgentTextStreamQuicPolicyV1.COMPONENT_ID]?.let {
            AgentTextStreamQuicPolicyV1.decode(it)
        }
    }

    /**
     * `foundation/identity.md`, as MDK's `validate_staged_commit_account_identity_proofs`
     * applies it on every send, ingest and convergence replay: in a
     * current-profile group every LeafNode a commit introduces carries a valid
     * `marmot.member.account-identity-proof.v2` bound to its credential and
     * signature key. That is each Add's KeyPackage leaf, each Update's leaf and
     * the committer's leaf (its UpdatePath leaf, or an external joiner's).
     *
     * Without it the credential identity is only a claim: a member holding a
     * leaf's MLS signing key could add a leaf naming any account, and since a
     * same-account Add needs no admin, a leaf of account A could add a rogue
     * "A" that every MDK member refuses and we would accept.
     */
    private fun validateIntroducedLeafProofs(
        parentExtensions: List<Extension>,
        proposals: List<PendingProposal>,
        committerLeafIndex: Int,
        resulting: GroupView,
    ) {
        if (!MarmotProtocolProfile.isCurrent(parentExtensions)) return
        check(MarmotProtocolProfile.isCurrent(resulting.extensions)) { "A commit may not take a group off the current profile" }
        for (pending in proposals) {
            when (val proposal = pending.proposal) {
                is Proposal.Add -> {
                    val keyPackage = proposal.keyPackage
                    val ciphersuite = AccountIdentityProofV2.ciphersuiteOf(keyPackage) ?: throw IllegalStateException("An added KeyPackage uses an unknown ciphersuite")
                    AccountIdentityProofV2.leafProblem(keyPackage.leafNode, ciphersuite)?.let { throw IllegalStateException("Add proposal: $it") }
                }

                is Proposal.Update -> {
                    AccountIdentityProofV2.leafProblem(proposal.leafNode)?.let { throw IllegalStateException("Update proposal: $it") }
                }

                else -> {}
            }
        }
        val committerLeaf = resulting.leafNode(committerLeafIndex) ?: throw IllegalStateException("The committer holds no leaf in the resulting state")
        AccountIdentityProofV2.leafProblem(committerLeaf)?.let { throw IllegalStateException("Committer leaf: $it") }
    }

    /**
     * `app-components/admin-policy-v1.md`, MDK's
     * `validate_admin_leaf_coupling_for_staged_commit`: every admin key of the
     * resulting state belongs to an account that still holds a leaf. A commit
     * that removes an admin account's last leaf must drop it from `admins` in
     * the same commit. The resulting admin set is the resulting `0x8003`, or the
     * parent's carried forward; a group without one has nothing to couple.
     */
    private fun validateAdminLeafCoupling(
        parentExtensions: List<Extension>,
        resulting: GroupView,
    ) {
        val admins = currentProfileAdmins(resulting.extensions) ?: currentProfileAdmins(parentExtensions) ?: return
        if (admins.isEmpty()) return
        val accounts = HashSet<String>()
        for (i in 0 until resulting.leafCount) resulting.memberIdentityHex(i)?.let { accounts.add(it) }
        val orphaned = admins.firstOrNull { it !in accounts }
        check(orphaned == null) { "The commit leaves admin ${orphaned?.take(8)}… without a leaf in the group" }
    }

    /**
     * The admins named by the `marmot.group.admin-policy.v1` component
     * (`0x8003`) in [extensions], or null when there is none. The rules MDK
     * reads from that component alone (admin SelfRemove, coupling) read it
     * through here, so a legacy group, whose admins live in `0xF2EE`, keeps the
     * rules it had.
     */
    private fun currentProfileAdmins(extensions: List<Extension>): Set<String>? = AppDataDictionary.fromExtensionsOrEmpty(extensions)[AdminPolicyV1.COMPONENT_ID]?.let { AdminPolicyV1.decode(it).adminHexKeys.toSet() }

    /**
     * MDK's `reject_admin_self_remove_proposals`, run for every commit: an
     * admin must step down before it leaves, so a SelfRemove whose sender is an
     * admin is refused, and so is the commit carrying it. A sender that does
     * not resolve to an account fails closed.
     */
    private fun rejectAdminSelfRemoves(
        group: GroupView,
        proposals: List<PendingProposal>,
    ) {
        val admins = currentProfileAdmins(group.extensions) ?: return
        if (admins.isEmpty()) return
        for (pending in proposals) {
            if (pending.proposal !is Proposal.SelfRemove) continue
            val sender = group.memberIdentityHex(pending.senderLeafIndex)
            check(sender != null && sender !in admins) { "An admin cannot SelfRemove: it steps down first (MIP-03)" }
        }
    }

    /**
     * MIP-03: SelfRemove is the only proposal a member sends on its own; every
     * other change is committed directly. The engine accepts any standalone
     * proposal RFC 9420 allows and pools it for the next commit, so a stray one
     * from a peer — a non-admin's Add, say — would be swept into an admin's
     * next commit, and [authorizeCommit] would then refuse that whole commit.
     * Refused on arrival instead, it never reaches the pool.
     */
    override fun authorizeProposal(
        group: GroupView,
        proposal: PendingProposal,
    ) {
        require(proposal.proposal is Proposal.SelfRemove) {
            "Only SelfRemove may be sent as a standalone proposal (MIP-03), not ${proposal.proposal::class.simpleName}"
        }
        // Refused on arrival as MDK does, so it never sits in the pool where
        // every later commit that swept it would be refused.
        rejectAdminSelfRemoves(group, listOf(proposal))
    }

    override fun authorizeSelfRemove(group: GroupView) {
        check(!isLocalAdmin(group)) {
            "Admin must self-demote via GroupContextExtensions before SelfRemove (MIP-01)"
        }
    }

    override fun validateJoin(group: GroupView) {
        requireAgentTextStreamRoles(group)
    }

    /**
     * `protocol-core/joining.md`, receiving flow steps 7 and 8: the joined
     * state must satisfy the required components' invariants, and the Welcome's
     * author — the GroupInfo signer, the member that committed our Add — must
     * have been allowed to add us: an active admin of the resulting state, or,
     * when that state requires `marmot.group.account-devices.v1`, a device of
     * our own account.
     *
     * A group that names no admins at all has no one who could have added us,
     * and is refused, as MDK's `require_admin` refuses it; only a MIP-era group
     * of this client's (on neither proof profile, which MDK cannot join at all)
     * is still let through in its bootstrap state.
     *
     * In a current-profile group, as MDK's join does (steps 5b and 5e), every
     * leaf of the joined tree must carry a valid account identity proof and
     * every admin must hold a leaf.
     */
    override fun validateJoin(
        group: GroupView,
        groupInfoSigner: Int,
        groupInfoExtensions: List<Extension>,
    ) {
        validateJoin(group)
        AccountDevicesV1.validateJoinedState(group, groupInfoExtensions)
        if (MarmotProtocolProfile.isCurrent(group.extensions)) {
            for (i in 0 until group.leafCount) {
                val leaf = group.leafNode(i) ?: continue
                AccountIdentityProofV2.leafProblem(leaf)?.let { throw IllegalStateException("Joined tree, leaf $i: $it") }
            }
            validateAdminLeafCoupling(group.extensions, group)
        }
        val admins = adminIdentitiesIn(group.extensions)
        if (admins.isEmpty()) {
            // Only this client's own MIP-era groups (0xF2EE, neither proof
            // profile) may still be bootstrapping with no admin set; MDK cannot
            // join those at all, so there is nothing to agree with.
            check(isMipEra(group.extensions)) { "The group names no admins, so no one could have invited us" }
            return
        }
        val author = group.memberIdentityHex(groupInfoSigner)
        val ownAccount = author != null && author == group.memberIdentityHex(group.myLeafIndex)
        require(author in admins || (ownAccount && AccountDevicesV1.isRequired(group.extensions))) {
            "The Welcome's author is not an active admin of the group it invites us to"
        }
    }

    /** Whether [extensions] are a MIP-era GroupContext: on neither the current nor the legacy-proof profile. */
    private fun isMipEra(extensions: List<Extension>): Boolean {
        val dictionary = AppDataDictionary.fromExtensionsOrEmpty(extensions)
        return AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2 !in ComponentsList.supportedOrRequired(dictionary) && !MarmotProtocolProfile.requiresLegacyProof(extensions)
    }

    /**
     * The admin set named by [extensions], preferring the current profile.
     *
     * Decodes ONLY the admin policy, never the whole component set. Authorization
     * must not depend on the validity of components it does not read: a
     * malformed group profile is a defect worth surfacing where the profile is
     * used, but it must not make the group un-committable by taking the admin
     * check down with it.
     *
     * Reads whichever profile this group is on: the current profile's
     * `marmot.group.admin-policy.v1` component (`0x8003`) when present,
     * otherwise MIP-01's `admin_pubkeys` field inside `marmot_group_data`
     * (`0xF2EE`). Empty means the group names no admins at all, which happens
     * during bootstrap and in groups that carry neither.
     */
    fun adminIdentitiesIn(extensions: List<Extension>): Set<String> {
        val policyBytes = AppDataDictionary.fromExtensionsOrEmpty(extensions)[AdminPolicyV1.COMPONENT_ID]
        if (policyBytes != null) return AdminPolicyV1.decode(policyBytes).adminHexKeys.toSet()
        return MarmotGroupData
            .fromExtensions(extensions)
            ?.adminPubkeys
            ?.toSet()
            .orEmpty()
    }

    /** True if the member at [leafIndex] is an ACTIVE admin: named in the admin set and still holding a leaf. */
    fun isLeafAdmin(
        group: GroupView,
        leafIndex: Int,
    ): Boolean {
        val id = group.memberIdentityHex(leafIndex) ?: return false
        return id in adminIdentitiesIn(group.extensions)
    }

    /** True if the local member is an active admin. */
    fun isLocalAdmin(group: GroupView): Boolean = isLeafAdmin(group, group.myLeafIndex)

    /**
     * `protocol-core/group-messaging.md`, "Commit authorization": a non-admin
     * may commit only a self-update, a SelfRemove-only Commit, or — in a group
     * whose parent state requires `marmot.group.account-devices.v1` — a
     * same-account Commit; never a mix. [MarmotCommitClass] decides which, the
     * same answer branch selection reads.
     *
     * An active admin may commit anything else its rules allow, including
     * other members' SelfRemoves referenced into its own commit.
     */
    internal fun enforceAuthorizedProposalSet(
        group: GroupView,
        proposals: List<PendingProposal>,
        committerLeafIndex: Int,
    ) {
        if (proposals.isEmpty()) return
        // Reads whichever profile the group is on: the admin-policy component
        // (0x8003) for current-profile groups, `marmot_group_data` (0xF2EE)
        // for legacy ones. An empty set means bootstrap — no admins named yet —
        // and the gate stays open, mirroring MlsGroupManager.updateGroupExtensions.
        val admins = adminIdentitiesIn(group.extensions)
        if (admins.isEmpty() || isLeafAdmin(group, committerLeafIndex)) return

        val commitClass = MarmotCommitClass.of(group, proposals, committerLeafIndex, hasUpdatePath = true)
        if (!commitClass.requiresAdmin) return

        throw IllegalStateException(
            "MIP-03: non-admin members may only commit a self-update, SelfRemove-only proposals or, " +
                "where account-devices is required, their own account's devices; got " +
                "${proposals.map { it.proposal::class.simpleName }} from leaf $committerLeafIndex",
        )
    }

    /**
     * Reject any commit that would leave the group without at least one member
     * still listed in `admin_pubkeys` (MIP-03 admin depletion guard).
     *
     * We simulate the post-commit member set and the post-commit `admin_pubkeys`
     * list, then require a non-empty intersection. The guard is only active
     * once the group has a configured admin set — it does not kick in during
     * bootstrap before any admin is named.
     */
    internal fun enforceNoAdminDepletion(
        group: GroupView,
        proposals: List<PendingProposal>,
    ) {
        val currentAdmins = adminIdentitiesIn(group.extensions)
        if (currentAdmins.isEmpty()) return // Bootstrap: no admins yet, nothing to deplete.

        // Resolve the effective admin list after this commit. Three carriers can
        // change it, and they are checked in the order the commit applies them:
        // an AppDataUpdate on 0x8003 (current profile), then a
        // GroupContextExtensions proposal replacing the whole extension list
        // (either profile). AppDataUpdate is resolved last because
        // `applyAppDataUpdateProposals` runs after the rest of the list.
        val gce =
            proposals
                .asSequence()
                .map { it.proposal }
                .filterIsInstance<Proposal.GroupContextExtensions>()
                .lastOrNull()
        val extensionsAfterGce = gce?.extensions ?: group.extensions

        val adminUpdate =
            proposals
                .asSequence()
                .map { it.proposal }
                .filterIsInstance<Proposal.AppDataUpdate>()
                .lastOrNull { it.componentId == AdminPolicyV1.COMPONENT_ID }

        val adminSet =
            when (val operation = adminUpdate?.operation) {
                is Proposal.AppDataUpdate.Operation.Update ->
                    AdminPolicyV1.decode(operation.data).adminHexKeys.toSet()

                // Removing the admin policy is never valid — it is the sole
                // admin authority for the group's lifetime — so an empty set
                // here trips the depletion check below, which is the outcome
                // we want.
                Proposal.AppDataUpdate.Operation.Remove -> emptySet()

                null -> adminIdentitiesIn(extensionsAfterGce)
            }
        check(adminSet.isNotEmpty()) {
            "commit would leave the group with no admins (admin depletion)"
        }

        // Compute which leaves remain after applying Removes/SelfRemoves.
        val removedLeaves = mutableSetOf<Int>()
        for (pending in proposals) {
            when (val p = pending.proposal) {
                is Proposal.Remove -> removedLeaves.add(p.removedLeafIndex)
                is Proposal.SelfRemove -> removedLeaves.add(pending.senderLeafIndex)
                else -> Unit
            }
        }

        val remainingAdminIdentities = mutableSetOf<String>()
        for (i in 0 until group.leafCount) {
            if (i in removedLeaves) continue
            val id = group.memberIdentityHex(i) ?: continue
            if (id in adminSet) remainingAdminIdentities.add(id)
        }

        check(remainingAdminIdentities.isNotEmpty()) {
            "MIP-03: commit would leave the group without any admin members"
        }
    }

    /**
     * Enforce the `0x8006` component's `required_member_roles` mask over
     * the joining tree.
     *
     * The component is retired but still supported in the groups that carry
     * it, and decoding it here also validates its state
     * ([AgentTextStreamQuicPolicyV1.decode]).
     *
     * A group carrying the agent-text-stream component requires each named
     * role as an MLS leaf capability (`0xF2D1` receive, `0xF2D2` send,
     * `0xF2D4` fanout). Advertising the component id alone is not enough —
     * that only says "understands the component"; the role capability says
     * "can actually do this".
     */
    private fun requireAgentTextStreamRoles(group: GroupView) {
        val policy =
            AppDataDictionary
                .fromExtensionsOrEmpty(group.extensions)[AgentTextStreamQuicPolicyV1.COMPONENT_ID]
                ?.let { AgentTextStreamQuicPolicyV1.decode(it) } ?: return
        val required = policy.requiredRoleCapabilities()
        if (required.isEmpty()) return

        val myLeaf = group.leafCapabilities(group.myLeafIndex)
        requireNotNull(myLeaf) { "Joiner's leaf is blank after tree reconstruction" }
        val missing = required.filterNot { myLeaf.extensions.contains(it) }
        require(missing.isEmpty()) {
            "Joiner does not advertise agent text stream roles this group requires: " +
                missing.joinToString { AppComponentIds.toHex(it) }
        }
    }
}
