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
package com.vitorpamplona.marmot.appComponents

import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.messages.Proposal
import com.vitorpamplona.mls.tree.Credential
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * `marmot.group.account-devices.v1` (`0x800d`): in a group that requires it, a
 * member adds and removes leaves of its OWN account without admin authority
 * (`app-components/account-devices-v1.md`).
 *
 * The component has no data anywhere. A leaf or KeyPackage advertises support
 * by listing the id in its `app_components` list, and a group requires it by
 * listing it in the GroupContext's. Everything here is a receiver rule every
 * member applies identically, because two members that disagree on which
 * commits are valid fork the group:
 *
 * - [isSameAccountOperation] / the same-account Commit shape, which
 *   `MarmotCommitClass` turns into authorization and branch priority;
 * - [validateResultingState]: once required, never un-required; every leaf
 *   advertises the id; at most [MAX_LEAVES_PER_ACCOUNT] leaves per account; no
 *   dictionary entry with the id at any location;
 * - [validateProposals]: no AppDataUpdate targeting the id while the parent
 *   requires it;
 * - [validateJoinedState]: the same invariants on a Welcome, plus the GroupInfo.
 *
 * Before a group requires it, an entry or an AppDataUpdate for `0x800d` is just
 * an unknown component's, so every check here is gated on the requirement.
 */
object AccountDevicesV1 {
    const val COMPONENT_ID = AppComponentIds.ACCOUNT_DEVICES_V1

    /**
     * `max_leaves_per_account`. Fixed for this component id: every member
     * enforces it, so a different value would be a different component.
     */
    const val MAX_LEAVES_PER_ACCOUNT = 20

    /**
     * Whether the GroupContext [extensions] require `0x800d`: they list it in
     * their required `app_components` AND put the group on the current
     * profile. MDK's `group_requires_account_devices`: the id in a legacy
     * group's list changes nothing, as for clients that predate the
     * component, so a same-account Commit there still needs an admin.
     */
    fun isRequired(extensions: List<Extension>): Boolean = COMPONENT_ID in ComponentsList.supportedOrRequired(AppDataDictionary.fromExtensionsOrEmpty(extensions)) && MarmotProtocolProfile.isCurrent(extensions)

    /** Whether [leaf] advertises `0x800d` in its own `app_components` list. */
    fun isAdvertisedBy(leaf: LeafNode): Boolean = COMPONENT_ID in advertised(leaf.extensions)

    /** The component ids a leaf's or KeyPackage's [extensions] advertise. */
    fun advertised(extensions: List<Extension>): List<Int> = AppDataDictionary.fromExtensions(extensions)?.let { ComponentsList.supportedOrRequired(it) }.orEmpty()

    /** The account (BasicCredential identity) of [leaf], as hex. */
    fun accountOf(leaf: LeafNode): HexKey? = (leaf.credential as? Credential.Basic)?.identity?.toHexKey()

    /**
     * account-devices-v1.md, "Same-account operations": carried BY VALUE in
     * [committer]'s own Commit, either an Add whose KeyPackage's account is the
     * committer's, or a Remove of a current leaf OTHER than the committer's
     * whose account is the committer's.
     *
     * By value means inline: the engine resolves an inline proposal with no
     * `authenticatedContentBytes` and the committer as its sender, while a
     * proposal committed by reference carries the bytes it arrived in.
     */
    fun isSameAccountOperation(
        parent: GroupView,
        committer: Int,
        pending: PendingProposal,
    ): Boolean = isSameAccountOperation(parent, committer, parent.memberIdentityHex(committer), pending)

    /** [isSameAccountOperation] with the committer's [account] read once for a whole commit. */
    fun isSameAccountOperation(
        parent: GroupView,
        committer: Int,
        account: HexKey?,
        pending: PendingProposal,
    ): Boolean {
        if (account == null || pending.authenticatedContentBytes != null || !pending.isFrom(committer)) return false
        return when (val proposal = pending.proposal) {
            is Proposal.Add -> accountOf(proposal.keyPackage.leafNode) == account
            is Proposal.Remove -> proposal.removedLeafIndex != committer && parent.memberIdentityHex(proposal.removedLeafIndex) == account
            else -> false
        }
    }

    /**
     * account-devices-v1.md, "Data": a Commit whose candidate parent requires
     * `0x800d` is invalid when it carries an AppDataUpdate for it. Applies to
     * every committer, admins included.
     */
    fun validateProposals(
        parent: GroupView,
        proposals: List<PendingProposal>,
    ) {
        if (!isRequired(parent.extensions)) return
        val update = proposals.any { (it.proposal as? Proposal.AppDataUpdate)?.componentId == COMPONENT_ID }
        check(!update) { "account-devices: no AppDataUpdate may target 0x800d once the group requires it" }
    }

    /**
     * The rules on the state a Commit produces ("Data", "Support invariant",
     * "Leaf limit", "Removal"). Checked against the complete resulting state of
     * every Commit, whoever commits it.
     */
    fun validateResultingState(
        parentExtensions: List<Extension>,
        proposals: List<PendingProposal>,
        resulting: GroupView,
    ) {
        val required = isRequired(resulting.extensions)
        check(required || !isRequired(parentExtensions)) {
            "account-devices: a group that requires 0x800d must keep requiring it"
        }
        if (!required) return
        validateState(resulting)
        for (pending in proposals) {
            val add = pending.proposal as? Proposal.Add ?: continue
            check(!AppDataDictionary.fromExtensionsOrEmpty(add.keyPackage.extensions).contains(COMPONENT_ID)) {
                "account-devices: an added KeyPackage carries a 0x800d dictionary entry"
            }
        }
    }

    /**
     * The same invariants on a state joined from a Welcome, plus its GroupInfo
     * ("Data": only the joiner sees the GroupInfo). A group that does not
     * require `0x800d` is valid, so nothing is checked then.
     */
    fun validateJoinedState(
        group: GroupView,
        groupInfoExtensions: List<Extension>,
    ) {
        if (!isRequired(group.extensions)) return
        validateState(group)
        check(!AppDataDictionary.fromExtensionsOrEmpty(groupInfoExtensions).contains(COMPONENT_ID)) {
            "account-devices: the GroupInfo carries a 0x800d dictionary entry"
        }
    }

    private fun validateState(state: GroupView) {
        check(!AppDataDictionary.fromExtensionsOrEmpty(state.extensions).contains(COMPONENT_ID)) {
            "account-devices: the GroupContext carries a 0x800d dictionary entry"
        }
        val leavesPerAccount = mutableMapOf<HexKey, Int>()
        for (i in 0 until state.leafCount) {
            val leaf = state.leafNode(i) ?: continue
            // One decode per leaf serves both checks.
            val dictionary = AppDataDictionary.fromExtensionsOrEmpty(leaf.extensions)
            check(COMPONENT_ID in ComponentsList.supportedOrRequired(dictionary)) { "account-devices: leaf $i does not advertise 0x800d" }
            check(!dictionary.contains(COMPONENT_ID)) {
                "account-devices: leaf $i carries a 0x800d dictionary entry"
            }
            val account = accountOf(leaf) ?: continue
            val count = (leavesPerAccount[account] ?: 0) + 1
            check(count <= MAX_LEAVES_PER_ACCOUNT) {
                "account-devices: an account would hold more than $MAX_LEAVES_PER_ACCOUNT leaves"
            }
            leavesPerAccount[account] = count
        }
    }
}
