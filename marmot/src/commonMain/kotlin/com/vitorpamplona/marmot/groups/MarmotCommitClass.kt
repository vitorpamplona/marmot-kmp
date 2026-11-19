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
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.messages.Proposal

/**
 * The one class a Commit has in its candidate parent state, which decides both
 * whether a non-admin may commit it and its branch priority
 * (`protocol-core/group-messaging.md`, "Commit authorization";
 * `protocol-core/convergence.md`, `tip_priority`).
 *
 * Mirrors MDK's `commit_class.rs`: authorization and `tip_priority` read the
 * same answer, so a committer never resolves a fork differently from the
 * members replaying its commit.
 */
enum class MarmotCommitClass {
    /**
     * No proposals, only the committer's UpdatePath. An Update proposal never
     * makes one: MLS refuses a committer's own Update, and MDK's classifier
     * calls any Update admin-required.
     */
    SELF_UPDATE,

    /** At least one SelfRemove and nothing else. */
    SELF_REMOVE_ONLY,

    /** Same-account Adds and Removes, by value, in a parent that requires `0x800d`. */
    SAME_ACCOUNT,

    /** Anything else: only an active admin may commit it. */
    ADMIN_REQUIRED,
    ;

    /** Whether only an active admin may commit it. */
    val requiresAdmin: Boolean get() = this == ADMIN_REQUIRED

    /** `privileged` in branch selection exactly when it needs an admin, whoever committed it. */
    val isPrivileged: Boolean get() = requiresAdmin

    companion object {
        /**
         * Classify a Commit of [proposals] by [committer] against [parent], its
         * candidate parent state. [hasUpdatePath] matters only for a Commit with
         * no proposals, which is a self-update when it replaces the committer's
         * leaf.
         */
        fun of(
            parent: GroupView,
            proposals: List<PendingProposal>,
            committer: Int,
            hasUpdatePath: Boolean,
        ): MarmotCommitClass {
            if (proposals.isEmpty()) return if (hasUpdatePath) SELF_UPDATE else ADMIN_REQUIRED
            if (proposals.all { it.proposal is Proposal.SelfRemove }) {
                // The shape-only rule counted SelfRemoves whoever sent them; a
                // committer's own (inline) SelfRemove is refused by MLS itself.
                return SELF_REMOVE_ONLY
            }
            val account = parent.memberIdentityHex(committer)
            if (proposals.all { AccountDevicesV1.isSameAccountOperation(parent, committer, account, it) } &&
                AccountDevicesV1.isRequired(parent.extensions)
            ) {
                return SAME_ACCOUNT
            }
            return ADMIN_REQUIRED
        }
    }
}
