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

import com.vitorpamplona.quartz.nip01Core.core.HexKey

/**
 * What one member may do to another, by the rules [MarmotGroupPolicy] enforces
 * on every commit, so a front end offers only the actions peers would accept.
 *
 * [admins] is the group's admin list as committed, which may still name an
 * account that has left; [members] is who is in the tree now.
 */
object MarmotGroupPermissions {
    /**
     * MIP-03: admins manage the group. A group that names no admins yet
     * (bootstrap) leaves the gate open to every member, as the policy does.
     */
    fun canManage(
        admins: Collection<HexKey>,
        actor: HexKey,
    ): Boolean = admins.isEmpty() || actor in admins

    /**
     * Remove [target] with a commit. Never the actor itself: a committer
     * cannot remove its own leaf, and leaving is a SelfRemove proposal
     * (`MarmotManager.leave`).
     */
    fun canRemove(
        admins: Collection<HexKey>,
        actor: HexKey,
        target: HexKey,
    ): Boolean = actor != target && canManage(admins, actor)

    fun canPromote(
        admins: Collection<HexKey>,
        actor: HexKey,
        target: HexKey,
    ): Boolean = target !in admins && canManage(admins, actor)

    /**
     * Demote [target], as long as an admin stays among [members]: a commit that
     * leaves none is refused as admin depletion. Counting the list alone is not
     * enough, because it may name someone who already left.
     */
    fun canDemote(
        admins: Collection<HexKey>,
        members: Collection<HexKey>,
        actor: HexKey,
        target: HexKey,
    ): Boolean = target in admins && canManage(admins, actor) && admins.any { it != target && it in members }
}
