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

import com.vitorpamplona.marmot.OutboundGroupEvent
import com.vitorpamplona.quartz.marmot.mip03GroupMessages.GroupEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The reactions every client owes the Marmot events it receives, on top of [ingest].
 *
 * Relays do not deliver kind:445 in the order it was sent, and a group event can only be opened
 * at the epoch its predecessors built. So:
 *
 *  - an event whose outer layer does not open ([MarmotIngestResult.UndecryptableOuter]) is held,
 *    per group, and given another go each time a commit advances that group;
 *  - a member's `SelfRemove` ([MarmotIngestResult.ProposalStaged]) only takes effect once an admin
 *    commits it, so the groups that staged one are remembered until [commitStagedProposals].
 *
 * Both front ends drive this: Amethyst's live subscription one event at a time, and
 * [MarmotSyncPolicy] a whole catch-up batch. What a client does with a result beyond that (index
 * a message, refresh a chat room, notify) is the [onResult] it passes, which hears about every
 * attempt, a replayed event's included.
 *
 * Proposals are committed when the caller says so, not as each arrives: two members leaving in
 * one batch must go out in one commit, because a proposal sent at an epoch cannot be committed
 * once the group moved past it. A batch caller calls [commitStagedProposals] after the batch; a
 * live one, once the events in hand are applied.
 */
class MarmotReceiver(
    private val marmot: MarmotManager,
    /** How many unopened events to hold per group; the oldest is dropped past it. */
    private val maxPendingPerGroup: Int = DEFAULT_MAX_PENDING_PER_GROUP,
    private val onResult: suspend (event: Event, result: MarmotIngestResult) -> Unit = { _, _ -> },
) {
    private val lock = Mutex()

    /**
     * Group → events whose outer layer did not open yet. Either the epoch predates our join, and
     * nothing will open it, or a commit that advances us to it has not arrived yet; the two look
     * the same from here, so both wait, bounded.
     */
    private val pending = mutableMapOf<HexKey, ArrayDeque<GroupEvent>>()

    /** Groups that staged a proposal since the last [commitStagedProposals]. */
    private val staged = linkedSetOf<HexKey>()

    /** Apply [event] through [ingest], then whatever it held back that a commit just made openable. */
    suspend fun receive(event: Event): MarmotIngestResult {
        val result = marmot.ingest(event)
        onResult(event, result)
        when (result) {
            is MarmotIngestResult.UndecryptableOuter -> {
                if (event is GroupEvent) hold(result.groupId, event)
            }

            is MarmotIngestResult.ProposalStaged -> {
                lock.withLock { staged.add(result.groupId) }
            }

            is MarmotIngestResult.Commit -> {
                replay(result.inner.groupId)
            }

            else -> {}
        }
        return result
    }

    /** How many events wait on a commit for [nostrGroupId]. */
    suspend fun pendingCount(nostrGroupId: HexKey): Int = lock.withLock { pending[nostrGroupId]?.size ?: 0 }

    /** Whether any group staged a proposal that [commitStagedProposals] has not handled yet. */
    suspend fun hasStagedProposals(): Boolean = lock.withLock { staged.isNotEmpty() }

    /**
     * Commit, in one commit per group, the proposals staged since the last call, in every group
     * where this account is an admin ([MarmotManager.commitStagedProposalsIfAdmin]). Returns the
     * commits made; a group where we are not an admin is left to one who is.
     */
    suspend fun commitStagedProposals(): Map<HexKey, OutboundGroupEvent> {
        val groups =
            lock.withLock {
                staged.toList().also { staged.clear() }
            }
        return buildMap {
            for (groupId in groups) {
                marmot.commitStagedProposalsIfAdmin(groupId)?.let { put(groupId, it) }
            }
        }
    }

    private suspend fun hold(
        groupId: HexKey,
        event: GroupEvent,
    ) = lock.withLock {
        val queue = pending.getOrPut(groupId) { ArrayDeque() }
        if (queue.any { it.id == event.id }) return@withLock
        if (queue.size >= maxPendingPerGroup) queue.removeFirst()
        queue.addLast(event)
    }

    /**
     * Give everything held for [groupId] another go. A replayed commit replays in turn; that
     * terminates, because each pass takes the queue it replays and an epoch only moves forward.
     */
    private suspend fun replay(groupId: HexKey) {
        val held = lock.withLock { pending.remove(groupId)?.toList() } ?: return
        for (event in held) receive(event)
    }

    companion object {
        const val DEFAULT_MAX_PENDING_PER_GROUP = 64
    }
}
