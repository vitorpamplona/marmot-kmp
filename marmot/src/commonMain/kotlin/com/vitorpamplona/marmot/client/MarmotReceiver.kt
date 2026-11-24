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

import com.vitorpamplona.marmot.MarmotMissingProposalException
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
 *  - a commit naming a proposal not received yet (a [MarmotIngestResult.Failure] caused by
 *    [MarmotMissingProposalException]) is held the same way, and given another go each time the
 *    group stages a proposal or advances;
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
 *
 * Opening an application message moves a receive ratchet that is written only every few
 * messages, so a live front end calls [flush] once the events in hand are applied (the same
 * moment as [commitStagedProposals]) and when the app goes to the background; [MarmotSyncPolicy]
 * calls it after each catch-up. Until then a restart opens those messages again.
 *
 * A catch-up must not move a group's `since` cursor past an event still [held] here: one that
 * is still waiting when the process ends (a one-shot `amy` run) is fetched again next time only
 * if the cursor stayed at or before it.
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
    private val pending = mutableMapOf<HexKey, ArrayDeque<HeldEvent>>()

    /** An event [MarmotReceiver] holds, and why. */
    class HeldEvent(
        val event: GroupEvent,
        /**
         * A commit naming a proposal not received yet. Its outer layer opened, so it belongs to an
         * epoch this device is at; an event whose outer layer did not open may instead be from
         * before this device joined, and never open.
         */
        val waitingForProposal: Boolean,
    )

    /** Groups that staged a proposal since the last [commitStagedProposals]. */
    private val staged = linkedSetOf<HexKey>()

    /** Apply [event] through [ingest], then whatever it held back that a commit just made openable. */
    suspend fun receive(event: Event): MarmotIngestResult {
        val result = marmot.ingest(event)
        onResult(event, result)
        when (result) {
            is MarmotIngestResult.UndecryptableOuter -> {
                if (event is GroupEvent) hold(result.groupId, event, waitingForProposal = false)
            }

            is MarmotIngestResult.ProposalStaged -> {
                lock.withLock { staged.add(result.groupId) }
                // A commit held for this proposal can apply now.
                replay(result.groupId)
            }

            is MarmotIngestResult.Failure -> {
                val missing = result.cause as? MarmotMissingProposalException
                if (missing != null && event is GroupEvent) hold(missing.groupId, event, waitingForProposal = true)
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

    /** The events held for [nostrGroupId], oldest held first. */
    suspend fun held(nostrGroupId: HexKey): List<HeldEvent> = lock.withLock { pending[nostrGroupId]?.toList().orEmpty() }

    /**
     * Write the receive state of every group whose ratchets moved since it was last written
     * ([MarmotManager.flushReceivedState]). Call it after a batch of live events and when the app
     * goes to the background.
     */
    suspend fun flush() = marmot.flushReceivedState()

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
        waitingForProposal: Boolean,
    ) = lock.withLock {
        val queue = pending.getOrPut(groupId) { ArrayDeque() }
        if (queue.any { it.event.id == event.id }) return@withLock
        if (queue.size >= maxPendingPerGroup) queue.removeFirst()
        queue.addLast(HeldEvent(event, waitingForProposal))
    }

    /**
     * Give everything held for [nostrGroupId] another go, for a change that [receive] cannot see:
     * convergence rewinding the group onto another branch, whose epochs open what the abandoned
     * one could not.
     */
    suspend fun retryHeld(nostrGroupId: HexKey) = replay(nostrGroupId)

    /**
     * Give everything held for [groupId] another go. A replayed commit replays in turn; that
     * terminates, because each pass takes the queue it replays and an epoch only moves forward.
     */
    private suspend fun replay(groupId: HexKey) {
        val held = lock.withLock { pending.remove(groupId)?.toList() } ?: return
        for (h in held) receive(h.event)
    }

    companion object {
        const val DEFAULT_MAX_PENDING_PER_GROUP = 64
    }
}
