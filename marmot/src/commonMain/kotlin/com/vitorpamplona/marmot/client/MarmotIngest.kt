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

import com.vitorpamplona.marmot.GroupEventResult
import com.vitorpamplona.marmot.MarmotInboundProcessor
import com.vitorpamplona.marmot.WelcomeResult
import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamRetirement
import com.vitorpamplona.marmot.features.deviceGroup.MarmotDeviceGroupKinds
import com.vitorpamplona.quartz.marmot.mip02Welcome.WelcomeEvent
import com.vitorpamplona.quartz.marmot.mip03GroupMessages.GroupEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip59Giftwrap.seals.SealEvent
import com.vitorpamplona.quartz.nip59Giftwrap.wraps.GiftWrapEvent
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Outcome of routing a single inbound Nostr event through the Marmot pipeline.
 *
 * Drives both Amethyst's `DecryptAndIndexProcessor.GroupEventHandler` and the
 * CLI's `Context.syncIncoming`. Platform-specific side effects (UI notifications,
 * "mark as known", cache hints) happen at the call site based on which variant
 * came back; the ingest method handles only the MLS/crypto parts that are the
 * same everywhere.
 */
sealed class MarmotIngestResult {
    /** A Welcome arrived and we successfully joined a new group. */
    data class JoinedGroup(
        val nostrGroupId: HexKey,
        val needsKeyPackageRotation: Boolean,
    ) : MarmotIngestResult()

    /** A Welcome for a group we're already in — benign replay. */
    data class AlreadyInGroup(
        val nostrGroupId: HexKey,
    ) : MarmotIngestResult()

    /** A kind:445 carried an application message we decrypted. Already persisted. */
    data class Message(
        val inner: GroupEventResult.ApplicationMessage,
    ) : MarmotIngestResult()

    /** A kind:445 carried a commit that advanced the group epoch. */
    data class Commit(
        val inner: GroupEventResult.CommitProcessed,
    ) : MarmotIngestResult()

    /**
     * A kind:445 carried a standalone Proposal (currently only `SelfRemove`)
     * which was staged in the group's pending pool. The group epoch did
     * not advance — a later Commit referencing this proposal will pick
     * it up.
     */
    data class ProposalStaged(
        val groupId: HexKey,
        val senderLeafIndex: Int,
    ) : MarmotIngestResult()

    /** A kind:445 whose outer layer we couldn't decrypt (pre-join epoch, etc). Debug-only. */
    data class UndecryptableOuter(
        val groupId: HexKey,
        val retainedEpochCount: Int,
    ) : MarmotIngestResult()

    /**
     * Deduplicate / out-of-order commits / unsupported content. Not an error.
     *
     * [reason] names the branch that produced it. Several very different
     * situations land here — a replayed event we already merged, a commit held
     * for convergence, an app message decrypted on a losing branch, traffic in
     * a group we have terminalized — and collapsing them into one unlabelled
     * result made a stuck client indistinguishable from a quiet one in the
     * logs.
     */
    data class Ignored(
        val reason: String,
    ) : MarmotIngestResult()

    /** Something blew up. Callers log. */
    data class Failure(
        val message: String,
        val cause: Throwable? = null,
    ) : MarmotIngestResult()
}

/**
 * Route a single event through the Marmot inbound pipeline.
 *
 * Kind 1059 (gift wraps): unwrap → if inner kind:444, process Welcome.
 * Kind 445 (group events): decrypt + process; on [GroupEventResult.ApplicationMessage],
 * persist the decrypted inner JSON so [MarmotManager.loadStoredMessages] sees it.
 *
 * Other kinds are returned as [MarmotIngestResult.Ignored] — callers decide
 * what to do with them (most route through their own feed ingestion).
 */
suspend fun MarmotManager.ingest(event: Event): MarmotIngestResult =
    when (event) {
        is GiftWrapEvent -> ingestGiftWrap(event)
        is GroupEvent -> ingestGroupEvent(event)
        else -> MarmotIngestResult.Ignored("unhandled kind ${event.kind}")
    }

private suspend fun MarmotManager.ingestGiftWrap(wrap: GiftWrapEvent): MarmotIngestResult {
    // A relay `since` cursor cannot skip a backdated event, and NIP-59 wraps
    // are backdated by up to two days on purpose — so without a durable marker
    // every wrap in that band is unwrapped and re-decided on every single sync.
    if (isTerminallyIngested(wrap.id)) return MarmotIngestResult.Ignored("already ingested")
    val result = ingestGiftWrapUncached(wrap)
    if (result.isTerminalForWelcome()) markTerminallyIngested(wrap.id)
    return result
}

/**
 * Apply a Welcome a client already unwrapped itself: the same join as [ingest] gives a gift wrap,
 * for a front end whose own gift-wrap pipeline peels the NIP-59 layers (Amethyst's does, to index
 * the seal and rumor like any other DM).
 *
 * Marks [welcome]'s id terminally ingested once nothing more can come of it, as [ingest] marks the
 * wrap's: joined, already in the group, or naming a KeyPackage this device never held. Any other
 * failure stays retryable.
 */
suspend fun MarmotManager.ingestWelcome(welcome: WelcomeEvent): MarmotIngestResult {
    if (isTerminallyIngested(welcome.id)) return MarmotIngestResult.Ignored("already ingested")
    val result =
        try {
            joinFromWelcome(welcome)
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            MarmotIngestResult.Failure("welcome failed: ${e.message}", e)
        }
    if (result.isTerminalForWelcome()) markTerminallyIngested(welcome.id)
    return result
}

/**
 * Joined, or already in the group: nothing more can come of this Welcome. And one naming a
 * KeyPackage whose private half we never held can never become processable either: bundles are
 * generated locally BEFORE the KeyPackage is published, so one we do not have is one we never will.
 */
private fun MarmotIngestResult.isTerminalForWelcome(): Boolean =
    when (this) {
        is MarmotIngestResult.JoinedGroup, is MarmotIngestResult.AlreadyInGroup -> true
        is MarmotIngestResult.Failure -> message.contains("No matching KeyPackageBundle")
        else -> false
    }

private suspend fun MarmotManager.ingestGiftWrapUncached(wrap: GiftWrapEvent): MarmotIngestResult =
    try {
        // NIP-59 wraps carry two encryption layers (kind:1059 → kind:13 → rumor),
        // and MIP-02 requires both: the Welcome rumor is sealed by the
        // inviter. A wrap whose inner event is not a seal carries a Welcome
        // nobody signed for, so it is refused here rather than read as one
        // (Quartz's unwrapAndUnsealOrNull handed such an inner event back
        // as-is). The rumor must claim the seal's author (NIP-59's
        // impersonation rule). The seal's signature is not checked here: its
        // author is proven by its NIP-44 encryption (only that key and ours
        // derive the conversation key), and the app verifies the seal itself
        // when it stores it (Amethyst's LocalCache skips one it already holds).
        val seal = wrap.unwrapOrNull(signer) ?: return MarmotIngestResult.Ignored("gift wrap is not for us")
        if (seal !is SealEvent) return MarmotIngestResult.Ignored("gift wrap does not carry a seal")
        val unsealed =
            try {
                seal.unsealRumorThrowing(signer)
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                return MarmotIngestResult.Ignored("gift wrap's seal does not open")
            }
        if (unsealed.pubKey != null && unsealed.pubKey != seal.pubKey) {
            return MarmotIngestResult.Ignored("gift wrap's rumor claims another author than its seal")
        }
        val rumor = seal.unsealed(unsealed)
        if (!MarmotInboundProcessor.isWelcomeEvent(rumor) || rumor !is WelcomeEvent) {
            return MarmotIngestResult.Ignored("gift wrap does not carry a Welcome")
        }
        joinFromWelcome(rumor)
    } catch (e: Exception) {
        currentCoroutineContext().ensureActive()
        MarmotIngestResult.Failure("giftwrap unwrap failed: ${e.message}", e)
    }

@OptIn(ExperimentalEncodingApi::class)
private suspend fun MarmotManager.joinFromWelcome(welcome: WelcomeEvent): MarmotIngestResult {
    // A Welcome for the KeyPackage a confirmed link reserved joins only as that link's
    // (`device-group.md` "Joining"); any other is refused and leaves the KeyPackage for the real one.
    deviceGroups?.let { dg ->
        if (dg.isReservedForLink(welcome.keyPackageEventId())) {
            return try {
                MarmotIngestResult.JoinedGroup(dg.joinLinkWelcome(Base64.decode(welcome.welcomeBase64())), needsKeyPackageRotation = true)
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                MarmotIngestResult.Failure("not the link's Welcome: ${e.message}", e)
            }
        }
    }
    return joinFromOrdinaryWelcome(welcome)
}

private suspend fun MarmotManager.joinFromOrdinaryWelcome(welcome: WelcomeEvent): MarmotIngestResult =
    when (val result = processWelcome(welcome, welcome.nostrGroupId())) {
        is WelcomeResult.Joined -> {
            // Establish the baseline for this group's system rows without
            // writing any: a joiner announcing every existing member as
            // newly added would be a timeline full of events that never
            // happened. Without it the first commit after joining becomes the
            // baseline instead, and the change it made is never shown.
            recordRetentionForCurrentEpoch(result.nostrGroupId)
            syncGroupSystemRows(result.nostrGroupId)
            MarmotIngestResult.JoinedGroup(
                nostrGroupId = result.nostrGroupId,
                needsKeyPackageRotation = result.needsKeyPackageRotation,
            )
        }

        is WelcomeResult.AlreadyJoined -> {
            MarmotIngestResult.AlreadyInGroup(result.nostrGroupId)
        }

        is WelcomeResult.Error -> {
            MarmotIngestResult.Failure(result.message, result.cause)
        }
    }

private suspend fun MarmotManager.ingestGroupEvent(ge: GroupEvent): MarmotIngestResult {
    // An application message this device sent: its echo can never decrypt here (see buildGroupMessage).
    // (Before 3.4 own echoes were kept with the terminal ingest markers; those still count.)
    if (isOwnEcho(ge.id) || isTerminallyIngested(ge.id)) return MarmotIngestResult.Ignored("own message")
    val result = ingestGroupEventUnrefreshed(ge)
    // A device-group Commit, applied directly or by a convergence pass, may change the roster.
    deviceGroups?.refresh()
    return result
}

private suspend fun MarmotManager.ingestGroupEventUnrefreshed(ge: GroupEvent): MarmotIngestResult =
    when (val result = processGroupEvent(ge)) {
        // An older client's kind-1200 stream start. The live preview it
        // announced is retired: it is not displayed, and its endpoint
        // candidates are never contacted (`agent-text-stream-quic-v1.md`,
        // "Receiving from older clients"). A kind 9 carrying stream tags is
        // not caught here: it is an ordinary chat message.
        is GroupEventResult.ApplicationMessage -> {
            val deviceGroups = deviceGroups
            if (deviceGroups != null && deviceGroups.isTrustedDeviceGroup(result.groupId)) {
                // The device group is not a chat: its traffic goes to the device-group flows and is
                // never stored or surfaced as a message (`device-group.md` "Keeping it out of sight").
                deviceGroups.onAppEvent(result.groupId, result.innerEventJson, result.senderLeafIndex, result.epoch)
                MarmotIngestResult.Ignored("device-group traffic")
            } else if (isRetiredStreamStart(result.innerEvent)) {
                MarmotIngestResult.Ignored("retired agent text stream start")
            } else if (isDeviceGroupTraffic(result.innerEvent)) {
                // `features/device-group.md`: these kinds are read only in the device group the device
                // trusts and ignored in every other group, so no chat projects one.
                MarmotIngestResult.Ignored("device-group kind outside a trusted device group")
            } else {
                // MLS ratchets once we decrypt; future reads of the same ciphertext
                // would fail — persist the plaintext now so restarts/replays see it.
                persistDecryptedMessage(result.groupId, result.innerEventJson, result.innerEvent, result.epoch)
                // Traffic is the natural clock for expiry: a group that is being
                // read is a group whose expired messages should already be gone.
                pruneExpiredMessagesIfDue(result.groupId)
                MarmotIngestResult.Message(result)
            }
        }

        is GroupEventResult.CommitProcessed -> {
            // The epoch just advanced, so whatever this commit changed about
            // the group is now canonical state — which is exactly what a
            // kind:1210 row is derived from. Deriving here rather than at
            // render time means the rows land in the same log as the messages
            // they sit between, in the order they happened.
            recordRetentionForCurrentEpoch(result.groupId)
            syncGroupSystemRows(result.groupId)
            MarmotIngestResult.Commit(result)
        }

        is GroupEventResult.ProposalStaged -> {
            MarmotIngestResult.ProposalStaged(result.groupId, result.senderLeafIndex)
        }

        is GroupEventResult.Duplicate -> MarmotIngestResult.Ignored("already merged")

        // Held, not dropped: a commit we cannot advance onto linearly is
        // candidate material for a convergence pass that has to settle before
        // it can be applied. Saying so matters — this is the one Ignored that
        // means "come back", and a client that never settles repeats it
        // forever while looking idle.
        is GroupEventResult.CommitPending -> MarmotIngestResult.Ignored("commit held for convergence")

        // Decrypted only on a losing branch: real protocol input (it may have
        // witnessed for that branch), but never application output.
        is GroupEventResult.AppMessageOnCandidateBranch ->
            MarmotIngestResult.Ignored("app message on a candidate branch")

        // Disbanded or locally unrecoverable — refused before decryption, so
        // there is nothing to deliver and nothing to retain.
        is GroupEventResult.RefusedByLifecycle ->
            MarmotIngestResult.Ignored("refused by lifecycle ${result.lifecycle}")

        is GroupEventResult.UndecryptableOuterLayer -> {
            MarmotIngestResult.UndecryptableOuter(result.groupId, result.retainedEpochCount)
        }

        is GroupEventResult.Error -> {
            MarmotIngestResult.Failure(result.message, result.cause)
        }
    }

private fun isRetiredStreamStart(inner: Event?): Boolean = inner?.kind?.let(AgentTextStreamRetirement::isStreamStart) == true

/** Whether a decrypted inner event is a device-group app event (`MarmotDeviceGroupKinds`). */
private fun isDeviceGroupTraffic(inner: Event?): Boolean = inner?.let { MarmotDeviceGroupKinds.isDeviceGroupKind(it.kind) } ?: false
