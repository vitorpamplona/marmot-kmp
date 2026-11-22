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
package com.vitorpamplona.marmot.features.devicePairing

import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * An existing device's side of pairing, for every session it sees (`features/device-pairing.md`
 * "Existing device", "Competing requests", "Rate limit", "Expiry"; MDK
 * `marmot-pairing/src/existing_device.rs`). One per device: every existing device sees every Request.
 *
 * It answers only when exactly one request is live and it has sent fewer than ten Answers in the last
 * hour, never confirms while two requests are live, and checks the new device's commitment before
 * showing a code. Whether this device WOULD link the KeyPackage (its roster, capacity, rejected slots)
 * is the caller's decision before [answer] (`device-group.md` "Before answering"); the caller also
 * fetches and validates the publication the Request names and passes what it decoded.
 */
class ExistingDevicePairing(
    private val account: HexKey,
    private val slot: HexKey,
) {
    /** The KeyPackage publication the caller fetched for a request: its event id and decoded ref. */
    data class PublishedKeyPackage(
        val eventId: HexKey,
        val keyPackageRef: HexKey,
    )

    private sealed class State {
        data object Requested : State()

        class Answered(
            val privateKey: ByteArray,
            val publicKey: ByteArray,
        ) : State()

        class Comparing(
            val shared: ByteArray,
            val sasBytes: ByteArray,
            var deviceGroup: Pair<HexKey, HexKey>? = null,
        ) : State()

        class Linked(
            val link: ConfirmedLink,
        ) : State()

        class Ended(
            val reason: PairingEndReason,
        ) : State()
    }

    private class Tracked(
        val request: PairingMessage.Request,
        var deadline: Long,
        var keepUntil: Long,
        var state: State,
    ) {
        fun isLive(now: Long) = now < deadline && (state is State.Requested || state is State.Answered || state is State.Comparing)

        fun binding(account: HexKey) = PairingCrypto.RequestBinding(request.sessionId, account, request.keyPackageEventId, request.keyPackageRef)

        fun moveTo(next: State) {
            when (val s = state) {
                is State.Answered -> s.privateKey.fill(0)
                is State.Comparing ->
                    if (next !is State.Comparing) {
                        s.shared.fill(0)
                        s.sasBytes.fill(0)
                    }
                else -> {}
            }
            state = next
        }
    }

    private val sessions = LinkedHashMap<HexKey, Tracked>()
    private var untrackedLiveUntil = 0L
    private val answeredAt = ArrayDeque<Long>()
    private val owedCancels = ArrayDeque<PairingMessage.Cancel>()

    sealed class Event {
        data class Ignored(
            val reason: PairingIgnoreReason,
        ) : Event()

        /** A new request: ask the user (unless [competing]: then offer nothing). */
        data class Requested(
            val sessionId: HexKey,
            val competing: Boolean,
        ) : Event()

        /** The new device took this device's answer; the code is ready. */
        data class CodeReady(
            val sessionId: HexKey,
        ) : Event()

        /** The new device's Confirm verified: add exactly [link]'s KeyPackage, from [link]'s leaf. */
        data class Linked(
            val link: ConfirmedLink,
        ) : Event()

        data class Ended(
            val sessionId: HexKey,
            val reason: PairingEndReason,
            val cancel: PairingMessage.Cancel?,
        ) : Event()
    }

    data class LiveRequest(
        val sessionId: HexKey,
        val keyPackageEventId: HexKey,
        val keyPackageRef: HexKey,
        val answered: Boolean,
    )

    fun competingRequests(now: Long): Boolean = liveCount(now) > 1

    fun liveRequests(now: Long): List<LiveRequest> = sessions.values.filter { it.isLive(now) }.map { LiveRequest(it.request.sessionId, it.request.keyPackageEventId, it.request.keyPackageRef, it.state !is State.Requested) }

    /** The seven emoji while this session's code is to be shown. */
    fun code(
        sessionId: HexKey,
        now: Long,
    ): List<SasEmoji>? {
        val t = sessions[sessionId] ?: return null
        val c = t.state as? State.Comparing ?: return null
        return if (c.deviceGroup == null && t.isLive(now)) SasEmoji.of(c.sasBytes) else null
    }

    /** Whether to show Link now: undecided, live, and no other request live. */
    fun canOfferLink(
        sessionId: HexKey,
        now: Long,
    ): Boolean {
        val t = sessions[sessionId] ?: return false
        val undecided = (t.state as? State.Comparing)?.deviceGroup == null && t.state is State.Comparing
        return undecided && t.isLive(now) && liveCount(now) == 1
    }

    fun linked(sessionId: HexKey): ConfirmedLink? = (sessions[sessionId]?.state as? State.Linked)?.link

    fun endReason(sessionId: HexKey): PairingEndReason? = (sessions[sessionId]?.state as? State.Ended)?.reason

    /** Sessions still holding key material (for tests). */
    fun sessionsHoldingSecrets(): Int = sessions.values.count { it.state is State.Answered || it.state is State.Comparing }

    /** [createdAt] is the rumor's `created_at`. */
    fun receive(
        message: PairingMessage,
        createdAt: Long,
        now: Long,
    ): Event {
        val timedOut = tick(now)
        if (message is PairingMessage.Request) return onRequest(message, createdAt, now)
        val sessionId = message.sessionId
        if (sessionId in timedOut) return Event.Ended(sessionId, PairingEndReason.Timeout, takeOwedCancel(sessionId))
        val tracked = sessions[sessionId] ?: return Event.Ignored(PairingIgnoreReason.OTHER_SESSION)
        when (tracked.state) {
            is State.Ended -> return Event.Ignored(PairingIgnoreReason.ENDED)
            // An existing device that confirmed the link ignores a later Cancel.
            is State.Linked -> return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
            else -> {}
        }
        return when (message) {
            is PairingMessage.Request -> error("handled above")
            is PairingMessage.Answer -> Event.Ignored(PairingIgnoreReason.OWN_ROLE)
            is PairingMessage.Reveal -> onReveal(tracked, message)
            is PairingMessage.Confirm -> onConfirm(tracked, message)
            is PairingMessage.Cancel -> {
                val reason = PairingEndReason.Cancelled(message.reason)
                tracked.moveTo(State.Ended(reason))
                Event.Ended(sessionId, reason, null)
            }
        }
    }

    private fun onRequest(
        request: PairingMessage.Request,
        createdAt: Long,
        now: Long,
    ): Event {
        if (sessions.containsKey(request.sessionId)) return Event.Ignored(PairingIgnoreReason.DUPLICATE)
        val stale = createdAt + PairingLimits.REQUEST_TTL_SECS <= now || createdAt > now + PairingLimits.REQUEST_MAX_FUTURE_SECS
        if (stale) return Event.Ignored(PairingIgnoreReason.STALE)
        if (sessions.size >= PairingLimits.MAX_TRACKED_REQUESTS) {
            untrackedLiveUntil = maxOf(untrackedLiveUntil, minOf(createdAt, now) + PairingLimits.REQUEST_TTL_SECS)
            return Event.Ignored(PairingIgnoreReason.CAPACITY)
        }
        sessions[request.sessionId] =
            Tracked(
                request = request,
                deadline = minOf(createdAt, now) + PairingLimits.REQUEST_TTL_SECS,
                keepUntil = maxOf(createdAt, now) + PairingLimits.REQUEST_TTL_SECS,
                state = State.Requested,
            )
        return Event.Requested(request.sessionId, competingRequests(now))
    }

    /**
     * Answers a request whose publication the caller fetched and validated as [keyPackage]. Throws
     * [PairingException] for a competing request, the rate limit, a mismatching KeyPackage or a session
     * past this step. Send the returned Answer.
     */
    fun answer(
        sessionId: HexKey,
        keyPackage: PublishedKeyPackage,
        now: Long,
    ): PairingMessage.Answer {
        val (privateKey, publicKey) = PairingCrypto.ephemeralKey()
        return answerWithKey(sessionId, keyPackage, privateKey, publicKey, now)
    }

    /** [answer] with a fixed X25519 private key, to reproduce a vector. */
    fun answerPinned(
        sessionId: HexKey,
        keyPackage: PublishedKeyPackage,
        privateKey: ByteArray,
        now: Long,
    ): PairingMessage.Answer = answerWithKey(sessionId, keyPackage, privateKey.copyOf(), PairingCrypto.publicKey(privateKey), now)

    private fun answerWithKey(
        sessionId: HexKey,
        keyPackage: PublishedKeyPackage,
        privateKey: ByteArray,
        publicKey: ByteArray,
        now: Long,
    ): PairingMessage.Answer {
        if (sessionId in tick(now)) throw PairingException(PairingError.EXPIRED)
        val competing = competingRequests(now)
        val retryAt = rateLimitedUntil(now)
        val tracked = sessions[sessionId] ?: throw PairingException(PairingError.UNKNOWN_SESSION)
        if (tracked.state !is State.Requested) throw PairingException(PairingError.WRONG_STEP)
        if (competing) throw PairingException(PairingError.COMPETING_REQUESTS)
        if (retryAt != null) throw PairingException(PairingError.RATE_LIMITED, retryAt)
        if (keyPackage.eventId != tracked.request.keyPackageEventId || keyPackage.keyPackageRef != tracked.request.keyPackageRef) {
            throw PairingException(PairingError.KEY_PACKAGE_MISMATCH)
        }
        tracked.moveTo(State.Answered(privateKey, publicKey))
        tracked.deadline = now + PairingLimits.SESSION_TTL_SECS
        tracked.keepUntil = maxOf(tracked.keepUntil, tracked.deadline)
        answeredAt.addLast(now)
        return PairingMessage.Answer(sessionId, slot, publicKey.toHexKey())
    }

    private fun onReveal(
        tracked: Tracked,
        reveal: PairingMessage.Reveal,
    ): Event {
        val sessionId = reveal.sessionId
        if (tracked.state is State.Comparing) return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        // The new device took another answer: end the session, answered or not, and send nothing.
        if (reveal.answerSlot != slot) return endTracked(tracked, PairingEndReason.AnsweredElsewhere)
        val answered = tracked.state as? State.Answered ?: return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        val binding = tracked.binding(account)
        val revealedKey = reveal.key.hexToByteArray()
        if (PairingCrypto.commitment(revealedKey, binding).toHexKey() != tracked.request.commitment) {
            return endTracked(tracked, PairingEndReason.MismatchedCommitment)
        }
        val shared = PairingCrypto.agree(answered.privateKey, revealedKey) ?: return endTracked(tracked, PairingEndReason.InvalidKey)
        val info = PairingCrypto.sasInfo(binding, slot, revealedKey, answered.publicKey)
        tracked.moveTo(State.Comparing(shared, PairingCrypto.sasBytes(shared, info)))
        return Event.CodeReady(sessionId)
    }

    private fun onConfirm(
        tracked: Tracked,
        confirm: PairingMessage.Confirm,
    ): Event {
        if (confirm.fromExistingDevice) return Event.Ignored(PairingIgnoreReason.OWN_ROLE)
        val comparing = tracked.state as? State.Comparing ?: return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        // A new device's Confirm before this device sent its own is ignored.
        val group = comparing.deviceGroup ?: return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        val expected =
            PairingCrypto.mac(
                comparing.shared,
                PairingCrypto.macInfo(tracked.binding(account), slot, PairingCrypto.SENDER_NEW_DEVICE, PairingCrypto.ITEM_KEY_PACKAGE_REF),
                tracked.request.keyPackageRef.hexToByteArray(),
            )
        if (!PairingCrypto.macMatches(expected, confirm.mac.hexToByteArray())) return endTracked(tracked, PairingEndReason.MismatchedConfirm)
        val link = ConfirmedLink(tracked.request.sessionId, tracked.request.keyPackageEventId, tracked.request.keyPackageRef, group.first, group.second, slot)
        tracked.moveTo(State.Linked(link))
        return Event.Linked(link)
    }

    /**
     * The user says the codes match: send the returned Confirm naming [deviceGroupId] (the group this
     * device will add the new device to, existing or about to be created) and [signatureKey] (its own
     * leaf's signature key there, kept through the adding Commit).
     */
    fun confirmLink(
        sessionId: HexKey,
        deviceGroupId: HexKey,
        signatureKey: HexKey,
        now: Long,
    ): PairingMessage.Confirm {
        val competing = competingRequests(now)
        val tracked = liveComparing(sessionId, now)
        val groupBytes = deviceGroupId.length / 2
        if (deviceGroupId.length % 2 != 0 || groupBytes !in 1..PairingMessage.GROUP_ID_MAX_BYTES) throw PairingException(PairingError.INVALID_GROUP_ID)
        val comparing = tracked.state as State.Comparing
        if (comparing.deviceGroup != null) throw PairingException(PairingError.WRONG_STEP)
        if (competing) throw PairingException(PairingError.COMPETING_REQUESTS)
        val mac =
            PairingCrypto.mac(
                comparing.shared,
                PairingCrypto.macInfo(tracked.binding(account), slot, PairingCrypto.SENDER_EXISTING_DEVICE, PairingCrypto.ITEM_DEVICE_GROUP),
                PairingCrypto.deviceGroupValue(deviceGroupId.hexToByteArray(), signatureKey.hexToByteArray()),
            )
        comparing.deviceGroup = deviceGroupId to signatureKey
        return PairingMessage.Confirm(sessionId, true, deviceGroupId, signatureKey, mac.toHexKey())
    }

    /** The user says the codes differ: send the returned Cancel. */
    fun rejectLink(
        sessionId: HexKey,
        now: Long,
    ): PairingMessage.Cancel {
        val tracked = liveComparing(sessionId, now)
        if ((tracked.state as State.Comparing).deviceGroup != null) throw PairingException(PairingError.WRONG_STEP)
        tracked.moveTo(State.Ended(PairingEndReason.MismatchedCode))
        return PairingMessage.Cancel(sessionId, CancelReason.MISMATCHED_CODE)
    }

    /** The user dismisses the request: a Cancel to send if this device had answered. */
    fun cancel(sessionId: HexKey): PairingMessage.Cancel? {
        val tracked = sessions[sessionId] ?: return null
        val answered =
            when (tracked.state) {
                State.Requested -> false
                is State.Answered, is State.Comparing -> true
                else -> return null
            }
        tracked.moveTo(State.Ended(PairingEndReason.UserCancelled))
        return if (answered) PairingMessage.Cancel(sessionId, CancelReason.USER) else null
    }

    /** Call on a timer: ends expired sessions and returns the Cancels they owe. */
    fun expire(now: Long): List<PairingMessage.Cancel> {
        tick(now)
        return owedCancels.toList().also { owedCancels.clear() }
    }

    private fun liveComparing(
        sessionId: HexKey,
        now: Long,
    ): Tracked {
        if (sessionId in tick(now)) throw PairingException(PairingError.EXPIRED)
        val tracked = sessions[sessionId] ?: throw PairingException(PairingError.UNKNOWN_SESSION)
        if (tracked.state !is State.Comparing) throw PairingException(PairingError.WRONG_STEP)
        return tracked
    }

    private fun liveCount(now: Long): Int = sessions.values.count { it.isLive(now) } + if (now < untrackedLiveUntil) 1 else 0

    private fun rateLimitedUntil(now: Long): Long? = if (answeredAt.size >= PairingLimits.MAX_ANSWERS_PER_WINDOW) maxOf(answeredAt.first() + PairingLimits.ANSWER_WINDOW_SECS, now) else null

    private fun tick(now: Long): Set<HexKey> {
        while (answeredAt.isNotEmpty() && answeredAt.first() + PairingLimits.ANSWER_WINDOW_SECS <= now) answeredAt.removeFirst()
        val timedOut = HashSet<HexKey>()
        for ((sessionId, tracked) in sessions) {
            val answered =
                when (tracked.state) {
                    State.Requested -> false
                    is State.Answered, is State.Comparing -> true
                    else -> continue
                }
            if (now < tracked.deadline) continue
            tracked.moveTo(State.Ended(PairingEndReason.Timeout))
            if (answered) {
                if (owedCancels.size == PairingLimits.MAX_TRACKED_REQUESTS) owedCancels.removeFirst()
                owedCancels.addLast(PairingMessage.Cancel(sessionId, CancelReason.TIMEOUT))
            }
            timedOut.add(sessionId)
        }
        sessions.entries.removeAll { now >= it.value.keepUntil }
        return timedOut
    }

    private fun takeOwedCancel(sessionId: HexKey): PairingMessage.Cancel? {
        val index = owedCancels.indexOfFirst { it.sessionId == sessionId }
        return if (index < 0) null else owedCancels.removeAt(index)
    }

    private fun endTracked(
        tracked: Tracked,
        reason: PairingEndReason,
    ): Event {
        tracked.moveTo(State.Ended(reason))
        return Event.Ended(tracked.request.sessionId, reason, reason.outgoingCancel?.let { PairingMessage.Cancel(tracked.request.sessionId, it) })
    }
}
