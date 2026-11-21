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
 * The new device's side of one pairing session (`features/device-pairing.md` "New device"; MDK
 * `marmot-pairing/src/new_device.rs`). It commits to its key in the Request, takes the first Answer,
 * reveals its key, shows the code, and sends its own Confirm only once its user confirmed AND the
 * existing device's Confirm verified. Transport-neutral and clock-free: the caller hands in messages
 * and `now` (Unix seconds) and sends what comes back.
 *
 * The private key, shared secret, code and MAC keys live only in this object, are never persisted, and
 * are wiped when the session ends. The [ConfirmedLink] it ends with is what the caller persists.
 */
class NewDevicePairing private constructor(
    private val request: PairingCrypto.RequestBinding,
    privateKey: ByteArray,
    private val publicKey: ByteArray,
    now: Long,
) {
    private sealed class State {
        class AwaitingAnswer(
            val privateKey: ByteArray,
            val deadline: Long,
        ) : State()

        class Comparing(
            val existingDeviceSlot: HexKey,
            val shared: ByteArray,
            val sasBytes: ByteArray,
            val deadline: Long,
            var userConfirmed: Boolean = false,
            var deviceGroup: Pair<HexKey, HexKey>? = null,
        ) : State()

        class Linked(
            val link: ConfirmedLink,
        ) : State()

        class Ended(
            val reason: PairingEndReason,
        ) : State()
    }

    private var state: State = State.AwaitingAnswer(privateKey, now + PairingLimits.REQUEST_TTL_SECS)
    private var owedCancel: PairingMessage.Cancel? = null

    /** The Request to send. */
    val requestMessage: PairingMessage.Request =
        PairingMessage.Request(request.sessionId, request.keyPackageEventId, request.keyPackageRef, PairingCrypto.commitment(publicKey, request).toHexKey())

    val sessionId: HexKey get() = request.sessionId

    /** What a received message did. */
    sealed class Event {
        data class Ignored(
            val reason: PairingIgnoreReason,
        ) : Event()

        /** Send [reveal]; the code is now on screen. */
        data class Reveal(
            val reveal: PairingMessage.Reveal,
        ) : Event()

        /** The existing device confirmed; waiting for this user. */
        data object PeerConfirmed : Event()

        /** Send [confirm]: the link is confirmed. */
        data class Linked(
            val confirm: PairingMessage.Confirm,
            val link: ConfirmedLink,
        ) : Event()

        data class Ended(
            val reason: PairingEndReason,
            val cancel: PairingMessage.Cancel?,
        ) : Event()
    }

    /** The seven emoji while the code is to be shown: answered, undecided and not expired. */
    fun code(now: Long): List<SasEmoji>? = (state as? State.Comparing)?.takeIf { !it.userConfirmed && now < it.deadline }?.let { SasEmoji.of(it.sasBytes) }

    fun existingDeviceSlot(): HexKey? =
        when (val s = state) {
            is State.Comparing -> s.existingDeviceSlot
            is State.Linked -> s.link.existingDeviceSlot
            else -> null
        }

    fun linked(): ConfirmedLink? = (state as? State.Linked)?.link

    fun endReason(): PairingEndReason? = (state as? State.Ended)?.reason

    /** Whether the session still holds key material (for tests: it must not after it ends). */
    fun holdsSecrets(): Boolean = state is State.AwaitingAnswer || state is State.Comparing

    fun receive(
        message: PairingMessage,
        now: Long,
    ): Event {
        val timedOut = tick(now)
        if (message.sessionId != sessionId) return Event.Ignored(PairingIgnoreReason.OTHER_SESSION)
        if (timedOut) return Event.Ended(PairingEndReason.Timeout, owedCancel.also { owedCancel = null })
        when (state) {
            is State.Ended -> return Event.Ignored(PairingIgnoreReason.ENDED)
            is State.Linked -> if (message !is PairingMessage.Cancel) return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
            else -> {}
        }
        return when (message) {
            is PairingMessage.Request, is PairingMessage.Reveal -> Event.Ignored(PairingIgnoreReason.OWN_ROLE)
            is PairingMessage.Answer -> onAnswer(message, now)
            is PairingMessage.Confirm -> onConfirm(message)
            is PairingMessage.Cancel -> {
                // A Cancel ends the session and, before its Welcome joined, the confirmed link too.
                val reason = PairingEndReason.Cancelled(message.reason)
                transition(State.Ended(reason))
                Event.Ended(reason, null)
            }
        }
    }

    private fun onAnswer(
        answer: PairingMessage.Answer,
        now: Long,
    ): Event {
        val awaiting = state as? State.AwaitingAnswer ?: return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        val shared = PairingCrypto.agree(awaiting.privateKey, answer.key.hexToByteArray()) ?: return end(PairingEndReason.InvalidKey)
        val info = PairingCrypto.sasInfo(request, answer.slot, publicKey, answer.key.hexToByteArray())
        transition(State.Comparing(answer.slot, shared, PairingCrypto.sasBytes(shared, info), now + PairingLimits.SESSION_TTL_SECS))
        return Event.Reveal(PairingMessage.Reveal(sessionId, answer.slot, publicKey.toHexKey()))
    }

    private fun onConfirm(confirm: PairingMessage.Confirm): Event {
        if (!confirm.fromExistingDevice) return Event.Ignored(PairingIgnoreReason.OWN_ROLE)
        val comparing = state as? State.Comparing ?: return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        if (comparing.deviceGroup != null) return Event.Ignored(PairingIgnoreReason.WRONG_STEP)
        val group = confirm.deviceGroup!!
        val key = confirm.signatureKey!!
        val expected =
            PairingCrypto.mac(
                comparing.shared,
                PairingCrypto.macInfo(request, comparing.existingDeviceSlot, PairingCrypto.SENDER_EXISTING_DEVICE, PairingCrypto.ITEM_DEVICE_GROUP),
                PairingCrypto.deviceGroupValue(group.hexToByteArray(), key.hexToByteArray()),
            )
        if (!PairingCrypto.macMatches(expected, confirm.mac.hexToByteArray())) return end(PairingEndReason.MismatchedConfirm)
        comparing.deviceGroup = group to key
        return if (comparing.userConfirmed) confirmAndLink().let { Event.Linked(it.first, it.second) } else Event.PeerConfirmed
    }

    /** What [confirmMatch] did. */
    sealed class Confirmation {
        /** The existing device has not confirmed yet; its Confirm will link. */
        data object Waiting : Confirmation()

        data class Linked(
            val confirm: PairingMessage.Confirm,
            val link: ConfirmedLink,
        ) : Confirmation()
    }

    /** The user says the codes match. */
    fun confirmMatch(now: Long): Confirmation {
        val comparing = liveComparing(now)
        if (comparing.userConfirmed) throw PairingException(PairingError.WRONG_STEP)
        comparing.userConfirmed = true
        if (comparing.deviceGroup == null) return Confirmation.Waiting
        val (confirm, link) = confirmAndLink()
        return Confirmation.Linked(confirm, link)
    }

    /** The user says the codes differ: send the returned Cancel. */
    fun rejectMatch(now: Long): PairingMessage.Cancel {
        val comparing = liveComparing(now)
        if (comparing.userConfirmed) throw PairingException(PairingError.WRONG_STEP)
        transition(State.Ended(PairingEndReason.MismatchedCode))
        return cancelMessage(PairingEndReason.MismatchedCode)
    }

    /** The user gives up before a link: send the returned Cancel, if any. */
    fun cancel(): PairingMessage.Cancel? =
        when (state) {
            is State.AwaitingAnswer, is State.Comparing -> {
                transition(State.Ended(PairingEndReason.UserCancelled))
                cancelMessage(PairingEndReason.UserCancelled)
            }
            else -> null
        }

    /** Call on a timer: ends an expired session and returns the Cancel it owes. */
    fun expire(now: Long): PairingMessage.Cancel? {
        tick(now)
        return owedCancel.also { owedCancel = null }
    }

    private fun tick(now: Long): Boolean {
        val deadline =
            when (val s = state) {
                is State.AwaitingAnswer -> s.deadline
                is State.Comparing -> s.deadline
                else -> return false
            }
        if (now < deadline) return false
        transition(State.Ended(PairingEndReason.Timeout))
        owedCancel = cancelMessage(PairingEndReason.Timeout)
        return true
    }

    private fun liveComparing(now: Long): State.Comparing {
        if (tick(now)) throw PairingException(PairingError.EXPIRED)
        return state as? State.Comparing ?: throw PairingException(PairingError.WRONG_STEP)
    }

    private fun confirmAndLink(): Pair<PairingMessage.Confirm, ConfirmedLink> {
        val comparing = state as State.Comparing
        val mac =
            PairingCrypto.mac(
                comparing.shared,
                PairingCrypto.macInfo(request, comparing.existingDeviceSlot, PairingCrypto.SENDER_NEW_DEVICE, PairingCrypto.ITEM_KEY_PACKAGE_REF),
                request.keyPackageRef.hexToByteArray(),
            )
        val (group, key) = comparing.deviceGroup!!
        val link = ConfirmedLink(sessionId, request.keyPackageEventId, request.keyPackageRef, group, key, comparing.existingDeviceSlot)
        transition(State.Linked(link))
        return PairingMessage.Confirm(sessionId, false, null, null, mac.toHexKey()) to link
    }

    private fun end(reason: PairingEndReason): Event {
        transition(State.Ended(reason))
        return Event.Ended(reason, reason.outgoingCancel?.let { cancelMessage(reason) })
    }

    private fun cancelMessage(reason: PairingEndReason) = PairingMessage.Cancel(sessionId, reason.outgoingCancel!!)

    /** Moves to [next], wiping the secrets of the state it leaves. */
    private fun transition(next: State) {
        when (val s = state) {
            is State.AwaitingAnswer -> if (next !is State.AwaitingAnswer) s.privateKey.fill(0)
            is State.Comparing ->
                if (next !is State.Comparing) {
                    s.shared.fill(0)
                    s.sasBytes.fill(0)
                }
            else -> {}
        }
        state = next
    }

    companion object {
        /**
         * Starts a session for this device's published KeyPackage ([keyPackageEventId], whose
         * `KeyPackageRef` is [keyPackageRef]) of [account] (hex x-only). Send [requestMessage].
         */
        fun start(
            account: HexKey,
            keyPackageEventId: HexKey,
            keyPackageRef: HexKey,
            now: Long,
        ): NewDevicePairing {
            val (privateKey, publicKey) = PairingCrypto.ephemeralKey()
            return NewDevicePairing(PairingCrypto.RequestBinding(PairingCrypto.randomSessionId(), account, keyPackageEventId, keyPackageRef), privateKey, publicKey, now)
        }

        /** [start] with a fixed session id and X25519 private key, to reproduce a vector. */
        fun startPinned(
            sessionId: HexKey,
            privateKey: ByteArray,
            account: HexKey,
            keyPackageEventId: HexKey,
            keyPackageRef: HexKey,
            now: Long,
        ): NewDevicePairing = NewDevicePairing(PairingCrypto.RequestBinding(sessionId, account, keyPackageEventId, keyPackageRef), privateKey.copyOf(), PairingCrypto.publicKey(privateKey), now)
    }
}
