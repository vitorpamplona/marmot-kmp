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

/** The timers and limits of `features/device-pairing.md` (MDK `marmot-pairing/src/session.rs`). */
object PairingLimits {
    /** A request with no answer taken lives this long. */
    const val REQUEST_TTL_SECS = 600L

    /** A session with an answer lives this long after the answer. */
    const val SESSION_TTL_SECS = 600L

    /** An existing device ignores a request dated further ahead than this. */
    const val REQUEST_MAX_FUTURE_SECS = 300L

    /** At most this many Answers in any [ANSWER_WINDOW_SECS] window. */
    const val MAX_ANSWERS_PER_WINDOW = 10
    const val ANSWER_WINDOW_SECS = 3600L

    /** Requests an existing device tracks; one beyond still counts as live. */
    const val MAX_TRACKED_REQUESTS = 32
}

/**
 * The outcome both sides hold once the link is confirmed: the new device's exact KeyPackage, the
 * group it joins and the signature key of the existing device's leaf there. Not a secret: the new
 * device keeps it across restarts until its Welcome wait ends (`device-group.md` "Joining").
 */
data class ConfirmedLink(
    val sessionId: HexKey,
    val keyPackageEventId: HexKey,
    val keyPackageRef: HexKey,
    val deviceGroupId: HexKey,
    val welcomeSenderKey: HexKey,
    val existingDeviceSlot: HexKey,
) {
    /** Whether a Welcome into [groupId], whose GroupInfo signer leaf has [senderSignatureKey], is this link's. */
    fun allowsWelcomeFor(
        groupId: HexKey,
        senderSignatureKey: HexKey,
    ): Boolean = deviceGroupId == groupId && welcomeSenderKey == senderSignatureKey
}

/** Why a session ended. [outgoingCancel] is the Cancel this side owes the other, if any. */
sealed class PairingEndReason {
    data class Cancelled(
        val reason: CancelReason,
    ) : PairingEndReason()

    data object UserCancelled : PairingEndReason()

    data object MismatchedCode : PairingEndReason()

    data object MismatchedCommitment : PairingEndReason()

    data object MismatchedConfirm : PairingEndReason()

    /** The other side's key made a zero shared secret. */
    data object InvalidKey : PairingEndReason()

    data object Timeout : PairingEndReason()

    /** The new device took another device's answer. Nothing is sent. */
    data object AnsweredElsewhere : PairingEndReason()

    val outgoingCancel: CancelReason?
        get() =
            when (this) {
                is Cancelled, AnsweredElsewhere -> null
                UserCancelled -> CancelReason.USER
                MismatchedCode -> CancelReason.MISMATCHED_CODE
                MismatchedCommitment -> CancelReason.MISMATCHED_COMMITMENT
                MismatchedConfirm -> CancelReason.MISMATCHED_CONFIRM
                InvalidKey -> CancelReason.UNEXPECTED_MESSAGE
                Timeout -> CancelReason.TIMEOUT
            }
}

/** Why a received message changed nothing. */
enum class PairingIgnoreReason {
    OTHER_SESSION,
    OWN_ROLE,
    WRONG_STEP,
    ENDED,
    DUPLICATE,
    STALE,
    CAPACITY,
}

enum class PairingError {
    UNKNOWN_SESSION,
    WRONG_STEP,
    EXPIRED,
    COMPETING_REQUESTS,
    RATE_LIMITED,
    KEY_PACKAGE_MISMATCH,
    INVALID_GROUP_ID,
}

class PairingException(
    val error: PairingError,
    /** For [PairingError.RATE_LIMITED]: when the next Answer may go out. */
    val retryAt: Long? = null,
) : IllegalStateException("pairing: $error")
