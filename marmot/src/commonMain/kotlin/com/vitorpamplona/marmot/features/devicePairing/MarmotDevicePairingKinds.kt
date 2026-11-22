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

/**
 * The rumor kinds of Marmot device pairing (`features/device-pairing.md`,
 * draft; MDK's `marmot-pairing` crate): each message is an unsigned rumor a
 * device gift-wraps (NIP-59) to its OWN account, to link a new device to the
 * account's others.
 *
 * Named here, beside the rest of the binding, so every client that does not
 * link devices recognises the same kinds as pairing traffic for another
 * client of the same account and keeps them out of its chats, instead of each
 * hardcoding the range. The exchange itself is [NewDevicePairing] and
 * [ExistingDevicePairing], over [PairingMessage] and [PairingCrypto]; carrying the
 * rumors over Nostr and acting on a confirmed link are the caller's.
 */
object MarmotDevicePairingKinds {
    /** Sent by the new device. */
    const val REQUEST = 452

    /** Sent by an existing device. */
    const val ANSWER = 453

    /** Sent by the new device. */
    const val REVEAL = 454

    /** Sent by either side. */
    const val CONFIRM = 455

    /** Sent by either side. */
    const val CANCEL = 456

    /** Every pairing kind. */
    val ALL: IntRange = REQUEST..CANCEL

    /** Whether a rumor of [kind] is device-pairing traffic. */
    fun isPairingKind(kind: Int): Boolean = kind in ALL
}
