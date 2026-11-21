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

import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.crypto.verify
import com.vitorpamplona.quartz.nip01Core.signers.NostrSigner
import com.vitorpamplona.quartz.nip01Core.signers.eventTemplate
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.Rumor
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import com.vitorpamplona.quartz.nip59Giftwrap.seals.SealEvent
import com.vitorpamplona.quartz.nip59Giftwrap.wraps.GiftWrapEvent
import com.vitorpamplona.quartz.utils.TimeUtils

/**
 * Pairing over Nostr (`transports/nostr.md` "Pairing delivery"): each message is an unsigned rumor of
 * kinds 452-456 with no tags, sealed by the account and gift-wrapped from the account to itself, for
 * the account's own kind 10050 inbox relays (which relays is the caller's). The rumor's `created_at`
 * is the send time the session rules read.
 */
object PairingDelivery {
    /** A pairing message an account sent itself, with its rumor's `created_at`. */
    data class Received(
        val message: PairingMessage,
        val createdAt: Long,
    )

    /** The gift wrap carrying [message] from [signer]'s account to itself. */
    suspend fun wrap(
        message: PairingMessage,
        signer: NostrSigner,
        createdAt: Long = TimeUtils.now(),
    ): GiftWrapEvent {
        val rumor = RumorAssembler.assembleRumor<Event>(signer.pubKey, eventTemplate<Event>(kind = message.kind, description = message.content(), createdAt = createdAt) {})
        val seal = SealEvent.create(rumor = Rumor.create(rumor), encryptTo = signer.pubKey, signer = signer)
        return GiftWrapEvent.create(event = seal, recipientPubKey = signer.pubKey)
    }

    /**
     * The pairing message in [wrap], or null when it is not one this account sent itself: a seal or
     * rumor not by this account, another rumor kind, content that does not parse, or a version this
     * client does not read. Tags on the rumor are ignored.
     */
    suspend fun unwrap(
        wrap: GiftWrapEvent,
        signer: NostrSigner,
    ): Received? {
        val seal = wrap.unwrapOrNull(signer) as? SealEvent ?: return null
        if (seal.pubKey != signer.pubKey || !seal.verify()) return null
        val rumor = seal.unsealOrNull(signer) ?: return null
        if (rumor.pubKey != signer.pubKey || !MarmotDevicePairingKinds.isPairingKind(rumor.kind)) return null
        return try {
            Received(PairingMessage.fromContent(rumor.kind, rumor.content), rumor.createdAt)
        } catch (e: PairingMessageException) {
            null
        }
    }
}
