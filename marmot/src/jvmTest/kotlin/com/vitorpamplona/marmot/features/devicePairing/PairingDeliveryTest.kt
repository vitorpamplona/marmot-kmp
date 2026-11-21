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
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip01Core.signers.eventTemplate
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.Rumor
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import com.vitorpamplona.quartz.nip59Giftwrap.seals.SealEvent
import com.vitorpamplona.quartz.nip59Giftwrap.wraps.GiftWrapEvent
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `transports/nostr.md` "Pairing delivery", and a full pairing run over gift wraps. */
class PairingDeliveryTest {
    private val keys = KeyPair()

    /** Two devices of one account: same key, separate pairing state. */
    private val laptop = NostrSignerInternal(keys)
    private val phone = NostrSignerInternal(keys)

    @Test
    fun aMessageGoesFromTheAccountToItself() =
        runBlocking<Unit> {
            val cancel = PairingMessage.Cancel("01".repeat(32), CancelReason.USER)
            val wrap = PairingDelivery.wrap(cancel, laptop, createdAt = 1_700_000_000)
            assertEquals(laptop.pubKey, wrap.recipientPubKey())
            val received = assertNotNull(PairingDelivery.unwrap(wrap, phone))
            assertEquals(cancel, received.message)
            assertEquals(1_700_000_000, received.createdAt)
        }

    @Test
    fun aRumorSealedByAnotherAccountIsDropped() =
        runBlocking<Unit> {
            val mallory = NostrSignerInternal(KeyPair())
            val content = PairingMessage.Cancel("01".repeat(32), CancelReason.USER).content()
            // Claims the account as the rumor's author, but mallory seals it.
            val rumor = RumorAssembler.assembleRumor<Event>(laptop.pubKey, eventTemplate<Event>(kind = 456, description = content) {})
            val seal = SealEvent.create(rumor = Rumor.create(rumor), encryptTo = laptop.pubKey, signer = mallory)
            assertNull(PairingDelivery.unwrap(GiftWrapEvent.create(event = seal, recipientPubKey = laptop.pubKey), phone))
            // Another kind in a self-addressed wrap is not pairing.
            val other = RumorAssembler.assembleRumor<Event>(laptop.pubKey, eventTemplate<Event>(kind = 14, description = content) {})
            val otherSeal = SealEvent.create(rumor = Rumor.create(other), encryptTo = laptop.pubKey, signer = laptop)
            assertNull(PairingDelivery.unwrap(GiftWrapEvent.create(event = otherSeal, recipientPubKey = laptop.pubKey), phone))
        }

    @Test
    fun twoDevicesOfOneAccountLinkOverGiftWraps() =
        runBlocking<Unit> {
            val now = 1_700_000_000L
            val account = laptop.pubKey
            val kpEvent = "b1".repeat(32)
            val kpRef = "f9".repeat(32)
            val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, now)
            val existing = ExistingDevicePairing(account, "f1".repeat(32))

            suspend fun hop(
                message: PairingMessage,
                from: NostrSignerInternal,
                to: NostrSignerInternal,
            ): PairingDelivery.Received = assertNotNull(PairingDelivery.unwrap(PairingDelivery.wrap(message, from, now), to))

            val request = hop(newDevice.requestMessage, laptop, phone)
            existing.receive(request.message, request.createdAt, now)
            val answer = existing.answer(newDevice.sessionId, ExistingDevicePairing.PublishedKeyPackage(kpEvent, kpRef), now)
            val reveal = (newDevice.receive(hop(answer, phone, laptop).message, now) as NewDevicePairing.Event.Reveal).reveal
            existing.receive(hop(reveal, laptop, phone).message, now, now)
            assertEquals(newDevice.code(now)!!.map { it.description }, existing.code(newDevice.sessionId, now)!!.map { it.description })
            val existingConfirm = existing.confirmLink(newDevice.sessionId, "30".repeat(16), "c3".repeat(32), now)
            newDevice.receive(hop(existingConfirm, phone, laptop).message, now)
            val linked = newDevice.confirmMatch(now) as NewDevicePairing.Confirmation.Linked
            val done = existing.receive(hop(linked.confirm, laptop, phone).message, now, now) as ExistingDevicePairing.Event.Linked
            assertEquals(linked.link, done.link)
            assertTrue(done.link.allowsWelcomeFor("30".repeat(16), "c3".repeat(32)))
        }
}
