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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The session rules and the attacks they stop (MDK `marmot-pairing/tests/lifecycle.rs`, `attacks.rs`). */
class PairingSessionTest {
    private val account = "24".repeat(32)
    private val kpEvent = "b1".repeat(32)
    private val kpRef = "f9".repeat(32)
    private val phoneSlot = "f1".repeat(32)
    private val group = "30".repeat(16)
    private val leafKey = "c3".repeat(32)
    private val t0 = 1_700_000_000L
    private val published = ExistingDevicePairing.PublishedKeyPackage(kpEvent, kpRef)

    private class Pair2(
        val newDevice: NewDevicePairing,
        val existing: ExistingDevicePairing,
    )

    /** Request, answer and reveal: both sides are comparing. */
    private fun comparing(now: Long = t0): Pair2 {
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, now)
        val existing = ExistingDevicePairing(account, phoneSlot)
        assertIs<ExistingDevicePairing.Event.Requested>(existing.receive(newDevice.requestMessage, now, now))
        val answer = existing.answer(newDevice.sessionId, published, now)
        val reveal = assertIs<NewDevicePairing.Event.Reveal>(newDevice.receive(answer, now)).reveal
        assertIs<ExistingDevicePairing.Event.CodeReady>(existing.receive(reveal, now, now))
        return Pair2(newDevice, existing)
    }

    @Test
    fun theCodesMatchAndBothSidesHoldTheSameLink() {
        val p = comparing()
        assertEquals(p.newDevice.code(t0)!!.map { it.number }, p.existing.code(p.newDevice.sessionId, t0)!!.map { it.number })
        val confirm = p.existing.confirmLink(p.newDevice.sessionId, group, leafKey, t0)
        assertEquals(NewDevicePairing.Event.PeerConfirmed, p.newDevice.receive(confirm, t0))
        val linked = assertIs<NewDevicePairing.Confirmation.Linked>(p.newDevice.confirmMatch(t0))
        assertEquals(ExistingDevicePairing.Event.Linked(linked.link), p.existing.receive(linked.confirm, t0, t0))
        // A confirmed link never times out on the new device.
        assertNull(p.newDevice.expire(t0 + 10 * PairingLimits.SESSION_TTL_SECS))
        assertEquals(linked.link, p.newDevice.linked())
    }

    @Test
    fun theNewDevicesConfirmBeforeTheExistingDevicesIsIgnored() {
        val p = comparing()
        val forged = PairingMessage.Confirm(p.newDevice.sessionId, false, null, null, "00".repeat(32))
        assertEquals(ExistingDevicePairing.Event.Ignored(PairingIgnoreReason.WRONG_STEP), p.existing.receive(forged, t0, t0))
    }

    @Test
    fun aWrongGroupOrSignerFailsTheConfirmation() {
        val p = comparing()
        val confirm = p.existing.confirmLink(p.newDevice.sessionId, group, leafKey, t0)
        val swapped = confirm.copy(signatureKey = "c4".repeat(32))
        val ended = assertIs<NewDevicePairing.Event.Ended>(p.newDevice.receive(swapped, t0))
        assertEquals(PairingEndReason.MismatchedConfirm, ended.reason)
        assertEquals(CancelReason.MISMATCHED_CONFIRM, ended.cancel!!.reason)
        assertTrue(!p.newDevice.holdsSecrets())
    }

    @Test
    fun aSubstitutedRevealKeyFailsTheCommitment() {
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        val existing = ExistingDevicePairing(account, phoneSlot)
        existing.receive(newDevice.requestMessage, t0, t0)
        val answer = existing.answer(newDevice.sessionId, published, t0)
        val reveal = assertIs<NewDevicePairing.Event.Reveal>(newDevice.receive(answer, t0)).reveal
        val attacker = reveal.copy(key = PairingCrypto.ephemeralKey().second.let { k -> k.joinToString("") { b -> (b.toInt() and 0xff).toString(16).padStart(2, '0') } })
        val ended = assertIs<ExistingDevicePairing.Event.Ended>(existing.receive(attacker, t0, t0))
        assertEquals(PairingEndReason.MismatchedCommitment, ended.reason)
    }

    @Test
    fun aLowOrderAnswerKeyIsRejected() {
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        val ended = assertIs<NewDevicePairing.Event.Ended>(newDevice.receive(PairingMessage.Answer(newDevice.sessionId, phoneSlot, "00".repeat(32)), t0))
        assertEquals(PairingEndReason.InvalidKey, ended.reason)
        assertEquals(CancelReason.UNEXPECTED_MESSAGE, ended.cancel!!.reason)
    }

    @Test
    fun anAttackerAnsweringFirstLeavesTheRealDeviceBlank() {
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        val real = ExistingDevicePairing(account, phoneSlot)
        val attacker = ExistingDevicePairing(account, "aa".repeat(32))
        real.receive(newDevice.requestMessage, t0, t0)
        attacker.receive(newDevice.requestMessage, t0, t0)
        val first = attacker.answer(newDevice.sessionId, published, t0)
        val second = real.answer(newDevice.sessionId, published, t0)
        val reveal = assertIs<NewDevicePairing.Event.Reveal>(newDevice.receive(first, t0)).reveal
        assertEquals(NewDevicePairing.Event.Ignored(PairingIgnoreReason.WRONG_STEP), newDevice.receive(second, t0))
        val ended = assertIs<ExistingDevicePairing.Event.Ended>(real.receive(reveal, t0, t0))
        assertEquals(PairingEndReason.AnsweredElsewhere, ended.reason)
        assertNull(ended.cancel)
        assertNull(real.code(newDevice.sessionId, t0))
    }

    @Test
    fun aMismatchingPublicationIsNotAnswered() {
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        val existing = ExistingDevicePairing(account, phoneSlot)
        existing.receive(newDevice.requestMessage, t0, t0)
        val e = assertFailsWith<PairingException> { existing.answer(newDevice.sessionId, published.copy(keyPackageRef = "f8".repeat(32)), t0) }
        assertEquals(PairingError.KEY_PACKAGE_MISMATCH, e.error)
    }

    @Test
    fun competingRequestsOfferNoLink() {
        val a = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        val b = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        val existing = ExistingDevicePairing(account, phoneSlot)
        existing.receive(a.requestMessage, t0, t0)
        assertEquals(ExistingDevicePairing.Event.Requested(b.sessionId, true), existing.receive(b.requestMessage, t0, t0))
        assertEquals(PairingError.COMPETING_REQUESTS, assertFailsWith<PairingException> { existing.answer(a.sessionId, published, t0) }.error)
    }

    @Test
    fun aCompetingRequestDuringAComparisonBlocksTheLink() {
        val p = comparing()
        val other = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        p.existing.receive(other.requestMessage, t0, t0)
        assertTrue(!p.existing.canOfferLink(p.newDevice.sessionId, t0))
        assertEquals(PairingError.COMPETING_REQUESTS, assertFailsWith<PairingException> { p.existing.confirmLink(p.newDevice.sessionId, group, leafKey, t0) }.error)
    }

    @Test
    fun atMostTenAnswersAnHour() {
        val existing = ExistingDevicePairing(account, phoneSlot)
        var now = t0
        repeat(PairingLimits.MAX_ANSWERS_PER_WINDOW) {
            val d = NewDevicePairing.start(account, kpEvent, kpRef, now)
            existing.receive(d.requestMessage, now, now)
            existing.answer(d.sessionId, published, now)
            existing.cancel(d.sessionId)
            now += 1
        }
        val d = NewDevicePairing.start(account, kpEvent, kpRef, now)
        existing.receive(d.requestMessage, now, now)
        val e = assertFailsWith<PairingException> { existing.answer(d.sessionId, published, now) }
        assertEquals(PairingError.RATE_LIMITED, e.error)
        assertEquals(t0 + PairingLimits.ANSWER_WINDOW_SECS, e.retryAt)
    }

    @Test
    fun requestsAndSessionsExpireAfterTenMinutes() {
        val newDevice = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        assertNull(newDevice.expire(t0 + PairingLimits.REQUEST_TTL_SECS - 1))
        assertEquals(CancelReason.TIMEOUT, newDevice.expire(t0 + PairingLimits.REQUEST_TTL_SECS)!!.reason)

        val p = comparing()
        assertTrue(p.existing.expire(t0 + PairingLimits.SESSION_TTL_SECS - 1).isEmpty())
        assertEquals(listOf(PairingMessage.Cancel(p.newDevice.sessionId, CancelReason.TIMEOUT)), p.existing.expire(t0 + PairingLimits.SESSION_TTL_SECS))
        assertNull(p.existing.code(p.newDevice.sessionId, t0 + PairingLimits.SESSION_TTL_SECS))
        assertEquals(0, p.existing.sessionsHoldingSecrets())
    }

    @Test
    fun aRequestDatedOutsideTheWindowIsIgnored() {
        val existing = ExistingDevicePairing(account, phoneSlot)
        val old = NewDevicePairing.start(account, kpEvent, kpRef, t0)
        assertEquals(ExistingDevicePairing.Event.Ignored(PairingIgnoreReason.STALE), existing.receive(old.requestMessage, t0 - PairingLimits.REQUEST_TTL_SECS, t0))
        assertEquals(ExistingDevicePairing.Event.Ignored(PairingIgnoreReason.STALE), existing.receive(old.requestMessage, t0 + PairingLimits.REQUEST_MAX_FUTURE_SECS + 1, t0))
    }

    @Test
    fun aCancelEndsTheSessionOnBothSidesAndALinkBeforeItsWelcome() {
        val p = comparing()
        val cancel = p.newDevice.cancel()!!
        assertEquals(CancelReason.USER, cancel.reason)
        assertEquals(PairingEndReason.Cancelled(CancelReason.USER), assertIs<ExistingDevicePairing.Event.Ended>(p.existing.receive(cancel, t0, t0)).reason)

        val q = comparing()
        val confirm = q.existing.confirmLink(q.newDevice.sessionId, group, leafKey, t0)
        q.newDevice.receive(confirm, t0)
        q.newDevice.confirmMatch(t0)
        // The existing device timed out waiting and cancelled: the new device withdraws its link.
        q.newDevice.receive(PairingMessage.Cancel(q.newDevice.sessionId, CancelReason.TIMEOUT), t0)
        assertNull(q.newDevice.linked())
    }

    @Test
    fun eachSideIgnoresItsOwnMessagesAndReplays() {
        val p = comparing()
        assertEquals(NewDevicePairing.Event.Ignored(PairingIgnoreReason.OWN_ROLE), p.newDevice.receive(p.newDevice.requestMessage, t0))
        assertEquals(ExistingDevicePairing.Event.Ignored(PairingIgnoreReason.DUPLICATE), p.existing.receive(p.newDevice.requestMessage, t0, t0))
        val confirm = p.existing.confirmLink(p.newDevice.sessionId, group, leafKey, t0)
        // Its own Confirm echoed back by its inbox relays.
        assertEquals(ExistingDevicePairing.Event.Ignored(PairingIgnoreReason.OWN_ROLE), p.existing.receive(confirm, t0, t0))
        assertNotEquals<Any?>(null, p.newDevice.receive(confirm, t0))
        assertEquals(NewDevicePairing.Event.Ignored(PairingIgnoreReason.WRONG_STEP), p.newDevice.receive(confirm, t0))
    }

    @Test
    fun aRejectedCodeCannotBeConfirmedAfterwards() {
        val p = comparing()
        assertEquals(CancelReason.MISMATCHED_CODE, p.newDevice.rejectMatch(t0).reason)
        assertEquals(PairingError.WRONG_STEP, assertFailsWith<PairingException> { p.newDevice.confirmMatch(t0) }.error)
        assertEquals(CancelReason.MISMATCHED_CODE, p.existing.rejectLink(p.newDevice.sessionId, t0).reason)
        assertEquals(PairingError.WRONG_STEP, assertFailsWith<PairingException> { p.existing.confirmLink(p.newDevice.sessionId, group, leafKey, t0) }.error)
    }
}
