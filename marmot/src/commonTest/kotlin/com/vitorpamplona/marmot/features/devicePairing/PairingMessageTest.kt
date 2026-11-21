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

/** "Messages": exact members, types and lengths, lowercase hex, `v` read first, 1024 bytes. */
class PairingMessageTest {
    private val s = "01".repeat(32)
    private val mac = "05".repeat(32)

    private fun error(
        kind: Int,
        content: String,
    ) = assertFailsWith<PairingMessageException> { PairingMessage.fromContent(kind, content) }.error

    @Test
    fun everyKindRoundTrips() {
        val messages =
            listOf(
                PairingMessage.Request(s, "02".repeat(32), "03".repeat(32), "04".repeat(32)),
                PairingMessage.Answer(s, "06".repeat(32), "07".repeat(32)),
                PairingMessage.Reveal(s, "06".repeat(32), "08".repeat(32)),
                PairingMessage.Confirm(s, false, null, null, mac),
                PairingMessage.Confirm(s, true, "09".repeat(16), "0a".repeat(32), mac),
                PairingMessage.Cancel(s, CancelReason.CANNOT_LINK),
                PairingMessage.Cancel(s, CancelReason.parse("future_reason_2")!!),
            )
        for (m in messages) assertEquals(m, PairingMessage.fromContent(m.kind, m.content()))
    }

    @Test
    fun aDifferentVersionIsIgnoredBeforeAnythingElseIsRead() {
        assertEquals(PairingMessageError.UNSUPPORTED_VERSION, error(456, """{"v":2,"whatever":true}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":"1","session":"$s","reason":"user"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"session":"$s","reason":"user"}"""))
    }

    @Test
    fun malformedContentIsRejected() {
        assertEquals(PairingMessageError.UNKNOWN_KIND, error(457, """{"v":1}"""))
        assertEquals(PairingMessageError.TOO_LARGE, error(456, """{"v":1,"session":"$s","reason":"${"a".repeat(1024)}"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, "[1]"))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"$s","reason":"user","extra":1}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"$s","session":"$s","reason":"user"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"${"ab".repeat(32).uppercase()}","reason":"user"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"${s.dropLast(2)}","reason":"user"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"$s","reason":"User"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"$s","reason":""}"""))
        assertEquals(PairingMessageError.MALFORMED, error(456, """{"v":1,"session":"$s","reason":"${"a".repeat(33)}"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(453, """{"v":1,"session":"$s","slot":1,"key":"$s"}"""))
        // A Confirm names the group and key exactly when the existing device sends it, never null.
        assertEquals(PairingMessageError.MALFORMED, error(455, """{"v":1,"session":"$s","from":"new_device","device_group":"0909","signature_key":"0a0a","mac":"$mac"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(455, """{"v":1,"session":"$s","from":"existing_device","mac":"$mac"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(455, """{"v":1,"session":"$s","from":"existing_device","device_group":null,"signature_key":"0a0a","mac":"$mac"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(455, """{"v":1,"session":"$s","from":"existing_device","device_group":"","signature_key":"0a0a","mac":"$mac"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(455, """{"v":1,"session":"$s","from":"existing_device","device_group":"09","signature_key":"${"0a".repeat(134)}","mac":"$mac"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(455, """{"v":1,"session":"$s","from":"someone","mac":"$mac"}"""))
        assertEquals(PairingMessageError.MALFORMED, error(452, """{"v":1,"session":"$s","key_package_event":"$s","key_package_ref":"${"03".repeat(65)}","commitment":"$s"}"""))
    }
}
