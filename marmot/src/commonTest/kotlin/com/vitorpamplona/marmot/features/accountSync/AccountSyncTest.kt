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
package com.vitorpamplona.marmot.features.accountSync

import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `features/account-sync.md`: the generation vector, the update codec and the merge rules. */
class AccountSyncTest {
    @Test
    fun theGenerationVector() {
        val a = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".hexToByteArray()
        val c =
            (
                "0001000111000102030405060708090a0b0c0d0e0f10000000000000000720111111111111111111111111111111111111111111111111111111111111111120222222222222222222222222222222222222222222222222222222222222222200"
            ).hexToByteArray()
        assertEquals(97, c.size)
        assertEquals("6d0ba86f166ff1fc424217574e7a62dbcf9c6d16a54efd61936dbc05a1f8fec2", InvitationGeneration.compute(a, c).toHexKey())
    }

    @Test
    fun theSpecUpdateParsesAndRoundTrips() {
        val content = """{"v":1,"items":[{"chat":"0102","item":"invite","generation":"0000000000000000000000000000000000000000000000000000000000000000","value":"accept","version":1}]}"""
        val items = SmallStateMessages.parse(content)!!
        assertEquals(listOf<SmallStateItem>(SmallStateItem.Invite("0102", "00".repeat(32), true, 1)), items)
        assertEquals(listOf(content), SmallStateMessages.updates(items))
    }

    @Test
    fun badUpdatesAreDroppedAndUnknownItemsSkipped() {
        assertNull(SmallStateMessages.parse("""{"v":2,"items":[]}"""))
        assertNull(SmallStateMessages.parse("""{"v":1,"v":1,"items":[]}"""))
        val two = """{"chat":"0102","item":"pin","value":true,"version":1,"change":"${"00".repeat(16)}"}"""
        assertNull(SmallStateMessages.parse("""{"v":1,"items":[$two,$two]}"""), "two items for one chat and name")
        val unknown = """{"chat":"0102","item":"star","value":1}"""
        assertEquals(1, SmallStateMessages.parse("""{"v":1,"items":[$unknown,$two]}""")!!.size)
        val badVersion = """{"chat":"0102","item":"pin","value":true,"version":0,"change":"${"00".repeat(16)}"}"""
        assertTrue(SmallStateMessages.parse("""{"v":1,"items":[$badVersion]}""")!!.isEmpty())
    }

    @Test
    fun mergeRules() {
        val pin1 = SmallStateItem.Versioned("01", "pin", "true", 1, "bb".repeat(16))
        val pin1Lower = SmallStateItem.Versioned("01", "pin", "false", 1, "aa".repeat(16))
        val pin2 = SmallStateItem.Versioned("01", "pin", "false", 2, "ff".repeat(16))
        assertTrue(SmallStateItem.wins(pin1Lower, pin1), "equal version: lower change id")
        assertTrue(SmallStateItem.wins(pin2, pin1Lower), "higher version")
        val accept = SmallStateItem.Invite("01", "00".repeat(32), true, 3)
        val decline = SmallStateItem.Invite("01", "00".repeat(32), false, 3)
        assertTrue(SmallStateItem.wins(decline, accept), "equal version: decline")
        assertFalse(SmallStateItem.wins(accept, decline))
        val r1 = SmallStateItem.Read("01", 2, 10, "aa".repeat(32))
        val r0 = SmallStateItem.Read("01", 1, 99, "ff".repeat(32))
        assertFalse(SmallStateItem.wins(r0, r1), "an earlier epoch is behind")
        val state =
            AccountSyncState()
                .merge(pin1)
                .first
                .merge(decline)
                .first
                .copy(generations = mapOf("01" to "00".repeat(32)), lastBroadcast = 5)
        assertEquals(state, AccountSyncState.decode(state.encode()))
    }
}
