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

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.marmot.TestResourceLoader
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * MDK's `marmot-pairing/testdata/pairing-v1.json` (an independent Python implementation's known answers,
 * the spec's two vectors among them) through the derivations and both state machines, as MDK's
 * `tests/vectors.rs` runs them; and the emoji table's digest.
 */
class PairingVectorsTest {
    private val vectors =
        Json
            .parseToJsonElement(TestResourceLoader().loadString("marmot/pairing/pairing-v1.json"))
            .jsonObject["vectors"]!!
            .jsonArray
            .map { it.jsonObject }

    private fun JsonObject.s(name: String) = this[name]!!.jsonPrimitive.content

    private fun JsonObject.content(name: String) = this["content"]!!.jsonObject[name]!!.jsonPrimitive.content

    @Test
    fun derivationsMatch() {
        assertEquals(3, vectors.size)
        for (v in vectors) {
            val name = v.s("name")
            val request = PairingCrypto.RequestBinding(v.s("session_id"), v.s("account"), v.s("key_package_event_id"), v.s("key_package_ref"))
            val newKey = PairingCrypto.publicKey(v.s("new_device_secret").hexToByteArray())
            val existingKey = PairingCrypto.publicKey(v.s("existing_device_secret").hexToByteArray())
            assertEquals(v.s("new_device_key"), newKey.toHexKey(), name)
            assertEquals(v.s("existing_device_key"), existingKey.toHexKey(), name)
            assertEquals(v.s("commitment"), PairingCrypto.commitment(newKey, request).toHexKey(), name)
            val shared = PairingCrypto.agree(v.s("new_device_secret").hexToByteArray(), existingKey)!!
            assertEquals(v.s("shared_secret"), shared.toHexKey(), name)
            assertEquals(shared.toHexKey(), PairingCrypto.agree(v.s("existing_device_secret").hexToByteArray(), newKey)!!.toHexKey(), name)
            val slot = v.s("existing_device_slot")
            val sasInfo = PairingCrypto.sasInfo(request, slot, newKey, existingKey)
            assertEquals(v.s("sas_info"), sasInfo.toHexKey(), name)
            val sas = PairingCrypto.sasBytes(shared, sasInfo)
            assertEquals(v.s("sas_bytes"), sas.toHexKey(), name)
            assertEquals(v["emoji_numbers"]!!.jsonArray.map { it.jsonPrimitive.int }, SasEmoji.numbers(sas), name)
            val newInfo = PairingCrypto.macInfo(request, slot, PairingCrypto.SENDER_NEW_DEVICE, PairingCrypto.ITEM_KEY_PACKAGE_REF)
            assertEquals(v.s("new_device_mac_info"), newInfo.toHexKey(), name)
            assertEquals(v.s("new_device_mac"), PairingCrypto.mac(shared, newInfo, request.keyPackageRef.hexToByteArray()).toHexKey(), name)
            val existingInfo = PairingCrypto.macInfo(request, slot, PairingCrypto.SENDER_EXISTING_DEVICE, PairingCrypto.ITEM_DEVICE_GROUP)
            assertEquals(v.s("existing_device_mac_info"), existingInfo.toHexKey(), name)
            val value = PairingCrypto.deviceGroupValue(v.s("device_group_id").hexToByteArray(), v.s("signature_key").hexToByteArray())
            assertEquals(v.s("existing_device_mac_value"), value.toHexKey(), name)
            assertEquals(v.s("existing_device_mac"), PairingCrypto.mac(shared, existingInfo, value).toHexKey(), name)
        }
    }

    @Test
    fun bothStateMachinesReproduceTheVectors() {
        val now = 1_700_000_000L
        for (v in vectors) {
            val name = v.s("name")
            val newDevice = NewDevicePairing.startPinned(v.s("session_id"), v.s("new_device_secret").hexToByteArray(), v.s("account"), v.s("key_package_event_id"), v.s("key_package_ref"), now)
            assertEquals(v.content("request"), newDevice.requestMessage.content(), name)
            assertNull(newDevice.code(now), "no code before an answer")

            val existing = ExistingDevicePairing(v.s("account"), v.s("existing_device_slot"))
            val request = PairingMessage.fromContent(452, v.content("request"))
            assertIs<ExistingDevicePairing.Event.Requested>(existing.receive(request, now, now))
            val answer = existing.answerPinned(v.s("session_id"), ExistingDevicePairing.PublishedKeyPackage(v.s("key_package_event_id"), v.s("key_package_ref")), v.s("existing_device_secret").hexToByteArray(), now)
            assertEquals(v.content("answer"), answer.content(), name)

            val reveal = assertIs<NewDevicePairing.Event.Reveal>(newDevice.receive(PairingMessage.fromContent(453, answer.content()), now)).reveal
            assertEquals(v.content("reveal"), reveal.content(), name)
            val expected = v["emoji_numbers"]!!.jsonArray.map { it.jsonPrimitive.int }
            assertEquals(expected, newDevice.code(now)!!.map { it.number }, name)

            assertIs<ExistingDevicePairing.Event.CodeReady>(existing.receive(PairingMessage.fromContent(454, reveal.content()), now, now))
            assertEquals(expected, existing.code(v.s("session_id"), now)!!.map { it.number }, name)
            assertTrue(existing.canOfferLink(v.s("session_id"), now))

            // Either user may tap first; the new device's Confirm waits for the existing device's.
            assertEquals(NewDevicePairing.Confirmation.Waiting, newDevice.confirmMatch(now))
            val existingConfirm = existing.confirmLink(v.s("session_id"), v.s("device_group_id"), v.s("signature_key"), now)
            assertEquals(v.content("existing_device_confirm"), existingConfirm.content(), name)
            val linked = assertIs<NewDevicePairing.Event.Linked>(newDevice.receive(PairingMessage.fromContent(455, existingConfirm.content()), now))
            assertEquals(v.content("new_device_confirm"), linked.confirm.content(), name)

            val done = assertIs<ExistingDevicePairing.Event.Linked>(existing.receive(PairingMessage.fromContent(455, linked.confirm.content()), now, now))
            assertEquals(linked.link, done.link, name)
            assertEquals(v.s("device_group_id"), done.link.deviceGroupId)
            assertTrue(done.link.allowsWelcomeFor(v.s("device_group_id"), v.s("signature_key")))
            assertFalse(done.link.allowsWelcomeFor(v.s("device_group_id"), "00".repeat(32)))
            assertFalse(newDevice.holdsSecrets())
            assertEquals(0, existing.sessionsHoldingSecrets())
        }
    }

    @Test
    fun theEmojiTableIsMatrixs() {
        assertEquals(64, SasEmoji.TABLE.size)
        val lines = SasEmoji.TABLE.joinToString("") { "${it.number}\t${it.emoji}\t${it.description}\t${it.unicode}\n" }
        assertEquals("2e6e8f1cdda84d2520dcbcc49152db6fc50c2a78546c36bd8991515eef48ba81", sha256(lines.encodeToByteArray()).toHexKey())
        assertEquals("Dog", SasEmoji.of(ByteArray(6)).first().description)
        assertEquals("Pin", SasEmoji.of(ByteArray(6) { -1 }).last().description)
        assertEquals(listOf("Butterfly", "Turtle", "Pig", "Bell", "Guitar", "Heart", "Unicorn"), SasEmoji.of("38b17be5d13a".hexToByteArray()).map { it.description })
    }
}
