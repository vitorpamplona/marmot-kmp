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
package com.vitorpamplona.marmot.conformance

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.marmot.TestResourceLoader
import com.vitorpamplona.quartz.marmot.mip02Welcome.WelcomeEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip59Giftwrap.wraps.GiftWrapEvent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/**
 * MDK's large-Welcome fixture (`nostr-welcome-nip44-extended-length.v1.json`):
 * a kind 1059 gift wrap whose NIP-44 layers both use the extended 6-byte
 * length prefix (`transports/nostr.md`, "NIP-44 and event size"). A Welcome
 * needs it from about 81 members; a client that cannot read it cannot join
 * such a group by Welcome at all.
 */
class LargeWelcomeNip44FixtureTest {
    private val fixture = Json.parseToJsonElement(TestResourceLoader().loadString("marmot/conformance/nostr-welcome-nip44-extended-length.v1.json")).jsonObject

    private fun field(name: String) = fixture["expected"]!!.jsonObject["fields"]!!.jsonObject[name]!!

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun weUnwrapAWelcomeWhoseLayersTakeTheExtendedPrefix() =
        runTest {
            val wrap = assertIs<GiftWrapEvent>(Event.fromJson(fixture["nostr_event"]!!.toString()))
            val recipient = NostrSignerInternal(KeyPair(fixture["recipient_secret_key_hex"]!!.jsonPrimitive.content.hexToByteArray()))

            val rumor = assertIs<WelcomeEvent>(assertNotNull(wrap.unwrapAndUnsealOrNull(recipient), "the gift wrap did not open"))
            assertEquals(field("rumor_id").jsonPrimitive.content, rumor.id)
            assertEquals(field("rumor_kind").jsonPrimitive.content.toInt(), rumor.kind)
            assertEquals(field("key_package_event_id").jsonPrimitive.content, rumor.keyPackageEventId())
            assertEquals(field("relays").jsonArray.map { it.jsonPrimitive.content }, rumor.relays()?.map { it.url.removeSuffix("/") })

            val welcome = Base64.decode(rumor.welcomeBase64())
            assertEquals(field("welcome_len").jsonPrimitive.content.toInt(), welcome.size)
            assertEquals(field("welcome_sha256").jsonPrimitive.content, sha256(welcome).toHexKey())
        }
}
