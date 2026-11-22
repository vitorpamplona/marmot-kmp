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
package com.vitorpamplona.marmot.features.deviceGroup

import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.client.ACCEPTING_RELAY
import com.vitorpamplona.marmot.client.MarmotManager
import com.vitorpamplona.marmot.client.SnapshotBundleStore
import com.vitorpamplona.marmot.client.SnapshotMessageStore
import com.vitorpamplona.marmot.client.SnapshotStateStore
import com.vitorpamplona.quartz.marmot.mip02Welcome.WelcomeEvent
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The device-group app-event contents (`features/device-group.md`) with real KeyPackages and Welcomes. */
@OptIn(ExperimentalEncodingApi::class)
class DeviceGroupMessagesTest {
    private val a = "aa".repeat(32)
    private val b = "bb".repeat(32)

    private class Device {
        val signer = NostrSignerInternal(KeyPair())
        val manager = MarmotManager(signer, SnapshotStateStore(), SnapshotMessageStore(), SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
    }

    private suspend fun keyPackageMessage(device: Device): ByteArray = Base64.decode(device.manager.generateKeyPackageEvent(relays = emptyList()).content)

    /** A real `mls_welcome` MLSMessage: alice adds bob. */
    private suspend fun welcomeMessage(): ByteArray {
        val alice = Device()
        val bob = Device()
        alice.manager.createCurrentProfileGroup(nostrGroupId = "e".repeat(64), relays = listOf("wss://relay.invalid"), profile = GroupProfileV1("w", ""))
        val (_, welcomes) = alice.manager.addMembers("e".repeat(64), listOf(bob.manager.generateKeyPackageEvent(relays = emptyList())), emptyList())
        val rumor = welcomes.single().giftWrapEvent.unwrapAndUnsealOrNull(bob.signer) as WelcomeEvent
        return Base64.decode(rumor.welcomeBase64())
    }

    @Test
    fun aGapFillClaimIsItsCanonicalEncodingOnly() {
        val claim = GapFillClaim(a, b, "0102")
        assertEquals("""{"v":1,"from":"$a","to":"$b","chat":"0102"}""", claim.content())
        assertEquals(claim, GapFillClaim.parse(claim.content()))
        for (bad in listOf(
            """{"v":1, "from":"$a","to":"$b","chat":"0102"}""",
            """{"from":"$a","v":1,"to":"$b","chat":"0102"}""",
            """{"v":1,"from":"${a.uppercase()}","to":"$b","chat":"0102"}""",
            """{"v":1,"from":"$a","to":"$a","chat":"0102"}""",
            """{"v":1,"from":"$a","to":"$b","chat":""}""",
            """{"v":1,"from":"$a","to":"$b","chat":"010"}""",
            """{"v":1,"from":"$a","to":"$b","chat":"0102","x":1}""",
            """{"v":1.0,"from":"$a","to":"$b","chat":"0102"}""",
        )) {
            assertNull(GapFillClaim.parse(bad), bad)
        }
        assertTrue(GapFillClaim.isLive(1000, 1000))
        assertTrue(GapFillClaim.isLive(1000, 1599))
        assertFalse(GapFillClaim.isLive(1000, 1600))
        assertFalse(GapFillClaim.isLive(1001, 1000), "future-dated")
    }

    @Test
    fun aPrivateKeyPackageRequestWantsOneToAHundred() {
        val request = PrivateKeyPackageRequest(a, b, 10)
        assertEquals("""{"v":1,"from":"$a","to":"$b","want":10}""", request.content())
        assertEquals(request, PrivateKeyPackageRequest.parse(request.content()))
        for (want in listOf("0", "101", "010", "-1", "1.0", "\"5\"")) {
            assertNull(PrivateKeyPackageRequest.parse("""{"v":1,"from":"$a","to":"$b","want":$want}"""), want)
        }
    }

    @Test
    fun aHandOffCarriesOneToTwentyKeyPackages() =
        runBlocking<Unit> {
            val device = Device()
            val packages = List(3) { keyPackageMessage(device) }
            val handOff = PrivateKeyPackageHandOff(a, b, packages)
            val parsed = assertNotNull(PrivateKeyPackageHandOff.parse(handOff.content()))
            assertEquals(3, parsed.keyPackages.size)
            packages.zip(parsed.keyPackages).forEach { (x, y) -> assertContentEquals(x, y) }
            assertFailsWith<IllegalArgumentException> { PrivateKeyPackageHandOff(a, b, emptyList()) }
            // A trailing byte or a non-KeyPackage MLSMessage does not decode.
            val raw = Base64.decode(handOff.content())
            assertNull(PrivateKeyPackageHandOff.parse(Base64.encode(raw + byteArrayOf(0))))
            assertNull(PrivateKeyPackageHandOff.parse(PrivateKeyPackageHandOff(a, b, listOf(welcomeMessage())).content()))
        }

    @Test
    fun siblingWelcomesRoundTripInEveryVersion() =
        runBlocking<Unit> {
            val welcome = welcomeMessage()
            val gen = "0c".repeat(32)
            val inviter = "0d".repeat(32)
            val relays = listOf("wss://relay.one", "wss://relay.two")
            for ((version, g, i, c) in listOf(
                Quad(1, null, null, false),
                Quad(2, gen, null, false),
                Quad(3, null, inviter, false),
                Quad(3, null, null, true),
                Quad(3, gen, inviter, false),
            )) {
                assertEquals(version, SiblingWelcome.choose(g, i, c))
                val sw = SiblingWelcome(version, a, b, g, i, c, "ee".repeat(32), welcome, relays)
                val parsed = assertNotNull(SiblingWelcome.parse(sw.content()), "v$version")
                assertEquals(version, parsed.version)
                assertEquals(g, parsed.invitationGeneration)
                assertEquals(i, parsed.inviter)
                assertEquals(c, parsed.confirmed)
                assertContentEquals(welcome, parsed.welcome)
                assertEquals(relays, parsed.relays)
                assertEquals(sw.content(), parsed.content())
            }
            // A version 3 that forwards nothing, or is confirmed beside a generation, is invalid.
            assertFailsWith<IllegalArgumentException> { SiblingWelcome(3, a, b, gen, null, false, "ee", welcome, relays) }
            assertFailsWith<IllegalArgumentException> { SiblingWelcome(3, a, b, gen, null, true, "ee", welcome, relays) }
            assertFailsWith<IllegalArgumentException> { SiblingWelcome(1, a, b, null, null, false, "ee", welcome, listOf("wss://r", "wss://r")) }
            assertFailsWith<IllegalArgumentException> { SiblingWelcome(1, a, b, null, null, false, "ee", welcome, emptyList()) }
            // Version 3's presence and confirmed bytes are 0 or 1.
            val v3 = Base64.decode(SiblingWelcome(3, a, b, null, null, true, "ee", welcome, relays).content())
            val confirmedAt = 1 + 32 + 32 + 1 + 1
            assertNull(SiblingWelcome.parse(Base64.encode(v3.copyOf().also { it[confirmedAt] = 2 })))
            assertNull(SiblingWelcome.parse(Base64.encode(v3.copyOf().also { it[1 + 64] = 2 })))
            assertNull(SiblingWelcome.parse(Base64.encode(v3.copyOf().also { it[0] = 4 })))
            // A KeyPackage where the Welcome goes does not decode.
            assertNull(SiblingWelcome.parse(SiblingWelcome(1, a, b, keyPackageRef = "ee", welcome = keyPackageMessage(Device()), relays = relays).content()))
        }

    private data class Quad(
        val v: Int,
        val g: String?,
        val i: String?,
        val c: Boolean,
    )

    @Test
    fun theInventoryTokenMatchesTheSpec() {
        val ref = ByteArray(32) { it.toByte() }
        val gid = ByteArray(64) { it.toByte() }
        assertEquals("40851b595a738955daa54e7b6bf77c5b9314d4a62af3559982f4c06192cea75b", LinkChatInventory.token(ref, gid).toHexKey())
        val page = LinkChatInventory(a, ref.toHexKey(), 1, 1_800_000_000, 1, 0, listOf(LinkChatInventory.token(ref, gid).toHexKey()))
        assertEquals(page, LinkChatInventory.parse(page.content()))
        assertEquals(page, LinkChatInventory.parse(page.content().replace("\"v\":1,\"to\"", "\"to\"").replaceFirst("{", "{\"v\":1,")), "field order is insignificant")
        assertNull(LinkChatInventory.parse(page.content().dropLast(1) + ",\"x\":1}"))
        assertNull(LinkChatInventory.parse(page.content().replace("\"revision\":1", "\"revision\":0")))
        assertNull(LinkChatInventory.parse(page.content().replace(a, a.uppercase())))
    }

    @Test
    fun theHeartbeatIsVersionOne() {
        assertEquals("""{"v":1}""", DeviceHeartbeat.CONTENT)
        assertEquals(457, DeviceHeartbeat.KIND)
    }
}
