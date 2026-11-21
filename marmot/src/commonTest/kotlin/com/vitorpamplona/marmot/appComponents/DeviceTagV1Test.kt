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
package com.vitorpamplona.marmot.appComponents

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** `app-components/device-tag-v1.md` "Test vectors", and "Reading tags" against a roster. */
class DeviceTagV1Test {
    private fun rep(
        byte: String,
        times: Int,
    ) = byte.repeat(times).hexToByteArray()

    private val leafTagKey = rep("33", 32)
    private val slot = rep("11", 32)
    private val leafKey = rep("66", 32)
    private val nonce = rep("77", 12)
    private val tagPrivate = rep("55", 32)
    private val tagPublic = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242"

    private val signature =
        "601cd5e2a4fc4fc0871cac3ce66a8f2376b199110700f92abb693460bb282849" +
            "695ff8afe6da3432ca7a60a1b409195e9cac96b3ed1ff25a31ab138f8c455e01"

    private val tagBytes =
        (
            "777777777777777777777777" + "4072" +
                "711af2f06f38f0f04032cfdf0f23a8ea57773ecac4fde7f4b8e7d4789c38ba13" +
                "4a727afee6b3858640acf81557466cdb6abd9251bafa8de2c6cb69d4e15993fe" +
                "39ed1ca968e78f4b4e804bf74ed76d782a2ba3d3a3ac51afda04f00318e3a2a5" +
                "7e181129d2430033adf59c6160510eae4782"
        ).hexToByteArray()

    @Test
    fun theSpecVectorReproduces() {
        assertEquals(tagPublic, Ed25519.keyPairFromSeed(tagPrivate).publicKey.toHexKey())
        assertEquals("11".repeat(32) + "20" + "66".repeat(32), DeviceTagV1.signedContent(slot, leafKey).toHexKey())
        assertEquals("11".repeat(32) + "4040" + signature, DeviceTagV1.content(slot, signature.hexToByteArray()).toHexKey())
        val tag = DeviceTagV1.produce(leafTagKey, slot, leafKey, tagPrivate, nonce)
        assertContentEquals(tagBytes, tag.encode())
        assertEquals(128, tag.encode().size)
    }

    private fun roster(
        devices: List<DeviceEntryV1> = emptyList(),
        rejected: List<RejectedSlotV1> = emptyList(),
    ) = DeviceRosterV1(leafTagKey.toHexKey(), devices, rejected)

    @Test
    fun aTagReadsAsItsDeviceOnlyUnderTheRostersKey() {
        val slotHex = slot.toHexKey()
        val listed = roster(listOf(DeviceEntryV1(slotHex, linkedAt = 0, tagSignatureKey = tagPublic)))
        assertEquals(DeviceTagV1.Claim.Device(slotHex), DeviceTagV1.read(tagBytes, leafKey, listed))
        // Copied into a leaf with another signature key, it does not open.
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(tagBytes, rep("67", 32), listed))
        // A device listed under another key does not verify it.
        val otherKey = Ed25519.keyPairFromSeed(rep("56", 32)).publicKey.toHexKey()
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(tagBytes, leafKey, roster(listOf(DeviceEntryV1(slotHex, linkedAt = 0, tagSignatureKey = otherKey)))))
        // No key yet, or a slot the roster does not hold: unclaimed.
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(tagBytes, leafKey, roster(listOf(DeviceEntryV1(slotHex, linkedAt = 0)))))
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(tagBytes, leafKey, roster()))
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(null, leafKey, listed))
        // A removed record keeps the key, so the tag still reads as that slot.
        val removed = roster(rejected = listOf(RejectedSlotV1(slotHex, RejectionReasonV1.REMOVED, 0, tagPublic)))
        assertEquals(DeviceTagV1.Claim.RemovedSlot(slotHex), DeviceTagV1.read(tagBytes, leafKey, removed))
        // Another account's roster key cannot open it.
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(tagBytes, leafKey, DeviceRosterV1("34".repeat(32), listed.devices)))
    }

    @Test
    fun decodingIsExact() {
        assertFailsWith<IllegalArgumentException> { DeviceTagV1.decode(tagBytes + byteArrayOf(0)) }
        assertFailsWith<IllegalArgumentException> { DeviceTagV1.decode(rep("77", 12) + byteArrayOf(0)) }
        assertEquals(DeviceTagV1.Claim.Unclaimed, DeviceTagV1.read(tagBytes + byteArrayOf(0), leafKey, roster()))
    }
}
