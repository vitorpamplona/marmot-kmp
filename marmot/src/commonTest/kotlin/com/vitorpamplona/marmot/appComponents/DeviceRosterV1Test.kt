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

import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** `app-components/device-roster-v1.md` "Test vectors", plus MDK's `device_roster.rs` invariant tests. */
class DeviceRosterV1Test {
    private fun rep(
        byte: String,
        times: Int,
    ) = byte.repeat(times)

    private fun hex(s: String) = s.filterNot { it.isWhitespace() }.hexToByteArray()

    private fun slot(n: Int) = n.toString(16).padStart(2, '0').repeat(32)

    private val phone =
        DeviceEntryV1(
            slot = rep("11", 32),
            label = "Phone",
            renameId = rep("55", 16),
            client = "wn",
            platform = "",
            linkedAt = 0x6553f100,
            linkedBy = null,
            settings = DeviceEntryV1.ADD_TO_ALL_CHATS or DeviceEntryV1.KEEP_WHILE_INACTIVE,
            status = DeviceStatusV1.ACTIVE,
            tagSignatureKey = rep("44", 32),
        )

    private val roster = DeviceRosterV1(leafTagKey = rep("33", 32), devices = listOf(phone))

    private val phoneBytes =
        """
        1111111111111111111111111111111111111111111111111111111111111111
        0550686f6e65 01 55555555555555555555555555555555 02776e 00 000000006553f100 00 05 00 00
        01 20 4444444444444444444444444444444444444444444444444444444444444444 00
        """

    private val rosterBytes = hex(rep("33", 32) + "406a" + phoneBytes + "00" + "00" + "00")

    @Test
    fun theSpecRosterEncodes() {
        assertContentEquals(rosterBytes, roster.encode())
        assertEquals(roster, DeviceRosterV1.decode(rosterBytes))
    }

    @Test
    fun anEmptyRosterIsItsKeyAndFourZeros() {
        assertContentEquals(hex(rep("33", 32) + "00000000"), DeviceRosterV1(rep("33", 32)).encode())
    }

    @Test
    fun theSpecRemovalUpdateEncodesAndApplies() {
        val update =
            DeviceRosterUpdateV1(
                listOf(
                    RosterOperationV1.RemoveDevice(rep("11", 32)),
                    RosterOperationV1.SetRejectedSlot(RejectedSlotV1(rep("11", 32), RejectionReasonV1.REMOVED, 0x6553f200, rep("44", 32))),
                ),
            )
        val bytes =
            hex(
                "406d 01" + rep("11", 32) + "02" + rep("11", 32) + "01 000000006553f200 01 20" + rep("44", 32),
            )
        assertContentEquals(bytes, update.encode())
        assertEquals(update, DeviceRosterUpdateV1.decode(bytes))

        val next = roster.apply(update)
        assertEquals(emptyList(), next.devices)
        assertEquals(RejectionReasonV1.REMOVED, next.rejectedSlot(rep("11", 32))!!.reason)
    }

    @Test
    fun theSpecAnnouncementUpdateEncodesAndApplies() {
        val announced = phone.copy(announcedKeyPackage = rep("66", 32))
        val update = DeviceRosterUpdateV1(listOf(RosterOperationV1.SetDevice(announced)))
        val entry =
            """
            1111111111111111111111111111111111111111111111111111111111111111
            0550686f6e65 01 55555555555555555555555555555555 02776e 00 000000006553f100 00 05 00
            01 20 6666666666666666666666666666666666666666666666666666666666666666
            01 20 4444444444444444444444444444444444444444444444444444444444444444 00
            """
        val bytes = hex("408c 00$entry")
        assertContentEquals(bytes, update.encode())
        val next = DeviceRosterV1.applyUpdate(rosterBytes, bytes)
        // devices<V> is 408b followed by the 139 entry bytes.
        assertContentEquals(hex(rep("33", 32) + "408b" + entry + "000000"), next)
    }

    @Test
    fun decodingIsCanonical() {
        val two = DeviceRosterV1(rep("33", 32), listOf(DeviceEntryV1(slot(1), "A", linkedAt = 1), DeviceEntryV1(slot(2), "B", linkedAt = 1)))
        val bytes = two.encode()
        val devicesAt = 32 + 2
        val entryLen = (bytes.size - devicesAt - 3) / 2
        val swapped =
            bytes.copyOfRange(0, devicesAt) +
                bytes.copyOfRange(devicesAt + entryLen, devicesAt + 2 * entryLen) +
                bytes.copyOfRange(devicesAt, devicesAt + entryLen) +
                bytes.copyOfRange(devicesAt + 2 * entryLen, bytes.size)
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(swapped) }

        val one = DeviceRosterV1(rep("33", 32), listOf(DeviceEntryV1(slot(1), "A", linkedAt = 1))).encode()
        val renameAt = 32 + 1 + 32 + 2
        val settingsAt = renameAt + 1 + 1 + 1 + 8 + 1

        fun mutated(
            at: Int,
            value: Int,
        ) = one.copyOf().also { it[at] = value.toByte() }
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(mutated(renameAt, 2)) }
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(mutated(settingsAt, 0b1000)) }
        assertEquals(
            DeviceStatusV1.MOVED,
            DeviceRosterV1
                .decode(mutated(settingsAt + 1, 3))
                .devices
                .single()
                .status,
        )
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(mutated(settingsAt + 1, 4)) }
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(mutated(settingsAt - 1, 2)) }
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(mutated(settingsAt + 3, 2)) }
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(mutated(32 + 1 + 32 + 1, 0xff)) }
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1.decode(one + byteArrayOf(0)) }
    }

    @Test
    fun theRosterKeepsItsInvariants() {
        val key = rep("33", 32)
        assertFailsWith<IllegalArgumentException> { DeviceRosterV1(key, (0..AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT).map { DeviceEntryV1(slot(it), linkedAt = 0) }).encode() }
        assertFailsWith<IllegalArgumentException> {
            DeviceRosterV1(key, listOf(DeviceEntryV1(slot(1), linkedAt = 0)), listOf(RejectedSlotV1(slot(1), RejectionReasonV1.NOT_ME, 0))).encode()
        }
        assertFailsWith<IllegalArgumentException> { DeviceEntryV1(slot(1), "x".repeat(65), linkedAt = 0) }
        val shared = DeviceRosterV1(key, listOf(DeviceEntryV1(slot(1), linkedAt = 0, tagSignatureKey = rep("0a", 32)), DeviceEntryV1(slot(2), linkedAt = 0, tagSignatureKey = rep("0a", 32))))
        assertFailsWith<IllegalArgumentException> { shared.encode() }
        assertFailsWith<IllegalArgumentException> { DeviceEntryV1(slot(1), linkedAt = 0, tagSignatureKey = "") }
        assertFailsWith<IllegalArgumentException> { DeviceEntryV1(slot(1), linkedAt = 0, tagSignatureKey = rep("0c", 256)) }
        // A removed slot keeps its device's key, and may share it with a device: the signature covers the slot.
        val device = DeviceEntryV1(slot(1), linkedAt = 0, tagSignatureKey = rep("06", 32))
        DeviceRosterV1(key, listOf(device), listOf(RejectedSlotV1(slot(2), RejectionReasonV1.REMOVED, 0, rep("06", 32)))).encode()
        assertFailsWith<IllegalArgumentException> {
            DeviceRosterV1(key, listOf(device), listOf(RejectedSlotV1(slot(2), RejectionReasonV1.NOT_ME, 0, rep("06", 32)))).encode()
        }
    }

    @Test
    fun anUpdateIsSortedWithOneOperationPerEntry() {
        assertFailsWith<IllegalArgumentException> { DeviceRosterUpdateV1.of(emptyList()) }
        assertFailsWith<IllegalArgumentException> {
            DeviceRosterUpdateV1.of(listOf(RosterOperationV1.SetDevice(DeviceEntryV1(slot(1), linkedAt = 0)), RosterOperationV1.RemoveDevice(slot(1))))
        }
        val update =
            DeviceRosterUpdateV1.of(
                listOf(
                    RosterOperationV1.SetAccount(AccountEntryV1()),
                    RosterOperationV1.RemoveRejectedSlot(slot(1)),
                    RosterOperationV1.RemoveDevice(slot(2)),
                    RosterOperationV1.RemoveDevice(slot(1)),
                ),
            )
        assertEquals(
            listOf(RosterOperationV1.RemoveDevice(slot(1)), RosterOperationV1.RemoveDevice(slot(2)), RosterOperationV1.RemoveRejectedSlot(slot(1)), RosterOperationV1.SetAccount(AccountEntryV1())),
            update.operations,
        )
        assertEquals(update, DeviceRosterUpdateV1.decode(update.encode()))

        val inOrder = DeviceRosterUpdateV1.of(listOf(RosterOperationV1.RemoveDevice(slot(1)), RosterOperationV1.RemoveDevice(slot(2)))).encode()
        val reversed = byteArrayOf(inOrder[0]) + inOrder.copyOfRange(34, inOrder.size) + inOrder.copyOfRange(1, 34)
        assertFailsWith<IllegalArgumentException> { DeviceRosterUpdateV1.decode(reversed) }
        for (opType in listOf(4, 5, 7)) {
            val unknown = inOrder.copyOf().also { it[1] = opType.toByte() }
            assertFailsWith<IllegalArgumentException> { DeviceRosterUpdateV1.decode(unknown) }
        }
        assertFailsWith<IllegalArgumentException> { DeviceRosterUpdateV1.decode(byteArrayOf(0)) }
    }

    @Test
    fun applyingAnUpdateSetsAndRemovesEntries() {
        val prior =
            DeviceRosterV1(
                rep("33", 32),
                listOf(DeviceEntryV1(slot(1), "Phone", linkedAt = 0, tagSignatureKey = rep("05", 32)), DeviceEntryV1(slot(2), "Laptop", linkedAt = 0)),
                listOf(RejectedSlotV1(slot(9), RejectionReasonV1.NOT_ME, 0)),
                AccountEntryV1(backupWriter = slot(1)),
            )
        val update =
            DeviceRosterUpdateV1.of(
                listOf(
                    RosterOperationV1.SetDevice(DeviceEntryV1(slot(2), "Work laptop", linkedAt = 0)),
                    RosterOperationV1.SetDevice(DeviceEntryV1(slot(3), "Tablet", linkedAt = 0)),
                    RosterOperationV1.RemoveRejectedSlot(slot(9)),
                ),
            )
        val next = prior.apply(update)
        assertEquals("Work laptop", next.device(slot(2))!!.label)
        assertEquals("Tablet", next.device(slot(3))!!.label)
        assertNull(next.rejectedSlot(slot(9)))
        assertEquals(prior.account, next.account)
        assertEquals(prior.leafTagKey, next.leafTagKey)
        assertEquals(next.encode().toHexKey(), DeviceRosterV1.applyUpdate(prior.encode(), update.encode()).toHexKey())

        for (invalid in listOf(
            RosterOperationV1.RemoveDevice(slot(7)),
            RosterOperationV1.RemoveRejectedSlot(slot(7)),
            RosterOperationV1.SetRejectedSlot(RejectedSlotV1(slot(1), RejectionReasonV1.NOT_ME, 0)),
            RosterOperationV1.SetDevice(DeviceEntryV1(slot(2), "Laptop", linkedAt = 0, tagSignatureKey = rep("05", 32))),
        )) {
            assertFailsWith<IllegalArgumentException>("$invalid") { prior.apply(DeviceRosterUpdateV1(listOf(invalid))) }
        }
    }
}
