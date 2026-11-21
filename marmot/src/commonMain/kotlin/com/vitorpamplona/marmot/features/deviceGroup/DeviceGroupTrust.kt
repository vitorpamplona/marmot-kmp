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

import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * What a device keeps, across restarts, about its device group (`features/device-group.md` "Trust",
 * "Joining", "A link that is not taken up"). Trust is recorded when the device creates the group or
 * joins it through its link's Welcome, and never inferred from group state.
 *
 * Persisted format (API): [encode] / [decode], version 1, in the Marmot binary profile. It holds the
 * device's tag signing seed, so a store MUST encrypt it at rest.
 */
data class DeviceGroupTrust(
    /** This device's KeyPackage publication slot. */
    val ownSlot: HexKey,
    /** The MLS group id of the trusted device group, or null with none. */
    val trustedGroupId: HexKey? = null,
    /** Its Nostr routing id: the key `MlsGroupManager` holds it under. */
    val trustedNostrGroupId: HexKey? = null,
    /** The Ed25519 seed this device signs its device tags with. Secret. */
    val tagSigningSeed: HexKey? = null,
    /** A new device's confirmed link, while it waits for that link's Welcome. */
    val pendingLink: PendingLink? = null,
    /** The links this device approved, by the new device's slot. */
    val approvals: List<Approval> = emptyList(),
) {
    val trustsDeviceGroup: Boolean get() = trustedGroupId != null

    /** A confirmed link waiting for its Welcome; it ends at [waitUntil] (600 s after the Confirm). */
    data class PendingLink(
        val link: ConfirmedLink,
        val waitUntil: Long,
    )

    enum class Outcome(
        val code: Int,
    ) {
        /** Added; the new device's first Commit is not on the selected branch yet. */
        PENDING(0),

        /** Its first Commit is selected: the link stays made. */
        MADE(1),

        /** Not made within 3600 s of `linked_at`: the approver undoes it. */
        FAILED(2),
    }

    data class Approval(
        val slot: HexKey,
        val linkedAt: Long,
        val outcome: Outcome,
    )

    fun encode(): ByteArray {
        val w = TlsWriter()
        w.putUint8(VERSION)
        w.putBytes(ownSlot.hexToByteArray())
        putOptionalVar(w, trustedGroupId)
        putOptionalVar(w, trustedNostrGroupId)
        putOptionalVar(w, tagSigningSeed)
        if (pendingLink == null) {
            w.putUint8(0)
        } else {
            w.putUint8(1)
            val l = pendingLink.link
            w.putOpaqueVarInt(l.sessionId.hexToByteArray())
            w.putOpaqueVarInt(l.keyPackageEventId.hexToByteArray())
            w.putOpaqueVarInt(l.keyPackageRef.hexToByteArray())
            w.putOpaqueVarInt(l.deviceGroupId.hexToByteArray())
            w.putOpaqueVarInt(l.welcomeSenderKey.hexToByteArray())
            w.putOpaqueVarInt(l.existingDeviceSlot.hexToByteArray())
            w.putUint64(pendingLink.waitUntil)
        }
        val a = TlsWriter()
        approvals.forEach {
            a.putBytes(it.slot.hexToByteArray())
            a.putUint64(it.linkedAt)
            a.putUint8(it.outcome.code)
        }
        w.putOpaqueVarInt(a.toByteArray())
        return w.toByteArray()
    }

    companion object {
        const val VERSION = 1

        private fun putOptionalVar(
            w: TlsWriter,
            hex: HexKey?,
        ) {
            if (hex == null) {
                w.putUint8(0)
            } else {
                w.putUint8(1)
                w.putOpaqueVarInt(hex.hexToByteArray())
            }
        }

        private fun readOptionalVar(r: TlsReader): HexKey? =
            when (r.readUint8()) {
                0 -> null
                1 -> r.readOpaqueVarInt().toHexKey()
                else -> throw IllegalArgumentException("invalid presence byte")
            }

        fun decode(bytes: ByteArray): DeviceGroupTrust {
            val r = TlsReader(bytes)
            require(r.readUint8() == VERSION) { "unknown device-group trust version" }
            val ownSlot = r.readBytes(32).toHexKey()
            val group = readOptionalVar(r)
            val nostr = readOptionalVar(r)
            val seed = readOptionalVar(r)
            val pending =
                when (r.readUint8()) {
                    0 -> null
                    1 -> {
                        val link =
                            ConfirmedLink(
                                sessionId = r.readOpaqueVarInt().toHexKey(),
                                keyPackageEventId = r.readOpaqueVarInt().toHexKey(),
                                keyPackageRef = r.readOpaqueVarInt().toHexKey(),
                                deviceGroupId = r.readOpaqueVarInt().toHexKey(),
                                welcomeSenderKey = r.readOpaqueVarInt().toHexKey(),
                                existingDeviceSlot = r.readOpaqueVarInt().toHexKey(),
                            )
                        PendingLink(link, r.readUint64())
                    }
                    else -> throw IllegalArgumentException("invalid presence byte")
                }
            val ar = TlsReader(r.readOpaqueVarInt())
            require(!r.hasRemaining) { "device-group trust has trailing bytes" }
            val approvals = ArrayList<Approval>()
            while (ar.hasRemaining) {
                val slot = ar.readBytes(32).toHexKey()
                val linkedAt = ar.readUint64()
                val code = ar.readUint8()
                approvals.add(Approval(slot, linkedAt, Outcome.entries.firstOrNull { it.code == code } ?: throw IllegalArgumentException("unknown outcome $code")))
            }
            return DeviceGroupTrust(ownSlot, group, nostr, seed, pending, approvals)
        }
    }
}

/** Where a device keeps its [DeviceGroupTrust]. An app's implementation encrypts it at rest. */
interface DeviceGroupTrustStore {
    suspend fun load(): DeviceGroupTrust?

    suspend fun save(trust: DeviceGroupTrust)
}

/** A [DeviceGroupTrustStore] in memory, for tests and headless runs. */
class InMemoryDeviceGroupTrustStore(
    private var trust: DeviceGroupTrust? = null,
) : DeviceGroupTrustStore {
    override suspend fun load(): DeviceGroupTrust? = trust

    override suspend fun save(trust: DeviceGroupTrust) {
        this.trust = trust
    }
}
