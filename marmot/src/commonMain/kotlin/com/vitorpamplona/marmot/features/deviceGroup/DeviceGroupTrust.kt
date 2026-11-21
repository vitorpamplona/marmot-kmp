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
 * "Joining", "A link that is not taken up", "Removing a device", "Heartbeats", "New sign-ins"). Trust
 * is recorded when the device creates the group or joins it through its link's Welcome, and is never
 * inferred from group state.
 *
 * Persisted format (API): [encode] / [decode], version 1, in the Marmot binary profile; the layout is
 * written out in `plans/2026-11-21-device-groups.md`. It holds the tag signing seed, so a store MUST
 * encrypt it at rest.
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
    /** The KeyPackageRef this device was linked with: the post-link inventory names it. */
    val linkedKeyPackageRef: HexKey? = null,
    /** The device group removed this device: it acts for the account no more (`On the removed device`). */
    val unlinked: Boolean = false,
    /** The links this device approved, by the new device's slot. */
    val approvals: List<Approval> = emptyList(),
    /** Removals this device decided, kept until the roster no longer lists the slot. */
    val removalDecisions: List<SlotTime> = emptyList(),
    /** When this device last sent a heartbeat that a relay accepted. */
    val lastHeartbeatSent: Long = 0,
    /** Each sibling's last activity, for its roster entry (slot and `linked_at`). */
    val activity: List<Activity> = emptyList(),
    /** Slots a roster this device applied held as `removed`, with the cutoff no sign-in older than raises. */
    val removedSlots: List<SlotTime> = emptyList(),
    /** The slots the first complete-or-answered sign-in check returned; null until it ran. */
    val firstCheckSlots: List<HexKey>? = null,
    /** Sign-ins this device's user answered "This wasn't me". */
    val ownRejections: List<SlotTime> = emptyList(),
) {
    val trustsDeviceGroup: Boolean get() = trustedGroupId != null

    data class PendingLink(
        val link: ConfirmedLink,
        val waitUntil: Long,
    )

    enum class Outcome(
        val code: Int,
    ) {
        PENDING(0),
        MADE(1),
        FAILED(2),
    }

    data class Approval(
        val slot: HexKey,
        val linkedAt: Long,
        val outcome: Outcome,
        /** The signature key of the leaf the approving Add created, to remove it if the link fails. */
        val leafSignatureKey: HexKey,
    )

    data class SlotTime(
        val slot: HexKey,
        val time: Long,
    )

    data class Activity(
        val slot: HexKey,
        val linkedAt: Long,
        val lastActivity: Long,
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
            listOf(l.sessionId, l.keyPackageEventId, l.keyPackageRef, l.deviceGroupId, l.welcomeSenderKey, l.existingDeviceSlot).forEach { w.putOpaqueVarInt(it.hexToByteArray()) }
            w.putUint64(pendingLink.waitUntil)
        }
        putOptionalVar(w, linkedKeyPackageRef)
        w.putUint8(if (unlinked) 1 else 0)
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    approvals.forEach {
                        a.putBytes(it.slot.hexToByteArray())
                        a.putUint64(it.linkedAt)
                        a.putUint8(it.outcome.code)
                        a.putOpaqueVarInt(it.leafSignatureKey.hexToByteArray())
                    }
                }.toByteArray(),
        )
        putSlotTimes(w, removalDecisions)
        w.putUint64(lastHeartbeatSent)
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    activity.forEach {
                        a.putBytes(it.slot.hexToByteArray())
                        a.putUint64(it.linkedAt)
                        a.putUint64(it.lastActivity)
                    }
                }.toByteArray(),
        )
        putSlotTimes(w, removedSlots)
        if (firstCheckSlots == null) {
            w.putUint8(0)
        } else {
            w.putUint8(1)
            w.putOpaqueVarInt(TlsWriter().also { a -> firstCheckSlots.forEach { a.putBytes(it.hexToByteArray()) } }.toByteArray())
        }
        putSlotTimes(w, ownRejections)
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

        private fun putSlotTimes(
            w: TlsWriter,
            list: List<SlotTime>,
        ) {
            w.putOpaqueVarInt(
                TlsWriter()
                    .also { a ->
                        list.forEach {
                            a.putBytes(it.slot.hexToByteArray())
                            a.putUint64(it.time)
                        }
                    }.toByteArray(),
            )
        }

        private fun readSlotTimes(r: TlsReader): List<SlotTime> {
            val a = TlsReader(r.readOpaqueVarInt())
            val out = ArrayList<SlotTime>()
            while (a.hasRemaining) out.add(SlotTime(a.readBytes(32).toHexKey(), a.readUint64()))
            return out
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
                        val f = List(6) { r.readOpaqueVarInt().toHexKey() }
                        PendingLink(ConfirmedLink(f[0], f[1], f[2], f[3], f[4], f[5]), r.readUint64())
                    }
                    else -> throw IllegalArgumentException("invalid presence byte")
                }
            val linkedRef = readOptionalVar(r)
            val unlinked =
                when (r.readUint8()) {
                    0 -> false
                    1 -> true
                    else -> throw IllegalArgumentException("invalid flag")
                }
            val ar = TlsReader(r.readOpaqueVarInt())
            val approvals = ArrayList<Approval>()
            while (ar.hasRemaining) {
                val slot = ar.readBytes(32).toHexKey()
                val linkedAt = ar.readUint64()
                val code = ar.readUint8()
                val outcome = Outcome.entries.firstOrNull { it.code == code } ?: throw IllegalArgumentException("unknown outcome $code")
                approvals.add(Approval(slot, linkedAt, outcome, ar.readOpaqueVarInt().toHexKey()))
            }
            val decisions = readSlotTimes(r)
            val lastHeartbeat = r.readUint64()
            val act = TlsReader(r.readOpaqueVarInt())
            val activity = ArrayList<Activity>()
            while (act.hasRemaining) activity.add(Activity(act.readBytes(32).toHexKey(), act.readUint64(), act.readUint64()))
            val removed = readSlotTimes(r)
            val first =
                when (r.readUint8()) {
                    0 -> null
                    1 -> {
                        val fr = TlsReader(r.readOpaqueVarInt())
                        val out = ArrayList<HexKey>()
                        while (fr.hasRemaining) out.add(fr.readBytes(32).toHexKey())
                        out
                    }
                    else -> throw IllegalArgumentException("invalid presence byte")
                }
            val rejections = readSlotTimes(r)
            require(!r.hasRemaining) { "device-group trust has trailing bytes" }
            return DeviceGroupTrust(ownSlot, group, nostr, seed, pending, linkedRef, unlinked, approvals, decisions, lastHeartbeat, activity, removed, first, rejections)
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
