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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * `marmot.account.device-roster.v1` (`0x800e`, draft): the roster of an account's device group, in the
 * GroupContext `app_data_dictionary` (`app-components/device-roster-v1.md`; MDK
 * `traits/src/app_components/device_roster.rs`).
 *
 * Every byte field is lowercase hex so entries compare and sort by value; text fields are UTF-8 kept as
 * written (never normalized). [decode] and [encode] are the canonical codec: a decoder rejects anything
 * that does not re-encode to the same bytes, and the state must pass [validate].
 *
 * The roster's update is a diff, not a replacement ([DeviceRosterUpdateV1], [apply]): the one component
 * whose AppDataUpdate a member applies to the candidate parent's bytes. A member that replaced the bytes
 * whole computes a different GroupContext and forks the device group.
 */
data class DeviceRosterV1(
    /** 32 bytes that seal the account's device tags ([DeviceTagV1]). No update changes it. */
    val leafTagKey: HexKey,
    /** Sorted by slot, unique. */
    val devices: List<DeviceEntryV1> = emptyList(),
    /** Sorted by slot, unique. */
    val rejectedSlots: List<RejectedSlotV1> = emptyList(),
    val account: AccountEntryV1 = AccountEntryV1(),
) {
    init {
        requireHex(leafTagKey, 32, "leaf_tag_key")
    }

    fun device(slot: HexKey): DeviceEntryV1? = devices.firstOrNull { it.slot == slot }

    fun rejectedSlot(slot: HexKey): RejectedSlotV1? = rejectedSlots.firstOrNull { it.slot == slot }

    /** The spec's "Validation" list; throws [IllegalArgumentException] on the first broken rule. */
    fun validate() {
        requireSortedUnique(devices.map { it.slot }, "devices")
        requireSortedUnique(rejectedSlots.map { it.slot }, "rejected_slots")
        require(devices.size <= AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT) { "device roster holds more than ${AccountDevicesV1.MAX_LEAVES_PER_ACCOUNT} devices" }
        val keys = devices.mapNotNull { it.tagSignatureKey }
        require(keys.size == keys.toSet().size) { "device roster gives two devices one tag signature key" }
        require(rejectedSlots.none { it.reason == RejectionReasonV1.NOT_ME && it.tagSignatureKey != null }) { "device roster gives a not_me slot a tag signature key" }
        val deviceSlots = devices.mapTo(HashSet()) { it.slot }
        require(rejectedSlots.none { it.slot in deviceSlots }) { "device roster lists a slot as both a device and rejected" }
    }

    /**
     * The roster after [update]: `set_*` insert or replace the entry with that key, `remove_*` remove it
     * (removing one the roster does not hold is invalid), `set_account` replaces the account entry. The
     * result must be valid, or the update, and the Commit carrying it, is invalid.
     */
    fun apply(update: DeviceRosterUpdateV1): DeviceRosterV1 {
        val nextDevices = devices.associateByTo(LinkedHashMap()) { it.slot }
        val nextRejected = rejectedSlots.associateByTo(LinkedHashMap()) { it.slot }
        var nextAccount = account
        for (op in update.operations) {
            when (op) {
                is RosterOperationV1.SetDevice -> nextDevices[op.device.slot] = op.device
                is RosterOperationV1.RemoveDevice -> require(nextDevices.remove(op.slot) != null) { "device roster update removes a device it does not hold" }
                is RosterOperationV1.SetRejectedSlot -> nextRejected[op.rejectedSlot.slot] = op.rejectedSlot
                is RosterOperationV1.RemoveRejectedSlot -> require(nextRejected.remove(op.slot) != null) { "device roster update removes a rejected slot it does not hold" }
                is RosterOperationV1.SetAccount -> nextAccount = op.account
            }
        }
        val next =
            DeviceRosterV1(
                leafTagKey = leafTagKey,
                devices = nextDevices.values.sortedBy { it.slot },
                rejectedSlots = nextRejected.values.sortedBy { it.slot },
                account = nextAccount,
            )
        next.validate()
        return next
    }

    fun encode(): ByteArray {
        validate()
        val deviceBytes = TlsWriter()
        devices.forEach { it.writeTo(deviceBytes) }
        val rejectedBytes = TlsWriter()
        rejectedSlots.forEach { it.writeTo(rejectedBytes) }
        val writer = TlsWriter()
        writer.putBytes(leafTagKey.hexToByteArray())
        writer.putOpaqueVarInt(deviceBytes.toByteArray())
        writer.putOpaqueVarInt(rejectedBytes.toByteArray())
        account.writeTo(writer)
        return writer.toByteArray()
    }

    companion object {
        const val COMPONENT_ID = AppComponentIds.DEVICE_ROSTER_V1
        const val SLOT_SIZE = 32
        const val RENAME_ID_SIZE = 16
        const val TEXT_MAX_BYTES = 64
        const val KEY_PACKAGE_REF_MAX_BYTES = 64
        const val KEY_MAX_BYTES = 255

        /** Decode canonical roster bytes: sorted, unique, valid, nothing left over. */
        fun decode(bytes: ByteArray): DeviceRosterV1 {
            val reader = TlsReader(bytes)
            val leafTagKey = reader.readBytes(32).toHexKey()
            val deviceReader = TlsReader(reader.readOpaqueVarInt())
            val rejectedReader = TlsReader(reader.readOpaqueVarInt())
            val account = AccountEntryV1.readFrom(reader)
            require(!reader.hasRemaining) { "device roster has trailing bytes" }
            val devices = ArrayList<DeviceEntryV1>()
            while (deviceReader.hasRemaining) devices.add(DeviceEntryV1.readFrom(deviceReader))
            val rejected = ArrayList<RejectedSlotV1>()
            while (rejectedReader.hasRemaining) rejected.add(RejectedSlotV1.readFrom(rejectedReader))
            return DeviceRosterV1(leafTagKey, devices, rejected, account).also { it.validate() }
        }

        /** MDK's `apply_device_roster_update_v1`: canonical state bytes plus canonical update bytes. */
        fun applyUpdate(
            prior: ByteArray,
            update: ByteArray,
        ): ByteArray = decode(prior).apply(DeviceRosterUpdateV1.decode(update)).encode()

        private fun requireSortedUnique(
            slots: List<HexKey>,
            what: String,
        ) {
            for (i in 1 until slots.size) require(slots[i - 1] < slots[i]) { "device roster $what must be sorted by slot and unique" }
        }
    }
}

/** `DeviceStatusV1`. */
enum class DeviceStatusV1(
    val code: Int,
) {
    ACTIVE(0),
    INACTIVE(1),
    LEAVING(2),
    MOVED(3),
    ;

    companion object {
        fun of(code: Int): DeviceStatusV1 = entries.firstOrNull { it.code == code } ?: throw IllegalArgumentException("device roster status $code is unknown")
    }
}

/** `RejectionReasonV1`. */
enum class RejectionReasonV1(
    val code: Int,
) {
    NOT_ME(0),
    REMOVED(1),
    ;

    companion object {
        fun of(code: Int): RejectionReasonV1 = entries.firstOrNull { it.code == code } ?: throw IllegalArgumentException("device roster rejection reason $code is unknown")
    }
}

/** `DeviceEntryV1`: one linked device. */
data class DeviceEntryV1(
    /** The device's KeyPackage publication slot: on Nostr, the 32 bytes of its kind-30443 `d`. */
    val slot: HexKey,
    val label: String = "",
    /** 16 random bytes; every user edit writes a new one. */
    val renameId: HexKey? = null,
    val client: String = "",
    val platform: String = "",
    /** Seconds since the Unix epoch, as the linking device wrote it. Never compared with a clock. */
    val linkedAt: Long,
    /** The linking device's slot; absent for the device that created the group. */
    val linkedBy: HexKey? = null,
    /** Bit 0 [ADD_TO_ALL_CHATS], bit 1 [BRING_HISTORY], bit 2 [KEEP_WHILE_INACTIVE]; others zero. */
    val settings: Int = ADD_TO_ALL_CHATS or BRING_HISTORY,
    val status: DeviceStatusV1 = DeviceStatusV1.ACTIVE,
    /** The `KeyPackageRef` the device announced for its slot, raw (no length prefix). */
    val announcedKeyPackage: HexKey? = null,
    /** The public key it signs its device tags with; absent until its first Commit sets it. */
    val tagSignatureKey: HexKey? = null,
    /** Its history key (`account-sync.md`); an opaque hint checked for bounds only. */
    val historyKey: HexKey? = null,
) {
    init {
        requireHex(slot, DeviceRosterV1.SLOT_SIZE, "slot")
        requireText(label, "label")
        renameId?.let { requireHex(it, DeviceRosterV1.RENAME_ID_SIZE, "rename_id") }
        requireText(client, "client")
        requireText(platform, "platform")
        linkedBy?.let { requireHex(it, DeviceRosterV1.SLOT_SIZE, "linked_by") }
        require(settings in 0..0xff && (settings and RESERVED_SETTINGS) == 0) { "device roster settings set a reserved bit" }
        announcedKeyPackage?.let { requireBoundedHex(it, DeviceRosterV1.KEY_PACKAGE_REF_MAX_BYTES, "announced_key_package") }
        tagSignatureKey?.let { requireBoundedHex(it, DeviceRosterV1.KEY_MAX_BYTES, "tag_signature_key") }
        historyKey?.let { requireBoundedHex(it, DeviceRosterV1.KEY_MAX_BYTES, "history_key") }
    }

    val addToAllChats: Boolean get() = (settings and ADD_TO_ALL_CHATS) != 0
    val bringHistory: Boolean get() = (settings and BRING_HISTORY) != 0
    val keepWhileInactive: Boolean get() = (settings and KEEP_WHILE_INACTIVE) != 0

    internal fun writeTo(writer: TlsWriter) {
        writer.putBytes(slot.hexToByteArray())
        writeEntryBody(writer)
    }

    internal fun writeEntryBody(writer: TlsWriter) {
        writer.putOpaqueVarInt(label.encodeToByteArray())
        writeOptionalFixed(writer, renameId)
        writer.putOpaqueVarInt(client.encodeToByteArray())
        writer.putOpaqueVarInt(platform.encodeToByteArray())
        writer.putUint64(linkedAt)
        writeOptionalFixed(writer, linkedBy)
        writer.putUint8(settings)
        writer.putUint8(status.code)
        writeOptionalVar(writer, announcedKeyPackage)
        writeOptionalVar(writer, tagSignatureKey)
        writeOptionalVar(writer, historyKey)
    }

    companion object {
        const val ADD_TO_ALL_CHATS = 0x01
        const val BRING_HISTORY = 0x02
        const val KEEP_WHILE_INACTIVE = 0x04
        private const val RESERVED_SETTINGS = 0xf8

        internal fun readFrom(reader: TlsReader): DeviceEntryV1 {
            val slot = reader.readBytes(DeviceRosterV1.SLOT_SIZE).toHexKey()
            return readBody(reader, slot)
        }

        internal fun readBody(
            reader: TlsReader,
            slot: HexKey,
        ): DeviceEntryV1 {
            val label = readText(reader, "label")
            val renameId = readOptional(reader, "rename_id") { it.readBytes(DeviceRosterV1.RENAME_ID_SIZE).toHexKey() }
            val client = readText(reader, "client")
            val platform = readText(reader, "platform")
            val linkedAt = reader.readUint64()
            val linkedBy = readOptional(reader, "linked_by") { it.readBytes(DeviceRosterV1.SLOT_SIZE).toHexKey() }
            val settings = reader.readUint8()
            val status = DeviceStatusV1.of(reader.readUint8())
            val announced = readOptional(reader, "announced_key_package") { readBounded(it, DeviceRosterV1.KEY_PACKAGE_REF_MAX_BYTES, "announced_key_package") }
            val tagKey = readOptional(reader, "tag_signature_key") { readBounded(it, DeviceRosterV1.KEY_MAX_BYTES, "tag_signature_key") }
            val historyKey = readOptional(reader, "history_key") { readBounded(it, DeviceRosterV1.KEY_MAX_BYTES, "history_key") }
            return DeviceEntryV1(slot, label, renameId, client, platform, linkedAt, linkedBy, settings, status, announced, tagKey, historyKey)
        }
    }
}

/** `RejectedSlotV1`: a sign-in the user rejected (`not_me`) or a removed device (`removed`). */
data class RejectedSlotV1(
    val slot: HexKey,
    val reason: RejectionReasonV1,
    /** For `removed`: when the removal was decided. Never compared with a clock by receivers. */
    val rejectedAt: Long,
    /** A `removed` record keeps the entry's key so its tags still read as the old slot; `not_me` has none. */
    val tagSignatureKey: HexKey? = null,
) {
    init {
        requireHex(slot, DeviceRosterV1.SLOT_SIZE, "slot")
        tagSignatureKey?.let { requireBoundedHex(it, DeviceRosterV1.KEY_MAX_BYTES, "tag_signature_key") }
    }

    internal fun writeTo(writer: TlsWriter) {
        writer.putBytes(slot.hexToByteArray())
        writeEntryBody(writer)
    }

    internal fun writeEntryBody(writer: TlsWriter) {
        writer.putUint8(reason.code)
        writer.putUint64(rejectedAt)
        writeOptionalVar(writer, tagSignatureKey)
    }

    companion object {
        internal fun readFrom(reader: TlsReader): RejectedSlotV1 = readBody(reader, reader.readBytes(DeviceRosterV1.SLOT_SIZE).toHexKey())

        internal fun readBody(
            reader: TlsReader,
            slot: HexKey,
        ): RejectedSlotV1 {
            val reason = RejectionReasonV1.of(reader.readUint8())
            val rejectedAt = reader.readUint64()
            val tagKey = readOptional(reader, "tag_signature_key") { readBounded(it, DeviceRosterV1.KEY_MAX_BYTES, "tag_signature_key") }
            return RejectedSlotV1(slot, reason, rejectedAt, tagKey)
        }
    }
}

/** `AccountEntryV1`: the account's backup settings (`account-sync.md`), opaque hints here. */
data class AccountEntryV1(
    val backupWriter: HexKey? = null,
    val recoveryPublicKey: HexKey? = null,
) {
    init {
        backupWriter?.let { requireHex(it, DeviceRosterV1.SLOT_SIZE, "backup_writer") }
        recoveryPublicKey?.let { requireBoundedHex(it, DeviceRosterV1.KEY_MAX_BYTES, "recovery_public_key") }
    }

    internal fun writeTo(writer: TlsWriter) {
        writeOptionalFixed(writer, backupWriter)
        writeOptionalVar(writer, recoveryPublicKey)
    }

    companion object {
        internal fun readFrom(reader: TlsReader): AccountEntryV1 {
            val writer = readOptional(reader, "backup_writer") { it.readBytes(DeviceRosterV1.SLOT_SIZE).toHexKey() }
            val recovery = readOptional(reader, "recovery_public_key") { readBounded(it, DeviceRosterV1.KEY_MAX_BYTES, "recovery_public_key") }
            return AccountEntryV1(writer, recovery)
        }
    }
}

/** `RosterOperationV1`. Types 4 and 5 are reserved and never decode. */
sealed class RosterOperationV1 {
    abstract val type: Int

    /** Sort key: device entries, then rejected slots, then the account entry; by slot within a kind. */
    internal abstract val entryKind: Int
    internal abstract val entrySlot: HexKey

    data class SetDevice(
        val device: DeviceEntryV1,
    ) : RosterOperationV1() {
        override val type get() = 0
        override val entryKind get() = 0
        override val entrySlot get() = device.slot
    }

    data class RemoveDevice(
        val slot: HexKey,
    ) : RosterOperationV1() {
        init {
            requireHex(slot, DeviceRosterV1.SLOT_SIZE, "slot")
        }

        override val type get() = 1
        override val entryKind get() = 0
        override val entrySlot get() = slot
    }

    data class SetRejectedSlot(
        val rejectedSlot: RejectedSlotV1,
    ) : RosterOperationV1() {
        override val type get() = 2
        override val entryKind get() = 1
        override val entrySlot get() = rejectedSlot.slot
    }

    data class RemoveRejectedSlot(
        val slot: HexKey,
    ) : RosterOperationV1() {
        init {
            requireHex(slot, DeviceRosterV1.SLOT_SIZE, "slot")
        }

        override val type get() = 3
        override val entryKind get() = 1
        override val entrySlot get() = slot
    }

    data class SetAccount(
        val account: AccountEntryV1,
    ) : RosterOperationV1() {
        override val type get() = 6
        override val entryKind get() = 2
        override val entrySlot get() = ""
    }

    internal fun writeTo(writer: TlsWriter) {
        writer.putUint8(type)
        when (this) {
            is SetDevice -> device.writeTo(writer)
            is RemoveDevice -> writer.putBytes(slot.hexToByteArray())
            is SetRejectedSlot -> rejectedSlot.writeTo(writer)
            is RemoveRejectedSlot -> writer.putBytes(slot.hexToByteArray())
            is SetAccount -> account.writeTo(writer)
        }
    }

    internal companion object {
        fun readFrom(reader: TlsReader): RosterOperationV1 =
            when (val type = reader.readUint8()) {
                0 -> SetDevice(DeviceEntryV1.readFrom(reader))
                1 -> RemoveDevice(reader.readBytes(DeviceRosterV1.SLOT_SIZE).toHexKey())
                2 -> SetRejectedSlot(RejectedSlotV1.readFrom(reader))
                3 -> RemoveRejectedSlot(reader.readBytes(DeviceRosterV1.SLOT_SIZE).toHexKey())
                6 -> SetAccount(AccountEntryV1.readFrom(reader))
                else -> throw IllegalArgumentException("device roster update has an unknown operation type $type")
            }
    }
}

/** `DeviceRosterUpdateV1`: one or more operations, at most one per entry, in canonical order. */
data class DeviceRosterUpdateV1(
    val operations: List<RosterOperationV1>,
) {
    init {
        require(operations.isNotEmpty()) { "device roster update has no operations" }
        for (i in 1 until operations.size) {
            require(ORDER.compare(operations[i - 1], operations[i]) < 0) { "device roster update operations must be sorted with one per entry" }
        }
    }

    fun encode(): ByteArray {
        val ops = TlsWriter()
        operations.forEach { it.writeTo(ops) }
        val writer = TlsWriter()
        writer.putOpaqueVarInt(ops.toByteArray())
        return writer.toByteArray()
    }

    companion object {
        private val ORDER: Comparator<RosterOperationV1> = compareBy<RosterOperationV1> { it.entryKind }.thenBy { it.entrySlot }

        /** Sorts [operations] into canonical order; still refuses an empty list and two operations on one entry. */
        fun of(operations: List<RosterOperationV1>): DeviceRosterUpdateV1 = DeviceRosterUpdateV1(operations.sortedWith(ORDER))

        fun decode(bytes: ByteArray): DeviceRosterUpdateV1 {
            val reader = TlsReader(bytes)
            val opsReader = TlsReader(reader.readOpaqueVarInt())
            require(!reader.hasRemaining) { "device roster update has trailing bytes" }
            val ops = ArrayList<RosterOperationV1>()
            while (opsReader.hasRemaining) ops.add(RosterOperationV1.readFrom(opsReader))
            return DeviceRosterUpdateV1(ops)
        }
    }
}

private val HEX_DIGITS = Regex("^[0-9a-f]*$")

private fun requireHex(
    value: String,
    bytes: Int,
    what: String,
) {
    require(value.length == bytes * 2 && HEX_DIGITS.matches(value)) { "device roster $what must be $bytes bytes of lowercase hex" }
}

private fun requireBoundedHex(
    value: String,
    maxBytes: Int,
    what: String,
) {
    require(value.isNotEmpty() && value.length % 2 == 0 && value.length <= maxBytes * 2 && HEX_DIGITS.matches(value)) { "device roster $what must be 1 to $maxBytes bytes of lowercase hex" }
}

private fun requireText(
    value: String,
    what: String,
) {
    require(value.encodeToByteArray().size <= DeviceRosterV1.TEXT_MAX_BYTES) { "device roster $what exceeds ${DeviceRosterV1.TEXT_MAX_BYTES} bytes" }
}

private fun writeOptionalFixed(
    writer: TlsWriter,
    hex: HexKey?,
) {
    if (hex == null) {
        writer.putUint8(0)
    } else {
        writer.putUint8(1)
        writer.putBytes(hex.hexToByteArray())
    }
}

private fun writeOptionalVar(
    writer: TlsWriter,
    hex: HexKey?,
) {
    if (hex == null) {
        writer.putUint8(0)
    } else {
        writer.putUint8(1)
        writer.putOpaqueVarInt(hex.hexToByteArray())
    }
}

private fun <T> readOptional(
    reader: TlsReader,
    what: String,
    read: (TlsReader) -> T,
): T? =
    when (reader.readUint8()) {
        0 -> null
        1 -> read(reader)
        else -> throw IllegalArgumentException("device roster $what has an invalid presence byte")
    }

private fun readBounded(
    reader: TlsReader,
    maxBytes: Int,
    what: String,
): HexKey {
    val bytes = reader.readOpaqueVarInt()
    require(bytes.isNotEmpty() && bytes.size <= maxBytes) { "device roster $what must be 1 to $maxBytes bytes" }
    return bytes.toHexKey()
}

private fun readText(
    reader: TlsReader,
    what: String,
): String {
    val bytes = reader.readOpaqueVarInt()
    require(bytes.size <= DeviceRosterV1.TEXT_MAX_BYTES) { "device roster $what exceeds ${DeviceRosterV1.TEXT_MAX_BYTES} bytes" }
    return try {
        bytes.decodeToString(throwOnInvalidSequence = true)
    } catch (e: CharacterCodingException) {
        throw IllegalArgumentException("device roster $what is not UTF-8", e)
    }
}
