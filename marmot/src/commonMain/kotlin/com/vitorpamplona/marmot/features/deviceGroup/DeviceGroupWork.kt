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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * Device-group work a device keeps across restarts that is not trust (`account-sync.md` "History
 * deliveries", `device-group.md` "Labels, clients and platforms"): the histories it owes siblings
 * its Commits added to chats, the deliveries it read and cannot import yet, the user edits of roster
 * labels it may have to make again after a lost fork, and the attachment keys imported histories
 * brought.
 *
 * Persisted format (API): [encode] / [decode], version 1, in the Marmot binary profile:
 *
 * ```text
 * uint8 version = 1;
 * OwedV1 owed<V>;    OwedV1 = opaque chat<V> (the chat's Nostr group id); opaque slot[32]; uint64 owed_at
 * KeptV1 kept<V>;    KeptV1 = opaque content<V> (the kind 473 content, UTF-8); opaque key[32];
 *                             opaque ciphertext_sha256[32]; uint64 read_at
 * EditV1 edits<V>;   EditV1 = opaque slot[32]; opaque label<V> (UTF-8); optional<uint32> settings;
 *                             opaque written<V> (16-byte rename_ids); opaque replaced<V> (16-byte rename_ids)
 * KeyV1 keys<V>;     KeyV1  = opaque chat<V> (Nostr group id); opaque ciphertext_sha256[32]; opaque file_key[32]
 * ```
 *
 * It holds bundle keys and attachment keys: a store MUST encrypt it at rest.
 */
data class DeviceGroupWork(
    val owed: List<OwedHistory> = emptyList(),
    val kept: List<KeptDelivery> = emptyList(),
    val edits: List<KeptEdit> = emptyList(),
    val attachmentKeys: List<AttachmentKey> = emptyList(),
) {
    /** A chat's history this device owes the sibling in [slot], since [owedAt]. */
    data class OwedHistory(
        val chat: HexKey,
        val slot: HexKey,
        val owedAt: Long,
    )

    /** A delivery read at [readAt] that waits for its chat or its blob, with the bundle key and hash it opened to. */
    class KeptDelivery(
        val content: String,
        val key: ByteArray,
        val hash: ByteArray,
        val readAt: Long,
    ) {
        override fun equals(other: Any?): Boolean = other is KeptDelivery && content == other.content && key.contentEquals(other.key) && hash.contentEquals(other.hash) && readAt == other.readAt

        override fun hashCode(): Int = content.hashCode() * 31 + readAt.hashCode()
    }

    /**
     * A user's edit of [slot]'s entry (`Labels, clients and platforms`): the [label] it intends, its
     * [settings] (null for a label-only rename, which never invents settings), the `rename_id`s it
     * wrote and the ones it replaced.
     */
    data class KeptEdit(
        val slot: HexKey,
        val label: String,
        val settings: Int? = null,
        val written: List<HexKey>,
        val replaced: List<HexKey>,
    )

    /** An attachment key an imported history brought, for a file of the chat [chat]. */
    data class AttachmentKey(
        val chat: HexKey,
        val ciphertextSha256: HexKey,
        val fileKey: HexKey,
    )

    fun encode(): ByteArray {
        val w = TlsWriter()
        w.putUint8(VERSION)
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    owed.forEach {
                        a.putOpaqueVarInt(it.chat.hexToByteArray())
                        a.putBytes(it.slot.hexToByteArray())
                        a.putUint64(it.owedAt)
                    }
                }.toByteArray(),
        )
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    kept.forEach {
                        a.putOpaqueVarInt(it.content.encodeToByteArray())
                        a.putBytes(it.key)
                        a.putBytes(it.hash)
                        a.putUint64(it.readAt)
                    }
                }.toByteArray(),
        )
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    edits.forEach {
                        a.putBytes(it.slot.hexToByteArray())
                        a.putOpaqueVarInt(it.label.encodeToByteArray())
                        if (it.settings == null) {
                            a.putUint8(0)
                        } else {
                            a.putUint8(1)
                            a.putUint32(it.settings.toLong())
                        }
                        a.putOpaqueVarInt(ids(it.written))
                        a.putOpaqueVarInt(ids(it.replaced))
                    }
                }.toByteArray(),
        )
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    attachmentKeys.forEach {
                        a.putOpaqueVarInt(it.chat.hexToByteArray())
                        a.putBytes(it.ciphertextSha256.hexToByteArray())
                        a.putBytes(it.fileKey.hexToByteArray())
                    }
                }.toByteArray(),
        )
        return w.toByteArray()
    }

    companion object {
        const val VERSION = 1
        private const val RENAME_ID_SIZE = 16

        private fun ids(list: List<HexKey>): ByteArray = TlsWriter().also { a -> list.forEach { a.putBytes(it.hexToByteArray()) } }.toByteArray()

        private fun readIds(bytes: ByteArray): List<HexKey> {
            require(bytes.size % RENAME_ID_SIZE == 0) { "a rename_id list is a run of 16-byte ids" }
            val r = TlsReader(bytes)
            val out = ArrayList<HexKey>()
            while (r.hasRemaining) out.add(r.readBytes(RENAME_ID_SIZE).toHexKey())
            return out
        }

        fun decode(bytes: ByteArray): DeviceGroupWork {
            val r = TlsReader(bytes)
            require(r.readUint8() == VERSION) { "unknown device-group work version" }
            val owed = ArrayList<OwedHistory>()
            TlsReader(r.readOpaqueVarInt()).let { a ->
                while (a.hasRemaining) owed.add(OwedHistory(a.readOpaqueVarInt().toHexKey(), a.readBytes(32).toHexKey(), a.readUint64()))
            }
            val kept = ArrayList<KeptDelivery>()
            TlsReader(r.readOpaqueVarInt()).let { a ->
                while (a.hasRemaining) kept.add(KeptDelivery(a.readOpaqueVarInt().decodeToString(), a.readBytes(32), a.readBytes(32), a.readUint64()))
            }
            val edits = ArrayList<KeptEdit>()
            TlsReader(r.readOpaqueVarInt()).let { a ->
                while (a.hasRemaining) {
                    val slot = a.readBytes(32).toHexKey()
                    val label = a.readOpaqueVarInt().decodeToString()
                    val settings =
                        when (a.readUint8()) {
                            0 -> null
                            1 -> a.readUint32().toInt()
                            else -> throw IllegalArgumentException("invalid presence byte")
                        }
                    edits.add(KeptEdit(slot, label, settings, readIds(a.readOpaqueVarInt()), readIds(a.readOpaqueVarInt())))
                }
            }
            val keys = ArrayList<AttachmentKey>()
            TlsReader(r.readOpaqueVarInt()).let { a ->
                while (a.hasRemaining) keys.add(AttachmentKey(a.readOpaqueVarInt().toHexKey(), a.readBytes(32).toHexKey(), a.readBytes(32).toHexKey()))
            }
            require(!r.hasRemaining) { "device-group work has trailing bytes" }
            return DeviceGroupWork(owed, kept, edits, keys)
        }
    }
}

/** Where a device keeps its [DeviceGroupWork]. An app's implementation encrypts it at rest. */
interface DeviceGroupWorkStore {
    suspend fun load(): DeviceGroupWork?

    suspend fun save(work: DeviceGroupWork)
}

/** A [DeviceGroupWorkStore] in memory, for tests and headless runs. */
class InMemoryDeviceGroupWorkStore(
    private var work: DeviceGroupWork? = null,
) : DeviceGroupWorkStore {
    override suspend fun load(): DeviceGroupWork? = work

    override suspend fun save(work: DeviceGroupWork) {
        this.work = work
    }
}
