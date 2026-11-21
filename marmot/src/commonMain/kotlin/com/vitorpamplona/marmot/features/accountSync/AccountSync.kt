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

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.marmot.foundation.appEvents.MarmotJson
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * `features/account-sync.md` "Invitation decisions": the generation an invitation decision is keyed by,
 * `SHA-256("marmot.invitation-generation.v1" || 0x00 || A[32] || uint64_be(len(C)) || C)` over the
 * account key and the post-admission GroupContext's TLS bytes.
 */
object InvitationGeneration {
    private const val LABEL = "marmot.invitation-generation.v1"

    fun compute(
        account: ByteArray,
        groupContextTls: ByteArray,
    ): ByteArray {
        require(account.size == 32) { "the account key is 32 bytes" }
        val w = TlsWriter()
        w.putBytes(LABEL.encodeToByteArray())
        w.putUint8(0)
        w.putBytes(account)
        w.putUint64(groupContextTls.size.toLong())
        w.putBytes(groupContextTls)
        return sha256(w.toByteArray())
    }
}

/** One small-state item (`account-sync.md` "Items"). [chat] is the raw MLS group id, hex. */
sealed class SmallStateItem {
    abstract val chat: HexKey
    abstract val name: String

    /** The item's identity: one value per key wins. */
    val key: String get() = if (this is Invite) "$chat/$name/$generation" else "$chat/$name"

    data class Read(
        override val chat: HexKey,
        val epoch: Long,
        val at: Long,
        val id: HexKey,
    ) : SmallStateItem() {
        override val name get() = "read"
    }

    /** `pin`, `mute` or `archive`. [value] is its JSON token: `true`/`false`, or a mute time. */
    data class Versioned(
        override val chat: HexKey,
        override val name: String,
        val value: String,
        val version: Long,
        val change: HexKey,
    ) : SmallStateItem()

    data class Invite(
        override val chat: HexKey,
        val generation: HexKey,
        val accept: Boolean,
        val version: Long,
    ) : SmallStateItem() {
        override val name get() = "invite"
    }

    fun toJson(): String =
        when (this) {
            is Read -> """{"chat":"$chat","item":"read","value":{"epoch":$epoch,"at":$at,"id":"$id"}}"""
            is Versioned -> """{"chat":"$chat","item":"$name","value":$value,"version":$version,"change":"$change"}"""
            is Invite -> """{"chat":"$chat","item":"invite","generation":"$generation","value":"${if (accept) "accept" else "decline"}","version":$version}"""
        }

    companion object {
        const val MAX_NUMBER = 9007199254740991L

        /**
         * Which of two values for the same item wins: the furthest read position; for pin/mute/archive
         * the higher version, then the lower change id, then the lower value bytes; for an invite the
         * higher version, then decline.
         */
        fun wins(
            candidate: SmallStateItem,
            held: SmallStateItem?,
        ): Boolean {
            if (held == null) return true
            return when (candidate) {
                is Read -> {
                    held as Read
                    compareValuesBy(candidate, held, { it.epoch }, { it.at }, { it.id }) > 0
                }
                is Versioned -> {
                    held as Versioned
                    when {
                        candidate.version != held.version -> candidate.version > held.version
                        candidate.change != held.change -> candidate.change < held.change
                        else -> candidate.value < held.value
                    }
                }
                is Invite -> {
                    held as Invite
                    if (candidate.version != held.version) candidate.version > held.version else !candidate.accept && held.accept
                }
            }
        }
    }
}

/** Kinds 475 and 476 (`account-sync.md` "Messages"). */
object SmallStateMessages {
    const val UPDATE_KIND = 475
    const val BROADCAST_REQUEST_KIND = 476
    const val BROADCAST_REQUEST = """{"v":1}"""
    const val MAX_CONTENT_BYTES = 32768

    private val HEX = Regex("^[0-9a-f]*$")
    private val NUMBER = Regex("^(0|[1-9][0-9]{0,15})$")

    /** The updates carrying [items], each within the size limit, at most one item per chat and name. */
    fun updates(items: List<SmallStateItem>): List<String> {
        val out = ArrayList<String>()
        var current = ArrayList<String>()
        var keys = HashSet<String>()

        fun flush() {
            if (current.isNotEmpty()) out.add("""{"v":1,"items":[${current.joinToString(",")}]}""")
            current = ArrayList()
            keys = HashSet()
        }
        for (item in items) {
            val json = item.toJson()
            val k = "${item.chat}/${item.name}"
            val size = 20 + current.sumOf { it.length + 1 } + json.length
            if (k in keys || size > MAX_CONTENT_BYTES) flush()
            current.add(json)
            keys.add(k)
        }
        flush()
        return out
    }

    /**
     * The items of an update, or null when the message is dropped whole (not one object, `v` not 1,
     * too long, a repeated member, two items for one chat and name). Items with an unknown name, or that
     * break a rule, are skipped one by one.
     */
    fun parse(content: String): List<SmallStateItem>? =
        try {
            require(content.encodeToByteArray().size <= MAX_CONTENT_BYTES)
            val obj = MarmotJson.parseObject(content)
            require(obj.duplicateKeys.isEmpty() && obj.keys == setOf("v", "items"))
            require((obj.element("v") as JsonPrimitive).let { !it.isString && it.content == "1" })
            val array = obj.element("items") as JsonArray
            require(array.isNotEmpty())
            val seen = HashSet<String>()
            val items = ArrayList<SmallStateItem>()
            for (element in array) {
                val o = element as JsonObject
                val chat = (o["chat"] as? JsonPrimitive)?.takeIf { it.isString }?.content
                val name = (o["item"] as? JsonPrimitive)?.takeIf { it.isString }?.content
                require(chat != null && name != null)
                require(seen.add("$chat/$name")) { "two items for one chat and name" }
                parseItem(o, chat, name)?.let { items.add(it) }
            }
            items
        } catch (e: Exception) {
            null
        }

    private fun num(p: Any?): Long? =
        (p as? JsonPrimitive)
            ?.takeIf { !it.isString && NUMBER.matches(it.content) }
            ?.content
            ?.toLongOrNull()
            ?.takeIf { it <= SmallStateItem.MAX_NUMBER }

    private fun hex(
        p: Any?,
        len: Int?,
    ): String? = (p as? JsonPrimitive)?.takeIf { it.isString && HEX.matches(it.content) && it.content.length % 2 == 0 && (len == null || it.content.length == len) }?.content

    private fun parseItem(
        o: JsonObject,
        chat: String,
        name: String,
    ): SmallStateItem? {
        if (!HEX.matches(chat) || chat.length !in 2..512 || chat.length % 2 != 0) return null
        return when (name) {
            "read" -> {
                if (o.keys != setOf("chat", "item", "value")) return null
                val v = o["value"] as? JsonObject ?: return null
                if (v.keys != setOf("epoch", "at", "id")) return null
                SmallStateItem.Read(chat, num(v["epoch"]) ?: return null, num(v["at"]) ?: return null, hex(v["id"], 64) ?: return null)
            }
            "pin", "mute", "archive" -> {
                if (o.keys != setOf("chat", "item", "value", "version", "change")) return null
                val value = o["value"] as? JsonPrimitive ?: return null
                if (value.isString) return null
                val token = value.content
                val ok = token == "true" || token == "false" || (name == "mute" && num(value) != null)
                if (!ok) return null
                val version = num(o["version"])?.takeIf { it >= 1 } ?: return null
                SmallStateItem.Versioned(chat, name, token, version, hex(o["change"], 32) ?: return null)
            }
            "invite" -> {
                if (o.keys != setOf("chat", "item", "generation", "value", "version")) return null
                val value = (o["value"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
                if (value != "accept" && value != "decline") return null
                val version = num(o["version"])?.takeIf { it >= 1 } ?: return null
                SmallStateItem.Invite(chat, hex(o["generation"], 64) ?: return null, value == "accept", version)
            }
            else -> null
        }
    }
}

/**
 * What a device holds of its account's small state: the winning value of every item, the invitation
 * generation of each local copy, and the broadcast clock.
 *
 * Persisted format (API): [encode] / [decode], version 1: `uint8 version; opaque item_json<V>
 * items<V>; Generation generations<V>; uint64 last_broadcast; uint64 last_request_answered`, where
 * `Generation = opaque chat<V>; opaque generation[32]`.
 */
data class AccountSyncState(
    val items: List<SmallStateItem> = emptyList(),
    /** Each local copy's MLS group id to its invitation generation. */
    val generations: Map<HexKey, HexKey> = emptyMap(),
    val lastBroadcast: Long = 0,
    val lastRequestAnswered: Long = 0,
) {
    fun held(key: String): SmallStateItem? = items.firstOrNull { it.key == key }

    /** Merges [item]; returns the new state and whether [item] became the winner. */
    fun merge(item: SmallStateItem): Pair<AccountSyncState, Boolean> {
        val held = held(item.key)
        if (!SmallStateItem.wins(item, held)) return this to false
        return copy(items = items.filterNot { it.key == item.key } + item) to true
    }

    fun encode(): ByteArray {
        val w = TlsWriter()
        w.putUint8(1)
        w.putOpaqueVarInt(TlsWriter().also { a -> items.forEach { a.putOpaqueVarInt(it.toJson().encodeToByteArray()) } }.toByteArray())
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    generations.entries.sortedBy { it.key }.forEach { (chat, gen) ->
                        a.putOpaqueVarInt(chat.hexToByteArray())
                        a.putBytes(gen.hexToByteArray())
                    }
                }.toByteArray(),
        )
        w.putUint64(lastBroadcast)
        w.putUint64(lastRequestAnswered)
        return w.toByteArray()
    }

    companion object {
        fun decode(bytes: ByteArray): AccountSyncState {
            val r = TlsReader(bytes)
            require(r.readUint8() == 1) { "unknown account-sync state version" }
            val ir = TlsReader(r.readOpaqueVarInt())
            val items = ArrayList<SmallStateItem>()
            while (ir.hasRemaining) {
                val json = ir.readOpaqueVarInt().decodeToString()
                SmallStateMessages.parse("""{"v":1,"items":[$json]}""")?.singleOrNull()?.let { items.add(it) }
            }
            val gr = TlsReader(r.readOpaqueVarInt())
            val gens = LinkedHashMap<HexKey, HexKey>()
            while (gr.hasRemaining) gens[gr.readOpaqueVarInt().toHexKey()] = gr.readBytes(32).toHexKey()
            val last = r.readUint64()
            val answered = r.readUint64()
            require(!r.hasRemaining) { "account-sync state has trailing bytes" }
            return AccountSyncState(items, gens, last, answered)
        }
    }
}

interface AccountSyncStore {
    suspend fun load(): AccountSyncState?

    suspend fun save(state: AccountSyncState)
}

class InMemoryAccountSyncStore(
    private var state: AccountSyncState? = null,
) : AccountSyncStore {
    override suspend fun load(): AccountSyncState? = state

    override suspend fun save(state: AccountSyncState) {
        this.state = state
    }
}
