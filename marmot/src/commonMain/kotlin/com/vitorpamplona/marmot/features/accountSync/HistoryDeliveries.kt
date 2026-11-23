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

import com.vitorpamplona.crypto.chacha.ChaCha20Poly1305
import com.vitorpamplona.crypto.curve25519.X25519KeyPair
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.marmot.appComponents.EncryptedMediaReferenceV2
import com.vitorpamplona.marmot.appComponents.EncryptedMediaV2
import com.vitorpamplona.marmot.features.deviceGroup.MarmotDeviceGroupKinds
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.crypto.Hpke
import com.vitorpamplona.mls.crypto.HpkeCiphertext
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.verifyId
import com.vitorpamplona.quartz.utils.EventFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlin.io.encoding.Base64

/**
 * A device's history key (`account-sync.md` "History keys"): an HPKE key pair under the device
 * group's KEM (X25519 for ciphersuite `0x0001`), whose public half goes in the device's own roster
 * entry. Derived from the device's tag signing seed, a secret it already keeps from a secure random
 * source (or its link KeyPackage's leaf key), through a labelled HKDF: the private half is never
 * stored apart from that seed, so no store layout changes, and never sent anywhere.
 */
object HistoryKeys {
    const val LABEL = "Marmot History"
    private val SALT = "marmot-kmp history key v1".encodeToByteArray()

    fun keyPair(seed: ByteArray): X25519KeyPair = Hpke.deriveKeyPair(MlsCryptoProvider.hkdfExtract(SALT, seed))

    fun publicKeyHex(seed: ByteArray): HexKey = keyPair(seed).publicKey.toHexKey()
}

/** A place in chat order (`account-sync.md` "Items"): epoch, then `created_at`, then id as bytes. */
data class HistoryPosition(
    val epoch: Long,
    val at: Long,
    val id: HexKey,
) : Comparable<HistoryPosition> {
    override fun compareTo(other: HistoryPosition): Int = compareValuesBy(this, other, { it.epoch }, { it.at }).let { if (it != 0) it else id.compareTo(other.id) }

    fun toJson(): JsonObject =
        buildJsonObject {
            put("epoch", epoch)
            put("at", at)
            put("id", id)
        }

    companion object {
        fun of(
            event: Event,
            epoch: Long,
        ) = HistoryPosition(epoch, event.createdAt, event.id)

        fun parse(obj: JsonObject?): HistoryPosition? {
            if (obj == null || obj.keys != setOf("epoch", "at", "id")) return null
            val epoch = HistoryBundles.number(obj["epoch"]) ?: return null
            val at = HistoryBundles.number(obj["at"]) ?: return null
            val id = (obj["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
            if (!HistoryBundles.isHex(id, 32)) return null
            return HistoryPosition(epoch, at, id)
        }
    }
}

/** An attachment key (`account-sync.md` "History bundles"): one media reference's `ciphertext_sha256` and its `file_key`. */
data class HistoryAttachmentKey(
    val ciphertextSha256: HexKey,
    val fileKey: HexKey,
)

/**
 * One event a bundle carries: the inner event, the epoch it was sent in, its retention if held, the
 * moderation verdict held for a review label or admin removal ([grant]), and the `file_key` of each
 * encrypted-media attachment the sender can give ([keys]).
 */
class HistoryEvent(
    val event: Event,
    val epoch: Long,
    val retention: Long? = null,
    val grant: Boolean? = null,
    val keys: List<HistoryAttachmentKey> = emptyList(),
) {
    val position: HistoryPosition get() = HistoryPosition.of(event, epoch)
}

/**
 * History bundles (`account-sync.md` "History bundles"): one stretch of one chat's history, as one
 * UTF-8 JSON object, encrypted with ChaCha20-Poly1305 under a fresh key, a zero nonce and the
 * `marmot history bundle v1` associated data, with each event's moderation `grant` and attachment
 * `keys` when the sender holds them.
 */
object HistoryBundles {
    const val MAX_BYTES = 8_388_608
    const val MAX_NUMBER = 9_007_199_254_740_991L

    /** A bundle whose plaintext is at most this long always fits a delivery inline. */
    const val INLINE_MAX_PLAINTEXT = 23_552

    private val AAD = "marmot history bundle v1".encodeToByteArray()
    private val NONCE = ByteArray(12)
    private val EVENT_MEMBERS = setOf("id", "pubkey", "created_at", "kind", "tags", "content")
    private val ITEM_MEMBERS = setOf("event", "epoch", "retention", "grant", "keys")
    private val LOWER_HEX = Regex("^[0-9a-f]*$")
    private val DECIMAL = Regex("^(0|[1-9][0-9]*)$")
    private val json = Json { isLenient = false }

    internal fun isHex(
        s: String,
        bytes: Int,
    ) = s.length == bytes * 2 && LOWER_HEX.matches(s)

    internal fun isChat(s: String) = s.isNotEmpty() && s.length % 2 == 0 && s.length <= 512 && LOWER_HEX.matches(s)

    /** A bundle number: a decimal integer from 0 to 2^53 - 1, written without leading zeros. */
    internal fun number(element: Any?): Long? {
        val p = element as? JsonPrimitive ?: return null
        if (p.isString || !DECIMAL.matches(p.content)) return null
        return p.longOrNull?.takeIf { it in 0..MAX_NUMBER }
    }

    private fun eventJson(event: Event): JsonObject =
        buildJsonObject {
            put("id", event.id)
            put("pubkey", event.pubKey)
            put("created_at", event.createdAt)
            put("kind", event.kind)
            put("tags", buildJsonArray { event.tags.forEach { tag -> add(buildJsonArray { tag.forEach { add(JsonPrimitive(it)) } }) } })
            put("content", event.content)
        }

    private fun itemJson(e: HistoryEvent): JsonObject =
        buildJsonObject {
            put("event", eventJson(e.event))
            put("epoch", e.epoch)
            e.retention?.let { put("retention", it) }
            if (carriesGrant(e.event.kind)) e.grant?.let { put("grant", it) }
            if (e.keys.isNotEmpty()) {
                put(
                    "keys",
                    buildJsonArray {
                        e.keys.forEach { k ->
                            add(
                                buildJsonObject {
                                    put("ciphertext_sha256", k.ciphertextSha256)
                                    put("key", k.fileKey)
                                },
                            )
                        }
                    },
                )
            }
        }

    /** Kinds whose authority a bundle carries as `grant`: a review label (1985) and an admin removal (4891). */
    fun carriesGrant(kind: Int) = kind == 1985 || kind == 4891

    /** The `encrypted-media-v2` references of [event]'s `imeta` tags that parse. */
    fun mediaReferences(event: Event): List<EncryptedMediaReferenceV2> = event.tags.mapNotNull { tag -> if (tag.isNotEmpty() && tag[0] == "imeta") EncryptedMediaV2.parseImetaTagOrNull(tag) else null }

    /** One bundle's plaintext, members in the order the spec shows. */
    fun encode(
        chat: HexKey,
        from: HistoryPosition,
        to: HistoryPosition,
        events: List<HistoryEvent>,
    ): String =
        buildJsonObject {
            put("v", 1)
            put("chat", chat)
            put("from", from.toJson())
            put("to", to.toJson())
            put("events", JsonArray(events.map { itemJson(it) }))
        }.toString()

    /**
     * [events] in chat order, split into consecutive bundles whose plaintext is at most [maxBytes]
     * each (`Splitting`): each bundle's `from` is the previous one's `to`. An event too large for any
     * bundle is left out; so is one whose numbers no bundle can hold.
     */
    fun split(
        chat: HexKey,
        events: List<HistoryEvent>,
        maxBytes: Int = INLINE_MAX_PLAINTEXT,
    ): List<String> {
        val sorted = events.filter { it.epoch <= MAX_NUMBER && it.event.createdAt in 0..MAX_NUMBER && (it.retention ?: 0) in 0..MAX_NUMBER }.sortedBy { it.position }
        val items = sorted.map { itemJson(it).toString().encodeToByteArray().size }
        val out = ArrayList<String>()
        var current = ArrayList<HistoryEvent>()
        var currentBytes = 0
        var start: HistoryPosition? = null

        // A bundle's length: its frame with no events, plus each item and a comma between two.
        fun frame(
            from: HistoryPosition,
            to: HistoryPosition,
        ) = encode(chat, from, to, emptyList()).encodeToByteArray().size

        fun size(
            from: HistoryPosition,
            to: HistoryPosition,
            itemBytes: Int,
            count: Int,
        ) = frame(from, to) + itemBytes + (count - 1).coerceAtLeast(0)

        fun flush() {
            if (current.isEmpty()) return
            val from = start ?: current.first().position
            out.add(encode(chat, from, current.last().position, current))
            start = current.last().position
            current = ArrayList()
            currentBytes = 0
        }
        for ((i, e) in sorted.withIndex()) {
            if (size(start ?: e.position, e.position, items[i], 1) > maxBytes) continue
            val from = start ?: current.firstOrNull()?.position ?: e.position
            if (current.isNotEmpty() && size(from, e.position, currentBytes + items[i], current.size + 1) > maxBytes) flush()
            current.add(e)
            currentBytes += items[i]
        }
        flush()
        return out
    }

    /** The parsed content of a bundle that passed the whole-bundle checks; [events] passed their own. */
    class Parsed(
        val chat: HexKey,
        val from: HistoryPosition,
        val to: HistoryPosition,
        val events: List<HistoryEvent>,
    )

    /**
     * `Importing`: the bundle, or null when the whole of it is dropped (wrong version or chat, `from`
     * after `to`, a member missing, extra, repeated or of the wrong kind, a number out of range, bad
     * hex, an empty `keys`). Events whose id does not match their content, that fall outside the
     * stretch, carry `grant` on another kind, or whose retention expired by [now] are left out.
     */
    fun parse(
        plaintext: String,
        chat: HexKey,
        now: Long,
    ): Parsed? {
        if (plaintext.encodeToByteArray().size > MAX_BYTES) return null
        return try {
            parseOrThrow(plaintext, chat, now)
        } catch (e: Exception) {
            null
        }
    }

    private fun parseOrThrow(
        plaintext: String,
        chat: HexKey,
        now: Long,
    ): Parsed? {
        val root = json.parseToJsonElement(plaintext) as? JsonObject ?: return null
        if (hasDuplicateMembers(plaintext)) return null
        if (root.keys != setOf("v", "chat", "from", "to", "events")) return null
        if (number(root["v"]) != 1L) return null
        val bundleChat = (root["chat"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        if (!isChat(bundleChat) || bundleChat != chat) return null
        val from = HistoryPosition.parse(root["from"] as? JsonObject) ?: return null
        val to = HistoryPosition.parse(root["to"] as? JsonObject) ?: return null
        if (from > to) return null
        val items = root["events"] as? JsonArray ?: return null
        val kept = ArrayList<HistoryEvent>()
        for (element in items) {
            val item = element as? JsonObject ?: return null
            if (!ITEM_MEMBERS.containsAll(item.keys) || "event" !in item.keys || "epoch" !in item.keys) return null
            val ev = item["event"] as? JsonObject ?: return null
            if (ev.keys != EVENT_MEMBERS) return null
            val epoch = number(item["epoch"]) ?: return null
            val retention = if ("retention" in item.keys) number(item["retention"]) ?: return null else null
            val grant = item["grant"]
            if (grant != null && (grant !is JsonPrimitive || grant.isString || (grant.content != "true" && grant.content != "false"))) return null
            val keys = item["keys"]?.let { keys -> keysOf(keys) ?: return null }.orEmpty()
            val event = eventOf(ev) ?: return null
            // Per-event checks: the event alone is left out.
            if (!event.verifyId()) continue
            val position = HistoryPosition.of(event, epoch)
            if (position < from || position > to) continue
            if (grant != null && event.kind != 1985 && event.kind != 4891) continue
            if (retention != null && retention > 0 && event.createdAt + retention <= now) continue
            if (MarmotDeviceGroupKinds.isDeviceGroupKind(event.kind)) continue
            // An attachment key that names none of the event's media references is dropped alone.
            val references = if (keys.isEmpty()) emptySet() else mediaReferences(event).map { it.ciphertextSha256.toHexKey() }.toSet()
            kept.add(HistoryEvent(event, epoch, retention, (grant as? JsonPrimitive)?.content?.toBooleanStrictOrNull(), keys.filter { it.ciphertextSha256 in references }))
        }
        return Parsed(bundleChat, from, to, kept)
    }

    /** The attachment keys of a `keys` member, or null when it breaks the encoding (an empty one included). */
    private fun keysOf(keys: Any): List<HistoryAttachmentKey>? {
        val array = keys as? JsonArray ?: return null
        if (array.isEmpty()) return null
        return array.map { k ->
            val o = k as? JsonObject ?: return null
            if (o.keys != setOf("ciphertext_sha256", "key")) return null
            if (!o.values.all { v -> v is JsonPrimitive && v.isString && isHex(v.content, 32) }) return null
            HistoryAttachmentKey((o["ciphertext_sha256"] as JsonPrimitive).content, (o["key"] as JsonPrimitive).content)
        }
    }

    private fun eventOf(obj: JsonObject): Event? {
        val id = (obj["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        val pubKey = (obj["pubkey"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        if (!isHex(id, 32) || !isHex(pubKey, 32)) return null
        val createdAt = number(obj["created_at"]) ?: return null
        val kind = number(obj["kind"])?.takeIf { it <= Int.MAX_VALUE }?.toInt() ?: return null
        val content = (obj["content"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        val tags =
            (obj["tags"] as? JsonArray)?.map { tag ->
                (tag as? JsonArray)?.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: return null }?.toTypedArray() ?: return null
            } ?: return null
        // Typed, as a live delivery's inner event is: an app that indexes it sees a chat message, not a bare Event.
        return EventFactory.create<Event>(id, pubKey, createdAt, kind, tags.toTypedArray(), content, "")
    }

    /** Whether any object in [text] repeats a member name (the parser would keep only one). */
    private fun hasDuplicateMembers(text: String): Boolean {
        val stack = ArrayList<MutableSet<String>?>()
        var i = 0
        var expectKey = false
        while (i < text.length) {
            when (val c = text[i]) {
                '{' -> {
                    stack.add(HashSet())
                    expectKey = true
                }
                '[' -> {
                    stack.add(null)
                    expectKey = false
                }
                '}', ']' -> {
                    if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                    expectKey = false
                }
                ',' -> expectKey = stack.lastOrNull() != null
                '"' -> {
                    val end = endOfString(text, i)
                    if (expectKey) {
                        val key = text.substring(i + 1, end)
                        val set = stack.lastOrNull()
                        if (set != null && !set.add(key)) return true
                        expectKey = false
                    }
                    i = end
                }
                else -> if (c == ':') expectKey = false
            }
            i++
        }
        return false
    }

    private fun endOfString(
        text: String,
        start: Int,
    ): Int {
        var i = start + 1
        while (i < text.length) {
            when (text[i]) {
                '\\' -> i++
                '"' -> return i
            }
            i++
        }
        return text.length - 1
    }

    /** A fresh key, and the bundle's ciphertext under it. */
    fun encrypt(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val key = RandomInstance.bytes(32)
        return key to ChaCha20Poly1305.encrypt(plaintext, AAD, NONCE, key)
    }

    fun decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
    ): ByteArray? = runCatching { ChaCha20Poly1305.decrypt(ciphertext, AAD, NONCE, key) }.getOrNull()
}

/**
 * Kind 473, a history delivery (`account-sync.md` "History deliveries"): one bundle for one sibling,
 * its key and ciphertext hash sealed to that sibling's history key, the ciphertext inline or on
 * Blossom servers. [content] is the exact encoding; [parse] takes nothing else.
 */
class HistoryDelivery(
    val from: HexKey,
    val to: HexKey,
    val chat: HexKey,
    val sealed: ByteArray,
    /** The ciphertext, when it travels inline. */
    val bundle: ByteArray?,
    /** The Blossom servers that hold the ciphertext, when it does not. */
    val blossom: List<String>?,
) {
    init {
        require(HistoryBundles.isHex(from, 32) && HistoryBundles.isHex(to, 32)) { "a history delivery names two slots" }
        require(HistoryBundles.isChat(chat)) { "a history delivery names a 1 to 256-byte MLS group id" }
        require((bundle == null) != (blossom == null)) { "a history delivery carries exactly one of bundle and blossom" }
        bundle?.let { require(it.isNotEmpty()) { "an inline bundle is not empty" } }
        blossom?.let { require(it.size in 1..MAX_SERVERS && it.distinct().size == it.size && it.all(::isServerUrl)) { "one to four distinct Blossom servers" } }
    }

    fun content(): String {
        val head = """{"v":1,"from":"$from","to":"$to","chat":"$chat","sealed":"${Base64.encode(sealed)}""""
        return if (bundle != null) {
            """$head,"bundle":"${Base64.encode(bundle)}"}"""
        } else {
            """$head,"blossom":[${blossom!!.joinToString(",") { "\"$it\"" }}]}"""
        }
    }

    companion object {
        const val KIND = MarmotDeviceGroupKinds.HISTORY_DELIVERY
        const val MAX_CONTENT_BYTES = 32_768
        const val MAX_SERVERS = 4

        /** How long a sender owes a history, and a receiver keeps a delivery it cannot import yet. */
        const val LIFETIME_SECS = 7 * 24 * 3600L

        private val PURPOSE = "marmot history delivery v1".encodeToByteArray()
        private const val B64 = "[A-Za-z0-9+/]+={0,2}"
        private val SHAPE =
            Regex(
                """^\{"v":1,"from":"([0-9a-f]{64})","to":"([0-9a-f]{64})","chat":"((?:[0-9a-f]{2}){1,256})","sealed":"($B64)",(?:"bundle":"($B64)"|"blossom":\[("[^"\\]+"(?:,"[^"\\]+"){0,3})\])\}$""",
            )

        /** A normalized `http(s)` base URL with a host and no userinfo, query or fragment. */
        fun isServerUrl(url: String): Boolean {
            val bytes = url.encodeToByteArray().size
            if (bytes !in 1..2048) return false
            val rest =
                when {
                    url.startsWith("https://") -> url.removePrefix("https://")
                    url.startsWith("http://") -> url.removePrefix("http://")
                    else -> return false
                }
            val host = rest.substringBefore('/')
            if (host.isEmpty() || '@' in host || '?' in url || '#' in url) return false
            return host == host.lowercase() && url.none { it.isWhitespace() || it == '\\' }
        }

        private fun canonicalBase64(s: String): ByteArray? = runCatching { Base64.decode(s) }.getOrNull()?.takeIf { Base64.encode(it) == s }

        fun parse(content: String): HistoryDelivery? {
            if (content.encodeToByteArray().size > MAX_CONTENT_BYTES) return null
            val m = SHAPE.matchEntire(content) ?: return null
            val (from, to, chat, sealed, bundle, blossom) = m.destructured
            val sealedBytes = canonicalBase64(sealed) ?: return null
            return runCatching {
                if (bundle.isNotEmpty()) {
                    HistoryDelivery(from, to, chat, sealedBytes, canonicalBase64(bundle) ?: return null, null)
                } else {
                    HistoryDelivery(from, to, chat, sealedBytes, null, blossom.split(",").map { it.removeSurrounding("\"") })
                }
            }.getOrNull()
        }

        /** `HistoryDeliveryContextV1`: purpose, the two slots and the chat, each `opaque<V>`. */
        fun context(
            from: HexKey,
            to: HexKey,
            chat: HexKey,
        ): ByteArray {
            val w = TlsWriter()
            w.putOpaqueVarInt(PURPOSE)
            w.putOpaqueVarInt(from.hexToByteArray())
            w.putOpaqueVarInt(to.hexToByteArray())
            w.putOpaqueVarInt(chat.hexToByteArray())
            return w.toByteArray()
        }

        /** The bundle's key and ciphertext hash, sealed to [historyKey] (`EncryptWithLabel`, "Marmot History"). */
        fun seal(
            historyKey: ByteArray,
            from: HexKey,
            to: HexKey,
            chat: HexKey,
            key: ByteArray,
            ciphertextHash: ByteArray,
        ): ByteArray {
            val ct = MlsCryptoProvider.encryptWithLabel(historyKey, HistoryKeys.LABEL, context(from, to, chat), key + ciphertextHash)
            return TlsWriter().also { ct.encodeTls(it) }.toByteArray()
        }

        /** The key and ciphertext hash, or null unless [sealed] is one `HPKECiphertext` that opens to 64 bytes. */
        fun open(
            privateKey: ByteArray,
            from: HexKey,
            to: HexKey,
            chat: HexKey,
            sealed: ByteArray,
        ): Pair<ByteArray, ByteArray>? =
            runCatching {
                val reader = TlsReader(sealed)
                val ct = HpkeCiphertext.decodeTls(reader)
                if (reader.hasRemaining) return null
                val plain = MlsCryptoProvider.decryptWithLabel(privateKey, HistoryKeys.LABEL, context(from, to, chat), ct.kemOutput, ct.ciphertext)
                if (plain.size != 64) return null
                plain.copyOfRange(0, 32) to plain.copyOfRange(32, 64)
            }.getOrNull()

        /** The ciphertext's Blossom address under [server]. */
        fun blobUrl(
            server: String,
            ciphertextHash: ByteArray,
        ): String = server.trimEnd('/') + "/" + ciphertextHash.toHexKey()

        fun hash(ciphertext: ByteArray): ByteArray = sha256(ciphertext)
    }
}
