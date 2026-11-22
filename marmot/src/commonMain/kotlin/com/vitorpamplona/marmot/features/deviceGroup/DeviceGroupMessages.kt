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

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.marmot.appComponents.NostrRoutingV1
import com.vitorpamplona.marmot.foundation.appEvents.MarmotJson
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.mls.messages.Welcome
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/*
 * The contents of the app events an account's devices exchange in their device group
 * (`features/device-group.md`). Codecs only: who may send one, from which leaf, and what a receiver
 * does with it are the device group's rules, applied by the caller. Every one is read only in the
 * device group the receiver trusts ([MarmotDeviceGroupKinds]).
 */

private val LOWER_HEX = Regex("^[0-9a-f]*$")

private fun isSlotHex(s: String) = s.length == 64 && LOWER_HEX.matches(s)

/** Kind 457: `{"v":1}`. A receiver does not read the content, so a later version can add to it. */
object DeviceHeartbeat {
    const val KIND = MarmotDeviceGroupKinds.HEARTBEAT
    const val CONTENT = """{"v":1}"""

    /** Send one when none was sent, or the last one is at least this old. */
    const val INTERVAL_SECS = 3600L
}

/**
 * Kind 458, a gap-fill claim: `{"v":1,"from":…,"to":…,"chat":…}`, exactly that, byte for byte. [chat]
 * is the raw MLS group id in lowercase hex, never the routing id. It expires 600 s after its
 * `created_at`; a future-dated claim is ignored.
 */
data class GapFillClaim(
    val from: HexKey,
    val to: HexKey,
    val chat: HexKey,
) {
    init {
        require(isSlotHex(from) && isSlotHex(to) && from != to) { "a gap-fill claim names two distinct slots" }
        require(chat.isNotEmpty() && chat.length % 2 == 0 && LOWER_HEX.matches(chat)) { "a gap-fill claim names a non-empty MLS group id in lowercase hex" }
    }

    fun content(): String = """{"v":1,"from":"$from","to":"$to","chat":"$chat"}"""

    companion object {
        const val KIND = MarmotDeviceGroupKinds.GAP_FILL_CLAIM
        const val LIFETIME_SECS = 600L
        const val MAX_CONTENT_BYTES = 32 * 1024

        private val SHAPE = Regex("""^\{"v":1,"from":"([0-9a-f]{64})","to":"([0-9a-f]{64})","chat":"((?:[0-9a-f]{2})+)"\}$""")

        /** The claim, or null unless [content] is exactly its canonical encoding. */
        fun parse(content: String): GapFillClaim? {
            if (content.encodeToByteArray().size > MAX_CONTENT_BYTES) return null
            val m = SHAPE.matchEntire(content) ?: return null
            val (from, to, chat) = m.destructured
            return if (from == to) null else GapFillClaim(from, to, chat)
        }

        /** Whether a claim sent at [createdAt] counts at [now]: not dated ahead, not expired. */
        fun isLive(
            createdAt: Long,
            now: Long,
        ): Boolean = createdAt <= now && now < createdAt + LIFETIME_SECS
    }
}

/** Kind 459: `{"v":1,"from":…,"to":…,"want":N}`, N from 1 to 100, decoded exactly. */
data class PrivateKeyPackageRequest(
    val from: HexKey,
    val to: HexKey,
    val want: Int,
) {
    init {
        require(isSlotHex(from) && isSlotHex(to)) { "a private KeyPackage request names two slots" }
        require(want in 1..MAX_WANT) { "want must be 1 to $MAX_WANT" }
    }

    fun content(): String = """{"v":1,"from":"$from","to":"$to","want":$want}"""

    companion object {
        const val KIND = MarmotDeviceGroupKinds.PRIVATE_KEY_PACKAGE_REQUEST
        const val MAX_WANT = 100

        /** A sibling repeats an unmet request at most this often. */
        const val RETRY_SECS = 3600L

        private val SHAPE = Regex("""^\{"v":1,"from":"([0-9a-f]{64})","to":"([0-9a-f]{64})","want":([1-9][0-9]{0,2})\}$""")

        fun parse(content: String): PrivateKeyPackageRequest? {
            val m = SHAPE.matchEntire(content) ?: return null
            val (from, to, want) = m.destructured
            val n = want.toInt()
            return if (n in 1..MAX_WANT) PrivateKeyPackageRequest(from, to, n) else null
        }
    }
}

/** Reads one MLSMessage whose wire format is [expected] off [reader], and returns its exact bytes. */
private fun readMlsMessage(
    reader: TlsReader,
    expected: WireFormat,
): ByteArray =
    reader
        .readCapturing { r ->
            require(r.readUint16() == 1) { "MLSMessage version must be mls10" }
            require(r.readUint16() == expected.value) { "MLSMessage wire format must be $expected" }
            when (expected) {
                WireFormat.KEY_PACKAGE -> MlsKeyPackage.decodeTls(r)
                WireFormat.WELCOME -> Welcome.decodeTls(r)
                else -> throw IllegalArgumentException("unexpected wire format $expected")
            }
        }.second

/**
 * Kind 460, a private KeyPackage hand-off: base64 (standard, padded) of
 * `struct { uint8 version = 1; SlotId from; SlotId to; MLSMessage key_packages<V>; }`, 1 to 20
 * `mls_key_package` MLSMessages. [keyPackages] holds each MLSMessage's exact bytes.
 */
@OptIn(ExperimentalEncodingApi::class)
class PrivateKeyPackageHandOff(
    val from: HexKey,
    val to: HexKey,
    val keyPackages: List<ByteArray>,
) {
    init {
        require(isSlotHex(from) && isSlotHex(to)) { "a hand-off names two slots" }
        require(keyPackages.size in 1..MAX_KEY_PACKAGES) { "a hand-off carries 1 to $MAX_KEY_PACKAGES KeyPackages" }
    }

    fun content(): String {
        val packages = TlsWriter()
        keyPackages.forEach { packages.putBytes(it) }
        val w = TlsWriter()
        w.putUint8(VERSION)
        w.putBytes(from.hexToByteArray())
        w.putBytes(to.hexToByteArray())
        w.putOpaqueVarInt(packages.toByteArray())
        return Base64.Default.encode(w.toByteArray())
    }

    companion object {
        const val KIND = MarmotDeviceGroupKinds.PRIVATE_KEY_PACKAGE_HAND_OFF
        const val VERSION = 1
        const val MAX_KEY_PACKAGES = 20

        /** The hand-off, or null unless [content] decodes exactly (each package is checked later, when used). */
        fun parse(content: String): PrivateKeyPackageHandOff? =
            try {
                val bytes = Base64.Default.decode(content)
                require(Base64.Default.encode(bytes) == content) { "not canonical base64" }
                val r = TlsReader(bytes)
                require(r.readUint8() == VERSION) { "unknown hand-off version" }
                val from = r.readBytes(32).toHexKey()
                val to = r.readBytes(32).toHexKey()
                val pr = TlsReader(r.readOpaqueVarInt())
                require(!r.hasRemaining) { "hand-off has trailing bytes" }
                val packages = ArrayList<ByteArray>()
                while (pr.hasRemaining) packages.add(readMlsMessage(pr, WireFormat.KEY_PACKAGE))
                PrivateKeyPackageHandOff(from, to, packages)
            } catch (e: Exception) {
                null
            }
    }
}

/**
 * Kind 461, a sibling Welcome (`device-group.md` "Message", #512): base64 of SiblingWelcomeV1, V2 or
 * V3. [welcome] is the exact MLSMessage bytes (`mls_welcome`); [keyPackageRef] the private
 * KeyPackage's raw ref; [relays] 1 to 16 distinct relay URLs, a fetch hint only.
 *
 * - V1 forwards nothing; V2 adds the original [invitationGeneration]; V3 adds the optional
 *   [inviter] (x-only key of the other account that invited the sender's copy) and [confirmed] (the
 *   sender's copy is confirmed and has no generation). A V3 that forwards nothing, or is confirmed
 *   beside a generation, is invalid. [choose] picks the version a sender uses.
 */
@OptIn(ExperimentalEncodingApi::class)
class SiblingWelcome(
    val version: Int,
    val from: HexKey,
    val to: HexKey,
    val invitationGeneration: HexKey? = null,
    val inviter: HexKey? = null,
    val confirmed: Boolean = false,
    val keyPackageRef: HexKey,
    val welcome: ByteArray,
    val relays: List<String>,
) {
    init {
        require(isSlotHex(from) && isSlotHex(to)) { "a sibling Welcome names two slots" }
        require(keyPackageRef.length % 2 == 0 && keyPackageRef.length / 2 in 1..64 && LOWER_HEX.matches(keyPackageRef)) { "key_package_ref must be 1 to 64 bytes" }
        invitationGeneration?.let { require(isSlotHex(it)) { "invitation_generation is 32 bytes" } }
        inviter?.let { require(isSlotHex(it)) { "inviter is 32 bytes" } }
        when (version) {
            1 -> require(invitationGeneration == null && inviter == null && !confirmed) { "version 1 forwards nothing" }
            2 -> require(invitationGeneration != null && inviter == null && !confirmed) { "version 2 carries only a generation" }
            3 -> {
                require(inviter != null || confirmed) { "version 3 forwards an inviter or a confirmation" }
                require(!(confirmed && invitationGeneration != null)) { "a confirmed copy with a generation is settled by its decision" }
            }
            else -> throw IllegalArgumentException("unknown sibling Welcome version $version")
        }
        require(relays.size in 1..MAX_RELAYS && relays.toSet().size == relays.size) { "a sibling Welcome lists 1 to $MAX_RELAYS distinct relays" }
        relays.forEach { NostrRoutingV1.requireValidRelayUrl(it) }
    }

    fun content(): String {
        val w = TlsWriter()
        w.putUint8(version)
        w.putBytes(from.hexToByteArray())
        w.putBytes(to.hexToByteArray())
        when (version) {
            2 -> w.putBytes(invitationGeneration!!.hexToByteArray())
            3 -> {
                putOptional32(w, invitationGeneration)
                putOptional32(w, inviter)
                w.putUint8(if (confirmed) 1 else 0)
            }
        }
        w.putOpaqueVarInt(keyPackageRef.hexToByteArray())
        w.putBytes(welcome)
        val relayBytes = TlsWriter()
        relays.forEach { relayBytes.putOpaqueVarInt(it.encodeToByteArray()) }
        w.putOpaqueVarInt(relayBytes.toByteArray())
        return Base64.Default.encode(w.toByteArray())
    }

    companion object {
        const val KIND = MarmotDeviceGroupKinds.SIBLING_WELCOME
        const val MAX_RELAYS = 16

        /** "Choosing the version": 3 when forwarding an inviter or a confirmation, else 2 with a generation, else 1. */
        fun choose(
            invitationGeneration: HexKey?,
            inviter: HexKey?,
            confirmed: Boolean,
        ): Int =
            when {
                inviter != null || (confirmed && invitationGeneration == null) -> 3
                invitationGeneration != null -> 2
                else -> 1
            }

        private fun putOptional32(
            w: TlsWriter,
            hex: HexKey?,
        ) {
            if (hex == null) {
                w.putUint8(0)
            } else {
                w.putUint8(1)
                w.putBytes(hex.hexToByteArray())
            }
        }

        private fun readOptional32(r: TlsReader): HexKey? =
            when (r.readUint8()) {
                0 -> null
                1 -> r.readBytes(32).toHexKey()
                else -> throw IllegalArgumentException("invalid presence byte")
            }

        /** The sibling Welcome, or null unless [content] decodes exactly as one of the three versions. */
        fun parse(content: String): SiblingWelcome? =
            try {
                val bytes = Base64.Default.decode(content)
                require(Base64.Default.encode(bytes) == content) { "not canonical base64" }
                val r = TlsReader(bytes)
                val version = r.readUint8()
                val from = r.readBytes(32).toHexKey()
                val to = r.readBytes(32).toHexKey()
                var generation: HexKey? = null
                var inviter: HexKey? = null
                var confirmed = false
                when (version) {
                    1 -> {}
                    2 -> generation = r.readBytes(32).toHexKey()
                    3 -> {
                        generation = readOptional32(r)
                        inviter = readOptional32(r)
                        confirmed =
                            when (r.readUint8()) {
                                0 -> false
                                1 -> true
                                else -> throw IllegalArgumentException("confirmed must be 0 or 1")
                            }
                    }
                    else -> throw IllegalArgumentException("unknown version")
                }
                val ref = r.readOpaqueVarInt().toHexKey()
                val welcome = readMlsMessage(r, WireFormat.WELCOME)
                val rr = TlsReader(r.readOpaqueVarInt())
                require(!r.hasRemaining) { "trailing bytes" }
                val relays = ArrayList<String>()
                while (rr.hasRemaining) {
                    val url = rr.readOpaqueVarInt()
                    require(url.size in 1..NostrRoutingV1.MAX_RELAY_URL_BYTES) { "relay URL out of bounds" }
                    relays.add(url.decodeToString(throwOnInvalidSequence = true))
                }
                SiblingWelcome(version, from, to, generation, inviter, confirmed, ref, welcome, relays)
            } catch (e: Exception) {
                null
            }
    }
}

/**
 * Kind 477, the post-link chat inventory (`device-group.md` "Post-link chat inventory", #511): the
 * approver's report of which chats a newly linked device can expect, as SHA-256 tokens of the link's
 * `KeyPackageRef` and each chat's MLS group id, sorted and paged by 128. Optional and advisory.
 */
data class LinkChatInventory(
    val to: HexKey,
    val link: HexKey,
    val revision: Long,
    val expiresAt: Long,
    val total: Long,
    val page: Long,
    /** The 32-byte tokens on this page, lowercase hex. */
    val chats: List<HexKey>,
) {
    init {
        require(isSlotHex(to)) { "to is a slot" }
        require(link.length % 2 == 0 && link.length / 2 in 1..64 && LOWER_HEX.matches(link)) { "link is a KeyPackageRef" }
        require(revision in 1..U32_MAX && total in 0..U32_MAX && page in 0..U32_MAX && expiresAt >= 0) { "inventory numbers out of range" }
        require(chats.size <= PAGE_SIZE && chats.all { isSlotHex(it) }) { "a page holds at most $PAGE_SIZE tokens" }
    }

    fun content(): String = """{"v":1,"to":"$to","link":"$link","revision":$revision,"expires_at":$expiresAt,"total":$total,"page":$page,"chats":"${chats.joinToString("")}"}"""

    companion object {
        const val KIND = MarmotDeviceGroupKinds.LINK_CHAT_INVENTORY
        const val PAGE_SIZE = 128
        const val MAX_CONTENT_BYTES = 8704
        const val TOKEN_LABEL = "marmot.link-chat-inventory.v1"
        private const val U32_MAX = 0xffffffffL

        /** SHA-256 of the label, then the ref and the MLS group id, each with its QUIC varint length. */
        fun token(
            keyPackageRef: ByteArray,
            mlsGroupId: ByteArray,
        ): ByteArray {
            val w = TlsWriter()
            w.putBytes(TOKEN_LABEL.encodeToByteArray())
            w.putOpaqueVarInt(keyPackageRef)
            w.putOpaqueVarInt(mlsGroupId)
            return sha256(w.toByteArray())
        }

        /** The page, or null when [content] is not one: extra or duplicate fields, wrong types, uppercase hex. */
        fun parse(content: String): LinkChatInventory? =
            try {
                require(content.encodeToByteArray().size <= MAX_CONTENT_BYTES)
                val obj = MarmotJson.parseObject(content)
                require(obj.duplicateKeys.isEmpty())
                require(obj.keys == setOf("v", "to", "link", "revision", "expires_at", "total", "page", "chats"))

                fun num(name: String): Long {
                    val p = obj.element(name) as JsonPrimitive
                    require(!p.isString && Regex("^(0|[1-9][0-9]*)$").matches(p.content))
                    return p.content.toLong()
                }

                fun str(name: String): String {
                    val p = obj.element(name) as JsonPrimitive
                    require(p.isString && LOWER_HEX.matches(p.content))
                    return p.content
                }
                require(num("v") == 1L)
                val chats = str("chats")
                require(chats.length % 64 == 0)
                LinkChatInventory(str("to"), str("link"), num("revision"), num("expires_at"), num("total"), num("page"), chats.chunked(64))
            } catch (e: Exception) {
                null
            }
    }
}
