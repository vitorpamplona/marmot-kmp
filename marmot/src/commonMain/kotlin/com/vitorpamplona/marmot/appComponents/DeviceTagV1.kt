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

import com.vitorpamplona.crypto.chacha.ChaCha20Poly1305
import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.tree.LeafNode
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * `marmot.member.device-tag.v1` (`0x800f`, draft): the LeafNode entry that tells an account's linked
 * devices which of the account's leaves belongs to which device (`app-components/device-tag-v1.md`;
 * MDK `traits/src/app_components/device_tag.rs`, `cgka-engine/src/device_tag.rs`).
 *
 * ```text
 * struct { opaque nonce[12]; opaque sealed<1..255>; } DeviceTagV1;
 * struct { opaque slot[32]; opaque signature<1..255>; } DeviceTagContentV1;
 * struct { opaque slot[32]; opaque leaf_signature_key<V>; } DeviceTagSignedContentV1;
 * sealed = ChaCha20-Poly1305(leaf_tag_key, nonce, DeviceTagContentV1, aad = leaf_signature_key)
 * signature = SignWithLabel(tag key, "Marmot DeviceTag", DeviceTagSignedContentV1)
 * ```
 *
 * A tag never makes anything invalid: to a reader, one that does not decode, open or verify is the same
 * as no tag. Only the account's devices hold `leaf_tag_key`; everyone else sees opaque bytes. No group
 * may require `0x800f`.
 */
class DeviceTagV1(
    val nonce: ByteArray,
    val sealed: ByteArray,
) {
    init {
        require(nonce.size == NONCE_SIZE) { "device tag nonce must be $NONCE_SIZE bytes" }
        require(sealed.size in 1..MAX_BYTES) { "device tag sealed bytes must be 1 to $MAX_BYTES bytes" }
    }

    fun encode(): ByteArray {
        val writer = TlsWriter()
        writer.putBytes(nonce)
        writer.putOpaqueVarInt(sealed)
        return writer.toByteArray()
    }

    /** Who a leaf belongs to, as one device of the account reads its tag. */
    sealed class Claim {
        /** A device the roster lists, whose `tag_signature_key` verified the tag. */
        data class Device(
            val slot: HexKey,
        ) : Claim()

        /** A `removed` record that keeps the slot's key, which verified the tag. */
        data class RemovedSlot(
            val slot: HexKey,
        ) : Claim()

        /** No entry, one that does not open or verify, or a slot the roster holds no key for. */
        data object Unclaimed : Claim()
    }

    companion object {
        const val COMPONENT_ID = AppComponentIds.DEVICE_TAG_V1
        const val NONCE_SIZE = 12
        const val SLOT_SIZE = 32
        const val MAX_BYTES = 255
        const val SIGN_LABEL = "Marmot DeviceTag"

        fun decode(bytes: ByteArray): DeviceTagV1 {
            val reader = TlsReader(bytes)
            val nonce = reader.readBytes(NONCE_SIZE)
            val sealed = reader.readOpaqueVarInt()
            require(!reader.hasRemaining) { "device tag has trailing bytes" }
            return DeviceTagV1(nonce, sealed)
        }

        /** `DeviceTagSignedContentV1`, the bytes the tag signature covers. */
        fun signedContent(
            slot: ByteArray,
            leafSignatureKey: ByteArray,
        ): ByteArray {
            require(slot.size == SLOT_SIZE) { "device tag slot must be $SLOT_SIZE bytes" }
            val writer = TlsWriter()
            writer.putBytes(slot)
            writer.putOpaqueVarInt(leafSignatureKey)
            return writer.toByteArray()
        }

        /** `DeviceTagContentV1`. */
        fun content(
            slot: ByteArray,
            signature: ByteArray,
        ): ByteArray {
            require(slot.size == SLOT_SIZE) { "device tag slot must be $SLOT_SIZE bytes" }
            require(signature.size in 1..MAX_BYTES) { "device tag signature must be 1 to $MAX_BYTES bytes" }
            val writer = TlsWriter()
            writer.putBytes(slot)
            writer.putOpaqueVarInt(signature)
            return writer.toByteArray()
        }

        /**
         * The tag for a leaf whose signature key is [leafSignatureKey], naming [slot], signed with the
         * device's Ed25519 tag signature private key (ciphersuite `0x0001`; the 32-byte seed or the 64-byte seed-plus-public form) and sealed under the roster's
         * [leafTagKey]. [nonce] is fresh randomness for every tag; pass one only to reproduce a vector.
         */
        fun produce(
            leafTagKey: ByteArray,
            slot: ByteArray,
            leafSignatureKey: ByteArray,
            tagSigningKey: ByteArray,
            nonce: ByteArray = RandomInstance.bytes(NONCE_SIZE),
        ): DeviceTagV1 {
            require(leafTagKey.size == 32) { "leaf_tag_key must be 32 bytes" }
            // crypto-kmp signs with the 64-byte seed-plus-public form; accept the bare 32-byte seed too.
            val signingKey = if (tagSigningKey.size == 32) Ed25519.keyPairFromSeed(tagSigningKey).privateKey else tagSigningKey
            val signature = MlsCryptoProvider.signWithLabel(signingKey, SIGN_LABEL, signedContent(slot, leafSignatureKey))
            val sealed = ChaCha20Poly1305.encrypt(content(slot, signature), leafSignatureKey, nonce, leafTagKey)
            return DeviceTagV1(nonce, sealed)
        }

        /**
         * Opens [entry] (a leaf's raw `0x800f` value) under [leafTagKey] with the leaf's signature key as
         * aad: the slot it names and the signature, or null when it does not decode or open (step 1 of
         * "Reading tags").
         */
        fun open(
            entry: ByteArray,
            leafTagKey: ByteArray,
            leafSignatureKey: ByteArray,
        ): Pair<ByteArray, ByteArray>? =
            try {
                val tag = decode(entry)
                val plain = ChaCha20Poly1305.decrypt(tag.sealed, leafSignatureKey, tag.nonce, leafTagKey)
                val reader = TlsReader(plain)
                val slot = reader.readBytes(SLOT_SIZE)
                val signature = reader.readOpaqueVarInt()
                if (reader.hasRemaining || signature.isEmpty() || signature.size > MAX_BYTES) null else slot to signature
            } catch (e: Exception) {
                null
            }

        /** Whether [signature] over [slot] and the leaf key verifies under [tagSignatureKey]. */
        fun verifies(
            slot: ByteArray,
            signature: ByteArray,
            leafSignatureKey: ByteArray,
            tagSignatureKey: ByteArray,
        ): Boolean =
            try {
                MlsCryptoProvider.verifyWithLabel(tagSignatureKey, SIGN_LABEL, signedContent(slot, leafSignatureKey), signature)
            } catch (e: Exception) {
                false
            }

        /**
         * "Reading tags" against [roster]: a device the roster lists with a key that verifies, else a
         * `removed` record whose kept key verifies, else unclaimed. [entry] null means the leaf has none.
         * The caller only reads leaves whose credential identity is its own account's.
         */
        fun read(
            entry: ByteArray?,
            leafSignatureKey: ByteArray,
            roster: DeviceRosterV1,
        ): Claim {
            if (entry == null) return Claim.Unclaimed
            val (slot, signature) = open(entry, roster.leafTagKey.hexToByteArray(), leafSignatureKey) ?: return Claim.Unclaimed
            val slotHex = slot.toHexKey()
            roster.device(slotHex)?.tagSignatureKey?.let { key ->
                return if (verifies(slot, signature, leafSignatureKey, key.hexToByteArray())) Claim.Device(slotHex) else Claim.Unclaimed
            }
            roster.rejectedSlot(slotHex)?.takeIf { it.reason == RejectionReasonV1.REMOVED }?.tagSignatureKey?.let { key ->
                return if (verifies(slot, signature, leafSignatureKey, key.hexToByteArray())) Claim.RemovedSlot(slotHex) else Claim.Unclaimed
            }
            return Claim.Unclaimed
        }

        /** [read] on a LeafNode: its `0x800f` entry and its signature key. */
        fun read(
            leaf: LeafNode,
            roster: DeviceRosterV1,
        ): Claim = read(entryOf(leaf), leaf.signatureKey, roster)

        /** A leaf's raw `0x800f` entry, if it has one. */
        fun entryOf(leaf: LeafNode): ByteArray? = AppDataDictionary.fromExtensions(leaf.extensions)?.get(COMPONENT_ID)
    }
}
