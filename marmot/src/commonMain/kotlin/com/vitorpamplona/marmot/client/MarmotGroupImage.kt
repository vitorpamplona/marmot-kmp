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
package com.vitorpamplona.marmot.client

import androidx.compose.runtime.Immutable
import com.vitorpamplona.crypto.SymmetricCipher
import com.vitorpamplona.marmot.appComponents.GroupBlossomImageCrypto
import com.vitorpamplona.marmot.appComponents.GroupBlossomImageV1
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupImageCipher
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray

/**
 * The parameters needed to fetch and decrypt a Marmot group's avatar image.
 *
 * The encrypted blob is content-addressed on Blossom by [hash]. How [key] and
 * [nonce] open it depends on where the group keeps its avatar, and the two
 * schemes are not interchangeable:
 *
 * - [Scheme.CURRENT_PROFILE], component `0x8002`
 *   ([com.vitorpamplona.marmot.appComponents.GroupBlossomImageCrypto]): [key] IS
 *   the ChaCha20-Poly1305 key and [mediaType] is bound into the AAD.
 * - [Scheme.MIP01], the legacy `marmot_group_data` extension
 *   ([com.vitorpamplona.marmot.mip01Groups.MarmotGroupImageEncryption]): [key] is
 *   an HKDF seed and the AAD is empty.
 *
 * Use [cipher] rather than picking one: decrypting a `0x8002` blob with the MIP-01
 * scheme (or the reverse) fails for every image another client uploaded.
 */
@Immutable
class MarmotGroupImage(
    /** SHA-256 (hex) of the encrypted blob — the Blossom content hash. */
    val hash: HexKey,
    /** The AEAD key ([Scheme.CURRENT_PROFILE]) or the HKDF seed it is derived from ([Scheme.MIP01]). */
    val key: ByteArray,
    /** 12-byte ChaCha20-Poly1305 nonce. */
    val nonce: ByteArray,
    val scheme: Scheme = Scheme.MIP01,
    /** Media type of the decrypted image; present for [Scheme.CURRENT_PROFILE], absent for MIP-01. */
    val mediaType: String? = null,
) {
    enum class Scheme { CURRENT_PROFILE, MIP01 }

    /** The cipher that opens this blob, verifying [hash] first for [Scheme.CURRENT_PROFILE]. */
    fun cipher(): SymmetricCipher =
        when (scheme) {
            Scheme.CURRENT_PROFILE ->
                GroupBlossomImageCrypto.cipher(
                    GroupBlossomImageV1(
                        imageHash = hash.hexToByteArray(),
                        imageKey = key,
                        imageNonce = nonce,
                        // Not needed to decrypt; the component requires all four fields together.
                        imageUploadKey = ByteArray(GroupBlossomImageV1.KEY_SIZE),
                        mediaType = mediaType,
                    ),
                )

            Scheme.MIP01 -> MarmotGroupImageCipher(key, nonce)
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MarmotGroupImage) return false
        return hash == other.hash &&
            key.contentEquals(other.key) &&
            nonce.contentEquals(other.nonce) &&
            scheme == other.scheme &&
            mediaType == other.mediaType
    }

    override fun hashCode(): Int {
        var result = hash.hashCode()
        result = 31 * result + key.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + scheme.hashCode()
        result = 31 * result + (mediaType?.hashCode() ?: 0)
        return result
    }
}
