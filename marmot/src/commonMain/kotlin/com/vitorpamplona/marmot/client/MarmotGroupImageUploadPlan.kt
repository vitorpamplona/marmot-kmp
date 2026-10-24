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

import com.vitorpamplona.crypto.SymmetricCipher
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.marmot.appComponents.GroupBlossomImageCrypto
import com.vitorpamplona.marmot.appComponents.GroupBlossomImageV1
import com.vitorpamplona.marmot.appComponents.MarmotMediaType
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupImageCipher
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupImageEncryption
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.crypto.Nip01Crypto

/**
 * Key material for uploading a new group avatar, in one group's scheme.
 *
 * The two schemes store different things under the same field names, which is
 * why a front end must not mint these itself:
 *
 * - current profile (`0x8002`): `image_key` is the AEAD key, the AAD binds the
 *   media type, and `image_upload_key` is the Blossom-auth secret key itself;
 * - MIP-01 (`marmot_group_data`): both are HKDF seeds and the AAD is empty.
 *
 * Obtain one from `MarmotManager.planGroupImageUpload`.
 */
class MarmotGroupImageUploadPlan private constructor(
    /** Encrypts the plaintext image. */
    val cipher: SymmetricCipher,
    /** The secret key that signs the Blossom upload authorization. */
    val uploadSecretKey: ByteArray,
    private val imageKey: ByteArray,
    private val imageNonce: ByteArray,
    private val storedUploadKey: ByteArray,
    /** Media type of the plaintext; canonical for the current profile. */
    val mediaType: String,
) {
    /** The component to commit once the ciphertext was uploaded as [imageHash] (its SHA-256). */
    fun componentFor(imageHash: HexKey): GroupBlossomImageV1 =
        GroupBlossomImageV1(
            imageHash = imageHash.hexToByteArray(),
            imageKey = imageKey,
            imageNonce = imageNonce,
            imageUploadKey = storedUploadKey,
            mediaType = mediaType,
        )

    /** The same, in the shape the app's upload flow carries until it commits. */
    fun uploadFor(imageHash: HexKey): MarmotGroupIconUpload =
        MarmotGroupIconUpload(
            imageHash = imageHash,
            imageKey = imageKey,
            imageNonce = imageNonce,
            imageUploadKey = storedUploadKey,
            mediaType = mediaType,
        )

    companion object {
        /** `marmot.group.blossom.image.v1`: raw keys, media-type AAD. */
        fun currentProfile(mediaType: String): MarmotGroupImageUploadPlan {
            val canonical = MarmotMediaType.requireCanonical(mediaType)
            val imageKey = RandomInstance.bytes(GroupBlossomImageCrypto.KEY_LENGTH)
            val imageNonce = RandomInstance.bytes(GroupBlossomImageCrypto.NONCE_LENGTH)
            val uploadKey = Nip01Crypto.privKeyCreate()
            return MarmotGroupImageUploadPlan(
                cipher = GroupBlossomImageCrypto.encryptingCipher(imageKey, imageNonce, canonical),
                uploadSecretKey = uploadKey,
                imageKey = imageKey,
                imageNonce = imageNonce,
                storedUploadKey = uploadKey,
                mediaType = canonical,
            )
        }

        /** MIP-01 v2, for a legacy group: HKDF seeds, empty AAD. */
        fun mip01(mediaType: String): MarmotGroupImageUploadPlan {
            val cipher = MarmotGroupImageCipher.forNewImage()
            val seed = MarmotGroupImageEncryption.generateUploadKey()
            return MarmotGroupImageUploadPlan(
                cipher = cipher,
                uploadSecretKey = MarmotGroupImageEncryption.deriveUploadKeypairSecret(seed),
                imageKey = cipher.imageKey,
                imageNonce = cipher.imageNonce,
                storedUploadKey = seed,
                mediaType = mediaType,
            )
        }
    }
}
