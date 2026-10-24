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

import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.marmot.appComponents.GroupBlossomImageCrypto
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupData
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupImageCipher
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupImageEncryption
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * A current-profile group keeps its avatar in `0x8002`, whose scheme is not
 * MIP-01's: the key is the AEAD key, the AAD binds the media type, and the upload
 * key is the Blossom secret key. Encrypting with MIP-01 and storing it in `0x8002`
 * produced avatars only Amethyst could read.
 */
class MarmotGroupImageSchemeTest {
    private val plaintext = "a picture of the group".encodeToByteArray()

    private fun manager() = MarmotManager(NostrSignerInternal(KeyPair()), SnapshotStateStore(), SnapshotMessageStore(), SnapshotBundleStore(), publisher = ACCEPTING_RELAY)

    @Test
    fun `a current-profile group uploads in the 0x8002 scheme a conformant client opens`() =
        runBlocking {
            val m = manager()
            val gid = "a".repeat(64)
            m.createCurrentProfileGroup(gid, listOf("wss://relay.invalid"))

            val plan = m.planGroupImageUpload(gid, "image/png")
            val ciphertext = plan.cipher.encrypt(plaintext)
            val component = plan.componentFor(sha256(ciphertext).toHexKey())

            // What any 0x8002 reader does.
            assertContentEquals(plaintext, GroupBlossomImageCrypto.decrypt(ciphertext, component))
            // The upload key is the Blossom secret itself, not a seed.
            assertContentEquals(plan.uploadSecretKey, component.imageUploadKey)
            // MIP-01 cannot open it, which is the bug this replaces.
            assertNull(MarmotGroupImageCipher(component.imageKey!!, component.imageNonce!!).decryptOrNull(ciphertext))

            m.setGroupImage(gid, component)
            val image = m.groupView(gid)!!.image!!
            assertEquals(MarmotGroupImage.Scheme.CURRENT_PROFILE, image.scheme)
            assertEquals("image/png", image.mediaType)
            assertContentEquals(plaintext, image.cipher().decrypt(ciphertext))
        }

    @Test
    fun `a legacy group keeps the MIP-01 scheme`() =
        runBlocking {
            val m = manager()
            val gid = "b".repeat(64)
            m.createGroup(gid, MarmotGroupData(nostrGroupId = gid, name = "legacy", relays = listOf("wss://relay.invalid")))

            val plan = m.planGroupImageUpload(gid, "image/png")
            val ciphertext = plan.cipher.encrypt(plaintext)
            val upload = plan.uploadFor(sha256(ciphertext).toHexKey())
            assertContentEquals(plaintext, MarmotGroupImageEncryption.decryptAny(ciphertext, upload.imageKey, upload.imageNonce))
            assertContentEquals(MarmotGroupImageEncryption.deriveUploadKeypairSecret(upload.imageUploadKey), plan.uploadSecretKey)
        }
}
