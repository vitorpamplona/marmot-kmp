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

import com.vitorpamplona.marmot.appComponents.EncryptedMediaPolicyV2
import com.vitorpamplona.marmot.appComponents.EncryptedMediaReferenceV2
import com.vitorpamplona.marmot.appComponents.EncryptedMediaV2
import com.vitorpamplona.marmot.appComponents.MediaLocatorV2
import com.vitorpamplona.marmot.groups.MarmotEpochMovedException
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull

/**
 * `features/encrypted-media.md` keys an attachment to the epoch of the message
 * that carries it. These pin that a message keeps resolving to its OWN epoch's
 * media key after later commits move the group on, after those commits push the
 * epoch out of the retained window, and after a restart.
 */
class MarmotMediaEpochKeyTest {
    private val nostrGroupId = "d".repeat(64)

    private class Fixture(
        val signer: NostrSignerInternal = NostrSignerInternal(KeyPair()),
        val mlsStore: SnapshotStateStore = SnapshotStateStore(),
        val messageStore: SnapshotMessageStore = SnapshotMessageStore(),
        val bundles: SnapshotBundleStore = SnapshotBundleStore(),
    ) {
        val manager = MarmotManager(signer, mlsStore, messageStore, bundles, publisher = ACCEPTING_RELAY)

        fun restarted() = Fixture(signer, mlsStore, messageStore, bundles)
    }

    @Test
    fun `an attachment keeps the key of its own epoch after the group moves on`() =
        runBlocking {
            val f = Fixture()
            f.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))

            val keyAtSend = f.manager.mediaExporterSecret(nostrGroupId)
            val plaintext = "a marmot in the snow".encodeToByteArray()
            val encrypted = EncryptedMediaV2.encrypt(plaintext, keyAtSend, "image/jpeg", "marmot.jpg")
            val sent = f.manager.buildTextMessage(nostrGroupId, "picture")

            // More commits than the retained-epoch window holds, so the send
            // epoch's exporter secret is gone from the MLS state itself.
            repeat(8) { i -> f.manager.setGroupProfile(nostrGroupId, "name $i", "") }
            assertFalse(keyAtSend.contentEquals(f.manager.mediaExporterSecret(nostrGroupId)))

            val resolved = assertNotNull(f.manager.mediaSecretForMessage(nostrGroupId, sent.innerEvent.id))
            assertContentEquals(keyAtSend, resolved)
            assertContentEquals(plaintext, f.manager.decryptMedia(nostrGroupId, encrypted.referenceFor(), encrypted.ciphertext, resolved))

            val again = f.restarted()
            again.manager.restoreAll()
            assertContentEquals(keyAtSend, again.manager.mediaSecretForMessage(nostrGroupId, sent.innerEvent.id))
        }

    /**
     * An upload takes long enough for a commit to land before the message carrying it is sent. Sent
     * pinned to the upload's epoch it goes out there, or not at all: in the next epoch no receiver
     * derives the key that encrypted it.
     */
    @Test
    fun `media is sent in the epoch that encrypted it or not at all`() =
        runBlocking {
            val f = Fixture()
            f.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))

            val first = f.manager.encryptMediaForSend(nostrGroupId, "one".encodeToByteArray(), "image/jpeg", "marmot.jpg")
            assertEquals(
                f.manager.groupManager
                    .getGroup(nostrGroupId)!!
                    .epoch,
                first.epoch,
            )
            assertContentEquals(f.manager.mediaExporterSecret(nostrGroupId), f.manager.mediaUploadKey(nostrGroupId)!!.mediaSecret)
            val sent = f.manager.buildMediaMessage(nostrGroupId, first.result.referenceFor(), sourceEpoch = first.epoch)
            assertEquals(first.epoch, sent.outbound.epoch)

            val stale = f.manager.encryptMediaForSend(nostrGroupId, "two".encodeToByteArray(), "image/jpeg", "marmot.jpg")
            f.manager.setGroupProfile(nostrGroupId, "moved on", "")
            val refused =
                assertFailsWith<MarmotEpochMovedException> {
                    f.manager.buildMediaMessage(nostrGroupId, stale.result.referenceFor(), sourceEpoch = stale.epoch)
                }
            assertEquals(stale.epoch, refused.expected)
            assertEquals(stale.epoch + 1, refused.current)
        }

    private fun EncryptedMediaV2.EncryptionResult.referenceFor() =
        EncryptedMediaReferenceV2(
            locators = listOf(MediaLocatorV2(EncryptedMediaPolicyV2.INITIAL_LOCATOR_KIND, "https://blossom.invalid/x")),
            ciphertextSha256 = ciphertextSha256,
            plaintextSha256 = plaintextSha256,
            nonce = nonce,
            mediaType = "image/jpeg",
            filename = "marmot.jpg",
        )
}
