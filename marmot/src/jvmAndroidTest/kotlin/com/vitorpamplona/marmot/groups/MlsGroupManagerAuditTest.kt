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
package com.vitorpamplona.marmot.groups

import com.vitorpamplona.marmot.mip01Groups.MarmotGroupData
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.mls.framing.ContentType
import com.vitorpamplona.mls.framing.MlsMessage
import com.vitorpamplona.mls.framing.PrivateMessage
import com.vitorpamplona.mls.framing.WireFormat
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.schedule.KeySchedule
import com.vitorpamplona.mls.schedule.SecretTree
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The library audit's confirming cases for [MlsGroupManager]: a former epoch's application
 * message is opened by mls-kmp's verified path and attributed in that epoch's tree, and a
 * Welcome for a group this device is a live member of never replaces that group.
 */
class MlsGroupManagerAuditTest {
    private val groupId = "b".repeat(64)

    private fun kp(name: String) = MlsGroup.create(name.encodeToByteArray(), policy = MarmotGroupPolicy).createKeyPackage(name.encodeToByteArray(), ByteArray(0))

    private suspend fun aliceGroup(manager: MlsGroupManager) = manager.createGroup(groupId, "alice".encodeToByteArray(), initialExtensions = listOf(MarmotGroupData(nostrGroupId = groupId, name = "x").toExtension()))

    /**
     * A PrivateMessage carol seals with epoch N's secrets alone, naming alice's leaf 0 as its
     * sender, with a zero signature: what any member who held epoch N can build.
     */
    private fun forgeFromLeafZero(group: MlsGroup): ByteArray {
        val rs = group.retainedSecrets()
        val st = SecretTree(rs.encryptionSecret, rs.leafCount)
        val kng = st.applicationKeyNonceForGeneration(0, 7)
        val pmc =
            TlsWriter()
                .apply {
                    putOpaqueVarInt("forged by carol".encodeToByteArray())
                    putOpaqueVarInt(ByteArray(64))
                }.toByteArray()
        val gid = group.groupId
        val aad =
            TlsWriter()
                .apply {
                    putOpaqueVarInt(gid)
                    putUint64(rs.epoch)
                    putUint8(ContentType.APPLICATION.value)
                    putOpaqueVarInt(ByteArray(0))
                }.toByteArray()
        val ct = MlsCryptoProvider.aeadEncrypt(kng.key, kng.nonce, aad, pmc)
        val sample = ct.copyOfRange(0, minOf(ct.size, MlsCryptoProvider.HASH_OUTPUT_LENGTH))
        val sdKey = MlsCryptoProvider.expandWithLabel(rs.senderDataSecret, "key", sample, MlsCryptoProvider.AEAD_KEY_LENGTH)
        val sdNonce = MlsCryptoProvider.expandWithLabel(rs.senderDataSecret, "nonce", sample, MlsCryptoProvider.AEAD_NONCE_LENGTH)
        val sd =
            TlsWriter()
                .apply {
                    putUint32(0)
                    putUint32(7)
                    putBytes(ByteArray(4))
                }.toByteArray()
        val sdAad =
            TlsWriter()
                .apply {
                    putOpaqueVarInt(gid)
                    putUint64(rs.epoch)
                    putUint8(ContentType.APPLICATION.value)
                }.toByteArray()
        val esd = MlsCryptoProvider.aeadEncrypt(sdKey, sdNonce, sdAad, sd)
        val pm = PrivateMessage(gid, rs.epoch, ContentType.APPLICATION, ByteArray(0), esd, ct)
        return MlsMessage(wireFormat = WireFormat.PRIVATE_MESSAGE, payload = pm.toTlsBytes()).toTlsBytes()
    }

    @Test
    fun aRemovedMemberCannotForgeAnotherMembersMessageInAFormerEpoch() =
        runBlocking<Unit> {
            val alice = MlsGroupManager(InMemoryGroupStateStore())
            val bob = MlsGroupManager(InMemoryGroupStateStore())
            val carol = MlsGroupManager(InMemoryGroupStateStore())
            aliceGroup(alice)
            val bobKp = kp("bob")
            val addBob = alice.addMember(groupId, bobKp.keyPackage.toTlsBytes())
            bob.processWelcome(addBob.welcomeBytes!!, bobKp, groupId)
            val carolKp = kp("carol")
            val addCarol = alice.addMember(groupId, carolKp.keyPackage.toTlsBytes())
            bob.processFramedCommit(groupId, addCarol.framedCommitBytes)
            carol.processWelcome(addCarol.welcomeBytes!!, carolKp, groupId)

            val cg = carol.getGroup(groupId)!!
            val forged = forgeFromLeafZero(cg)

            val remove = alice.removeMember(groupId, cg.leafIndex)
            bob.processFramedCommit(groupId, remove.framedCommitBytes)

            assertFailsWith<Exception> { bob.decrypt(groupId, forged) }
            assertFailsWith<Exception> { bob.decryptAndAttribute(groupId, forged) }
        }

    @Test
    fun aLateMessageOpensOnceAndNamesTheSenderOfItsOwnEpoch() =
        runBlocking<Unit> {
            val alice = MlsGroupManager(InMemoryGroupStateStore())
            val bobStore = InMemoryGroupStateStore()
            val bob = MlsGroupManager(bobStore)
            val carol = MlsGroupManager(InMemoryGroupStateStore())
            aliceGroup(alice)
            val bobKp = kp("bob")
            val addBob = alice.addMember(groupId, bobKp.keyPackage.toTlsBytes())
            bob.processWelcome(addBob.welcomeBytes!!, bobKp, groupId)
            val carolKp = kp("carol")
            val addCarol = alice.addMember(groupId, carolKp.keyPackage.toTlsBytes())
            bob.processFramedCommit(groupId, addCarol.framedCommitBytes)
            carol.processWelcome(addCarol.welcomeBytes!!, carolKp, groupId)
            val carolLeaf = carol.getGroup(groupId)!!.leafIndex

            // Carol speaks in epoch N; the message reaches Bob only after she is removed and Dave
            // takes her leaf.
            val late = carol.encrypt(groupId, "carol in epoch N".encodeToByteArray())
            bob.processFramedCommit(groupId, alice.removeMember(groupId, carolLeaf).framedCommitBytes)
            val daveKp = kp("dave")
            bob.processFramedCommit(groupId, alice.addMember(groupId, daveKp.keyPackage.toTlsBytes()).framedCommitBytes)
            assertEquals("dave".encodeToByteArray().toHexKey(), bob.memberIdentityHex(groupId, carolLeaf))

            val opened = bob.decryptAndAttribute(groupId, late)
            assertContentEquals("carol in epoch N".encodeToByteArray(), opened.message.content)
            assertEquals(carolLeaf, opened.message.senderLeafIndex)
            assertEquals("carol".encodeToByteArray().toHexKey(), opened.senderIdentityHex)

            // The epoch's ratchet moved: the same ciphertext does not open twice, not even after a restart.
            assertFailsWith<Exception> { bob.decrypt(groupId, late) }
            bob.flushReceivedState()
            val restarted = MlsGroupManager(bobStore).also { it.restoreAll() }
            assertFailsWith<Exception> { restarted.decrypt(groupId, late) }
        }

    @Test
    fun aReplayedWelcomeDoesNotRewindALiveGroup() =
        runBlocking<Unit> {
            val alice = MlsGroupManager(InMemoryGroupStateStore())
            val bobStore = InMemoryGroupStateStore()
            val bob = MlsGroupManager(bobStore)
            aliceGroup(alice)
            val bobKp = kp("bob")
            val addBob = alice.addMember(groupId, bobKp.keyPackage.toTlsBytes())
            bob.processWelcome(addBob.welcomeBytes!!, bobKp, null)
            val joinEpoch = bob.getGroup(groupId)!!.epoch
            bob.processFramedCommit(groupId, alice.commit(groupId).framedCommitBytes)
            bob.processFramedCommit(groupId, alice.commit(groupId).framedCommitBytes)

            // The same Welcome again: a relay redelivery after a restart, with no h tag.
            val refused = assertFailsWith<MarmotAlreadyMemberException> { bob.processWelcome(addBob.welcomeBytes!!, bobKp, null) }
            assertEquals(groupId, refused.nostrGroupId)
            assertEquals(joinEpoch + 2, bob.getGroup(groupId)!!.epoch)
            assertEquals(joinEpoch + 2, MlsGroupManager(bobStore).also { it.restoreAll() }.getGroup(groupId)!!.epoch)
        }

    @Test
    fun aWelcomeStillRejoinsAGroupThisDeviceWasRemovedFrom() =
        runBlocking<Unit> {
            val alice = MlsGroupManager(InMemoryGroupStateStore())
            val bob = MlsGroupManager(InMemoryGroupStateStore())
            aliceGroup(alice)
            val bobKp = kp("bob")
            val addBob = alice.addMember(groupId, bobKp.keyPackage.toTlsBytes())
            bob.processWelcome(addBob.welcomeBytes!!, bobKp, null)
            bob.processFramedCommit(groupId, alice.removeMember(groupId, bob.getGroup(groupId)!!.leafIndex).framedCommitBytes)
            assertFalse(bob.isMember(groupId))

            val again = kp("bob")
            bob.processWelcome(alice.addMember(groupId, again.keyPackage.toTlsBytes()).welcomeBytes!!, again, groupId)
            assertNotNull(bob.getGroup(groupId)?.takeIf { bob.isMember(groupId) })
        }

    /**
     * A retained-epoch record as 3.2 and earlier wrote it (RetainedEpochSecrets: epoch 3, the
     * sender-data and encryption secrets, leaf count 2, the exporter secret). Frozen: it must keep
     * loading, and its two decryption secrets are dropped from disk on the first restore.
     */
    @Test
    fun aRetainedRecordFromBefore330StillLoadsAndLosesItsDecryptionSecrets() =
        runBlocking<Unit> {
            val legacy = "0000000000000003" + "20" + "11".repeat(32) + "20" + "22".repeat(32) + "00000002" + "20" + "33".repeat(32)
            val stripped = "0000000000000003" + "00" + "00" + "00000002" + "20" + "33".repeat(32)
            val store = InMemoryGroupStateStore()
            aliceGroup(MlsGroupManager(store))
            store.saveRetainedEpochs(groupId, listOf(legacy.hexToByteArray()))

            val restored = MlsGroupManager(store).also { it.restoreAll() }

            assertEquals(listOf(stripped), store.loadRetainedEpochs(groupId).map { it.toHexKey() })
            val exporter = KeySchedule.mlsExporter("33".repeat(32).hexToByteArray(), "marmot", "group-event".encodeToByteArray(), 32)
            assertContentEquals(exporter, restored.retainedExporterSecrets(groupId).single())
        }

    @Test
    fun theLockFreeReadersStayConsistentWhileCommitsApply() =
        runBlocking<Unit> {
            val alice = MlsGroupManager(InMemoryGroupStateStore())
            aliceGroup(alice)
            val done = AtomicBoolean(false)
            val reader =
                async(Dispatchers.Default) {
                    var reads = 0
                    while (!done.get()) {
                        alice.retainedExporterSecrets(groupId)
                        alice.exporterSecret(groupId)
                        alice.memberIdentityHex(groupId, 0)
                        alice.mediaExporterSecretAt(groupId, 1)
                        alice.activeGroupIds()
                        reads++
                    }
                    reads
                }
            repeat(60) { alice.commit(groupId) }
            done.set(true)
            assertTrue(reader.await() > 0)
            assertEquals(MlsGroupManager.EPOCH_RETENTION_WINDOW, alice.retainedExporterSecrets(groupId).size)
            assertContentEquals(alice.getGroup(groupId)!!.exporterSecret("marmot", "group-event".encodeToByteArray(), 32), alice.exporterSecret(groupId))
        }
}
