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

import com.vitorpamplona.marmot.appComponents.AppComponentIds
import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A Commit replaces the committer's own leaf through the UpdatePath. That leaf
 * is the SAME member with new key material, so everything the leaf says about
 * the member has to survive: its `capabilities`, and its extensions.
 *
 * Rebuilding from defaults instead cost us every invitation. A current-profile
 * leaf carries `marmot.member.account-identity-proof.v2` inside an
 * `app_data_dictionary` LEAF extension, and no proposal can put a leaf
 * extension back, so the first Commit silently demoted the creator out of the
 * current profile. Worse, the rebuilt leaf stopped advertising the
 * `app_data_dictionary` extension and `app_data_update` proposal that the
 * group's own `required_capabilities` demands, so the resulting tree failed
 * RFC 9420 leaf validation for every receiver: MDK's openmls reported
 * `LeafNodeValidation(UnsupportedExtensions)` and dropped the Welcome we had
 * just minted from that same commit.
 */
class CommitPreservesLeafIdentityTest {
    /** `app_data_update`, the proposal a current-profile group requires. */
    private val appDataUpdateProposalType = 0x0008

    private fun signer(seed: Byte) = NostrSignerInternal(KeyPair(ByteArray(32) { seed }))

    private suspend fun aCurrentProfileGroup(): MlsGroup =
        CurrentProfileGroupFactory.createGroup(
            signer = signer(0x11),
            nostrGroupId = ByteArray(32) { 0x22 },
            relays = listOf("wss://relay.example.com"),
            profile = GroupProfileV1("Interop", ""),
        )

    private fun MlsGroup.myLeaf() = members().firstOrNull { it.first == leafIndex }?.second

    @Test
    fun theCommitterLeafKeepsItsCurrentProfileCapabilities() =
        runBlocking<Unit> {
            val group = aCurrentProfileGroup()
            val before = assertNotNull(group.myLeaf()).capabilities

            val invitee = CurrentProfileGroupFactory.createKeyPackage(signer(0x33))
            group.proposeAdd(invitee.keyPackage.toTlsBytes())
            group.commit()

            val after = assertNotNull(group.myLeaf()).capabilities
            assertContains(after.extensions, AppDataDictionary.EXTENSION_TYPE)
            assertContains(after.proposals, appDataUpdateProposalType)
            assertTrue(before.extensions.all { it in after.extensions })
            assertTrue(before.proposals.all { it in after.proposals })
        }

    @Test
    fun theCommitterLeafKeepsItsAccountIdentityProof() =
        runBlocking<Unit> {
            val group = aCurrentProfileGroup()

            val invitee = CurrentProfileGroupFactory.createKeyPackage(signer(0x33))
            group.proposeAdd(invitee.keyPackage.toTlsBytes())
            group.commit()

            val leaf = assertNotNull(group.myLeaf())
            val dictionary =
                assertNotNull(
                    leaf.extensions.firstOrNull { it.extensionType == AppDataDictionary.EXTENSION_TYPE },
                )
            val decoded = AppDataDictionary.decode(dictionary.extensionData)
            assertNotNull(decoded[AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2])
        }

    /**
     * A signing-key rotation would carry the leaf's account identity proof
     * over to a new signature key it does not name, so in a current-profile
     * group the commit is refused before it is built, as every MDK member
     * would refuse it (`validate_staged_commit_account_identity_proofs`). A
     * current-profile self-update keeps its key (`stageLeafRefresh`).
     */
    @Test
    fun aSigningKeyRotationIsRefusedBecauseTheProofNamesTheOldKey() =
        runBlocking<Unit> {
            val group = aCurrentProfileGroup()
            val before = assertNotNull(group.myLeaf())

            group.proposeSigningKeyRotation()
            assertFailsWith<IllegalStateException> { group.commit() }

            assertEquals(0L, group.epoch)
            assertContentEquals(before.signatureKey, assertNotNull(group.myLeaf()).signatureKey)
        }
}
