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
@file:OptIn(InternalMlsApi::class)

package com.vitorpamplona.marmot.appComponents

import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.groups.currentGroupState
import com.vitorpamplona.mls.InternalMlsApi
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.group.PendingProposal
import com.vitorpamplona.mls.tree.Extension
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith

/**
 * A commit or Welcome whose GroupContext carries bytes a known app component cannot decode is
 * refused, as MDK refuses it; an id this client does not know stays opaque. Without the check the
 * group applied the junk and failed later, wherever the component was read.
 */
class GroupContextComponentsTest {
    private val aliceKeys = TestAccount()
    private val bobKeys = TestAccount()
    private val aliceAccount = aliceKeys.identity
    private val bobAccount = bobKeys.identity

    /** One byte no component of ours decodes as a whole value. */
    private val junk = byteArrayOf(0x7f)

    private val knownIds =
        listOf(
            AppComponentIds.GROUP_PROFILE_V1,
            AppComponentIds.GROUP_BLOSSOM_IMAGE_V1,
            AppComponentIds.ADMIN_POLICY_V1,
            AppComponentIds.NOSTR_ROUTING_V1,
            AppComponentIds.MESSAGE_RETENTION_V1,
            AppComponentIds.GROUP_AVATAR_URL_V1,
            AppComponentIds.GROUP_ENCRYPTED_MEDIA_V2,
            AppComponentIds.GROUP_LIFECYCLE_V1,
        )

    /** Marmot's rules but none of the component checks: a sender that writes what it likes. */
    private object CarelessPolicy : MlsGroupPolicy by MarmotGroupPolicy {
        override fun validateResultingState(
            parentExtensions: List<Extension>,
            proposals: List<PendingProposal>,
            committerLeafIndex: Int,
            resulting: GroupView,
        ) {}

        override fun validateJoin(group: GroupView) {}

        override fun validateJoin(
            group: GroupView,
            groupInfoSigner: Int,
            groupInfoExtensions: List<Extension>,
        ) {}
    }

    private fun MlsGroup.bobKeyPackage() =
        bobKeys.provenLeaf().let { leaf ->
            createKeyPackage(bobAccount, ByteArray(0), leafSignatureKeyPair = leaf.signatureKeyPair, leafExtensions = leaf.leafExtensions, capabilities = MarmotCapabilities.currentProfileLeaf())
        }

    private fun aliceGroup(policy: MlsGroupPolicy): MlsGroup {
        val leaf = aliceKeys.provenLeaf()
        val group =
            MlsGroup.create(
                aliceAccount,
                signingKey = leaf.signatureKeyPair.privateKey,
                leafExtensions = leaf.leafExtensions,
                capabilities = MarmotCapabilities.currentProfileLeaf(),
                policy = policy,
            )
        val dictionary =
            MarmotGroupState.buildDictionary(
                adminPolicy = AdminPolicyV1.of(listOf(aliceAccount)),
                routing = NostrRoutingV1.of(ByteArray(32) { 0x5a }, listOf("wss://relay.example")),
                profile = GroupProfileV1("Interop", ""),
            )
        group.proposeGroupContextExtensions(listOf(dictionary.toExtension()))
        group.commit()
        return group
    }

    @Test
    fun aCommitWritingUndecodableBytesUnderAKnownIdIsRefused() {
        for (id in knownIds) {
            val alice = aliceGroup(MarmotGroupPolicy)
            alice.proposeAppDataUpdate(id, junk)
            // Refused, here or by an earlier rule that reads the same component (the admin policy).
            assertFails("junk under ${AppComponentIds.toHex(id)}") { alice.commit() }
        }
    }

    @Test
    fun aReceivedCommitWritingUndecodableBytesIsRefusedAndLeavesTheGroupAsItWas() {
        val alice = aliceGroup(CarelessPolicy)
        val bobBundle = alice.bobKeyPackage()
        val add = alice.addMember(bobBundle.keyPackage.toTlsBytes())
        val bob = MlsGroup.processWelcome(add.welcomeBytes!!, bobBundle, policy = MarmotGroupPolicy)
        val epoch = bob.epoch

        alice.proposeAppDataUpdate(AppComponentIds.GROUP_PROFILE_V1, junk)
        val commit = alice.commit()

        assertFailsWith<IllegalStateException> { bob.processFramedCommit(commit.framedCommitBytes) }
        assertEquals(epoch, bob.epoch)
        assertEquals("Interop", bob.currentGroupState().profile?.name)
    }

    @Test
    fun aWelcomeInstallingUndecodableBytesIsRefused() {
        val alice = aliceGroup(CarelessPolicy)
        alice.proposeAppDataUpdate(AppComponentIds.GROUP_LIFECYCLE_V1, junk)
        alice.commit()
        val bobBundle = alice.bobKeyPackage()
        val add = alice.addMember(bobBundle.keyPackage.toTlsBytes())

        assertFailsWith<IllegalStateException> { MlsGroup.processWelcome(add.welcomeBytes!!, bobBundle, policy = MarmotGroupPolicy) }
    }

    @Test
    fun anUnknownIdStaysOpaque() {
        val alice = aliceGroup(MarmotGroupPolicy)
        alice.proposeAppDataUpdate(0x9001, junk)
        alice.commit()
        assertContentEquals(junk, alice.appDataDictionary()[0x9001])
    }

    @Test
    fun groupContextStateIsRefusedForLeafOnlyIds() {
        assertFailsWith<IllegalStateException> { GroupContextComponents.validate(AppComponentIds.SAFE_AAD, ByteArray(1)) }
        assertFailsWith<IllegalStateException> { GroupContextComponents.validate(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2, ByteArray(1)) }
    }

    @Test
    fun validBytesPass() {
        GroupContextComponents.validate(AppComponentIds.GROUP_PROFILE_V1, GroupProfileV1("A", "B").encode())
        GroupContextComponents.validate(AppComponentIds.GROUP_LIFECYCLE_V1, GroupLifecycleV1.DISBANDED.encode())
    }
}
