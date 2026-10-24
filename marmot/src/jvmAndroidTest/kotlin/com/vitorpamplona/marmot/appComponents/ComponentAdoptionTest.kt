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

import com.vitorpamplona.marmot.TestGroupStateStore
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.groups.MlsGroupManager
import com.vitorpamplona.mls.InternalMlsApi
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `app-components/README.md`, "Enabling a Component in an Existing Group" (spec #439):
 * a member must advertise every component the group requires, a component may be
 * required only once every leaf advertises it, and a member refreshes a stale leaf
 * through the UpdatePath of its own commit. MDK checks the same on every staged commit.
 */
class ComponentAdoptionTest {
    private val nostrGroupId = ByteArray(32) { 0x42 }
    private val withoutMediaV2 = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AppComponentIds.GROUP_ENCRYPTED_MEDIA_V2

    private fun requiredOf(group: MlsGroup) = ComponentsList.supportedOrRequired(group.appDataDictionary())

    /** Alice's group, with Bob added from a KeyPackage that advertises [bobSupports]. */
    private fun twoMembers(bobSupports: List<Int>): Pair<MlsGroup, MlsGroup> =
        runBlocking {
            val alice = CurrentProfileGroupFactory.createGroup(NostrSignerInternal(KeyPair()), nostrGroupId, listOf("wss://relay.invalid"))
            val bobKp = CurrentProfileGroupFactory.createKeyPackage(NostrSignerInternal(KeyPair()), supportedComponents = bobSupports)
            val add = alice.addMember(bobKp.keyPackage.toTlsBytes())
            alice to MlsGroup.processWelcome(add.welcomeBytes!!, bobKp, policy = MarmotGroupPolicy)
        }

    @Test
    fun anAddOfAKeyPackageMissingARequiredComponentIsRefused(): Unit =
        runBlocking {
            val alice = CurrentProfileGroupFactory.createGroup(NostrSignerInternal(KeyPair()), nostrGroupId, listOf("wss://relay.invalid"))
            assertTrue(AppComponentIds.GROUP_LIFECYCLE_V1 in requiredOf(alice))
            val stale =
                CurrentProfileGroupFactory.createKeyPackage(
                    NostrSignerInternal(KeyPair()),
                    supportedComponents = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AppComponentIds.GROUP_LIFECYCLE_V1,
                )
            assertFailsWith<IllegalArgumentException> { alice.addMember(stale.keyPackage.toTlsBytes()) }
        }

    /**
     * Receivers refuse an UpdatePath leaf that drops a required component. The
     * committer must refuse it too, before merging: otherwise it moves to an
     * epoch no peer accepts and forks itself.
     */
    @Test
    fun aCommitThatStopsAdvertisingARequiredComponentIsRefusedByItsCommitter(): Unit =
        runBlocking {
            val alice = CurrentProfileGroupFactory.createGroup(NostrSignerInternal(KeyPair()), nostrGroupId, listOf("wss://relay.invalid"))
            assertTrue(AppComponentIds.GROUP_LIFECYCLE_V1 in requiredOf(alice))
            val mine = alice.members().first { it.first == alice.leafIndex }.second
            val dropped =
                AppDataDictionary
                    .fromExtensionsOrEmpty(mine.extensions)
                    .with(
                        ComponentsList.APP_COMPONENTS_ID,
                        ComponentsList.encode(CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AppComponentIds.GROUP_LIFECYCLE_V1),
                    )
            val epoch = alice.epoch
            alice.advertiseInNextCommit(
                MarmotCapabilities.currentProfileLeaf(),
                mine.extensions.filterNot { it.extensionType == AppDataDictionary.EXTENSION_TYPE } + dropped.toExtension(),
            )
            assertFailsWith<IllegalArgumentException> { alice.commit() }
            assertEquals(epoch, alice.epoch)
        }

    @Test
    fun aComponentCannotBeActivatedUntilEveryLeafAdvertisesIt() {
        val (alice, bob) = twoMembers(withoutMediaV2)

        fun proposeActivation(group: MlsGroup) {
            group.proposeAppDataUpdate(EncryptedMediaPolicyV2.COMPONENT_ID, EncryptedMediaPolicyV2.REFERENCE.encode())
            group.proposeAppDataUpdate(
                ComponentsList.APP_COMPONENTS_ID,
                ComponentsList.encode(requiredOf(group) + AppComponentIds.GROUP_ENCRYPTED_MEDIA_V2),
            )
        }

        // Staged on a clone, as MlsGroupManager does: a refused commit must not touch Alice.
        val attempt = MlsGroup.restore(alice.saveState(), MarmotGroupPolicy)
        proposeActivation(attempt)
        assertFailsWith<IllegalArgumentException>("Bob's leaf does not advertise 0x800b") { attempt.commit() }

        // Bob refreshes his leaf; Alice processes it through the UpdatePath check.
        val refreshed =
            runBlocking {
                val manager = MlsGroupManager(TestGroupStateStore())
                val gid = "42".repeat(32)
                manager.adoptGroup(gid, bob)
                assertEquals(setOf(AppComponentIds.GROUP_ENCRYPTED_MEDIA_V2), manager.ownLeafMissingComponents(gid))
                manager.stageLeafRefresh(gid)
            }
        alice.processFramedCommit(refreshed.result.framedCommitBytes)

        val clean = MlsGroup.restore(alice.saveState(), MarmotGroupPolicy)
        proposeActivation(clean)
        clean.commit()
        assertTrue(AppComponentIds.GROUP_ENCRYPTED_MEDIA_V2 in requiredOf(clean))
    }
}
