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

import com.vitorpamplona.marmot.appComponents.AccountDevicesV1
import com.vitorpamplona.marmot.appComponents.CurrentProfileGroupFactory
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageUtils
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.quartz.marmot.mip00KeyPackages.KeyPackageEvent
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.EventTemplate
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.utils.TimeUtils
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `foundation/key-packages.md`, "Selection and lifecycle", and
 * `transports/nostr.md`, "Slot deletion": an inviter adds one leaf per fresh
 * KeyPackage of an account (at most 20), never one a held kind-5 request
 * withdrew, never one incompatible with the group.
 */
class MarmotInviteSelectionTest {
    private val account = KeyPair()
    private val signer = NostrSignerInternal(account)

    private fun device(supported: List<Int> = CurrentProfileGroupFactory.SUPPORTED_COMPONENTS) = MarmotManager(signer, SnapshotStateStore(), SnapshotMessageStore(), SnapshotBundleStore(), publisher = ACCEPTING_RELAY, supportedComponents = supported)

    private suspend fun keyPackages(count: Int) = (1..count).map { device().generateKeyPackageEvent(relays = emptyList()) }

    private suspend fun slotDeletion(
        event: KeyPackageEvent,
        createdAt: Long,
    ): Event =
        signer.sign(
            EventTemplate<Event>(
                createdAt = createdAt,
                kind = KeyPackageUtils.DELETION_KIND,
                tags = arrayOf(arrayOf("a", "${KeyPackageEvent.KIND}:${signer.pubKey}:${event.dTag()}"), arrayOf("k", "${KeyPackageEvent.KIND}")),
                content = "",
            ),
        )

    @Test
    fun everyDeviceOfTheAccountIsSelected() =
        runBlocking<Unit> {
            val found = keyPackages(3)
            val selected = KeyPackageUtils.selectAllForInvite(found, signer.pubKey)
            assertEquals(found.map { it.id }.toSet(), selected.map { it.id }.toSet())
        }

    @Test
    fun noMoreThanTwentyPerAccount() =
        runBlocking<Unit> {
            val found = keyPackages(KeyPackageUtils.MAX_PER_ACCOUNT + 1)
            assertEquals(KeyPackageUtils.MAX_PER_ACCOUNT, KeyPackageUtils.selectAllForInvite(found, signer.pubKey).size)
        }

    @Test
    fun aSlotDeletionWithdrawsThatSlotOnly() =
        runBlocking<Unit> {
            val (withdrawn, kept) = keyPackages(2)
            val deletion = slotDeletion(withdrawn, withdrawn.createdAt + 1)
            val selected = KeyPackageUtils.selectAllForInvite(listOf(withdrawn, kept, deletion), signer.pubKey)
            assertEquals(listOf(kept.id), selected.map { it.id })

            // A request older than the publication does not cover it.
            val stale = slotDeletion(withdrawn, withdrawn.createdAt - 10)
            assertEquals(2, KeyPackageUtils.selectAllForInvite(listOf(withdrawn, kept, stale), signer.pubKey).size)

            // Nor does one signed by somebody else.
            val forged =
                NostrSignerInternal(KeyPair()).sign<Event>(
                    EventTemplate(withdrawn.createdAt + 1, KeyPackageUtils.DELETION_KIND, arrayOf(arrayOf("a", "${KeyPackageEvent.KIND}:${signer.pubKey}:${withdrawn.dTag()}")), ""),
                )
            assertEquals(2, KeyPackageUtils.selectAllForInvite(listOf(withdrawn, kept, forged), signer.pubKey).size)
        }

    @Test
    fun anIncompatibleKeyPackageIsNeverSelected() =
        runBlocking<Unit> {
            val old = device(CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AccountDevicesV1.COMPONENT_ID).generateKeyPackageEvent(relays = emptyList())
            val current = device().generateKeyPackageEvent(relays = emptyList())
            val needsDevices = { kp: MlsKeyPackage -> AccountDevicesV1.COMPONENT_ID in AccountDevicesV1.advertised(kp.leafNode.extensions) }
            assertEquals(listOf(current.id), KeyPackageUtils.selectAllForInvite(listOf(old, current), signer.pubKey, compatible = needsDevices).map { it.id })
            // Even when it is the only one.
            assertTrue(KeyPackageUtils.selectAllForInvite(listOf(old), signer.pubKey, compatible = needsDevices).isEmpty())
        }

    @Test
    fun withNothingFreshTheSingleBestStillInvites() =
        runBlocking<Unit> {
            val found = keyPackages(3)
            // 31 days on: past freshness, within the KeyPackages' lifetime.
            val later = TimeUtils.now() + 31 * 24 * 3600
            val selected = KeyPackageUtils.selectAllForInvite(found, signer.pubKey, nowSeconds = later)
            assertEquals(1, selected.size)
        }

    @Test
    fun theGroupSaysWhichKeyPackagesItCanTake() =
        runBlocking<Unit> {
            val alice = MarmotManager(NostrSignerInternal(KeyPair()), SnapshotStateStore(), SnapshotMessageStore(), SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
            val groupId = "e".repeat(64)
            alice.createCurrentProfileGroup(groupId, listOf("wss://relay.invalid"))
            alice.addMembers(groupId, keyPackages(1), emptyList())
            assertTrue(alice.requiresAccountDevices(groupId))
            val old = device(CurrentProfileGroupFactory.SUPPORTED_COMPONENTS - AccountDevicesV1.COMPONENT_ID).generateKeyPackageEvent(relays = emptyList())
            val current = device().generateKeyPackageEvent(relays = emptyList())
            val selected = KeyPackageUtils.selectAllForInvite(listOf(old, current), signer.pubKey, compatible = alice.inviteCompatibility(groupId))
            assertEquals(listOf(current.id), selected.map { it.id })
        }
}
