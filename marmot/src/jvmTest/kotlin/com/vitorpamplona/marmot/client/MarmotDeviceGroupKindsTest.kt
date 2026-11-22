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

import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.marmot.features.deviceGroup.MarmotDeviceGroupKinds
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip01Core.signers.eventTemplate
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Device-group app events (`features/device-group.md`: kinds 457-461, 473,
 * 475-477) travel only in an account's own device group. A White Noise device
 * with device groups on (MDK 0.18) never sends one in a chat, and a receiver
 * ignores one there: no chat projects it. This client trusts no device group
 * yet, so every one it decrypts is ignored, and none is sent from here.
 */
class MarmotDeviceGroupKindsTest {
    private val nostrGroupId = "d".repeat(64)

    private class Device {
        val signer = NostrSignerInternal(KeyPair())
        val manager = MarmotManager(signer, SnapshotStateStore(), SnapshotMessageStore(), SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
    }

    private suspend fun rumor(
        device: Device,
        kind: Int,
        content: String,
    ): Event = RumorAssembler.assembleRumor<Event>(device.signer.pubKey, eventTemplate<Event>(kind = kind, description = content) {})

    private suspend fun pair(): Pair<Device, Device> {
        val alice = Device()
        val bob = Device()
        alice.manager.createCurrentProfileGroup(nostrGroupId = nostrGroupId, relays = listOf("wss://relay.invalid"), profile = GroupProfileV1("kinds", ""))
        val (_, welcomes) = alice.manager.addMembers(nostrGroupId, listOf(bob.manager.generateKeyPackageEvent(relays = emptyList())), emptyList())
        assertIs<MarmotIngestResult.JoinedGroup>(bob.manager.ingest(welcomes.single().giftWrapEvent))
        return alice to bob
    }

    @Test
    fun theKindsMatchTheRegistry() {
        assertEquals(listOf(457, 458, 459, 460, 461, 473, 475, 476, 477), MarmotDeviceGroupKinds.ALL.sorted())
        assertTrue(MarmotDeviceGroupKinds.isDeviceGroupKind(461))
        assertFalse(MarmotDeviceGroupKinds.isDeviceGroupKind(9))
        assertFalse(MarmotDeviceGroupKinds.isDeviceGroupKind(474))
    }

    @Test
    fun aDeviceGroupKindInAChatIsIgnoredAndNotStored() =
        runBlocking<Unit> {
            val (alice, bob) = pair()
            for (kind in MarmotDeviceGroupKinds.ALL) {
                // The bytes a client without the sender rule would publish.
                val outbound = alice.manager.outboundProcessor.buildGroupEvent(nostrGroupId, rumor(alice, kind, "{\"v\":1}"), null)
                val result = bob.manager.ingest(outbound.signedEvent)
                assertIs<MarmotIngestResult.Ignored>(result, "kind $kind")
            }
            assertTrue(bob.manager.loadStoredMessages(nostrGroupId).none { (Event.fromJsonOrNull(it)?.kind ?: 0) in MarmotDeviceGroupKinds.ALL })

            // Ordinary traffic still flows after them.
            val text = alice.manager.buildTextMessage(nostrGroupId, "hi")
            assertIs<MarmotIngestResult.Message>(bob.manager.ingest(text.outbound.signedEvent))
        }

    @Test
    fun aDeviceGroupKindIsNeverSentToAChat() =
        runBlocking<Unit> {
            val (alice, _) = pair()
            assertFailsWith<IllegalArgumentException> {
                alice.manager.buildGroupMessage(nostrGroupId, rumor(alice, MarmotDeviceGroupKinds.HEARTBEAT, "{\"v\":1}"))
            }
        }
}
