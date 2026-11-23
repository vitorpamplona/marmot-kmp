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

import com.vitorpamplona.marmot.InMemoryIngestDedupStore
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The relay echo of an application message this device sent can never decrypt here: the sender's
 * ratchet generation was spent encrypting it. It used to come back as a "decrypts on no canonical
 * epoch" failure on every sync (`amy` printed one per own message per command) and counted toward
 * the desync detector, newer than the last message decrypted.
 */
class MarmotOwnEchoTest {
    private val nostrGroupId = "e".repeat(64)

    private class Device(
        val signer: NostrSignerInternal = NostrSignerInternal(KeyPair()),
        val state: SnapshotStateStore = SnapshotStateStore(),
        val messages: SnapshotMessageStore = SnapshotMessageStore(),
        val bundles: SnapshotBundleStore = SnapshotBundleStore(),
        val ingested: InMemoryIngestDedupStore = InMemoryIngestDedupStore(),
    ) {
        val manager = MarmotManager(signer, state, messages, bundles, publisher = ACCEPTING_RELAY, ingestDedupStore = ingested)

        /** The same account and stores in a fresh process, as each `amy` command is. */
        suspend fun restarted(): Device = Device(signer, state, messages, bundles, ingested).also { it.manager.restoreAll() }
    }

    private suspend fun pair(): Pair<Device, Device> {
        val alice = Device()
        val bob = Device()
        alice.manager.createCurrentProfileGroup(nostrGroupId = nostrGroupId, relays = listOf("wss://relay.invalid"), profile = GroupProfileV1("echo", ""))
        val (_, welcomes) = alice.manager.addMembers(nostrGroupId, listOf(bob.manager.generateKeyPackageEvent(relays = emptyList())), emptyList())
        assertIs<MarmotIngestResult.JoinedGroup>(bob.manager.ingest(welcomes.single().giftWrapEvent))
        return alice to bob
    }

    @Test
    fun theEchoOfOurOwnMessageIsNotAFailure() =
        runBlocking<Unit> {
            val (alice, bob) = pair()
            val sent =
                alice.manager
                    .buildTextMessage(nostrGroupId, "hi")
                    .outbound.signedEvent

            assertIs<MarmotIngestResult.Ignored>(alice.manager.ingest(sent))
            assertIs<MarmotIngestResult.Message>(bob.manager.ingest(sent), "the other member still reads it")
        }

    @Test
    fun theEchoIsStillRecognisedAfterARestart() =
        runBlocking<Unit> {
            val (alice, _) = pair()
            val sent =
                alice.manager
                    .buildTextMessage(nostrGroupId, "hi")
                    .outbound.signedEvent

            val result = alice.restarted().manager.ingest(sent)
            assertEquals(MarmotIngestResult.Ignored("own message"), result)
        }
}
