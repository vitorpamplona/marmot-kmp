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
import com.vitorpamplona.marmot.MarmotIngestDedupStore
import com.vitorpamplona.marmot.appComponents.GroupProfileV1
import com.vitorpamplona.quartz.nip01Core.core.HexKey
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
        val ingested: MarmotIngestDedupStore = InMemoryIngestDedupStore(),
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

    /** Records which kind of marker each write was. */
    private class RecordingDedupStore(
        private val inner: InMemoryIngestDedupStore = InMemoryIngestDedupStore(),
    ) : MarmotIngestDedupStore by inner {
        val marks = mutableListOf<HexKey>()

        override suspend fun mark(eventId: HexKey) {
            marks += eventId
            inner.mark(eventId)
        }
    }

    /**
     * Every sent message used to add a durable ingest marker, so the markers an app keeps bounded
     * (Amethyst keeps the newest ten thousand) soon held only own echoes and lost the Welcome and
     * created-locally markers they exist for. Own echoes now go to their own bounded record.
     */
    @Test
    fun sentMessagesDoNotCrowdOutTheIngestMarkers() =
        runBlocking<Unit> {
            val store = RecordingDedupStore()
            val alice = Device(ingested = store).manager
            alice.createCurrentProfileGroup(nostrGroupId = nostrGroupId, relays = listOf("wss://relay.invalid"), profile = GroupProfileV1("echo", ""))
            val before = store.marks.size
            val sent = (1..3).map { alice.buildTextMessage(nostrGroupId, "hi $it").outbound.signedEvent }

            assertEquals(before, store.marks.size, "no ingest marker per sent message")
            sent.forEach { assertEquals(MarmotIngestResult.Ignored("own message"), alice.ingest(it)) }
            assertEquals(sent.map { it.id }, store.loadOwnEchoes().takeLast(3))
        }

    @Test
    fun theOwnEchoRecordIsBounded() =
        runBlocking<Unit> {
            val store = InMemoryIngestDedupStore()
            val ids = (0 until MarmotIngestDedupStore.OWN_ECHO_LIMIT + 10).map { it.toString().padStart(64, '0') }
            ids.forEach { store.markOwnEcho(it) }
            assertEquals(ids.takeLast(MarmotIngestDedupStore.OWN_ECHO_LIMIT), store.loadOwnEchoes())
        }
}
