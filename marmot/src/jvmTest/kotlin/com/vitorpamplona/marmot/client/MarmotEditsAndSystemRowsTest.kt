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

import com.vitorpamplona.marmot.foundation.appEvents.MarmotAppEvent
import com.vitorpamplona.marmot.foundation.appEvents.MarmotReport
import com.vitorpamplona.marmot.foundation.appEvents.MarmotReportDismissal
import com.vitorpamplona.marmot.foundation.appEvents.MarmotSystemEvent
import com.vitorpamplona.marmot.foundation.appEvents.MarmotSystemType
import com.vitorpamplona.marmot.mip01Groups.MarmotGroupData
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip09Deletions.DeletionRequestEvent
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Message edits (kind 1009) and group system rows (kind 1210) through the app
 * layer.
 *
 * Both are places where getting the RULE wrong is invisible until two clients
 * disagree: who may replace a message, which of two edits wins, and whether a
 * caption gets written once or on every look.
 */
class MarmotEditsAndSystemRowsTest {
    private val nostrGroupId = "e".repeat(64)

    private class Fixture {
        val signer = NostrSignerInternal(KeyPair())
        val mlsStore = SnapshotStateStore()
        val messageStore = SnapshotMessageStore()

        /**
         * A commit only becomes canonical state once a relay took it — a
         * manager with no publisher discards its pending state and never
         * advances the epoch, so there would be nothing for a row to describe.
         */
        val manager = MarmotManager(signer, mlsStore, messageStore, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
    }

    private suspend fun Fixture.createGroup(name: String = "edits") =
        manager.createGroup(
            nostrGroupId,
            MarmotGroupData(nostrGroupId = nostrGroupId, name = name, relays = listOf("wss://relay.invalid")),
        )

    private suspend fun MarmotManager.storedEvents(): List<Event> = loadStoredMessages(nostrGroupId).mapNotNull { Event.fromJsonOrNull(it) }

    @Test
    fun `an author's own edit replaces their message`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            val original = f.manager.buildTextMessage(nostrGroupId, "frist post")
            f.manager.buildMessageEdit(nostrGroupId, original.innerEvent.id, "first post")

            val overlays = f.manager.editOverlays(f.manager.storedEvents())
            assertEquals("first post", overlays[original.innerEvent.id])
        }

    @Test
    fun `an edit from another account is ignored`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            val original = f.manager.buildTextMessage(nostrGroupId, "mine")

            // Hand-built rather than sent, because the point is a receiver
            // refusing it: if authorship were checked only at send time, any
            // member could rewrite anyone's words and no reader would notice.
            val impostor = "f".repeat(64)
            val forged =
                MarmotAppEvent.build(
                    pubKey = impostor,
                    kind = MarmotAppEvent.KIND_EDIT,
                    content = "not mine",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", original.innerEvent.id)),
                )
            f.manager.persistDecryptedMessage(nostrGroupId, forged.toJson().dropLast(1) + ",\"sig\":\"\"}")

            assertNull(f.manager.editOverlays(f.manager.storedEvents())[original.innerEvent.id])
        }

    @Test
    fun `an author's own kind 5 retracts their message`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            val doomed = f.manager.buildTextMessage(nostrGroupId, "delete me")
            f.manager.buildDeletionMessage(nostrGroupId, listOf(doomed.innerEvent))

            assertTrue(doomed.innerEvent.id in f.manager.deletedIds(f.manager.storedEvents()))
        }

    @Test
    fun `a deletion from another account is ignored`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            val mine = f.manager.buildTextMessage(nostrGroupId, "mine")

            // Same shape as the forged edit above, and the same reason: the
            // transport lets any member publish a well-formed kind:5 naming
            // someone else's message, so the reader is the only place that can
            // refuse it. MDK additionally honours an authenticated admin
            // moderation grant here; we issue none, so every cross-author
            // delete is ignored.
            val impostor = "f".repeat(64)
            val forged =
                MarmotAppEvent.build(
                    pubKey = impostor,
                    kind = DeletionRequestEvent.KIND,
                    content = "",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", mine.innerEvent.id)),
                )
            f.manager.persistDecryptedMessage(nostrGroupId, forged.toJson().dropLast(1) + ",\"sig\":\"\"}")

            assertTrue(mine.innerEvent.id !in f.manager.deletedIds(f.manager.storedEvents()))
        }

    @Test
    fun `an admin's kind 4891 removal retracts a message, a non-admin's does not`() =
        runBlocking {
            // White Noise sends 4891 instead of kind 5 whenever the deleter is an admin,
            // for their own messages too; missing it meant those deletions never applied.
            val f = Fixture()
            f.manager.createGroup(
                nostrGroupId,
                MarmotGroupData(
                    nostrGroupId = nostrGroupId,
                    name = "moderated",
                    relays = listOf("wss://relay.invalid"),
                    adminPubkeys = listOf(f.signer.pubKey),
                ),
            )
            val target = f.manager.buildTextMessage(nostrGroupId, "moderate me")
            val admin = f.signer.pubKey
            val stranger = "f".repeat(64)

            fun removal(by: String) =
                MarmotAppEvent.build(
                    pubKey = by,
                    kind = MarmotAppEvent.KIND_REMOVE,
                    content = """{"v":1,"action":"remove"}""",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", target.innerEvent.id)),
                )
            val epoch = f.manager.currentEpoch(nostrGroupId)
            val byStranger = removal(stranger)
            f.manager.persistDecryptedMessage(nostrGroupId, byStranger.toJson().dropLast(1) + ",\"sig\":\"\"}", epoch)
            assertTrue(target.innerEvent.id !in f.manager.deletedIds(nostrGroupId, f.manager.storedEvents()))
            assertTrue(f.manager.adminRemovalTargets(nostrGroupId, Event.fromJson(byStranger.toJson().dropLast(1) + ",\"sig\":\"\"}")).isEmpty())

            val byAdmin = removal(admin)
            f.manager.persistDecryptedMessage(nostrGroupId, byAdmin.toJson().dropLast(1) + ",\"sig\":\"\"}", epoch)
            assertTrue(target.innerEvent.id in f.manager.deletedIds(nostrGroupId, f.manager.storedEvents()))
            assertEquals(
                listOf(target.innerEvent.id),
                f.manager.adminRemovalTargets(nostrGroupId, Event.fromJson(byAdmin.toJson().dropLast(1) + ",\"sig\":\"\"}")),
            )
        }

    @Test
    fun `a report names the message its author and reason, and an admin's kind 1985 dismisses it`() =
        runBlocking {
            // A dismissal is authorized exactly like a 4891: by the admin set of its source epoch.
            val f = Fixture()
            f.manager.createGroup(
                nostrGroupId,
                MarmotGroupData(
                    nostrGroupId = nostrGroupId,
                    name = "moderated",
                    relays = listOf("wss://relay.invalid"),
                    adminPubkeys = listOf(f.signer.pubKey),
                ),
            )
            val target = f.manager.buildTextMessage(nostrGroupId, "report me")
            val report = f.manager.buildReportRumor(target.innerEvent, MarmotReport.Reason.SPAM, "ads")
            val reference = MarmotReport.referenceOf(report)!!
            assertEquals(target.innerEvent.id, reference.target)
            assertEquals(target.innerEvent.pubKey, reference.author)
            assertEquals(MarmotReport.Reason.SPAM, reference.reason)
            assertEquals("ads", report.content)

            val epoch = f.manager.currentEpoch(nostrGroupId)

            fun dismissal(by: String): Event {
                val tags = MarmotReportDismissal.tags(listOf(report.id))!!
                val event = MarmotAppEvent.build(pubKey = by, kind = MarmotAppEvent.KIND_REVIEW, content = "", createdAt = 1_800_000_000L, tags = tags)
                val json = event.toJson().dropLast(1) + ",\"sig\":\"\"}"
                runBlocking { f.manager.persistDecryptedMessage(nostrGroupId, json, epoch) }
                return Event.fromJson(json)
            }

            assertTrue(f.manager.dismissedReportIds(nostrGroupId, dismissal("f".repeat(64))).isEmpty())
            assertEquals(listOf(report.id), f.manager.dismissedReportIds(nostrGroupId, dismissal(f.signer.pubKey)))
        }

    @Test
    fun `an admin deletion is decided by its source epoch and a later demotion does not undo it`() =
        runBlocking {
            // `features/content-moderation.md`: authority is the admin set of the
            // event's source epoch, recorded, so neither a demotion nor a restart
            // brings the deleted message back.
            val signer = NostrSignerInternal(KeyPair())
            val mlsStore = SnapshotStateStore()
            val messageStore = SnapshotMessageStore()
            val bundles = SnapshotBundleStore()
            val manager = MarmotManager(signer, mlsStore, messageStore, bundles, publisher = ACCEPTING_RELAY)
            manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))
            val target = manager.buildTextMessage(nostrGroupId, "moderate me")
            val removal =
                MarmotAppEvent.build(
                    pubKey = signer.pubKey,
                    kind = MarmotAppEvent.KIND_REMOVE,
                    content = """{"v":1,"action":"remove"}""",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", target.innerEvent.id)),
                )
            val removalJson = removal.toJson().dropLast(1) + ",\"sig\":\"\"}"
            manager.persistDecryptedMessage(nostrGroupId, removalJson, manager.currentEpoch(nostrGroupId))
            assertTrue(target.innerEvent.id in manager.deletedIds(nostrGroupId, manager.loadStoredMessages(nostrGroupId).mapNotNull { Event.fromJsonOrNull(it) }))

            // Move the group on so the source epoch's state is long gone, then restart.
            repeat(7) { i -> manager.setGroupProfile(nostrGroupId, "renamed $i", "") }
            val restarted = MarmotManager(signer, mlsStore, messageStore, bundles, publisher = ACCEPTING_RELAY)
            restarted.restoreAll()
            assertEquals(listOf(target.innerEvent.id), restarted.adminRemovalTargets(nostrGroupId, Event.fromJson(removalJson)))
        }

    @Test
    fun `an admin deletion whose epoch is unknown is not authorized`() =
        runBlocking {
            val f = Fixture()
            f.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))
            val target = f.manager.buildTextMessage(nostrGroupId, "keep me")
            val removal =
                MarmotAppEvent.build(
                    pubKey = f.signer.pubKey,
                    kind = MarmotAppEvent.KIND_REMOVE,
                    content = """{"v":1,"action":"remove"}""",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", target.innerEvent.id)),
                )
            // An epoch this device never held: no proof of authority, so no effect.
            f.manager.persistDecryptedMessage(nostrGroupId, removal.toJson().dropLast(1) + ",\"sig\":\"\"}", 999L)
            assertTrue(target.innerEvent.id !in f.manager.deletedIds(nostrGroupId, f.manager.storedEvents()))
            // ...and not knowing is not a decision: no denial is frozen in the store.
            assertTrue(removal.id !in f.messageStore.loadModerationVerdicts(nostrGroupId))
        }

    @Test
    fun `a late deletion from an epoch this member closed with its own commit is authorized`() =
        runBlocking {
            // The member's first act in the group is a commit of its own, so no inbound
            // event ever captured who administered the epoch it closed.
            val f = Fixture()
            f.manager.createCurrentProfileGroup(nostrGroupId, listOf("wss://relay.invalid"))
            val sourceEpoch = f.manager.currentEpoch(nostrGroupId)!!
            f.manager.setGroupProfile(nostrGroupId, "renamed", "")
            assertTrue(f.manager.currentEpoch(nostrGroupId)!! > sourceEpoch)

            val targetId = "c".repeat(64)
            val removal =
                MarmotAppEvent.build(
                    pubKey = f.signer.pubKey,
                    kind = MarmotAppEvent.KIND_REMOVE,
                    content = """{"v":1,"action":"remove"}""",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", targetId)),
                )
            val removalJson = removal.toJson().dropLast(1) + ",\"sig\":\"\"}"
            f.manager.persistDecryptedMessage(nostrGroupId, removalJson, sourceEpoch)
            assertEquals(listOf(targetId), f.manager.adminRemovalTargets(nostrGroupId, Event.fromJson(removalJson)))
        }

    @Test
    fun `one kind 5 retracts every message it names`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            val first = f.manager.buildTextMessage(nostrGroupId, "one")
            val second = f.manager.buildTextMessage(nostrGroupId, "two")
            val spared = f.manager.buildTextMessage(nostrGroupId, "three")
            f.manager.buildDeletionMessage(nostrGroupId, listOf(first.innerEvent, second.innerEvent))

            val deleted = f.manager.deletedIds(f.manager.storedEvents())
            assertEquals(setOf(first.innerEvent.id, second.innerEvent.id), deleted)
            assertTrue(spared.innerEvent.id !in deleted)
        }

    @Test
    fun `a deletion naming a message we do not hold retracts nothing`() =
        runBlocking {
            // Not invalid — the target may simply not have arrived yet — so it
            // contributes nothing rather than being treated as an error. The
            // overlay is recomputed from the whole log on every read, so it
            // resolves as soon as the target lands.
            val f = Fixture()
            f.createGroup()
            val absent = "9".repeat(64)
            val forged =
                MarmotAppEvent.build(
                    pubKey = f.signer.pubKey,
                    kind = DeletionRequestEvent.KIND,
                    content = "",
                    createdAt = 1_800_000_000L,
                    tags = arrayOf(arrayOf("e", absent)),
                )
            f.manager.persistDecryptedMessage(nostrGroupId, forged.toJson().dropLast(1) + ",\"sig\":\"\"}")

            assertTrue(f.manager.deletedIds(f.manager.storedEvents()).isEmpty())
        }

    @Test
    fun `the latest edit wins`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            val original = f.manager.buildTextMessage(nostrGroupId, "v1")
            val author = f.signer.pubKey
            for ((at, text) in listOf(1_800_000_000L to "v2", 1_800_000_100L to "v3", 1_800_000_050L to "v2b")) {
                val edit =
                    MarmotAppEvent.build(
                        pubKey = author,
                        kind = MarmotAppEvent.KIND_EDIT,
                        content = text,
                        createdAt = at,
                        tags = arrayOf(arrayOf("e", original.innerEvent.id)),
                    )
                f.manager.persistDecryptedMessage(nostrGroupId, edit.toJson().dropLast(1) + ",\"sig\":\"\"}")
            }
            assertEquals("v3", f.manager.editOverlays(f.manager.storedEvents())[original.innerEvent.id])
        }

    @Test
    fun `an edit for a message we do not hold overlays nothing`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            f.manager.buildMessageEdit(nostrGroupId, "9".repeat(64), "orphan")
            assertTrue(f.manager.editOverlays(f.manager.storedEvents()).isEmpty())
        }

    @Test
    fun `the first look at a group writes no system rows`() =
        runBlocking {
            val f = Fixture()
            f.createGroup()
            // createGroup already established a baseline through the commit
            // path; looking again with nothing changed must stay silent.
            assertEquals(emptyList(), f.manager.syncGroupSystemRows(nostrGroupId))
            assertTrue(f.manager.storedEvents().none { it.kind == MarmotAppEvent.KIND_SYSTEM })
        }

    @Test
    fun `a rename derives one row and only one`() =
        runBlocking {
            val f = Fixture()
            f.createGroup(name = "before")
            f.manager.syncGroupSystemRows(nostrGroupId)

            f.manager.setGroupProfile(nostrGroupId, "after", "")

            val rows = f.manager.storedEvents().filter { it.kind == MarmotAppEvent.KIND_SYSTEM }
            assertEquals(1, rows.size, "one rename, one row")
            val decoded = MarmotSystemEvent.fromAppEvent(MarmotAppEvent.fromEvent(rows.single()))
            assertEquals(MarmotSystemType.GROUP_RENAMED, decoded?.systemType)
            assertEquals("after", decoded?.name)
            assertEquals(f.signer.pubKey, decoded?.actor)

            // Deriving again against the recorded baseline must not re-write
            // the caption. Without that, every sync would add a row for a
            // change that happened once.
            f.manager.syncGroupSystemRows(nostrGroupId)
            assertEquals(1, f.manager.storedEvents().count { it.kind == MarmotAppEvent.KIND_SYSTEM })
        }

    @Test
    fun `the baseline survives a restart, so a change across one is still described`() =
        runBlocking {
            val f = Fixture()
            f.createGroup(name = "before")
            f.manager.syncGroupSystemRows(nostrGroupId)

            // A fresh manager over the same stores: the snapshot is what
            // carries "where I left off" across the process boundary, and
            // without it a restart would either lose the caption or re-derive
            // the group from nothing.
            val restarted = MarmotManager(f.signer, f.mlsStore, f.messageStore, SnapshotBundleStore(), publisher = ACCEPTING_RELAY)
            restarted.restoreAll()
            restarted.setGroupProfile(nostrGroupId, "after", "")

            val rows = restarted.loadStoredMessages(nostrGroupId).mapNotNull { Event.fromJsonOrNull(it) }.filter { it.kind == MarmotAppEvent.KIND_SYSTEM }
            assertEquals(1, rows.size)
        }

    @Test
    fun `a derived row is surfaced as it happens, not only after a restart`() =
        runBlocking {
            // Rows used to reach the conversation only when a restart re-read
            // the local log, which is the wrong moment to learn that someone
            // was removed from the group.
            val f = Fixture()
            f.createGroup(name = "before")
            f.manager.syncGroupSystemRows(nostrGroupId)

            val surfaced = mutableListOf<Event>()
            f.manager.onSystemRowDerived = { _, row -> surfaced.add(row) }
            f.manager.setGroupProfile(nostrGroupId, "after", "")

            assertEquals(1, surfaced.size, "a rename must surface exactly one row")
            assertEquals(MarmotAppEvent.KIND_SYSTEM, surfaced.single().kind)
            // Authored by this client: a derived row is OUR reading of
            // authenticated state, and the feed admits a 1210 on exactly that.
            assertEquals(f.signer.pubKey, surfaced.single().pubKey)
        }
}
