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
package com.vitorpamplona.marmot.foundation.appEvents

import com.vitorpamplona.marmot.TestResourceLoader
import com.vitorpamplona.marmot.appComponents.EncryptedMediaV2
import com.vitorpamplona.marmot.client.InMemoryMlsGroupStateStore
import com.vitorpamplona.marmot.client.MarmotManager
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.KeyPair
import com.vitorpamplona.quartz.nip01Core.signers.NostrSignerInternal
import com.vitorpamplona.quartz.nip01Core.tags.people.PTag
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The app events of a real White Noise conversation, both ways, against what MDK made of them.
 *
 * `marmot/tools/app-event-vector-gen` ran MDK's `wn`/`wnd` release binaries and amy (marmot-kmp)
 * in one group on a loopback relay. Each case is one rumor and `expect`, MDK's reading of it:
 * whether it is a timeline row, what it replies to, whom it mentions, what a reaction, edit,
 * deletion, admin removal or vote did, which attachments it carries. Here marmot-kmp reads the
 * same rumor through its own API and must reach the same answer.
 *
 * - `mdk-<v>-sent.json`: rumors White Noise built, so a change in how we read them shows up.
 * - `ours-read-by-mdk-<v>.json`: rumors our builders built and White Noise read. Each one built by
 *   a builder is rebuilt here from the same inputs, so a change in what we send fails until the
 *   generator has been rerun and White Noise has read the new shape.
 *
 * Effects ("applied", "counted") are decided over the whole recorded conversation, as a client
 * holding all of it would. Rumors no builder makes (an `e`-only reply, a kind-5 against someone
 * else's message, a vote for an option the poll lacks) were sent hand-shaped by the generator.
 */
class MarmotAppEventVectorTest {
    private fun load(name: String) = Json.parseToJsonElement(TestResourceLoader().loadString("marmot/app-events/$name")).jsonObject

    private val files = listOf("mdk-0.19.0-sent.json", "ours-read-by-mdk-0.19.0.json")

    private fun JsonObject.str(key: String) = get(key)?.takeIf { it !is JsonNull }?.jsonPrimitive?.content

    private fun event(json: JsonElement): Event {
        val o = json.jsonObject
        return Event(
            id = o.str("id")!!,
            pubKey = o.str("pubkey")!!,
            createdAt = o["created_at"]!!.jsonPrimitive.long,
            kind = o["kind"]!!.jsonPrimitive.content.toInt(),
            tags = o["tags"]!!.jsonArray.map { t -> t.jsonArray.map { it.jsonPrimitive.content }.toTypedArray() }.toTypedArray(),
            content = o.str("content")!!,
            sig = "",
        )
    }

    private fun strings(values: Collection<String>) = buildJsonArray { values.forEach { add(JsonPrimitive(it)) } }

    /** Everything one client concluded about the conversation, in the vectors' vocabulary. */
    private class Reading(
        val conversation: List<Event>,
        val admins: Set<HexKey>,
        manager: MarmotManager,
    ) {
        val byId = conversation.associateBy { it.id }
        val deleted: Set<HexKey> = manager.deletedIds(conversation)
        val overlays: Map<HexKey, String> = manager.editOverlays(conversation)

        /** MDK applies a kind 4891 to a kind-9 chat message when its sender is a group admin. */
        val removed: Map<HexKey, HexKey> =
            conversation
                .filter { it.kind == MarmotAdminDeletion.KIND && it.pubKey in admins }
                .mapNotNull { removal -> MarmotAdminDeletion.targetOf(removal)?.takeIf { byId[it]?.kind == MarmotAppEvent.KIND_CHAT }?.let { it to removal.id } }
                .toMap()

        fun isGone(id: HexKey) = id in deleted || id in removed

        /** Each voter's newest response that [MarmotPolls.castVote] counts, per poll. */
        val effectiveVotes: Set<HexKey> =
            conversation
                .filter { it.kind == MarmotPolls.KIND_POLL_RESPONSE && it.id !in deleted }
                .mapNotNull { vote ->
                    val pollId = MarmotPolls.parseResponse(vote)?.first ?: return@mapNotNull null
                    val poll = byId[pollId]?.let(MarmotPolls::parsePoll) ?: return@mapNotNull null
                    MarmotPolls.castVote(pollId, poll, vote)?.let { (pollId to vote.pubKey) to vote }
                }.groupBy({ it.first }, { it.second })
                .values
                .map { votes -> votes.maxWith(compareBy<Event>({ it.createdAt }, { it.id })).id }
                .toSet()
    }

    private fun Reading.interpret(
        rumor: Event,
        self: HexKey,
    ): JsonObject =
        buildJsonObject {
            put("row", MarmotAppEvent.isTimelineRow(rumor.kind, rumor.pubKey, self))
            when (rumor.kind) {
                MarmotAppEvent.KIND_CHAT, MarmotAppEvent.KIND_POLL -> {
                    put("reply_to", MarmotMessageReferences.replyTarget(rumor))
                    if (rumor.kind == MarmotAppEvent.KIND_CHAT) {
                        put("mentions", strings(MarmotMessageReferences.mentions(rumor).sorted()))
                        put("media", media(rumor))
                    } else {
                        put("poll", poll(rumor))
                    }
                }

                7 -> {
                    val target = MarmotMessageReferences.reactionTarget(rumor)
                    put(
                        "reaction",
                        buildJsonObject {
                            put("target", target)
                            put("emoji", rumor.content)
                            put("custom_emoji_url", MarmotMessageReferences.customEmojiUrl(rumor))
                        },
                    )
                    // MDK drops the reactions of a message once it is deleted or removed.
                    val onRow = target != null && byId[target]?.let { MarmotAppEvent.isTimelineRow(it.kind, it.pubKey, self) } == true
                    put("counted", onRow && rumor.id !in deleted && !isGone(target))
                }

                MarmotAppEvent.KIND_EDIT -> {
                    val edit = MarmotMessageEdit.fromAppEvent(MarmotAppEvent.fromEvent(rumor))
                    put(
                        "edit",
                        buildJsonObject {
                            put("target", edit?.targetId)
                            put("content", edit?.replacement)
                        },
                    )
                    put("applied", edit != null && overlays[edit.targetId] == edit.replacement)
                }

                5 -> {
                    val targets = rumor.tags.filter { it.size > 1 && it[0] == "e" }.map { it[1] }
                    put("deletes", strings(targets))
                    put("applied", strings(targets.filter { it in deleted && byId[it]?.pubKey == rumor.pubKey }))
                }

                MarmotAdminDeletion.KIND -> {
                    val target = MarmotAdminDeletion.targetOf(rumor)
                    put("removes", target)
                    put("applied", target != null && removed[target] == rumor.id)
                }

                MarmotPolls.KIND_POLL_RESPONSE -> {
                    val parsed = MarmotPolls.parseResponse(rumor)
                    val poll = parsed?.first?.let { byId[it] }?.let(MarmotPolls::parsePoll)
                    put(
                        "vote",
                        buildJsonObject {
                            put("poll", parsed?.first)
                            put("options", strings(parsed?.second ?: emptyList()))
                            put("valid", poll != null && MarmotPolls.castVote(parsed.first, poll, rumor) != null)
                            put("counted", rumor.id in effectiveVotes)
                        },
                    )
                }
            }
        }

    private fun media(rumor: Event) =
        buildJsonArray {
            MarmotCustomEmoji.attachments(rumor).forEach { ref ->
                add(
                    buildJsonObject {
                        put("url", MarmotCustomEmoji.firstLocator(ref))
                        put("mime", ref.mediaType)
                        put("filename", ref.filename)
                        put("dim", ref.dim)
                        put("thumbhash", ref.thumbhash)
                        put("plaintext_sha256", ref.plaintextSha256.toHexKey())
                        put("ciphertext_sha256", ref.ciphertextSha256.toHexKey())
                        put("nonce", ref.nonce.toHexKey())
                    },
                )
            }
        }

    private fun poll(rumor: Event): JsonElement {
        val poll = MarmotPolls.parsePoll(rumor) ?: return JsonNull
        return buildJsonObject {
            put("question", poll.question)
            put("type", poll.type.nip88)
            put(
                "options",
                buildJsonArray {
                    poll.options.forEach { option ->
                        add(
                            buildJsonObject {
                                put("id", option.id)
                                put("label", option.label)
                            },
                        )
                    }
                },
            )
            put("ends_at", poll.endsAt)
        }
    }

    private fun newManager() = MarmotManager(NostrSignerInternal(KeyPair()), InMemoryMlsGroupStateStore())

    @Test
    fun marmotKmpReadsEveryRumorAsMdkDoes() {
        val failures = mutableListOf<String>()
        var cases = 0
        for (file in files) {
            val vector = load(file)
            val conversation = vector["conversation"]!!.jsonArray.map(::event)
            val admins = vector["admins"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
            val self = vector["members"]!!.jsonObject.str("amethyst")!!
            val reading = Reading(conversation, admins, newManager())
            for (case in vector["cases"]!!.jsonArray.map { it.jsonObject }) {
                cases++
                val rumor = event(case["rumor"]!!)
                if (!MarmotAppEvent.fromEvent(rumor).hasValidId()) failures += "$file ${case.str("name")}: rumor id does not match its content"
                val expect = case["expect"]!!.jsonObject
                val actual = reading.interpret(rumor, self)
                for ((key, want) in expect) {
                    val got = actual[key] ?: JsonNull
                    if (got != want) failures += "$file ${case.str("name")}: $key expected $want, marmot-kmp read $got"
                }
            }
        }
        assertTrue(cases > 30, "the vectors hold only $cases cases")
        if (failures.isNotEmpty()) fail(failures.joinToString("\n", "${failures.size} disagreement(s) with MDK:\n"))
    }

    /**
     * What we send has not drifted from what White Noise read: each rumor a builder made is
     * rebuilt from the same inputs and must come out with the same kind, tags and content.
     */
    @Test
    fun ourBuildersStillSendWhatWhiteNoiseRead() =
        runTest {
            val vector = load("ours-read-by-mdk-0.19.0.json")
            val byId = vector["conversation"]!!.jsonArray.map(::event).associateBy { it.id }
            val manager = newManager()
            val failures = mutableListOf<String>()
            var rebuilt = 0
            for (case in vector["cases"]!!.jsonArray.map { it.jsonObject }) {
                val name = case.str("name")
                val recorded = event(case["rumor"]!!)
                val spec = case["builder"]?.jsonObject
                val again: Event? =
                    when {
                        spec == null && recorded.tags.any { it[0] == "imeta" } -> {
                            val refs = recorded.tags.filter { it[0] == "imeta" }.map { EncryptedMediaV2.parseImetaTagOrNull(it) ?: fail("$name: unreadable imeta") }
                            manager.buildMediaRumor(refs.single(), recorded.content)
                        }

                        spec == null || spec.str("op") == "raw" || spec["raw"]?.jsonPrimitive?.booleanOrNull == true -> {
                            null
                        }

                        else -> {
                            fun target(key: String) = event(spec[key]!!)
                            when (spec.str("op")) {
                                "text" -> manager.buildTextRumor(spec.str("text")!!, mentions = (spec["mentions"] as? JsonArray ?: JsonArray(emptyList())).map { PTag(it.jsonPrimitive.content) })
                                "reply" -> target("target").let { manager.buildTextRumor(spec.str("text")!!, it.id, it.pubKey) }
                                "react" -> manager.buildReactionRumor(target("target"), spec.str("reaction")!!)
                                "edit" -> manager.buildMessageEditRumor(spec.str("target_id")!!, spec.str("text")!!)
                                "delete" -> manager.buildDeletionRumor(spec["targets"]!!.jsonArray.map(::event))
                                "remove" -> manager.buildAdminDeletionRumor(spec.str("target_id")!!)
                                "poll" ->
                                    MarmotPolls.pollRumor(
                                        author = manager.signer.pubKey,
                                        question = spec.str("question")!!,
                                        options = spec["options"]!!.jsonArray.map { it.jsonPrimitive.content },
                                        type = if (spec["multiple"]?.jsonPrimitive?.booleanOrNull == true) MarmotPolls.PollType.MULTIPLE_CHOICE else MarmotPolls.PollType.SINGLE_CHOICE,
                                        endsAt = spec["ends_at"]?.jsonPrimitive?.long,
                                        createdAt = recorded.createdAt,
                                    )
                                "vote" ->
                                    MarmotPolls.voteRumor(
                                        author = manager.signer.pubKey,
                                        poll = byId.getValue(target("poll").id),
                                        optionIds = spec["option_ids"]!!.jsonArray.map { it.jsonPrimitive.content },
                                        createdAt = recorded.createdAt,
                                    )
                                else -> fail("$name: unknown builder ${spec.str("op")}")
                            }
                        }
                    }
                if (again == null) continue
                rebuilt++
                val same = again.kind == recorded.kind && again.content == recorded.content && again.tags.contentDeepEquals(recorded.tags)
                if (!same) failures += "$name: builders now send kind ${again.kind} ${again.tags.map { it.toList() }} '${again.content}', White Noise read kind ${recorded.kind} ${recorded.tags.map { it.toList() }} '${recorded.content}'"
            }
            assertTrue(rebuilt > 10, "only $rebuilt cases were rebuilt")
            if (failures.isNotEmpty()) fail(failures.joinToString("\n", "rerun marmot/tools/app-event-vector-gen; our output changed:\n"))
        }
}
