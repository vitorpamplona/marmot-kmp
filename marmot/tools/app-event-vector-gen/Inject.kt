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

// Generator-only helper, never part of the build: gen.sh compiles this file with
// kotlin-compiler-embeddable against amy's runtime classpath, with this repo's
// freshly built marmot-jvm jar first, so every OURS rumor comes from the
// marmot-kmp builders in this checkout and is sent from amy's account A.
//
//   inject dump GID              every rumor A holds for the group, one JSON per line
//   inject send GID SPEC_JSON    build the rumor SPEC names, send it, print it
//
// SPEC_JSON is {"op": …} with:
//   text     text, mentions[]                      MarmotManager.buildTextRumor
//   reply    text, target (rumor JSON)             buildTextRumor(replyTo…)
//   react    target (rumor JSON), reaction         buildReactionRumor
//   edit     target_id, text                       buildMessageEditRumor
//   delete   targets[] (rumor JSON)                buildDeletionRumor
//   remove   target_id                             buildAdminDeletionRumor
//   poll     question, options[], multiple, ends_at   MarmotPolls.pollRumor
//   vote     poll (rumor JSON), option_ids[], raw   MarmotPolls.voteRumor (raw: responseTags, no checks)
//   raw      kind, tags, content                   a hand-shaped rumor (shapes no builder makes)
import com.vitorpamplona.amethyst.cli.Context
import com.vitorpamplona.amethyst.cli.DataDir
import com.vitorpamplona.amethyst.cli.secrets.SecretStore
import com.vitorpamplona.marmot.foundation.appEvents.MarmotPolls
import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.signers.EventTemplate
import com.vitorpamplona.quartz.nip01Core.tags.people.PTag
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import com.vitorpamplona.quartz.utils.TimeUtils
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.system.exitProcess

private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

private fun JsonObject.strs(key: String) = (get(key) as? JsonArray)?.map { it.jsonPrimitive.content } ?: emptyList()

private fun JsonObject.event(key: String) = Event.fromJson(getValue(key).toString())

fun main(args: Array<String>) {
    val secrets = SecretStore.from(backendFlag = "plaintext", passphraseFile = null)
    val dataDir = DataDir.resolve(accountFlag = "A", secrets = secrets)
    val code =
        runBlocking {
            Context.open(dataDir).use { ctx ->
                ctx.prepare()
                val gid = ctx.resolveGroupId(args[1])
                ctx.syncIncoming()
                when (args[0]) {
                    "dump" -> {
                        ctx.marmot.loadStoredMessages(gid).forEach { println(it) }
                        0
                    }

                    "send" -> {
                        val spec = Json.parseToJsonElement(args[2]).jsonObject
                        val me = ctx.identity.pubKeyHex
                        val rumor: Event =
                            when (spec.str("op")) {
                                "text" -> {
                                    ctx.marmot.buildTextRumor(spec.str("text"), mentions = spec.strs("mentions").map { PTag(it) })
                                }

                                "reply" -> {
                                    val target = spec.event("target")
                                    ctx.marmot.buildTextRumor(spec.str("text"), target.id, target.pubKey)
                                }

                                "react" -> {
                                    ctx.marmot.buildReactionRumor(spec.event("target"), spec.str("reaction"))
                                }

                                "edit" -> {
                                    ctx.marmot.buildMessageEditRumor(spec.str("target_id"), spec.str("text"))
                                }

                                "delete" -> {
                                    ctx.marmot.buildDeletionRumor(spec.getValue("targets").jsonArray.map { Event.fromJson(it.toString()) })
                                }

                                "remove" -> {
                                    ctx.marmot.buildAdminDeletionRumor(spec.str("target_id"))
                                }

                                "poll" -> {
                                    val type = if (spec["multiple"]?.jsonPrimitive?.boolean == true) MarmotPolls.PollType.MULTIPLE_CHOICE else MarmotPolls.PollType.SINGLE_CHOICE
                                    MarmotPolls.pollRumor(me, spec.str("question"), spec.strs("options"), type, spec["ends_at"]?.jsonPrimitive?.long)
                                        ?: error("pollRumor refused the spec")
                                }

                                "vote" -> {
                                    val poll = spec.event("poll")
                                    if (spec["raw"]?.jsonPrimitive?.boolean == true) {
                                        val tags = MarmotPolls.responseTags(poll.id, spec.strs("option_ids")) ?: error("responseTags refused")
                                        RumorAssembler.assembleRumor(me, EventTemplate<Event>(TimeUtils.now(), MarmotPolls.KIND_POLL_RESPONSE, tags, ""))
                                    } else {
                                        MarmotPolls.voteRumor(me, poll, spec.strs("option_ids")) ?: error("voteRumor refused the spec")
                                    }
                                }

                                "raw" -> {
                                    val tags = spec.getValue("tags").jsonArray.map { t -> t.jsonArray.map { it.jsonPrimitive.content }.toTypedArray() }.toTypedArray()
                                    RumorAssembler.assembleRumor(me, EventTemplate<Event>(TimeUtils.now(), spec.getValue("kind").jsonPrimitive.content.toInt(), tags, spec.str("content")))
                                }

                                else -> {
                                    error("unknown op ${spec.str("op")}")
                                }
                            }
                        val outbound = ctx.marmot.buildGroupMessage(gid, rumor)
                        ctx.marmot.persistDecryptedMessage(gid, rumor.toJson(), outbound.epoch)
                        val relays = ctx.marmotGroupRelays(gid).ifEmpty { ctx.outboxRelays() }
                        val acks = ctx.publish(outbound.signedEvent, relays)
                        if (acks.values.none { it.accepted }) {
                            System.err.println("no relay accepted ${outbound.signedEvent.id}: $acks")
                            1
                        } else {
                            println(rumor.toJson())
                            0
                        }
                    }

                    else -> {
                        System.err.println("usage: inject dump GID | inject send GID SPEC_JSON")
                        2
                    }
                }
            }
        }
    exitProcess(code)
}
