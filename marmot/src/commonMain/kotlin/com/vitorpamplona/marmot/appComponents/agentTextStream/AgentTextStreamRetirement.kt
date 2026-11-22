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
package com.vitorpamplona.marmot.appComponents.agentTextStream

import com.vitorpamplona.marmot.appComponents.AppComponentIds
import com.vitorpamplona.quartz.nip01Core.core.TagArray
import com.vitorpamplona.quartz.nip01Core.core.fastAny

/**
 * The retired agent text stream over raw QUIC
 * (`app-components/agent-text-stream-quic-v1.md`, "Retirement"; MDK 0.19.0).
 *
 * Clients no longer send or watch live previews. What is left is what existing
 * groups need ([AgentTextStreamQuicPolicyV1] validation, the `receive` role
 * advertisement in [AgentTextStreamRoles]) and the identifiers below, which the
 * spec reserves so nothing ever reuses them ("Reserved identifiers").
 *
 * The send-side rules ("What clients stop doing") are enforced through
 * [requireNotRetired]: no kind [STREAM_START_KIND] and no stream tags on a
 * kind 9 we send. On the receive side ("Receiving from older clients") a kind
 * [STREAM_START_KIND] is not shown, and a kind 9 carrying [STREAM_TAGS] is an
 * ordinary chat message: nothing here reads those tags.
 */
object AgentTextStreamRetirement {
    /** Component `0x8006`. */
    const val COMPONENT_ID = AppComponentIds.AGENT_TEXT_STREAM_QUIC_V1
    const val COMPONENT_NAME = "marmot.group.agent-text-stream.quic.v1"

    /** The app event kind of a stream start. Reserved; never sent. */
    const val STREAM_START_KIND = 1200

    /** `MLS-Exporter("marmot", "agent-text-stream-quic", 32)`, reserved; never derived. */
    const val EXPORTER_LABEL = "marmot"
    const val EXPORTER_CONTEXT = "agent-text-stream-quic"

    /** The ALPN identifiers of `transports/quic.md`, reserved; never dialled. */
    const val ALPN_DIRECT = "marmot.quic_stream.v1"
    const val ALPN_BROKER = "marmot.quic_broker.v1"

    /** The tags an older client put on the kind 9 that ended a stream. */
    const val STREAM_TAG = "stream"
    const val STREAM_START_TAG = "stream-start"
    const val STREAM_HASH_TAG = "stream-hash"
    const val STREAM_CHUNKS_TAG = "stream-chunks"
    val STREAM_TAGS: Set<String> = setOf(STREAM_TAG, STREAM_START_TAG, STREAM_HASH_TAG, STREAM_CHUNKS_TAG)

    /** A kind 9 ends a retired stream when it carries any of [STREAM_TAGS]. */
    const val FINAL_KIND = 9

    fun isStreamStart(kind: Int): Boolean = kind == STREAM_START_KIND

    fun carriesStreamTags(tags: TagArray): Boolean = tags.fastAny { it.isNotEmpty() && it[0] in STREAM_TAGS }

    /**
     * Refuses an app event the retirement forbids a client to send: a kind
     * [STREAM_START_KIND] stream start, or a kind [FINAL_KIND] carrying a
     * stream tag. Throws [IllegalArgumentException]; a send queued before an
     * upgrade is therefore dropped at drain rather than published, as MDK does.
     */
    fun requireNotRetired(
        kind: Int,
        tags: TagArray,
    ) {
        require(!isStreamStart(kind)) { "the agent text stream is retired: kind $STREAM_START_KIND is never sent" }
        require(kind != FINAL_KIND || !carriesStreamTags(tags)) {
            "the agent text stream is retired: a kind $FINAL_KIND never carries stream tags"
        }
    }
}
