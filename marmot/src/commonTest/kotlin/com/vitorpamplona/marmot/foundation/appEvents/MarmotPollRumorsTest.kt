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

import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.tags.people.PTag
import com.vitorpamplona.quartz.nip59Giftwrap.rumors.RumorAssembler
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** [MarmotPolls.pollRumor] and [MarmotPolls.voteRumor]: the rumors every Marmot front end sends. */
class MarmotPollRumorsTest {
    private val alice = "a".repeat(64)
    private val bob = "b".repeat(64)
    private val now = 1_800_000_000L

    private fun poll(
        type: MarmotPolls.PollType = MarmotPolls.PollType.SINGLE_CHOICE,
        endsAt: Long? = null,
        mentions: List<PTag> = emptyList(),
    ) = assertNotNull(MarmotPolls.pollRumor(alice, "Lunch?", listOf("Pizza", "Sushi", "Tacos"), type, endsAt, mentions, createdAt = now))

    @Test
    fun pollIsAnUnsignedRumorMdkCanRead() {
        val poll = poll()
        assertEquals(MarmotPolls.KIND_POLL, poll.kind)
        assertEquals("", poll.sig)
        assertEquals(alice, poll.pubKey)
        val definition = assertNotNull(MarmotPolls.parsePoll(poll))
        assertEquals(listOf("0", "1", "2"), definition.options.map { it.id })
        assertEquals("Lunch?", definition.question)
    }

    @Test
    fun badInputReportsWhy() {
        var reason: MarmotPolls.BuildError? = null
        assertNull(MarmotPolls.pollRumor(alice, "Q", listOf("only one"), MarmotPolls.PollType.SINGLE_CHOICE, null, onError = { reason = it }))
        assertEquals(MarmotPolls.BuildError.InvalidOptionCount, reason)
    }

    @Test
    fun mentionsAreTaggedOnceAndCappedAtTheTagLimit() {
        val once = poll(mentions = listOf(PTag(bob), PTag(bob)))
        assertEquals(1, once.tags.count { it[0] == "p" })

        val many = (0 until 40).map { PTag(it.toString().padStart(64, '0')) }
        val capped = poll(mentions = many)
        assertEquals(MarmotPolls.MAX_TAGS, capped.tags.size)
        // Still a poll MDK reads: the cap leaves every tag it defines in place.
        assertNotNull(MarmotPolls.parsePoll(capped))
    }

    @Test
    fun voteGoesOutInThePollsOrder() {
        val poll = poll(MarmotPolls.PollType.MULTIPLE_CHOICE)
        val vote = assertNotNull(MarmotPolls.voteRumor(bob, poll, listOf("2", "0"), createdAt = now + 1))
        assertEquals(MarmotPolls.KIND_POLL_RESPONSE, vote.kind)
        val (target, options) = assertNotNull(MarmotPolls.parseResponse(vote))
        assertEquals(poll.id, target)
        assertContentEquals(listOf("0", "2"), options)
        assertTrue(MarmotPolls.castVote(poll.id, assertNotNull(MarmotPolls.parsePoll(poll)), vote) != null)
    }

    @Test
    fun refusesWhatThePollDoesNotAllow() {
        val single = poll()
        assertNull(MarmotPolls.voteRumor(bob, single, listOf("0", "1"), createdAt = now + 1), "two picks on a single-choice poll")
        assertNull(MarmotPolls.voteRumor(bob, single, listOf("7"), createdAt = now + 1), "an option the poll does not define")
        val closing = poll(endsAt = now + 60)
        assertNull(MarmotPolls.voteRumor(bob, closing, listOf("0"), createdAt = now + 61), "a closed poll")
        assertNull(MarmotPolls.voteRumor(bob, closing.copyAsText(), listOf("0"), createdAt = now + 1), "not a poll")
    }

    private fun Event.copyAsText() = RumorAssembler.assembleRumor<Event>(pubKey, createdAt, 9, tags, content)
}
