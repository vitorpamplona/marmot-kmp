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
import com.vitorpamplona.quartz.nip19Bech32.entities.NProfile
import com.vitorpamplona.quartz.nip19Bech32.entities.NPub
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The corners of [MarmotMessageReferences] the recorded White Noise conversation does not reach. */
class MarmotMessageReferencesTest {
    private val alice = "a".repeat(64)
    private val bob = "b".repeat(64)
    private val target = "c".repeat(64)
    private val other = "d".repeat(64)

    private fun event(
        kind: Int,
        content: String = "",
        vararg tags: Array<String>,
    ) = Event("0".repeat(64), alice, 1L, kind, arrayOf(*tags), content, "")

    @Test
    fun anNprofileInTheTextIsAMention() {
        val text = "hi nostr:${NProfile.create(bob, emptyList())}"
        assertEquals(setOf(bob), MarmotMessageReferences.mentions(event(9, text)))
    }

    @Test
    fun aBareNpubWithoutPrefixIsNotAMention() {
        // MDK's Markdown tokenizer only reads `nostr:` URIs and `@` handles as mentions.
        assertEquals(emptySet(), MarmotMessageReferences.mentions(event(9, "see ${NPub.create(bob)}")))
    }

    @Test
    fun aMentionPastTheScanBoundDoesNotCount() {
        val text = "x".repeat(MarmotMessageReferences.MAX_MENTION_SCAN_BYTES) + " nostr:${NPub.create(bob)}"
        assertEquals(emptySet(), MarmotMessageReferences.mentions(event(9, text)))
        assertEquals(setOf(bob), MarmotMessageReferences.mentions(event(9, text, arrayOf("p", bob))))
    }

    @Test
    fun onlyChatMessagesMention() {
        assertEquals(emptySet(), MarmotMessageReferences.mentions(event(1009, "nostr:${NPub.create(bob)}", arrayOf("p", bob))))
    }

    @Test
    fun theQuoteWinsOverTheEventTagWhicheverComesFirst() {
        assertEquals(target, MarmotMessageReferences.replyTarget(event(9, "", arrayOf("e", other), arrayOf("q", target))))
        assertEquals(target, MarmotMessageReferences.replyTarget(event(9, "", arrayOf("q", target), arrayOf("e", other))))
        assertEquals(target, MarmotMessageReferences.replyTarget(event(1068, "", arrayOf("e", target))))
    }

    @Test
    fun modifiersAreNotReplies() {
        assertNull(MarmotMessageReferences.replyTarget(event(7, "+", arrayOf("e", target))))
        assertEquals(target, MarmotMessageReferences.reactionTarget(event(7, "+", arrayOf("e", target), arrayOf("e", other))))
    }

    @Test
    fun aCustomEmojiUrlNeedsItsShortcodeTag() {
        val party = event(7, ":party:", arrayOf("e", target), arrayOf("emoji", "party", "https://x/p.png"))
        assertEquals("https://x/p.png", MarmotMessageReferences.customEmojiUrl(party))
        assertNull(MarmotMessageReferences.customEmojiUrl(event(7, ":party:", arrayOf("e", target), arrayOf("emoji", "cake", "https://x/c.png"))))
        assertNull(MarmotMessageReferences.customEmojiUrl(event(7, "+", arrayOf("e", target))))
    }
}
