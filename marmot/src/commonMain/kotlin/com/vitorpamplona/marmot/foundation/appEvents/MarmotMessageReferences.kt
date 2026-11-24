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
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.TagArray
import com.vitorpamplona.quartz.nip19Bech32.Nip19Parser
import com.vitorpamplona.quartz.nip19Bech32.entities.IPubKeyEntity

/**
 * How one group message points at another, read the way MDK reads it, so a reply, a mention
 * or a reaction lands on the same message in every client of the group.
 *
 * MIP-03 makes the inner events ordinary Nostr events and leaves these choices to the clients
 * (NIP-C7 replies, NIP-27 mentions, NIP-25 reactions), and those NIPs leave room: a kind 9 may
 * carry both an `e` and a `q`, a mention may be a `p` tag, inline text, or both. Two clients
 * that resolve that room differently show one group two ways, so the choices are pinned here,
 * against MDK's timeline (`storage-sqlite` `timeline.rs`) and notification code
 * (`marmot-app` `notifications.rs`), and checked by the app-event vectors
 * (`commonTest/resources/marmot/app-events/`).
 */
object MarmotMessageReferences {
    /** MDK's bound on the text a receiver scans for inline mentions (`MAX_MARKDOWN_MENTION_SCAN_BYTES`). */
    const val MAX_MENTION_SCAN_BYTES = 65_519

    /**
     * The message a chat message or poll replies to, or null when it replies to nothing.
     *
     * The first `q` tag wins, then the first `e` tag. White Noise sends a reply with both, naming
     * the same message; Amethyst sends only the `q` (NIP-C7), older clients only the `e`. When
     * they disagree the `q` is the reply and the `e` is just a reference, as MDK decides it
     * (`timeline_row_from_chat`).
     *
     * The value is returned as written: a `q` may name an addressable event (`kind:pubkey:d`)
     * rather than a group message, and MDK keeps that too. Resolving it is the caller's job.
     * Other kinds have no reply here: a reaction's or an edit's `e` names what it modifies.
     */
    fun replyTarget(event: Event): String? {
        if (event.kind != MarmotAppEvent.KIND_CHAT && event.kind != MarmotAppEvent.KIND_POLL) return null
        return event.tags.firstValue("q") ?: event.tags.firstValue("e")
    }

    /**
     * The accounts a chat message mentions: each `p` tag, plus each `nostr:npub1…`,
     * `nostr:nprofile1…` or `@npub1…` in its text, as MDK classifies a mention for its
     * notifications (`message_text_mentions_account`). A sender that forgets the `p` tag still
     * mentions whoever its text names. Only the first [MAX_MENTION_SCAN_BYTES] of the text are
     * scanned, as MDK does.
     *
     * MDK reads the text as Markdown and finds no mention inside code, so neither does this:
     * fenced code blocks (``` or ~~~, to their closing fence or the end of the text) and inline
     * code spans are skipped ([outsideCode]). A `p` tag counts wherever the text names it.
     */
    fun mentions(event: Event): Set<HexKey> {
        if (event.kind != MarmotAppEvent.KIND_CHAT) return emptySet()
        val found = LinkedHashSet<HexKey>()
        for (tag in event.tags) {
            if (tag.size > 1 && tag[0] == "p" && isHexKey(tag[1])) found.add(tag[1])
        }
        INLINE_MENTION.findAll(outsideCode(boundedPrefix(event.content))).forEach { match ->
            pubKeyOf(match.groupValues[1])?.let { found.add(it) }
        }
        return found
    }

    /** The message a kind-7 reaction reacts to: its first `e` tag, as MDK reads it. */
    fun reactionTarget(event: Event): HexKey? = if (event.kind == KIND_REACTION) event.tags.firstValue("e") else null

    /**
     * The image URL of a NIP-30 custom-emoji reaction (`:name:` content and an
     * `["emoji", name, url]` tag), or null for any other reaction. MDK groups reactions by their
     * content, so the `:name:` is the reaction and this URL is only its picture.
     */
    fun customEmojiUrl(event: Event): String? {
        if (event.kind != KIND_REACTION) return null
        val shortcode = MarmotCustomEmoji.reactionShortcode(event.content) ?: return null
        val name = shortcode.substring(1, shortcode.length - 1)
        return event.tags.firstOrNull { it.size > 2 && it[0] == MarmotCustomEmoji.TAG_EMOJI && it[1] == name }?.get(2)
    }

    private const val KIND_REACTION = 7

    private val INLINE_MENTION = Regex("(?:nostr:|@)((?:npub1|nprofile1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)")

    private fun TagArray.firstValue(name: String): String? = firstOrNull { it.size > 1 && it[0] == name }?.get(1)

    private fun isHexKey(value: String) = value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun pubKeyOf(bech32: String): HexKey? = (Nip19Parser.uriToRoute(bech32)?.entity as? IPubKeyEntity)?.hex

    /**
     * [text] with its Markdown code blanked out, as CommonMark reads it: fenced code blocks (a line
     * of three or more backticks or tildes, up to three spaces in and after any `>` quote markers,
     * to a closing fence of the same character at least as long, or to the end of the text) and
     * inline code spans (a run of backticks to the next run of the same length within the
     * paragraph; an unmatched run, or one a backslash escapes, is literal). Everything else keeps
     * its place, so a mention never joins across blanked code.
     */
    fun outsideCode(text: String): String {
        if ('`' !in text && '~' !in text) return text
        val out = StringBuilder(text.length)
        val paragraph = StringBuilder()

        fun flushParagraph() {
            out.append(blankCodeSpans(paragraph))
            paragraph.setLength(0)
        }
        var fence: Pair<Char, Int>? = null
        for (line in text.split('\n').withIndex()) {
            val newline = if (line.index > 0) "\n" else ""
            val body = line.value
            val marker = fenceOf(body)
            if (fence != null) {
                // Inside a fence: everything is code, up to a closing fence.
                out.append(newline).append(" ".repeat(body.length))
                if (marker != null && marker.first == fence.first && marker.second >= fence.second && marker.third.isBlank()) fence = null
                continue
            }
            if (marker != null && (marker.first == '~' || '`' !in marker.third)) {
                flushParagraph()
                out.append(newline).append(" ".repeat(body.length))
                fence = marker.first to marker.second
                continue
            }
            if (body.isBlank()) {
                flushParagraph()
                out.append(newline).append(body)
                continue
            }
            paragraph.append(newline).append(body)
        }
        flushParagraph()
        return out.toString()
    }

    /** The fence character, its run length and what follows the run on [line], or null for no fence. */
    private fun fenceOf(line: String): Triple<Char, Int, String>? {
        var i = 0
        // Quote markers, each with an optional space after it.
        while (true) {
            var j = i
            while (j < line.length && j - i < 3 && line[j] == ' ') j++
            if (j < line.length && line[j] == '>') {
                i = j + 1
                if (i < line.length && line[i] == ' ') i++
            } else {
                break
            }
        }
        var indent = 0
        while (i < line.length && line[i] == ' ' && indent < 4) {
            i++
            indent++
        }
        if (indent > 3 || i >= line.length) return null
        val c = line[i]
        if (c != '`' && c != '~') return null
        var n = 0
        while (i + n < line.length && line[i + n] == c) n++
        if (n < 3) return null
        return Triple(c, n, line.substring(i + n))
    }

    /** [paragraph] with each inline code span blanked out. */
    private fun blankCodeSpans(paragraph: CharSequence): CharSequence {
        if ('`' !in paragraph) return paragraph
        val chars = StringBuilder(paragraph)
        var i = 0
        while (i < chars.length) {
            val c = chars[i]
            if (c == '\\' && i + 1 < chars.length) {
                i += 2
                continue
            }
            if (c != '`') {
                i++
                continue
            }
            val run = runLength(chars, i)
            var j = i + run
            var close = -1
            while (j < chars.length) {
                if (chars[j] == '`') {
                    val other = runLength(chars, j)
                    if (other == run) {
                        close = j
                        break
                    }
                    j += other
                } else {
                    j++
                }
            }
            if (close < 0) {
                i += run
                continue
            }
            for (k in i until close + run) if (chars[k] != '\n') chars[k] = ' '
            i = close + run
        }
        return chars
    }

    private fun runLength(
        chars: CharSequence,
        from: Int,
    ): Int {
        var n = 0
        while (from + n < chars.length && chars[from + n] == '`') n++
        return n
    }

    /** The longest prefix of [text] that fits in [MAX_MENTION_SCAN_BYTES] of UTF-8, cut at a character boundary. */
    private fun boundedPrefix(text: String): String {
        // A char is at most 3 UTF-8 bytes (a surrogate pair is 4 for two chars), so short text fits as is.
        if (text.length * 3 <= MAX_MENTION_SCAN_BYTES) return text
        var bytes = 0
        var i = 0
        while (i < text.length) {
            val c = text[i]
            val (width, chars) =
                when {
                    c.code < 0x80 -> 1 to 1
                    c.code < 0x800 -> 2 to 1
                    c.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate() -> 4 to 2
                    else -> 3 to 1
                }
            if (bytes + width > MAX_MENTION_SCAN_BYTES) break
            bytes += width
            i += chars
        }
        return text.substring(0, i)
    }
}
