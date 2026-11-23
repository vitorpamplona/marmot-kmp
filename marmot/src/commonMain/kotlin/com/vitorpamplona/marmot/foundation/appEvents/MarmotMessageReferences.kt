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
     * MDK reads the text as Markdown and skips entities inside code; this scan does not.
     */
    fun mentions(event: Event): Set<HexKey> {
        if (event.kind != MarmotAppEvent.KIND_CHAT) return emptySet()
        val found = LinkedHashSet<HexKey>()
        for (tag in event.tags) {
            if (tag.size > 1 && tag[0] == "p" && isHexKey(tag[1])) found.add(tag[1])
        }
        INLINE_MENTION.findAll(boundedPrefix(event.content)).forEach { match ->
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
