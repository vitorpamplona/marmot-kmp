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

/**
 * Kind 1984, a member's report of a message in the group (`features/content-moderation.md`).
 *
 * A NIP-56 report kept inside the group: every member sees it and who sent it. Exactly one
 * `e` tag names the reported app event and carries the reason as its third element, and
 * exactly one `p` tag names that event's author. These are MDK's rules (`parse_report`): a
 * report with any other shape, or a reason outside NIP-56's seven, is not a report there,
 * so it is not one here either.
 */
object MarmotReport {
    const val KIND = MarmotAppEvent.KIND_REPORT

    /** NIP-56's categories, the only reasons MDK reads. */
    enum class Reason(
        val code: String,
    ) {
        NUDITY("nudity"),
        MALWARE("malware"),
        PROFANITY("profanity"),
        ILLEGAL("illegal"),
        SPAM("spam"),
        IMPERSONATION("impersonation"),
        OTHER("other"),
        ;

        companion object {
            fun parse(code: String): Reason? = entries.firstOrNull { it.code == code }
        }
    }

    class Reference(
        val target: HexKey,
        val author: HexKey,
        val reason: Reason,
    )

    /** What [event] reports, or null when it is not a well-formed kind-1984 report. */
    fun referenceOf(event: Event): Reference? = if (event.kind == KIND) referenceOf(event.tags) else null

    /** What a kind 1984 with [tags] reports, or null when malformed. */
    fun referenceOf(tags: TagArray): Reference? {
        val event = oneTag(tags, "e") ?: return null
        val author = oneTag(tags, "p")?.getOrNull(1) ?: return null
        val target = event.getOrNull(1) ?: return null
        val reason = event.getOrNull(2)?.let { Reason.parse(it) } ?: return null
        if (!isEventId(target) || !isEventId(author)) return null
        return Reference(target, author, reason)
    }

    /** The tags of a report of [targetId], written by [targetAuthor], for [reason]. */
    fun tags(
        targetId: HexKey,
        targetAuthor: HexKey,
        reason: Reason,
    ): TagArray = arrayOf(arrayOf("e", targetId, reason.code), arrayOf("p", targetAuthor))

    private fun oneTag(
        tags: TagArray,
        name: String,
    ): Array<String>? {
        var found: Array<String>? = null
        for (tag in tags) {
            if (tag.isEmpty() || tag[0] != name) continue
            if (found != null) return null
            found = tag
        }
        return found
    }
}

/**
 * Kind 1985, an admin's dismissal of reports: a NIP-32 label in the `marmot.report-review.v1`
 * namespace (`features/content-moderation.md`).
 *
 * Without both the `L` namespace tag and the `l` "dismissed" label it dismisses nothing. Each
 * `e` tag names one report; a malformed one is skipped without voiding the others, and trailing
 * elements or extra labels change nothing. These are MDK's rules (`parse_dismissal`).
 *
 * Whether the author MAY dismiss is a separate question, answered against the admin set of the
 * event's source epoch, as for an admin deletion (see `MarmotManager.dismissedReportIds`).
 */
object MarmotReportDismissal {
    const val KIND = MarmotAppEvent.KIND_REVIEW

    const val NAMESPACE = "marmot.report-review.v1"
    const val LABEL = "dismissed"

    /** How many reports one dismissal may name; MDK refuses to send more. */
    const val MAX_REPORTS = 100

    /** The reports [event] dismisses, or null when it is not a well-formed kind-1985 dismissal. */
    fun reportIdsOf(event: Event): List<HexKey>? = if (event.kind == KIND) reportIdsOf(event.tags) else null

    /** The reports a kind 1985 with [tags] dismisses, or null when it dismisses nothing. */
    fun reportIdsOf(tags: TagArray): List<HexKey>? {
        val hasNamespace = tags.any { it.size >= 2 && it[0] == "L" && it[1] == NAMESPACE }
        val hasLabel = tags.any { it.size >= 3 && it[0] == "l" && it[1] == LABEL && it[2] == NAMESPACE }
        if (!hasNamespace || !hasLabel) return null
        val ids = tags.mapNotNull { tag -> if (tag.isNotEmpty() && tag[0] == "e") tag.getOrNull(1)?.takeIf { isEventId(it) } else null }
        return ids.ifEmpty { null }
    }

    /**
     * The tags of a dismissal of [reportIds], sorted and without repeats as MDK writes them, or
     * null when there are none, more than [MAX_REPORTS], or one is not an event id.
     */
    fun tags(reportIds: Collection<HexKey>): TagArray? {
        val ids = reportIds.toSet().sorted()
        if (ids.isEmpty() || ids.size > MAX_REPORTS || !ids.all { isEventId(it) }) return null
        return arrayOf(arrayOf("L", NAMESPACE), arrayOf("l", LABEL, NAMESPACE)) + ids.map { arrayOf("e", it) }
    }
}

private fun isEventId(value: String): Boolean = value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
