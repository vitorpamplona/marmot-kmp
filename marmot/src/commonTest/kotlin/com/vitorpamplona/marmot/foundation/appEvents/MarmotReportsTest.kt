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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The kind-1984 report and kind-1985 dismissal shapes, case for case with MDK's `reporting.rs`. */
class MarmotReportsTest {
    private val message = "11".repeat(32)
    private val author = "22".repeat(32)

    @Test
    fun everyNip56ReasonIsAReport() {
        for (reason in MarmotReport.Reason.entries) {
            val reference = assertNotNull(MarmotReport.referenceOf(MarmotReport.tags(message, author, reason)))
            assertEquals(message, reference.target)
            assertEquals(author, reference.author)
            assertEquals(reason, reference.reason)
        }
    }

    @Test
    fun aReportNeedsOneETagWithAKnownReasonAndOnePTag() {
        assertNull(MarmotReport.referenceOf(arrayOf(arrayOf("e", message), arrayOf("p", author))), "no reason")
        assertNull(MarmotReport.referenceOf(arrayOf(arrayOf("e", message, "harassment"), arrayOf("p", author))), "not one of NIP-56's seven")
        assertNull(MarmotReport.referenceOf(arrayOf(arrayOf("e", message, "spam"))), "no author")
        assertNull(MarmotReport.referenceOf(arrayOf(arrayOf("e", message, "spam"), arrayOf("e", author, "spam"), arrayOf("p", author))), "two targets")
        assertNull(MarmotReport.referenceOf(arrayOf(arrayOf("e", message, "spam"), arrayOf("p", author), arrayOf("p", message))), "two authors")
        assertNull(MarmotReport.referenceOf(arrayOf(arrayOf("e", "AB".repeat(32), "spam"), arrayOf("p", author))), "uppercase id")
    }

    @Test
    fun aDismissalNeedsTheNamespaceAndLabelAndSkipsBadReferences() {
        val tags =
            arrayOf(
                arrayOf("L", "other"),
                arrayOf("L", MarmotReportDismissal.NAMESPACE, "extension"),
                arrayOf("l", "dismissed", MarmotReportDismissal.NAMESPACE, "extension"),
                arrayOf("l", "other", "other"),
                arrayOf("e", "bad"),
                arrayOf("e"),
                arrayOf("e", message, "extension"),
            )
        assertEquals(listOf(message), MarmotReportDismissal.reportIdsOf(tags))
        assertNull(MarmotReportDismissal.reportIdsOf(arrayOf(arrayOf("e", message))), "no label")
        assertNull(MarmotReportDismissal.reportIdsOf(arrayOf(arrayOf("L", MarmotReportDismissal.NAMESPACE), arrayOf("e", message))), "no l tag")
        assertNull(
            MarmotReportDismissal.reportIdsOf(arrayOf(arrayOf("L", MarmotReportDismissal.NAMESPACE), arrayOf("l", "dismissed", MarmotReportDismissal.NAMESPACE))),
            "no report",
        )
    }

    @Test
    fun dismissalTagsAreSortedWithoutRepeatsAndBounded() {
        val tags = assertNotNull(MarmotReportDismissal.tags(listOf(author, message, author)))
        assertContentEquals(arrayOf("L", MarmotReportDismissal.NAMESPACE), tags[0])
        assertContentEquals(arrayOf("l", "dismissed", MarmotReportDismissal.NAMESPACE), tags[1])
        assertContentEquals(arrayOf("e", message), tags[2])
        assertContentEquals(arrayOf("e", author), tags[3])
        assertEquals(4, tags.size)
        assertNull(MarmotReportDismissal.tags(emptyList()))
        assertNull(MarmotReportDismissal.tags((0 until 101).map { it.toString().padStart(64, '0') }))
        assertNull(MarmotReportDismissal.tags(listOf("short")))
    }
}
