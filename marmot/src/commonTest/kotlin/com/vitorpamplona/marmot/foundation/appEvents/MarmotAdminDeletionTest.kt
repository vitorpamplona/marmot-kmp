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
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The kind-4891 shape rules, case for case with MDK's `parse_removal`. */
class MarmotAdminDeletionTest {
    private val id = "ab".repeat(32)

    @Test
    fun theCanonicalRemovalNamesItsOneTarget() {
        val tags = arrayOf(arrayOf("e", id, "extension"), arrayOf("other", "ignored"))
        assertEquals(id, MarmotAdminDeletion.targetOf(tags, MarmotAdminDeletion.CONTENT))
        assertEquals(id, MarmotAdminDeletion.targetOf(tags, """ { "action" : "remove" , "v" : 1 } """))
    }

    @Test
    fun anyOtherContentIsMalformed() {
        val tags = MarmotAdminDeletion.tags(id)
        for (content in listOf(
            """{"v":1,"v":1,"action":"remove"}""",
            """{"v":1.0,"action":"remove"}""",
            """{"v":"1","action":"remove"}""",
            """{"v":1,"action":"remove","extra":0}""",
            """{"v":2,"action":"remove"}""",
            """{"v":1,"action":"dismiss"}""",
            """{"v":1}""",
            "",
            "remove",
            "[1]",
        )) {
            assertNull(MarmotAdminDeletion.targetOf(tags, content), content)
        }
    }

    @Test
    fun itNeedsExactlyOneValidETag() {
        val content = MarmotAdminDeletion.CONTENT
        assertNull(MarmotAdminDeletion.targetOf(arrayOf(), content))
        assertNull(MarmotAdminDeletion.targetOf(arrayOf(arrayOf("e", id), arrayOf("e", "cd".repeat(32))), content))
        assertNull(MarmotAdminDeletion.targetOf(arrayOf(arrayOf("e")), content))
        assertNull(MarmotAdminDeletion.targetOf(arrayOf(arrayOf("e", "AB".repeat(32))), content))
        assertNull(MarmotAdminDeletion.targetOf(arrayOf(arrayOf("e", "short")), content))
        assertNull(MarmotAdminDeletion.targetOf(arrayOf(arrayOf("e", id), arrayOf("e", "bad")), content))
    }
}
