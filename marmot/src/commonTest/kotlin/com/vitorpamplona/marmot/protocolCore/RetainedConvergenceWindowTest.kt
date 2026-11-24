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
package com.vitorpamplona.marmot.protocolCore

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** The convergence window is a persisted format: its layout is pinned here. */
class RetainedConvergenceWindowTest {
    private fun commit(
        bytes: ByteArray,
        sourceEpoch: Long,
    ) = CandidateCommit(bytes.joinToString("") { it.toString() }, bytes, sourceEpoch)

    @Test
    fun versionOneLayoutStillReads() {
        // What 3.3.0 wrote: no settled losers.
        val v1 = byteArrayOf(1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 2, 7, 8)
        val decoded = assertNotNull(RetainedConvergenceWindow.decodeOrNull(v1, ::commit))
        assertEquals(0, decoded.states.size)
        assertEquals(3L, decoded.commits.single().sourceEpoch)
        assertContentEquals(byteArrayOf(7, 8), decoded.commits.single().bytes)
        assertEquals(emptyList(), decoded.settledLosers)
    }

    @Test
    fun versionTwoLayoutIsPinned() {
        val loser = "ab".repeat(32)
        val window = RetainedConvergenceWindow(emptyList(), listOf(commit(byteArrayOf(7, 8), 3)), listOf(loser))
        val expected = byteArrayOf(2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 2, 7, 8, 0, 1, 32) + ByteArray(32) { 0xab.toByte() }
        assertContentEquals(expected, window.encode())

        val decoded = assertNotNull(RetainedConvergenceWindow.decodeOrNull(expected, ::commit))
        assertEquals(3L, decoded.commits.single().sourceEpoch)
        assertEquals(listOf(loser), decoded.settledLosers)
    }

    @Test
    fun unreadableBytesStartOverFromTheTip() {
        assertNull(RetainedConvergenceWindow.decodeOrNull(byteArrayOf(3, 0, 0, 0, 0, 0, 0), ::commit), "an unknown version")
        assertNull(RetainedConvergenceWindow.decodeOrNull(byteArrayOf(1, 0, 0, 0, 0, 9), ::commit), "trailing bytes")
        assertNull(RetainedConvergenceWindow.decodeOrNull(byteArrayOf(1, 0, 1), ::commit), "a cut record")
        assertNull(RetainedConvergenceWindow.decodeOrNull(byteArrayOf(2, 0, 0, 0, 0), ::commit), "a version 2 record without its losers")
    }
}
