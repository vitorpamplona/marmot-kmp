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
package com.vitorpamplona.marmot.features.deviceGroup

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** `PrivateKeyPackages` v1 round-trips and rejects trailing bytes. */
class PrivateKeyPackagesTest {
    @Test
    fun theStoreRoundTrips() {
        val kps =
            PrivateKeyPackages(
                issued = listOf(PrivateKeyPackages.Issued("01".repeat(32), "02".repeat(32), 10, 20, 15, byteArrayOf(1, 2, 3))),
                held = listOf(PrivateKeyPackages.Held("03".repeat(32), "04".repeat(32), 10, 20, byteArrayOf(4))),
                used = listOf(PrivateKeyPackages.Ref("05".repeat(32), 30)),
                answeredRequests = listOf("06".repeat(32)),
                repairs = listOf(PrivateKeyPackages.Repair("07".repeat(32), "08".repeat(32), "09".repeat(32), 40, 35, "abc=")),
            )
        val back = PrivateKeyPackages.decode(kps.encode())
        assertEquals(kps.issued.single().ref, back.issued.single().ref)
        assertContentEquals(kps.issued.single().bundle, back.issued.single().bundle)
        assertEquals(15, back.issued.single().halfway)
        assertContentEquals(kps.held.single().keyPackage, back.held.single().keyPackage)
        assertEquals(kps.used, back.used)
        assertEquals(kps.answeredRequests, back.answeredRequests)
        assertEquals(kps.repairs, back.repairs)
        assertEquals("01" + "00000000" + "00", PrivateKeyPackages().encode().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') })
        assertFailsWith<IllegalArgumentException> { PrivateKeyPackages.decode(PrivateKeyPackages().encode() + byteArrayOf(0)) }
    }
}
