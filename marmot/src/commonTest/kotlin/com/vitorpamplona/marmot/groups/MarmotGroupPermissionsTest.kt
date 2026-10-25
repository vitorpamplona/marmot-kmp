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
package com.vitorpamplona.marmot.groups

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MarmotGroupPermissionsTest {
    private val alice = "a".repeat(64)
    private val bob = "b".repeat(64)
    private val carol = "c".repeat(64)
    private val gone = "d".repeat(64)

    @Test
    fun onlyAdminsManageOnceTheGroupNamesAny() {
        assertTrue(MarmotGroupPermissions.canRemove(listOf(alice), alice, bob))
        assertFalse(MarmotGroupPermissions.canRemove(listOf(alice), bob, carol))
        assertFalse(MarmotGroupPermissions.canPromote(listOf(alice), bob, bob))
    }

    @Test
    fun aGroupWithNoAdminsIsOpenToEveryMember() {
        assertTrue(MarmotGroupPermissions.canRemove(emptyList(), bob, carol))
        assertTrue(MarmotGroupPermissions.canPromote(emptyList(), bob, bob))
    }

    @Test
    fun nobodyRemovesThemselves() {
        assertFalse(MarmotGroupPermissions.canRemove(listOf(alice), alice, alice))
    }

    @Test
    fun aDemotionMustLeaveAnAdminAmongTheMembers() {
        val members = listOf(alice, bob, carol)
        assertTrue(MarmotGroupPermissions.canDemote(listOf(alice, bob), members, alice, bob))
        assertTrue(MarmotGroupPermissions.canDemote(listOf(alice, bob), members, alice, alice))
        assertFalse(MarmotGroupPermissions.canDemote(listOf(alice), members, alice, alice))
        // The other listed admin already left, so demoting alice would leave none.
        assertFalse(MarmotGroupPermissions.canDemote(listOf(alice, gone), members, alice, alice))
        assertFalse(MarmotGroupPermissions.canDemote(listOf(alice, bob), members, carol, bob))
        assertFalse(MarmotGroupPermissions.canDemote(listOf(alice), members, alice, carol))
    }
}
