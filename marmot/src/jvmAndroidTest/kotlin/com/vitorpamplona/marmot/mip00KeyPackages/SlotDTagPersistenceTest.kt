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
package com.vitorpamplona.marmot.mip00KeyPackages

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A device's publication slot outlives a restart even when it never published a KeyPackage: its
 * device tag names that slot, so a device that came back with another one no longer read as itself
 * in its device group (its owed histories never went out).
 */
class SlotDTagPersistenceTest {
    private class MemoryStore : KeyPackageBundleStore {
        var snapshot: ByteArray? = null

        override suspend fun save(snapshot: ByteArray) {
            this.snapshot = snapshot
        }

        override suspend fun load(): ByteArray? = snapshot

        override suspend fun delete() {
            snapshot = null
        }
    }

    @Test
    fun aNewSlotIsStillTheSlotAfterARestart() =
        runBlocking {
            val store = MemoryStore()
            val slot = KeyPackageRotationManager(store).getOrCreateSlotDTag("primary")
            val restarted = KeyPackageRotationManager(store)
            restarted.restoreFromStore()
            assertEquals(slot, restarted.getOrCreateSlotDTag("primary"))
        }
}
