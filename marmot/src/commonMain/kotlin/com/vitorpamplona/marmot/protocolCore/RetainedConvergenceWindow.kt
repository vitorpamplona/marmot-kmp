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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.group.MlsGroupState
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * The part of [MarmotConvergenceEngine]'s memory that has to survive a restart: the retained
 * canonical states, oldest first, and the Commits that joined them
 * (`protocol-core/retained-history.md`, "Retained anchor"; `protocol-core/durability.md`,
 * "Restart equivalence").
 *
 * Without it a restarted client holds only its tip, and a competing Commit authored against the
 * parent it left authenticates against nothing it retains: the fork is read as an echo and the
 * group stays split for good. Only canonical material is kept. Divergent Commits and witnesses
 * are input, which relays deliver again, and candidate states are rebuilt from them.
 *
 * The settled losers are the ids of Commits a pass already ruled out. A relay or a catch-up whose
 * cursor did not move delivers them again, and each still authenticates against the parent this
 * window retains: without the list, every redelivery after a restart reopened a pass for a contest
 * already decided.
 *
 * The encoding is a persisted format, so it never changes in place: a new layout takes a new
 * [VERSION] and keeps reading the older ones.
 *
 * ```text
 * uint8 version = 2  (1: the same, without settled_losers)
 * uint16 state_count;  state_count  x opaque<V> MlsGroupState
 * uint16 commit_count; commit_count x (uint64 source_epoch, opaque<V> framed_commit)
 * uint16 loser_count;  loser_count  x opaque<V> commit_digest          (version 2 only)
 * ```
 */
internal class RetainedConvergenceWindow(
    val states: List<MlsGroupState>,
    val commits: List<CandidateCommit>,
    /** Commit digests (hex, [CandidateCommit.id]) that lost a settled pass, oldest first. */
    val settledLosers: List<String> = emptyList(),
) {
    /**
     * [encodeState] lets the engine reuse the bytes of a state it already wrote: the window moves
     * by one state per Commit, so re-encoding all of them on every write was the whole cost.
     */
    fun encode(encodeState: (MlsGroupState) -> ByteArray = { it.encodeTls() }): ByteArray {
        val writer = TlsWriter()
        writer.putUint8(VERSION)
        writer.putUint16(states.size)
        states.forEach { writer.putOpaqueVarInt(encodeState(it)) }
        writer.putUint16(commits.size)
        commits.forEach {
            writer.putUint64(it.sourceEpoch)
            writer.putOpaqueVarInt(it.bytes)
        }
        writer.putUint16(settledLosers.size)
        settledLosers.forEach { writer.putOpaqueVarInt(it.hexToByteArray()) }
        return writer.toByteArray()
    }

    companion object {
        const val VERSION = 2
        private const val VERSION_ONE = 1

        /** Null for bytes this version cannot read: the caller starts over from its tip. */
        fun decodeOrNull(
            bytes: ByteArray,
            commitOf: (bytes: ByteArray, sourceEpoch: Long) -> CandidateCommit,
        ): RetainedConvergenceWindow? =
            try {
                val reader = TlsReader(bytes)
                val version = reader.readUint8()
                if (version != VERSION && version != VERSION_ONE) {
                    null
                } else {
                    val states = (0 until reader.readUint16()).map { MlsGroupState.decodeTls(reader.readOpaqueVarInt()) }
                    val commits =
                        (0 until reader.readUint16()).map {
                            val epoch = reader.readUint64()
                            commitOf(reader.readOpaqueVarInt(), epoch)
                        }
                    val losers =
                        if (version == VERSION_ONE) {
                            emptyList()
                        } else {
                            (0 until reader.readUint16()).map { reader.readOpaqueVarInt().toHexKey() }
                        }
                    if (reader.remaining != 0) null else RetainedConvergenceWindow(states, commits, losers)
                }
            } catch (_: Exception) {
                null
            }
    }
}
