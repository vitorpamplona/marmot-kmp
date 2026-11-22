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
package com.vitorpamplona.marmot.appComponents.agentTextStream

import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `marmot.group.agent-text-stream.quic.v1` (0x8006), checked against the bytes
 * MDK 0.9.20 actually installs. The fixture is the component state read off a
 * group `wn groups create` made on the interop harness.
 *
 * This component is the one that decides whether MDK will let us into a group
 * it created: its `required_member_roles` mask names MLS leaf capabilities, so
 * a client that neither advertises `0x8006` nor the `0xF2D1` receive
 * capability is refused at the Add, before any of our own code runs.
 */
class AgentTextStreamQuicPolicyV1Test {
    /** `wn groups create` default: require receive, allow receive+send, 4096-byte frames. */
    private val mdkDefaultState = "010300001000000000000000".hexToByteArray()

    @Test
    fun decodesTheComponentStateMdkInstalls() {
        val policy = AgentTextStreamQuicPolicyV1.decode(mdkDefaultState)

        assertEquals(AgentTextStreamRoles.RECEIVE, policy.requiredMemberRoles)
        assertEquals(AgentTextStreamRoles.RECEIVE or AgentTextStreamRoles.SEND, policy.allowedMemberRoles)
        assertEquals(4096L, policy.maxPlaintextFrameLen)
        assertEquals(0L, policy.replayTtlSecs)
        assertEquals(0, policy.paddingBucketBytes)
        assertTrue(policy.requires(AgentTextStreamRoles.RECEIVE))
        assertTrue(policy.allows(AgentTextStreamRoles.SEND))
    }

    @Test
    fun ourDefaultEncodesToTheSameBytes() {
        assertContentEquals(mdkDefaultState, AgentTextStreamQuicPolicyV1.userToAgentDefault().encode())
    }

    @Test
    fun requiredRolesMapToLeafCapabilities() {
        val policy = AgentTextStreamQuicPolicyV1.decode(mdkDefaultState)
        assertEquals(listOf(AgentTextStreamRoles.RECEIVE_CAPABILITY), policy.requiredRoleCapabilities())
        assertEquals(0xF2D1, AgentTextStreamRoles.RECEIVE_CAPABILITY)
        assertEquals(0xF2D2, AgentTextStreamRoles.SEND_CAPABILITY)
        assertEquals(0xF2D4, AgentTextStreamRoles.FANOUT_CAPABILITY)
    }

    @Test
    fun roundTripsEveryFieldAtItsBound() {
        val policy =
            AgentTextStreamQuicPolicyV1(
                requiredMemberRoles = AgentTextStreamRoles.MASK,
                allowedMemberRoles = AgentTextStreamRoles.MASK,
                maxPlaintextFrameLen = AgentTextStreamQuicPolicyV1.MAX_PLAINTEXT_FRAME_LEN,
                replayTtlSecs = AgentTextStreamQuicPolicyV1.MAX_REPLAY_TTL_SECS,
                paddingBucketBytes = AgentTextStreamQuicPolicyV1.MAX_PADDING_BUCKET_BYTES,
            )
        assertEquals(policy, AgentTextStreamQuicPolicyV1.decode(policy.encode()))
    }

    /**
     * These bytes sit in signed group state. A decoder that repaired them
     * would admit a member the group's own policy refuses, so every one of
     * these is a hard failure rather than a default.
     */
    @Test
    fun rejectsStateItCannotActOn() {
        // Wrong length.
        assertFailsWith<IllegalArgumentException> { AgentTextStreamQuicPolicyV1.decode(ByteArray(11)) }
        assertFailsWith<IllegalArgumentException> { AgentTextStreamQuicPolicyV1.decode(ByteArray(13)) }
        // No required role at all.
        assertFailsWith<IllegalArgumentException> {
            AgentTextStreamQuicPolicyV1.decode("000300001000000000000000".hexToByteArray())
        }
        // Unknown role bit — a mask we cannot map to a capability.
        assertFailsWith<IllegalArgumentException> {
            AgentTextStreamQuicPolicyV1.decode("080b00001000000000000000".hexToByteArray())
        }
        // Required roles outside the allowed set.
        assertFailsWith<IllegalArgumentException> {
            AgentTextStreamQuicPolicyV1.decode("020100001000000000000000".hexToByteArray())
        }
        // Zero frame limit, and one past the app-profile cap (65519 -> 65520).
        assertFailsWith<IllegalArgumentException> {
            AgentTextStreamQuicPolicyV1.decode("010300000000000000000000".hexToByteArray())
        }
        assertFailsWith<IllegalArgumentException> {
            AgentTextStreamQuicPolicyV1.decode("01030000fff0000000000000".hexToByteArray())
        }
        assertNull(AgentTextStreamQuicPolicyV1.decodeOrNull(ByteArray(0)))
    }
}

/**
 * The retirement's send rules and reserved identifiers
 * (`agent-text-stream-quic-v1.md`, "What clients stop doing", "Reserved
 * identifiers").
 */
class AgentTextStreamRetirementTest {
    @Test
    fun theReservedIdentifiersKeepTheirValues() {
        assertEquals(0x8006, AgentTextStreamRetirement.COMPONENT_ID)
        assertEquals("marmot.group.agent-text-stream.quic.v1", AgentTextStreamRetirement.COMPONENT_NAME)
        assertEquals(1200, AgentTextStreamRetirement.STREAM_START_KIND)
        assertEquals("marmot", AgentTextStreamRetirement.EXPORTER_LABEL)
        assertEquals("agent-text-stream-quic", AgentTextStreamRetirement.EXPORTER_CONTEXT)
        assertEquals("marmot.quic_stream.v1", AgentTextStreamRetirement.ALPN_DIRECT)
        assertEquals("marmot.quic_broker.v1", AgentTextStreamRetirement.ALPN_BROKER)
        assertEquals(listOf(0xF2D1, 0xF2D2, 0xF2D4), AgentTextStreamRoles.ALL_CAPABILITIES)
    }

    @Test
    fun aStreamStartIsNeverSent() {
        assertFailsWith<IllegalArgumentException> { AgentTextStreamRetirement.requireNotRetired(1200, emptyArray()) }
    }

    @Test
    fun aKind9NeverCarriesAStreamTag() {
        for (tag in listOf("stream", "stream-start", "stream-hash", "stream-chunks")) {
            assertFailsWith<IllegalArgumentException>(tag) {
                AgentTextStreamRetirement.requireNotRetired(9, arrayOf(arrayOf(tag, "00")))
            }
        }
        // An ordinary kind 9, and these tag names on another kind, are fine.
        AgentTextStreamRetirement.requireNotRetired(9, arrayOf(arrayOf("p", "00")))
        AgentTextStreamRetirement.requireNotRetired(7, arrayOf(arrayOf("stream", "00")))
    }
}
