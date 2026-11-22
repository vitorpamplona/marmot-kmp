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
package com.vitorpamplona.marmot.features.devicePairing

import com.vitorpamplona.marmot.foundation.appEvents.MarmotJson
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import kotlinx.serialization.json.JsonPrimitive

/** Why a pairing rumor's content was not read. */
enum class PairingMessageError {
    UNKNOWN_KIND,
    TOO_LARGE,
    MALFORMED,

    /** `v` is not `1`: the message is ignored, not an error to report. */
    UNSUPPORTED_VERSION,
}

class PairingMessageException(
    val error: PairingMessageError,
) : IllegalArgumentException("pairing content: $error")

/** A `Cancel` reason: one of the defined ones, or any other 1-32 bytes of `[a-z0-9_]`. */
class CancelReason private constructor(
    val token: String,
) {
    override fun equals(other: Any?) = other is CancelReason && other.token == token

    override fun hashCode() = token.hashCode()

    override fun toString() = token

    val isKnown: Boolean get() = token in KNOWN

    companion object {
        val USER = CancelReason("user")
        val TIMEOUT = CancelReason("timeout")
        val MISMATCHED_COMMITMENT = CancelReason("mismatched_commitment")
        val MISMATCHED_CODE = CancelReason("mismatched_code")
        val MISMATCHED_CONFIRM = CancelReason("mismatched_confirm")
        val UNEXPECTED_MESSAGE = CancelReason("unexpected_message")
        val COMPETING_REQUESTS = CancelReason("competing_requests")
        val RATE_LIMITED = CancelReason("rate_limited")
        val CANNOT_LINK = CancelReason("cannot_link")

        private val KNOWN =
            setOf(
                "user",
                "timeout",
                "mismatched_commitment",
                "mismatched_code",
                "mismatched_confirm",
                "unexpected_message",
                "competing_requests",
                "rate_limited",
                "cannot_link",
            )

        /** A reason token in the spec's format, or null. */
        fun parse(token: String): CancelReason? = if (token.length in 1..32 && token.all { it in 'a'..'z' || it in '0'..'9' || it == '_' }) CancelReason(token) else null
    }
}

/**
 * The five pairing messages (`features/device-pairing.md` "Messages"; MDK `marmot-pairing/src/message.rs`).
 * Each is the content of an unsigned rumor of kinds 452-456 that a device gift-wraps to its own account.
 * Byte strings are lowercase hex. [content] writes the members in the spec's order without whitespace;
 * [fromContent] is strict: at most 1024 bytes, exactly the listed members, right types and lengths.
 */
sealed class PairingMessage {
    abstract val sessionId: HexKey
    abstract val kind: Int

    data class Request(
        override val sessionId: HexKey,
        val keyPackageEventId: HexKey,
        val keyPackageRef: HexKey,
        val commitment: HexKey,
    ) : PairingMessage() {
        override val kind get() = MarmotDevicePairingKinds.REQUEST
    }

    data class Answer(
        override val sessionId: HexKey,
        val slot: HexKey,
        val key: HexKey,
    ) : PairingMessage() {
        override val kind get() = MarmotDevicePairingKinds.ANSWER
    }

    data class Reveal(
        override val sessionId: HexKey,
        val answerSlot: HexKey,
        val key: HexKey,
    ) : PairingMessage() {
        override val kind get() = MarmotDevicePairingKinds.REVEAL
    }

    /** [deviceGroup] and [signatureKey] are present exactly when the existing device sends it. */
    data class Confirm(
        override val sessionId: HexKey,
        val fromExistingDevice: Boolean,
        val deviceGroup: HexKey?,
        val signatureKey: HexKey?,
        val mac: HexKey,
    ) : PairingMessage() {
        init {
            require(fromExistingDevice == (deviceGroup != null) && fromExistingDevice == (signatureKey != null)) {
                "an existing device's Confirm names its group and key; a new device's names neither"
            }
        }

        override val kind get() = MarmotDevicePairingKinds.CONFIRM
    }

    data class Cancel(
        override val sessionId: HexKey,
        val reason: CancelReason,
    ) : PairingMessage() {
        override val kind get() = MarmotDevicePairingKinds.CANCEL
    }

    fun content(): String =
        when (this) {
            is Request -> """{"v":1,"session":"$sessionId","key_package_event":"$keyPackageEventId","key_package_ref":"$keyPackageRef","commitment":"$commitment"}"""
            is Answer -> """{"v":1,"session":"$sessionId","slot":"$slot","key":"$key"}"""
            is Reveal -> """{"v":1,"session":"$sessionId","answer_slot":"$answerSlot","key":"$key"}"""
            is Confirm ->
                if (fromExistingDevice) {
                    """{"v":1,"session":"$sessionId","from":"existing_device","device_group":"$deviceGroup","signature_key":"$signatureKey","mac":"$mac"}"""
                } else {
                    """{"v":1,"session":"$sessionId","from":"new_device","mac":"$mac"}"""
                }
            is Cancel -> """{"v":1,"session":"$sessionId","reason":"${reason.token}"}"""
        }

    companion object {
        const val MAX_CONTENT_BYTES = 1024
        const val KEY_PACKAGE_REF_MAX_BYTES = 64
        const val GROUP_ID_MAX_BYTES = 255
        const val SIGNATURE_KEY_MAX_BYTES = 133

        private fun malformed(): Nothing = throw PairingMessageException(PairingMessageError.MALFORMED)

        /** Parses [content] of a rumor of [kind]; throws [PairingMessageException]. */
        fun fromContent(
            kind: Int,
            content: String,
        ): PairingMessage {
            if (!MarmotDevicePairingKinds.isPairingKind(kind)) throw PairingMessageException(PairingMessageError.UNKNOWN_KIND)
            if (content.encodeToByteArray().size > MAX_CONTENT_BYTES) throw PairingMessageException(PairingMessageError.TOO_LARGE)
            val obj =
                try {
                    MarmotJson.parseObject(content)
                } catch (e: Exception) {
                    malformed()
                }
            if (obj.duplicateKeys.isNotEmpty()) malformed()
            // `v` is read before any other member, and anything but 1 is ignored.
            val v = obj.element("v") as? JsonPrimitive ?: malformed()
            if (v.isString) malformed()
            val version = v.content.toLongOrNull() ?: malformed()
            if (version != 1L) throw PairingMessageException(PairingMessageError.UNSUPPORTED_VERSION)

            fun members(vararg names: String) {
                if (obj.keys != setOf("v", *names)) malformed()
            }

            fun str(name: String): String {
                val p = obj.element(name) as? JsonPrimitive ?: malformed()
                if (!p.isString) malformed()
                return p.content
            }

            fun hex(
                name: String,
                minBytes: Int,
                maxBytes: Int,
            ): HexKey {
                val s = str(name)
                if (s.length % 2 != 0 || s.length / 2 !in minBytes..maxBytes || !s.all { it in '0'..'9' || it in 'a'..'f' }) malformed()
                return s
            }

            fun hex32(name: String) = hex(name, 32, 32)

            return when (kind) {
                MarmotDevicePairingKinds.REQUEST -> {
                    members("session", "key_package_event", "key_package_ref", "commitment")
                    Request(hex32("session"), hex32("key_package_event"), hex("key_package_ref", 1, KEY_PACKAGE_REF_MAX_BYTES), hex32("commitment"))
                }
                MarmotDevicePairingKinds.ANSWER -> {
                    members("session", "slot", "key")
                    Answer(hex32("session"), hex32("slot"), hex32("key"))
                }
                MarmotDevicePairingKinds.REVEAL -> {
                    members("session", "answer_slot", "key")
                    Reveal(hex32("session"), hex32("answer_slot"), hex32("key"))
                }
                MarmotDevicePairingKinds.CONFIRM -> {
                    when (str("from")) {
                        "new_device" -> {
                            members("session", "from", "mac")
                            Confirm(hex32("session"), false, null, null, hex32("mac"))
                        }
                        "existing_device" -> {
                            members("session", "from", "device_group", "signature_key", "mac")
                            Confirm(hex32("session"), true, hex("device_group", 1, GROUP_ID_MAX_BYTES), hex("signature_key", 1, SIGNATURE_KEY_MAX_BYTES), hex32("mac"))
                        }
                        else -> malformed()
                    }
                }
                else -> {
                    members("session", "reason")
                    Cancel(hex32("session"), CancelReason.parse(str("reason")) ?: malformed())
                }
            }
        }
    }
}
