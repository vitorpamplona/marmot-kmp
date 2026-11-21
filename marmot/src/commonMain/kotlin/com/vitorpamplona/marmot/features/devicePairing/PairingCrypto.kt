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

import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.equalsConstantTime
import com.vitorpamplona.crypto.mac.MacInstance
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.mls.crypto.MlsCryptoProvider
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * The derivations of Marmot device pairing (`features/device-pairing.md` "Derivations"): Matrix's
 * `m.sas.v1` with `curve25519-hkdf-sha256` and `hkdf-hmac-sha256.v2`, in the Marmot binary profile. HKDF
 * is HKDF-SHA256 with the shared secret as input keying material and no salt. MDK:
 * `crates/marmot-pairing/src/sas.rs`.
 */
object PairingCrypto {
    const val COMMITMENT_LABEL = "marmot-pairing-v1-commitment"
    const val SAS_LABEL = "marmot-pairing-v1-sas"
    const val MAC_LABEL = "marmot-pairing-v1-mac"
    const val SAS_BYTES = 6

    /** `PairingConfirmSender`. */
    const val SENDER_NEW_DEVICE = 1
    const val SENDER_EXISTING_DEVICE = 2

    /** `PairingConfirmItem`. */
    const val ITEM_KEY_PACKAGE_REF = 1
    const val ITEM_DEVICE_GROUP = 2

    /** What a Request binds: the session, the account and the new device's KeyPackage. */
    class RequestBinding(
        val sessionId: HexKey,
        val account: HexKey,
        val keyPackageEventId: HexKey,
        val keyPackageRef: HexKey,
    )

    /** `SHA-256(PairingCommitmentInput)`. */
    fun commitment(
        newDeviceKey: ByteArray,
        request: RequestBinding,
    ): ByteArray {
        val w = TlsWriter()
        w.putOpaqueVarInt(COMMITMENT_LABEL.encodeToByteArray())
        w.putBytes(fixed32(newDeviceKey))
        w.putBytes(fixed32(request.sessionId.hexToByteArray()))
        w.putBytes(fixed32(request.account.hexToByteArray()))
        w.putBytes(fixed32(request.keyPackageEventId.hexToByteArray()))
        w.putOpaqueVarInt(request.keyPackageRef.hexToByteArray())
        return sha256(w.toByteArray())
    }

    /** `PairingSasInfo`. */
    fun sasInfo(
        request: RequestBinding,
        existingDeviceSlot: HexKey,
        newDeviceKey: ByteArray,
        existingDeviceKey: ByteArray,
    ): ByteArray {
        val w = TlsWriter()
        w.putOpaqueVarInt(SAS_LABEL.encodeToByteArray())
        w.putBytes(fixed32(request.sessionId.hexToByteArray()))
        w.putBytes(fixed32(request.account.hexToByteArray()))
        w.putOpaqueVarInt(request.keyPackageRef.hexToByteArray())
        w.putBytes(fixed32(newDeviceKey))
        w.putBytes(fixed32(existingDeviceSlot.hexToByteArray()))
        w.putBytes(fixed32(existingDeviceKey))
        return w.toByteArray()
    }

    /** `PairingMacInfo`. */
    fun macInfo(
        request: RequestBinding,
        existingDeviceSlot: HexKey,
        sender: Int,
        item: Int,
    ): ByteArray {
        val w = TlsWriter()
        w.putOpaqueVarInt(MAC_LABEL.encodeToByteArray())
        w.putUint8(sender)
        w.putBytes(fixed32(request.sessionId.hexToByteArray()))
        w.putBytes(fixed32(request.account.hexToByteArray()))
        w.putOpaqueVarInt(request.keyPackageRef.hexToByteArray())
        w.putBytes(fixed32(existingDeviceSlot.hexToByteArray()))
        w.putUint8(item)
        return w.toByteArray()
    }

    /** `PairingDeviceGroup`: the value the existing device's confirmation covers. */
    fun deviceGroupValue(
        groupId: ByteArray,
        signatureKey: ByteArray,
    ): ByteArray {
        val w = TlsWriter()
        w.putOpaqueVarInt(groupId)
        w.putOpaqueVarInt(signatureKey)
        return w.toByteArray()
    }

    /** HKDF-SHA256(salt = none, ikm = [sharedSecret], info, length). */
    fun hkdf(
        sharedSecret: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray = MlsCryptoProvider.hkdfExpand(MlsCryptoProvider.hkdfExtract(ByteArray(32), sharedSecret), info, length)

    fun sasBytes(
        sharedSecret: ByteArray,
        sasInfo: ByteArray,
    ): ByteArray = hkdf(sharedSecret, sasInfo, SAS_BYTES)

    /** `HMAC-SHA256(HKDF(info = macInfo, 32), opaque value<V>)`. */
    fun mac(
        sharedSecret: ByteArray,
        macInfo: ByteArray,
        value: ByteArray,
    ): ByteArray {
        val key = hkdf(sharedSecret, macInfo, 32)
        val message = TlsWriter().also { it.putOpaqueVarInt(value) }.toByteArray()
        val mac = MacInstance("HmacSHA256", key)
        mac.update(message)
        val out = mac.doFinal()
        key.fill(0)
        return out
    }

    /** Constant-time comparison of a received MAC. */
    fun macMatches(
        expected: ByteArray,
        received: ByteArray,
    ): Boolean = expected.size == received.size && expected.equalsConstantTime(received)

    /**
     * X25519 of [privateKey] and [peerPublic], or null when it is 32 zero bytes (a low-order key) or the
     * peer key is unusable: the side ends the session.
     */
    fun agree(
        privateKey: ByteArray,
        peerPublic: ByteArray,
    ): ByteArray? {
        val shared =
            try {
                X25519.dh(privateKey, peerPublic)
            } catch (e: Exception) {
                return null
            }
        if (shared.size != 32 || shared.all { it == 0.toByte() }) return null
        return shared
    }

    /** A fresh X25519 key pair for one session: (private, public). Never reused, never persisted. */
    fun ephemeralKey(): Pair<ByteArray, ByteArray> {
        val pair = X25519.generateKeyPair()
        return pair.privateKey to pair.publicKey
    }

    /** The public key of an X25519 private key (to reproduce a vector). */
    fun publicKey(privateKey: ByteArray): ByteArray = X25519.publicFromPrivate(privateKey)

    fun randomSessionId(): HexKey = RandomInstance.bytes(32).toHexKey()

    private fun fixed32(bytes: ByteArray): ByteArray {
        require(bytes.size == 32) { "expected 32 bytes, got ${bytes.size}" }
        return bytes
    }
}
