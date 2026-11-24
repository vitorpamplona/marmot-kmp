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

import com.vitorpamplona.marmot.features.accountSync.AccountSyncStore
import com.vitorpamplona.marmot.features.accountSync.InMemoryAccountSyncStore
import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.codec.TlsWriter
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * The private KeyPackages a device exchanges with its siblings (`device-group.md` "Private KeyPackages"):
 * those it issued, with their private keys, and those siblings handed it.
 *
 * Persisted format (API): [encode] / [decode], version 1, layout in `plans/2026-11-21-device-groups.md`.
 * [Issued.bundle] holds private key material: a store MUST encrypt it at rest.
 */
data class PrivateKeyPackages(
    val issued: List<Issued> = emptyList(),
    val held: List<Held> = emptyList(),
    /** KeyPackages this device used to add a sibling, kept until their `not_after`. */
    val used: List<Ref> = emptyList(),
    /** Ids of the request events this device answered, so it answers each once. */
    val answeredRequests: List<HexKey> = emptyList(),
    /** Sibling Welcomes this device sent, kept to repair a lost delivery (`Resending a published sibling Welcome`). */
    val repairs: List<Repair> = emptyList(),
) {
    /** One sent sibling Welcome: its exact content, its chat, and when its carrier last went out. */
    data class Repair(
        val toSlot: HexKey,
        val chat: HexKey,
        val ref: HexKey,
        val notAfter: Long,
        val publishedAt: Long,
        val content: String,
    )

    /** A KeyPackage this device issued to [toSlot]; [bundle] is its `KeyPackageBundleCodec` bytes. */
    class Issued(
        val toSlot: HexKey,
        val ref: HexKey,
        val notBefore: Long,
        val notAfter: Long,
        /** When it was last handed over: the stock counts those at or after the sibling's latest request. */
        val handedAt: Long,
        val bundle: ByteArray,
    ) {
        val halfway: Long get() = notBefore + (notAfter - notBefore) / 2
    }

    /** A KeyPackage [fromSlot] handed this device: its MLSMessage bytes. */
    class Held(
        val fromSlot: HexKey,
        val ref: HexKey,
        val notBefore: Long,
        val notAfter: Long,
        val keyPackage: ByteArray,
    ) {
        val halfway: Long get() = notBefore + (notAfter - notBefore) / 2
    }

    data class Ref(
        val ref: HexKey,
        val notAfter: Long,
    )

    fun encode(): ByteArray {
        val w = TlsWriter()
        w.putUint8(VERSION)
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    issued.forEach {
                        a.putBytes(it.toSlot.hexToByteArray())
                        a.putOpaqueVarInt(it.ref.hexToByteArray())
                        a.putUint64(it.notBefore)
                        a.putUint64(it.notAfter)
                        a.putUint64(it.handedAt)
                        a.putOpaqueVarInt(it.bundle)
                    }
                }.toByteArray(),
        )
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    held.forEach {
                        a.putBytes(it.fromSlot.hexToByteArray())
                        a.putOpaqueVarInt(it.ref.hexToByteArray())
                        a.putUint64(it.notBefore)
                        a.putUint64(it.notAfter)
                        a.putOpaqueVarInt(it.keyPackage)
                    }
                }.toByteArray(),
        )
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    used.forEach {
                        a.putOpaqueVarInt(it.ref.hexToByteArray())
                        a.putUint64(it.notAfter)
                    }
                }.toByteArray(),
        )
        w.putOpaqueVarInt(TlsWriter().also { a -> answeredRequests.forEach { a.putBytes(it.hexToByteArray()) } }.toByteArray())
        w.putOpaqueVarInt(
            TlsWriter()
                .also { a ->
                    repairs.forEach {
                        a.putBytes(it.toSlot.hexToByteArray())
                        a.putOpaqueVarInt(it.chat.hexToByteArray())
                        a.putOpaqueVarInt(it.ref.hexToByteArray())
                        a.putUint64(it.notAfter)
                        a.putUint64(it.publishedAt)
                        a.putOpaqueVarInt(it.content.encodeToByteArray())
                    }
                }.toByteArray(),
        )
        return w.toByteArray()
    }

    companion object {
        const val VERSION = 1

        fun decode(bytes: ByteArray): PrivateKeyPackages {
            val r = TlsReader(bytes)
            require(r.readUint8() == VERSION) { "unknown private KeyPackage store version" }
            val ir = TlsReader(r.readOpaqueVarInt())
            val issued = ArrayList<Issued>()
            while (ir.hasRemaining) issued.add(Issued(ir.readBytes(32).toHexKey(), ir.readOpaqueVarInt().toHexKey(), ir.readUint64(), ir.readUint64(), ir.readUint64(), ir.readOpaqueVarInt()))
            val hr = TlsReader(r.readOpaqueVarInt())
            val held = ArrayList<Held>()
            while (hr.hasRemaining) held.add(Held(hr.readBytes(32).toHexKey(), hr.readOpaqueVarInt().toHexKey(), hr.readUint64(), hr.readUint64(), hr.readOpaqueVarInt()))
            val ur = TlsReader(r.readOpaqueVarInt())
            val used = ArrayList<Ref>()
            while (ur.hasRemaining) used.add(Ref(ur.readOpaqueVarInt().toHexKey(), ur.readUint64()))
            val ar = TlsReader(r.readOpaqueVarInt())
            val answered = ArrayList<HexKey>()
            while (ar.hasRemaining) answered.add(ar.readBytes(32).toHexKey())
            val rr = TlsReader(r.readOpaqueVarInt())
            val repairs = ArrayList<Repair>()
            while (rr.hasRemaining) repairs.add(Repair(rr.readBytes(32).toHexKey(), rr.readOpaqueVarInt().toHexKey(), rr.readOpaqueVarInt().toHexKey(), rr.readUint64(), rr.readUint64(), rr.readOpaqueVarInt().decodeToString()))
            require(!r.hasRemaining) { "private KeyPackage store has trailing bytes" }
            return PrivateKeyPackages(issued, held, used, answered, repairs)
        }
    }
}

/** Where a device keeps its [PrivateKeyPackages]. An app's implementation encrypts it at rest. */
interface PrivateKeyPackageStore {
    suspend fun load(): PrivateKeyPackages?

    suspend fun save(keyPackages: PrivateKeyPackages)
}

class InMemoryPrivateKeyPackageStore(
    private var keyPackages: PrivateKeyPackages? = null,
) : PrivateKeyPackageStore {
    override suspend fun load(): PrivateKeyPackages? = keyPackages

    override suspend fun save(keyPackages: PrivateKeyPackages) {
        this.keyPackages = keyPackages
    }
}

/** The device-group switch for `MarmotManager`: its stores, and where the device group's traffic goes. */
class MarmotDeviceGroupConfig(
    val trustStore: DeviceGroupTrustStore,
    val privateKeyPackageStore: PrivateKeyPackageStore,
    /** The relays of a device group this device creates, when [relayProvider] is null or names none. */
    val relays: List<String>,
    /** Small state shared with siblings (`account-sync.md`): invitation decisions, read, pin, mute, archive. */
    val accountSyncStore: AccountSyncStore = InMemoryAccountSyncStore(),
    /**
     * The account's relays as they are now, read when this device creates its device group: an app
     * whose relay lists load after the account is built passes them here, so the group does not
     * start on a default set. [MarmotDeviceGroupManager.stageRelays] moves an existing group.
     */
    val relayProvider: (suspend () -> List<String>)? = null,
    /**
     * This device's `client` and `platform` for its own roster entry (`device-group.md` "Labels,
     * clients and platforms"): the client name its KeyPackages carry, and a short platform name such
     * as `Android`. Written in its founding entry, its first Commit and its slot announcements.
     */
    val client: String = "",
    val platform: String = "",
    /**
     * Owed histories, deliveries waiting for their chat or blob, user roster edits a fork may undo,
     * and imported attachment keys ([DeviceGroupWork]), so they survive a restart. Encrypt at rest.
     */
    val workStore: DeviceGroupWorkStore = InMemoryDeviceGroupWorkStore(),
) {
    @Deprecated("Kept for binary compatibility", level = DeprecationLevel.HIDDEN)
    constructor(
        trustStore: DeviceGroupTrustStore,
        privateKeyPackageStore: PrivateKeyPackageStore,
        relays: List<String>,
        accountSyncStore: AccountSyncStore,
    ) : this(trustStore, privateKeyPackageStore, relays, accountSyncStore, null, "", "")

    @Deprecated("Kept for binary compatibility", level = DeprecationLevel.HIDDEN)
    constructor(
        trustStore: DeviceGroupTrustStore,
        privateKeyPackageStore: PrivateKeyPackageStore,
        relays: List<String>,
        accountSyncStore: AccountSyncStore,
        relayProvider: (suspend () -> List<String>)?,
        client: String,
        platform: String,
    ) : this(trustStore, privateKeyPackageStore, relays, accountSyncStore, relayProvider, client, platform, InMemoryDeviceGroupWorkStore())
}
