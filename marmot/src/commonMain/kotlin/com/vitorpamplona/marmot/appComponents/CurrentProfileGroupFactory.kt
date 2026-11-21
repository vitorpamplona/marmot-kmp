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
package com.vitorpamplona.marmot.appComponents

import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.curve25519.Ed25519KeyPair
import com.vitorpamplona.marmot.appComponents.accountIdentityProof.AccountIdentityProofV2
import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamQuicPolicyV1
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.marmot.mip01Groups.MlsCiphersuite
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentData
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.messages.KeyPackageBundle
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.signers.NostrSigner

/**
 * Builds current-profile Marmot leaves, KeyPackages and groups.
 *
 * ## Why this exists as a factory
 *
 * A current-profile leaf must carry `marmot.member.account-identity-proof.v2`
 * over its OWN MLS signature key, and only the account key can produce that
 * proof — through a signer that may be a remote bunker or an external app. MLS
 * leaf construction is synchronous and normally generates its signature keypair
 * internally, so the proof cannot be added afterwards by code that only sees a
 * finished leaf.
 *
 * The order is therefore fixed: generate the leaf keypair, ask the account
 * signer to authorize its public half, then build the leaf around both. Every
 * function here follows it.
 */
object CurrentProfileGroupFactory {
    /**
     * The component ids this client supports, advertised in every leaf.
     *
     * `0x0001` is in the list because a client advertising `app_data_dictionary`
     * must understand and advertise `app_components` itself.
     *
     * This list is what decides which groups will accept us. A group states the
     * components it REQUIRES, and a leaf that does not advertise every one of
     * them is refused — so a component we implement but forget to list here is
     * invisible, and one we list but do not implement is a lie that surfaces
     * later as a group we cannot actually participate in. Add an id here only
     * when the component is implemented.
     */
    val SUPPORTED_COMPONENTS: List<Int> =
        listOf(
            ComponentsList.APP_COMPONENTS_ID,
            AppComponentIds.GROUP_PROFILE_V1,
            AppComponentIds.GROUP_BLOSSOM_IMAGE_V1,
            AppComponentIds.GROUP_AVATAR_URL_V1,
            AppComponentIds.ADMIN_POLICY_V1,
            AppComponentIds.NOSTR_ROUTING_V1,
            AppComponentIds.MESSAGE_RETENTION_V1,
            AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2,
            AppComponentIds.GROUP_ENCRYPTED_MEDIA_V2,
            AppComponentIds.GROUP_LIFECYCLE_V1,
            // `0x800d` account-devices: enforced by `MarmotGroupPolicy` through
            // `AccountDevicesV1` (same-account commits, the support invariant,
            // the 20-leaf limit, no data, never un-required). MDK refuses to
            // invite a KeyPackage without it into a group that requires it, and
            // every group its users create requires it when they all support it.
            AppComponentIds.ACCOUNT_DEVICES_V1,
            // `0x8006`, the retired agent text stream: a SUPPORT claim, not a
            // running service. New groups never include it, but every group
            // created before its retirement requires it (with the `receive`
            // role, `MarmotCapabilities.currentProfileLeaf`) and refuses an
            // invitee whose KeyPackage omits it, so support stays advertised
            // ("What clients keep doing"). It needs no QUIC code: it is the
            // validation in `AgentTextStreamQuicPolicyV1` and `MarmotGroupPolicy`.
            AppComponentIds.AGENT_TEXT_STREAM_QUIC_V1,
        )

    /**
     * [SUPPORTED_COMPONENTS] plus the device-group components, `0x800e` (device roster) and `0x800f`
     * (device tag). NOT advertised by default: a device that advertises `0x800e` can be linked into a
     * device group and must then run the device-group flows, so a client opts in by passing this list
     * where it creates KeyPackages and leaves, once it does (`plans/2026-11-21-device-groups.md`).
     */
    val DEVICE_GROUP_SUPPORTED_COMPONENTS: List<Int> = SUPPORTED_COMPONENTS + listOf(AppComponentIds.DEVICE_ROSTER_V1, AppComponentIds.DEVICE_TAG_V1)

    /** A leaf keypair plus the account proof authorizing it. */
    class LeafIdentity(
        val signatureKeyPair: Ed25519KeyPair,
        val leafExtensions: List<Extension>,
    )

    /**
     * Generate a leaf signature keypair and have [signer] authorize it.
     *
     * The returned leaf dictionary carries the supported-component list, an
     * explicit EMPTY `safe_aad` list (understood, nothing contributed — required
     * of anyone advertising `app_data_dictionary`), and the 104-byte proof.
     */
    suspend fun newLeafIdentity(
        signer: NostrSigner,
        ciphersuite: MlsCiphersuite = MlsCiphersuite.DEFAULT,
        supportedComponents: List<Int> = SUPPORTED_COMPONENTS,
    ): LeafIdentity = newLeafIdentity(signer, ciphersuite, supportedComponents) { emptyList() }

    /**
     * [newLeafIdentity] with more leaf dictionary entries, built from the new leaf's signature key:
     * a linked device's `0x800f` device tag, which is bound to that key.
     */
    suspend fun newLeafIdentity(
        signer: NostrSigner,
        ciphersuite: MlsCiphersuite,
        supportedComponents: List<Int>,
        leafComponents: (signatureKey: ByteArray) -> List<ComponentData>,
    ): LeafIdentity {
        val keyPair = Ed25519.generateKeyPair()
        val proof = AccountIdentityProofV2.create(signer, ciphersuite, keyPair.publicKey)

        val dictionary =
            AppDataDictionary(
                listOf(
                    ComponentData(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(supportedComponents)),
                    ComponentData(ComponentsList.SAFE_AAD_ID, ComponentsList.encode(emptyList())),
                    ComponentData(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2, proof.encode()),
                ) + leafComponents(keyPair.publicKey),
            )
        return LeafIdentity(keyPair, listOf(dictionary.toExtension()))
    }

    /**
     * Publish-ready current-profile KeyPackage for [signer]'s account.
     *
     * [lastResort] adds the empty-data `last_resort_key_package` component to
     * the KEYPACKAGE-level dictionary — a separate dictionary from the embedded
     * LeafNode's, and a component rather than the extension type the MIP-era
     * profile used.
     */
    suspend fun createKeyPackage(
        signer: NostrSigner,
        lastResort: Boolean = true,
        ciphersuite: MlsCiphersuite = MlsCiphersuite.DEFAULT,
        /** The component ids the KeyPackage's leaf advertises; an older release advertised fewer. */
        supportedComponents: List<Int> = SUPPORTED_COMPONENTS,
    ): KeyPackageBundle = createKeyPackage(signer, lastResort, ciphersuite, supportedComponents) { emptyList() }

    /** [createKeyPackage] whose leaf also carries [leafComponents] of its signature key (a device tag). */
    suspend fun createKeyPackage(
        signer: NostrSigner,
        lastResort: Boolean,
        ciphersuite: MlsCiphersuite,
        supportedComponents: List<Int>,
        leafComponents: (signatureKey: ByteArray) -> List<ComponentData>,
    ): KeyPackageBundle {
        val identity = signer.pubKey.hexToByteArray()
        val leaf = newLeafIdentity(signer, ciphersuite, supportedComponents, leafComponents)

        val keyPackageExtensions =
            if (lastResort) {
                listOf(
                    AppDataDictionary(
                        listOf(ComponentData(AppComponentIds.LAST_RESORT_KEY_PACKAGE, ByteArray(0))),
                    ).toExtension(),
                )
            } else {
                emptyList()
            }

        // Under Marmot's policy, so the KeyPackage carries no GREASE values
        // (see MarmotGroupPolicy.greaseCapabilities).
        return MlsGroup.createKeyPackage(
            identity = identity,
            policy = MarmotGroupPolicy,
            leafSignatureKeyPair = leaf.signatureKeyPair,
            leafExtensions = leaf.leafExtensions,
            capabilities = MarmotCapabilities.currentProfileLeaf(),
            keyPackageExtensions = keyPackageExtensions,
        )
    }

    /** The 2.x signature, kept so code compiled against it still links. */
    @Deprecated("Use the overload with supportedComponents. Removed in 3.0.0.", level = DeprecationLevel.HIDDEN)
    suspend fun createKeyPackage(
        signer: NostrSigner,
        lastResort: Boolean = true,
        ciphersuite: MlsCiphersuite = MlsCiphersuite.DEFAULT,
    ): KeyPackageBundle = createKeyPackage(signer, lastResort, ciphersuite, SUPPORTED_COMPONENTS)

    /** The 2.x signature, kept so code compiled against it still links. */
    @Deprecated("Use the overload with supportedComponents. Removed in 3.0.0.", level = DeprecationLevel.HIDDEN)
    suspend fun createGroup(
        signer: NostrSigner,
        nostrGroupId: ByteArray,
        relays: List<String>,
        profile: GroupProfileV1? = null,
        additionalAdmins: List<ByteArray> = emptyList(),
        retention: MessageRetentionV1? = null,
        encryptedMedia: EncryptedMediaPolicyV2? = null,
        // Retired: never put into a new group ("Retirement"), so it is ignored.
        @Suppress("UNUSED_PARAMETER") agentTextStream: AgentTextStreamQuicPolicyV1? = null,
        ciphersuite: MlsCiphersuite = MlsCiphersuite.DEFAULT,
    ): MlsGroup = createGroup(signer, nostrGroupId, relays, profile, additionalAdmins, retention, encryptedMedia, ciphersuite, SUPPORTED_COMPONENTS)

    /**
     * Create a current-profile group with [signer]'s account as its sole
     * initial admin.
     *
     * Epoch 0 carries `required_capabilities` of extension `0x0006` and
     * proposal `0x0008`, and a GroupContext dictionary with the required
     * component list plus admin policy, routing, and the rest of the initial
     * state. The creator's leaf carries its own dictionary with the identity
     * proof. It never carries the retired agent text stream component
     * `0x8006` (`protocol-core/group-setup.md`).
     */
    suspend fun createGroup(
        signer: NostrSigner,
        nostrGroupId: ByteArray,
        relays: List<String>,
        profile: GroupProfileV1? = null,
        additionalAdmins: List<ByteArray> = emptyList(),
        retention: MessageRetentionV1? = null,
        /**
         * The media policy (`0x800b`), off by default.
         *
         * The component is "required for new app groups under a media-capable
         * application profile", but that is application-profile policy rather
         * than something epoch 0 has to carry — and the reference
         * implementation's own epoch-0 GroupContext does not carry it. Putting
         * it there unasked would make our group context differ from the
         * reference's for the same inputs AND would require every joiner to
         * advertise `0x800b` before it could be added. A group that wants a
         * media policy commits one, which is also how it gets changed later.
         */
        encryptedMedia: EncryptedMediaPolicyV2? = null,
        ciphersuite: MlsCiphersuite = MlsCiphersuite.DEFAULT,
        /** The component ids the creator's leaf advertises. */
        supportedComponents: List<Int> = SUPPORTED_COMPONENTS,
    ): MlsGroup = createGroup(signer, nostrGroupId, relays, profile, additionalAdmins, retention, encryptedMedia, agentTextStream, ciphersuite, supportedComponents) { emptyList() }

    /** [createGroup] whose creator leaf also carries [leafComponents] of its signature key (a device tag). */
    suspend fun createGroup(
        signer: NostrSigner,
        nostrGroupId: ByteArray,
        relays: List<String>,
        profile: GroupProfileV1?,
        additionalAdmins: List<ByteArray>,
        retention: MessageRetentionV1?,
        encryptedMedia: EncryptedMediaPolicyV2?,
        agentTextStream: AgentTextStreamQuicPolicyV1?,
        ciphersuite: MlsCiphersuite,
        supportedComponents: List<Int>,
        leafComponents: (signatureKey: ByteArray) -> List<ComponentData>,
    ): MlsGroup {
        val identity = signer.pubKey.hexToByteArray()
        val leaf = newLeafIdentity(signer, ciphersuite, supportedComponents, leafComponents)

        val dictionary =
            MarmotGroupState.buildDictionary(
                adminPolicy = AdminPolicyV1.of(listOf(identity) + additionalAdmins),
                routing = NostrRoutingV1.of(nostrGroupId, relays),
                profile = profile,
                retention = retention,
                encryptedMedia = encryptedMedia,
                lifecycle = GroupLifecycleV1.ACTIVE,
            )

        return MlsGroup.create(
            identity = identity,
            signingKey = leaf.signatureKeyPair.privateKey,
            initialExtensions = listOf(dictionary.toExtension()),
            leafExtensions = leaf.leafExtensions,
            // The current profile shares Marmot's authorization rules but
            // advertises a different capability set, so both are named here.
            policy = MarmotGroupPolicy,
            capabilities = MarmotCapabilities.currentProfileLeaf(),
            requiredCapabilities = MarmotCapabilities.currentProfileRequired(),
        )
    }
}
