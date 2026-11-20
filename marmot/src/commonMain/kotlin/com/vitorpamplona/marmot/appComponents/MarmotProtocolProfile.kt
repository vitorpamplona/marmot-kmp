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

import com.vitorpamplona.mls.codec.TlsReader
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.mls.tree.Extension

/**
 * Which Marmot protocol profile a GroupContext is on, as MDK classifies it
 * (`account_identity_proof.rs`, `protocol_profile_of_group`).
 *
 * - **current**: the `app_components` list requires
 *   `marmot.member.account-identity-proof.v2` (`0x8009`).
 * - **legacy proof**: MLS `required_capabilities` requires the custom
 *   extension `0xf2f1` (`marmot.account-identity-proof.v1`).
 *
 * A group requiring both, or one carrying `0x8009` data in its GroupContext,
 * is invalid to MDK. A group requiring neither is invalid to MDK as well, but
 * it is what this client's own MIP-era groups (`0xF2EE` only) are, so it is
 * simply "not current" here. Rules that only the current profile has
 * (account-devices, receiver-side proof checks) read [isCurrent], which fails
 * closed on every one of those mixed cases.
 */
object MarmotProtocolProfile {
    /** The legacy account identity proof extension, `marmot.account-identity-proof.v1`. */
    const val LEGACY_ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE = 0xF2F1

    /** Whether [extensions], a GroupContext's, put the group on the current profile and nothing else. */
    fun isCurrent(extensions: List<Extension>): Boolean {
        val dictionary = AppDataDictionary.fromExtensionsOrEmpty(extensions)
        if (dictionary.contains(AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2)) return false
        if (AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2 !in ComponentsList.supportedOrRequired(dictionary)) return false
        return !requiresLegacyProof(extensions)
    }

    /** Whether the MLS `required_capabilities` among [extensions] require `0xf2f1`. */
    fun requiresLegacyProof(extensions: List<Extension>): Boolean {
        val required = extensions.firstOrNull { it.extensionType == MlsGroup.REQUIRED_CAPABILITIES_EXTENSION_TYPE } ?: return false
        val reader = TlsReader(TlsReader(required.extensionData).readOpaqueVarInt())
        while (reader.hasRemaining) {
            if (reader.readUint16() == LEGACY_ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE) return true
        }
        return false
    }
}
