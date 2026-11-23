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

import com.vitorpamplona.marmot.appComponents.agentTextStream.AgentTextStreamQuicPolicyV1
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.tree.Extension

/**
 * The byte-level validity of the app components a GroupContext `app_data_dictionary` carries, as
 * MDK's `validate_app_component_bytes` checks them: every id this client knows must hold bytes its
 * decoder accepts, two ids may hold no GroupContext data at all (`safe_aad`, and the account
 * identity proof, which is LeafNode-only), and an id this client does not know stays opaque.
 *
 * A group's state is signed by whoever committed it, not by us: without this a member could commit
 * a profile, routing or lifecycle entry no client can read, every member would apply it, and the
 * group would fail later wherever that component is read (its name, its relays, whether it is
 * disbanded) instead of the commit being refused. MDK refuses such a commit, so accepting it also
 * forks us from it.
 *
 * The device roster (`0x800e`) is checked by [DeviceRosterRules] and the account-devices marker
 * (`0x800d`) by [AccountDevicesV1]; the frozen encrypted-media v1 (`0x8008`) belongs to legacy groups
 * this client never joins, so it is left opaque.
 */
object GroupContextComponents {
    /** Throws [IllegalStateException] when [data] is not a valid GroupContext value of [componentId]. */
    fun validate(
        componentId: Int,
        data: ByteArray,
    ) {
        check(componentId != ComponentsList.SAFE_AAD_ID) { "safe_aad carries no GroupContext state" }
        check(componentId != AppComponentIds.ACCOUNT_IDENTITY_PROOF_V2) { "The account identity proof is LeafNode-only, never GroupContext state" }
        try {
            when (componentId) {
                ComponentsList.APP_COMPONENTS_ID -> ComponentsList.decode(data)
                GroupProfileV1.COMPONENT_ID -> GroupProfileV1.decode(data)
                AdminPolicyV1.COMPONENT_ID -> AdminPolicyV1.decode(data)
                NostrRoutingV1.COMPONENT_ID -> NostrRoutingV1.decode(data)
                GroupBlossomImageV1.COMPONENT_ID -> GroupBlossomImageV1.decode(data)
                GroupAvatarUrlV1.COMPONENT_ID -> GroupAvatarUrlV1.decode(data)
                MessageRetentionV1.COMPONENT_ID -> MessageRetentionV1.decode(data)
                AgentTextStreamQuicPolicyV1.COMPONENT_ID -> AgentTextStreamQuicPolicyV1.decode(data)
                EncryptedMediaPolicyV2.COMPONENT_ID -> EncryptedMediaPolicyV2.decode(data)
                GroupLifecycleV1.COMPONENT_ID -> GroupLifecycleV1.decode(data)
                else -> Unit
            }
        } catch (e: IllegalArgumentException) {
            throw IllegalStateException("Invalid app component ${AppComponentIds.toHex(componentId)}: ${e.message}", e)
        } catch (e: IndexOutOfBoundsException) {
            throw IllegalStateException("Invalid app component ${AppComponentIds.toHex(componentId)}: truncated", e)
        }
    }

    /** Every entry of the GroupContext dictionary in [extensions]: what a Welcome installs whole. */
    fun validateAll(extensions: List<Extension>) {
        AppDataDictionary.fromExtensionsOrEmpty(extensions).entries.forEach { validate(it.componentId, it.data) }
    }

    /**
     * The entries a commit wrote: those of [resulting] whose bytes differ from [parent]'s, through
     * an AppDataUpdate or a GroupContextExtensions alike. An entry the commit left alone is not
     * re-judged, so a group that already holds one this version would refuse stays committable.
     */
    fun validateChanged(
        parent: List<Extension>,
        resulting: List<Extension>,
    ) {
        val before = AppDataDictionary.fromExtensionsOrEmpty(parent)
        AppDataDictionary.fromExtensionsOrEmpty(resulting).entries.forEach { entry ->
            val old = before[entry.componentId]
            if (old == null || !old.contentEquals(entry.data)) validate(entry.componentId, entry.data)
        }
    }
}
