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

import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.tree.Extension

/**
 * The receiver rules of `marmot.account.device-roster.v1` (`0x800e`) and the one GroupContext rule of
 * `marmot.member.device-tag.v1` (`0x800f`), as every member applies them (`device-roster-v1.md`
 * "Update", "Requirement", "Removal"; `device-tag-v1.md` "Registry"; MDK `cgka-engine` `app_components.rs`
 * `resolved_app_data_update`, `validate_device_roster_state`).
 *
 * - While the parent requires `0x800e`, its AppDataUpdate is a diff applied to the parent's roster
 *   ([resolveUpdate], through mls-kmp's `MlsGroupPolicy.resolveAppDataUpdate`). Before that, its bytes
 *   are an unknown component's and replace whole, as for members that do not support it.
 * - A group requires `0x800e` from creation or never: no Commit adds or drops the requirement.
 * - While required, the GroupContext carries a valid roster (so a `remove` is invalid), and every
 *   leaf has the same credential identity: a device group holds one account's devices.
 * - No GroupContext ever requires `0x800f`.
 *
 * Requiring `0x800e` never makes a group trusted; which device group a device trusts is the caller's
 * record ([com.vitorpamplona.marmot.features.deviceGroup.DeviceGroupTrust]).
 */
object DeviceRosterRules {
    private fun required(extensions: List<Extension>): List<Int> = ComponentsList.supportedOrRequired(AppDataDictionary.fromExtensionsOrEmpty(extensions))

    /** Whether the GroupContext [extensions] require `0x800e`: a device group. */
    fun isRequired(extensions: List<Extension>): Boolean = DeviceRosterV1.COMPONENT_ID in required(extensions)

    /** The roster the GroupContext [extensions] carry, or null when none decodes. */
    fun rosterOf(extensions: List<Extension>): DeviceRosterV1? =
        AppDataDictionary.fromExtensionsOrEmpty(extensions)[DeviceRosterV1.COMPONENT_ID]?.let {
            try {
                DeviceRosterV1.decode(it)
            } catch (e: IllegalArgumentException) {
                null
            }
        }

    /** The new value of [componentId] for an AppDataUpdate [update], given the parent's [parentData]. */
    fun resolveUpdate(
        parentExtensions: List<Extension>,
        componentId: Int,
        parentData: ByteArray?,
        update: ByteArray,
    ): ByteArray {
        if (componentId != DeviceRosterV1.COMPONENT_ID || !isRequired(parentExtensions)) return update
        val prior = requireNotNull(parentData) { "device roster: the required roster has no GroupContext state" }
        return DeviceRosterV1.applyUpdate(prior, update)
    }

    /** The state rules, for every Commit's complete resulting state. */
    fun validateResultingState(
        parentExtensions: List<Extension>,
        resulting: GroupView,
    ) {
        check(DeviceTagV1.COMPONENT_ID !in required(resulting.extensions)) { "device tag: no group may require 0x800f" }
        val wasRequired = isRequired(parentExtensions)
        val isRequired = isRequired(resulting.extensions)
        check(wasRequired == isRequired) { "device roster: a group requires 0x800e from its creation or never" }
        if (isRequired) validateState(resulting)
    }

    /** The same rules on a state joined from a Welcome (joining.md, receiving flow, step 7). */
    fun validateJoinedState(group: GroupView) {
        check(DeviceTagV1.COMPONENT_ID !in required(group.extensions)) { "device tag: no group may require 0x800f" }
        if (isRequired(group.extensions)) validateState(group)
    }

    private fun validateState(state: GroupView) {
        val bytes = AppDataDictionary.fromExtensionsOrEmpty(state.extensions)[DeviceRosterV1.COMPONENT_ID]
        checkNotNull(bytes) { "device roster: the required roster has no GroupContext state" }
        try {
            DeviceRosterV1.decode(bytes)
        } catch (e: IllegalArgumentException) {
            throw IllegalStateException("device roster: invalid state: ${e.message}", e)
        }
        var account: String? = null
        for (i in 0 until state.leafCount) {
            val identity = state.memberIdentityHex(i) ?: continue
            if (account == null) account = identity
            check(identity == account) { "device roster: a device group holds the devices of one account and no others" }
        }
    }
}
