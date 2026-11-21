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

import com.vitorpamplona.marmot.appComponents.DeviceRosterRules
import com.vitorpamplona.marmot.features.devicePairing.ConfirmedLink
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.mls.group.GroupView
import com.vitorpamplona.mls.group.MlsGroupPolicy
import com.vitorpamplona.mls.tree.Extension
import com.vitorpamplona.quartz.nip01Core.core.toHexKey

/**
 * Marmot's rules for joining the one Welcome a confirmed link names (`features/device-pairing.md`
 * "New device" step 5, `features/device-group.md` "Joining"): the group requires `0x800e` and the
 * GroupInfo's signer leaf has the signature key the existing device's Confirm named. Everything else
 * is [MarmotGroupPolicy]'s, which refuses any other device-group Welcome. The caller also checks that
 * the Welcome consumes the link's KeyPackage and joins the link's group id.
 */
class DeviceGroupLinkJoinPolicy(
    private val link: ConfirmedLink,
) : MlsGroupPolicy by MarmotGroupPolicy {
    override fun validateJoin(
        group: GroupView,
        groupInfoSigner: Int,
        groupInfoExtensions: List<Extension>,
    ) {
        MarmotGroupPolicy.validateJoin(group)
        check(DeviceRosterRules.isRequired(group.extensions)) { "The link's Welcome must join a device group" }
        val signerKey = group.leafNode(groupInfoSigner)?.signatureKey?.toHexKey()
        check(signerKey == link.welcomeSenderKey) { "The Welcome is not from the leaf the link named" }
        MarmotGroupPolicy.validateJoinedChecks(group, groupInfoSigner, groupInfoExtensions)
    }
}
