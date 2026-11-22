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
import com.vitorpamplona.marmot.groups.MarmotCapabilities
import com.vitorpamplona.marmot.groups.MarmotGroupPolicy
import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.group.MlsGroup
import com.vitorpamplona.quartz.nip01Core.core.hexToByteArray
import com.vitorpamplona.quartz.nip01Core.signers.NostrSigner

/**
 * A current-profile group as a build from before the agent text stream's
 * retirement created it: the same epoch 0 as [CurrentProfileGroupFactory.createGroup],
 * plus component `0x8006` in the dictionary and in the required
 * `app_components`. The factory no longer can, so tests that need such a group
 * build it here.
 */
object LegacyAgentTextStreamGroup {
    /** [base] with the `0x8006` [policy] added to its state and its required components. */
    fun withAgentTextStream(
        base: AppDataDictionary,
        policy: AgentTextStreamQuicPolicyV1 = AgentTextStreamQuicPolicyV1.userToAgentDefault(),
    ): AppDataDictionary {
        val required = ComponentsList.supportedOrRequired(base) + AgentTextStreamQuicPolicyV1.COMPONENT_ID
        return base
            .with(AgentTextStreamQuicPolicyV1.COMPONENT_ID, policy.encode())
            .with(ComponentsList.APP_COMPONENTS_ID, ComponentsList.encode(required))
    }

    suspend fun create(
        signer: NostrSigner,
        nostrGroupId: ByteArray,
        relays: List<String>,
        profile: GroupProfileV1? = null,
        policy: AgentTextStreamQuicPolicyV1 = AgentTextStreamQuicPolicyV1.userToAgentDefault(),
    ): MlsGroup {
        val identity = signer.pubKey.hexToByteArray()
        val leaf = CurrentProfileGroupFactory.newLeafIdentity(signer)
        val dictionary =
            withAgentTextStream(
                MarmotGroupState.buildDictionary(
                    adminPolicy = AdminPolicyV1.of(listOf(identity)),
                    routing = NostrRoutingV1.of(nostrGroupId, relays),
                    profile = profile,
                    lifecycle = GroupLifecycleV1.ACTIVE,
                ),
                policy,
            )
        return MlsGroup.create(
            identity = identity,
            signingKey = leaf.signatureKeyPair.privateKey,
            initialExtensions = listOf(dictionary.toExtension()),
            leafExtensions = leaf.leafExtensions,
            policy = MarmotGroupPolicy,
            capabilities = MarmotCapabilities.currentProfileLeaf(),
            requiredCapabilities = MarmotCapabilities.currentProfileRequired(),
        )
    }
}
