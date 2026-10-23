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
package com.vitorpamplona.marmot.mip00KeyPackages

import com.vitorpamplona.mls.components.AppDataDictionary
import com.vitorpamplona.mls.components.ComponentsList
import com.vitorpamplona.mls.messages.MlsKeyPackage
import com.vitorpamplona.quartz.marmot.mip00KeyPackages.KeyPackageEvent
import com.vitorpamplona.quartz.nip01Core.core.TagArrayBuilder
import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.utils.TimeUtils
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

// The one part of KeyPackageEvent that reads MLS bytes. The event class is Quartz's, which carries
// no MLS engine, so building the event from an MlsKeyPackage lives here.

/**
 * Build the event from the KeyPackage itself, deriving every id-list
 * tag from the bytes it advertises.
 *
 * The tags duplicate metadata that is already inside the KeyPackage, so
 * writing them by hand is writing a second source of truth — and MDK
 * rejects a KeyPackage whose `mls_extensions` tag "does not exactly
 * match decoded KeyPackage metadata". Adding one leaf capability and
 * forgetting the tag is enough to make every one of our KeyPackages
 * unusable, which is exactly what happened.
 *
 * `app_components` lists the Marmot registry ids only. The
 * `app_components` component itself (`0x0001`) and the other upstream
 * MLS-extensions component ids live below `0x8000` and are not app
 * components being advertised.
 */
@OptIn(ExperimentalEncodingApi::class)
fun KeyPackageEvent.Companion.buildCurrentProfileFrom(
    keyPackage: MlsKeyPackage,
    dTagSlot: String,
    clientName: String? = null,
    createdAt: Long = TimeUtils.now(),
    initializer: TagArrayBuilder<KeyPackageEvent>.() -> Unit = {},
) = buildCurrentProfile(
    keyPackageBase64 = Base64.encode(KeyPackageUtils.frameKeyPackage(keyPackage)),
    dTagSlot = dTagSlot,
    keyPackageRef = keyPackage.reference().toHexKey(),
    appComponentIds = advertisedAppComponents(keyPackage).map(this::idHex),
    ciphersuite = idHex(keyPackage.cipherSuite),
    mlsExtensionIds =
        keyPackage.leafNode.capabilities.extensions
            .map(this::idHex),
    mlsProposalIds =
        keyPackage.leafNode.capabilities.proposals
            .map(this::idHex),
    clientName = clientName,
    createdAt = createdAt,
    initializer = initializer,
)

/** Marmot app-component ids the leaf advertises, from its `app_components` component. */
private fun advertisedAppComponents(keyPackage: MlsKeyPackage): List<Int> =
    try {
        val dictionary = AppDataDictionary.fromExtensionsOrEmpty(keyPackage.leafNode.extensions)
        val list = dictionary[ComponentsList.APP_COMPONENTS_ID] ?: return emptyList()
        ComponentsList.decode(list).filter { it >= MARMOT_COMPONENT_RANGE_START }
    } catch (_: Exception) {
        emptyList()
    }

/** Marmot's own component registry starts here; lower ids are upstream MLS-extensions ones. */
private const val MARMOT_COMPONENT_RANGE_START = 0x8000
