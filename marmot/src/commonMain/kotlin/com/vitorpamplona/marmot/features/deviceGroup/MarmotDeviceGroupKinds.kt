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

/**
 * The Marmot app-event kinds an account's devices send only inside their own
 * device group (`features/device-group.md`, `features/account-sync.md`,
 * `foundation/registries.md`).
 *
 * A device reads one only in the device group it trusts and ignores it in any
 * other group: no chat projects one, and no client sends one to a chat (MDK
 * `marmot-app/src/client/device_group/messages.rs` `is_device_group_kind`).
 */
object MarmotDeviceGroupKinds {
    /** `{"v":1}`: the sending device is running. */
    const val HEARTBEAT = 457

    /** Advisory claim before filling a sibling's missing chat. */
    const val GAP_FILL_CLAIM = 458

    /** Ask a sibling for private KeyPackages. */
    const val PRIVATE_KEY_PACKAGE_REQUEST = 459

    /** Private KeyPackages handed to one sibling. */
    const val PRIVATE_KEY_PACKAGE_HAND_OFF = 460

    /** The Welcome of an Add that used a sibling's private KeyPackage. */
    const val SIBLING_WELCOME = 461

    /** A chat's history sealed to a newly added sibling (`account-sync.md`). */
    const val HISTORY_DELIVERY = 473

    /** A small-state item: names, invitation decisions, … (`account-sync.md`). */
    const val SMALL_STATE_UPDATE = 475

    /** Ask the siblings to broadcast their small state again. */
    const val SMALL_STATE_BROADCAST_REQUEST = 476

    /** Which chats a newly linked device can expect to join. */
    const val LINK_CHAT_INVENTORY = 477

    val ALL: Set<Int> =
        setOf(
            HEARTBEAT,
            GAP_FILL_CLAIM,
            PRIVATE_KEY_PACKAGE_REQUEST,
            PRIVATE_KEY_PACKAGE_HAND_OFF,
            SIBLING_WELCOME,
            HISTORY_DELIVERY,
            SMALL_STATE_UPDATE,
            SMALL_STATE_BROADCAST_REQUEST,
            LINK_CHAT_INVENTORY,
        )

    /** Whether an app event of [kind] belongs only in a device group. */
    fun isDeviceGroupKind(kind: Int): Boolean = kind in ALL
}
