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
package com.vitorpamplona.marmot

import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageEvent
import com.vitorpamplona.marmot.mip00KeyPackages.KeyPackageRelayListEvent
import com.vitorpamplona.marmot.mip00KeyPackages.LegacyKeyPackageEvent
import com.vitorpamplona.marmot.mip02Welcome.WelcomeEvent
import com.vitorpamplona.marmot.mip03GroupMessages.GroupEvent
import com.vitorpamplona.marmot.mip05PushNotifications.NotificationRequestEvent
import com.vitorpamplona.marmot.mip05PushNotifications.TokenListEvent
import com.vitorpamplona.marmot.mip05PushNotifications.TokenRemovalEvent
import com.vitorpamplona.marmot.mip05PushNotifications.TokenRequestEvent
import com.vitorpamplona.quartz.utils.EventBuilder
import com.vitorpamplona.quartz.utils.EventFactory
import kotlin.concurrent.Volatile

/**
 * Teaches Quartz's [EventFactory] the Marmot event classes.
 *
 * Quartz does not know Marmot, so until this runs a kind:445 parses as a bare `Event`, every
 * `is GroupEvent` check is false, and signing a Marmot template fails its cast. The library
 * calls [register] itself from every entry point (the managers, processors and fetchers, and
 * each event class's companion), so code that goes through Marmot is covered. An app that
 * parses events from relays before touching Marmot (into its own cache, say) must call it at
 * startup too. It is cheap and idempotent.
 */
object MarmotEvents {
    /** The kinds [register] adds, so a caller can tell which kinds are Marmot's. */
    val KINDS: Set<Int> =
        setOf(
            KeyPackageEvent.KIND,
            KeyPackageRelayListEvent.KIND,
            LegacyKeyPackageEvent.KIND,
            WelcomeEvent.KIND,
            GroupEvent.KIND,
            NotificationRequestEvent.KIND,
            TokenRequestEvent.KIND,
            TokenListEvent.KIND,
            TokenRemovalEvent.KIND,
        )

    @Volatile
    private var registered = false

    fun register() {
        if (registered) return
        EventFactory.factories[KeyPackageEvent.KIND] = EventBuilder(::KeyPackageEvent)
        EventFactory.factories[KeyPackageRelayListEvent.KIND] = EventBuilder(::KeyPackageRelayListEvent)
        EventFactory.factories[LegacyKeyPackageEvent.KIND] = EventBuilder(::LegacyKeyPackageEvent)
        EventFactory.factories[WelcomeEvent.KIND] = EventBuilder(::WelcomeEvent)
        EventFactory.factories[GroupEvent.KIND] = EventBuilder(::GroupEvent)
        EventFactory.factories[NotificationRequestEvent.KIND] = EventBuilder(::NotificationRequestEvent)
        EventFactory.factories[TokenRequestEvent.KIND] = EventBuilder(::TokenRequestEvent)
        EventFactory.factories[TokenListEvent.KIND] = EventBuilder(::TokenListEvent)
        EventFactory.factories[TokenRemovalEvent.KIND] = EventBuilder(::TokenRemovalEvent)
        registered = true
    }
}
