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
package com.vitorpamplona.marmot.foundation.appEvents

import com.vitorpamplona.quartz.nip01Core.core.Event
import com.vitorpamplona.quartz.nip01Core.core.HexKey
import com.vitorpamplona.quartz.nip01Core.core.TagArray
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonPrimitive

/**
 * Kind 4891, an admin's deletion of a chat message (`features/content-moderation.md`).
 *
 * The shape is strict because "a malformed or unauthorized deletion MUST have no deletion
 * effect": exactly one `e` tag naming a 64-lowercase-hex id, and `content` exactly
 * `{"v":1,"action":"remove"}` (no other members, no duplicate keys, `v` the integer 1).
 * Trailing elements of the `e` tag and other tags are ignored. These are the same rules MDK
 * applies (`parse_removal`), so both sides agree on which events delete anything.
 *
 * Whether the author MAY delete is a separate question, answered against the admin set of
 * the event's source epoch (see `MarmotManager.adminRemovalTargets`).
 */
object MarmotAdminDeletion {
    const val KIND = MarmotAppEvent.KIND_REMOVE

    /** The canonical content of a v1 removal. */
    const val CONTENT = "{\"v\":1,\"action\":\"remove\"}"

    /** The message [event] deletes, or null when it is not a well-formed kind-4891 deletion. */
    fun targetOf(event: Event): HexKey? = if (event.kind == KIND) targetOf(event.tags, event.content) else null

    /** The message a kind-4891 with [tags] and [content] deletes, or null when malformed. */
    fun targetOf(
        tags: TagArray,
        content: String,
    ): HexKey? {
        if (!isRemoveDecision(content)) return null
        var target: HexKey? = null
        for (tag in tags) {
            if (tag.isEmpty() || tag[0] != "e") continue
            // A second `e` tag, or one without a valid id, makes the whole event malformed.
            if (target != null) return null
            val id = tag.getOrNull(1) ?: return null
            if (!isEventId(id)) return null
            target = id
        }
        return target
    }

    /** The tags of a v1 removal of [targetId]. */
    fun tags(targetId: HexKey): TagArray = arrayOf(arrayOf("e", targetId))

    private fun isRemoveDecision(content: String): Boolean {
        val json =
            try {
                MarmotJson.parseObject(content)
            } catch (_: IllegalArgumentException) {
                return false
            } catch (_: SerializationException) {
                return false
            }
        if (json.duplicateKeys.isNotEmpty() || json.keys != setOf("v", "action")) return false
        val v = json.element("v") as? JsonPrimitive ?: return false
        val action = json.element("action") as? JsonPrimitive ?: return false
        return !v.isString && v.content == "1" && action.isString && action.content == "remove"
    }

    private fun isEventId(value: String): Boolean = value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
}
