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
package com.vitorpamplona.marmot.groups

/**
 * Encrypted local storage for decrypted Marmot inner event JSONs.
 *
 * Marmot MLS group messages are encrypted with per-message ratchet keys that
 * advance as each message is decrypted. After the ratchet has advanced past
 * a message, that ciphertext can no longer be decrypted — even by its
 * original recipient. To make group history survive app restarts we must
 * persist the *plaintext* inner events at the moment they are first
 * decrypted, rather than relying on relay redelivery.
 *
 * Implementations MUST encrypt all data at rest — the stored blobs contain
 * the contents of private group conversations.
 *
 * Each group's messages are stored independently, keyed by the hex-encoded
 * Nostr group ID (the `h` tag value from MIP-01).
 */
interface MarmotMessageStore {
    /**
     * Append a decrypted inner event JSON to the group's persisted message log.
     *
     * Appends MUST be idempotent: appending a JSON string that is already in
     * the group's log is a no-op. After a restart the MLS ratchet rewinds to
     * the last persisted commit, so relays replaying recent kind:445 events
     * can re-decrypt — and re-persist — messages already captured in a
     * previous session; without dedup the log grows on every restart.
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     * @param innerEventJson the decrypted inner Nostr event JSON (e.g., kind:9 chat)
     */
    suspend fun appendMessage(
        nostrGroupId: String,
        innerEventJson: String,
    )

    /**
     * Load all persisted inner event JSONs for a group, in append order.
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     * @return list of inner event JSON strings, empty if none
     */
    suspend fun loadMessages(nostrGroupId: String): List<String>

    /**
     * Delete all persisted messages for a group (after leaving).
     *
     * @param nostrGroupId hex-encoded Nostr group ID
     */
    suspend fun delete(nostrGroupId: String)

    /**
     * Remember which MLS epoch delivered [innerEventId].
     *
     * Almost nothing needs this — the inner event is the message. Agent text
     * streams do: their record key context binds `mls_epoch`, so a receiver
     * that derives keys for a stream must use the epoch that carried the
     * stream's kind:1200 anchor, not whatever epoch the group has reached by
     * the time someone watches. A commit landing in between would otherwise
     * silently produce a different key and an empty preview.
     *
     * Optional: a store that does not keep it simply cannot render a live
     * preview for a stream anchored in an older epoch, which is a degraded
     * feature and not a broken group.
     */
    suspend fun recordEpoch(
        nostrGroupId: String,
        innerEventId: String,
        epoch: Long,
    ) = Unit

    /** Inner event id → the MLS epoch that delivered it, for what was recorded. */
    suspend fun loadEpochs(nostrGroupId: String): Map<String, Long> = emptyMap()

    /**
     * Remember the encrypted-media key of [epoch]
     * (`MLS-Exporter("marmot", "encrypted-media", 32)` under that epoch).
     *
     * An attachment's key comes from the epoch of the message that carries it
     * (`features/encrypted-media.md`), and the MLS state forgets an epoch's
     * exporter secret a few commits later. Capturing the media key while the
     * epoch is still held is what lets a picture sent before the last commit
     * still open, after a restart as much as before it.
     *
     * One entry per epoch that delivered a message, not one per message. It is
     * a secret: store it under the same at-rest encryption as the messages.
     *
     * Optional, like [recordEpoch]: a store that keeps none can only open
     * attachments from epochs the group still retains.
     */
    suspend fun recordMediaSecret(
        nostrGroupId: String,
        epoch: Long,
        mediaSecret: ByteArray,
    ) = Unit

    /** MLS epoch → its encrypted-media key, for what was recorded. */
    suspend fun loadMediaSecrets(nostrGroupId: String): Map<Long, ByteArray> = emptyMap()

    // ── Admin moderation authority ───────────────────────────────────────────
    //
    // `features/content-moderation.md`: an admin deletion (kind 4891) is
    // authorized by the admin set of the event's SOURCE epoch, not the current
    // one, and "pruning source-epoch state MUST NOT undo an authorized
    // deletion". So the admin set of each epoch this device passes through is
    // kept, and each deletion's verdict is recorded once and read back after a
    // restart. Optional, like [recordEpoch]: a store that keeps neither can
    // still decide deletions that arrive in the current epoch while the app
    // runs, and treats anything it cannot prove as unauthorized.

    /** Remember the active admin account keys of [epoch]. First write wins. */
    suspend fun recordEpochAdmins(
        nostrGroupId: String,
        epoch: Long,
        admins: Set<String>,
    ) = Unit

    /** MLS epoch → its active admins, for what was recorded. */
    suspend fun loadEpochAdmins(nostrGroupId: String): Map<Long, Set<String>> = emptyMap()

    /** Remember whether the moderation event [innerEventId] was authorized. First write wins. */
    suspend fun recordModerationVerdict(
        nostrGroupId: String,
        innerEventId: String,
        authorized: Boolean,
    ) = Unit

    /** Moderation event id → whether it was authorized, for what was recorded. */
    suspend fun loadModerationVerdicts(nostrGroupId: String): Map<String, Boolean> = emptyMap()

    /**
     * Remember the group state the last kind `1210` rows were derived FROM.
     *
     * System rows are synthesized locally from canonical state rather than
     * received as messages, so a client needs a baseline to derive against —
     * otherwise it either re-emits every row each time it looks at the group,
     * or emits none at all. This is that baseline: a client's memory of where
     * it left off, never a wire value.
     *
     * Optional, like [recordEpoch]. A store that keeps no snapshot simply
     * derives no rows, which is a missing caption rather than a broken group.
     */
    suspend fun recordGroupSnapshot(
        nostrGroupId: String,
        snapshotJson: String,
    ) = Unit

    /** The last recorded snapshot, or null when there is no baseline yet. */
    suspend fun loadGroupSnapshot(nostrGroupId: String): String? = null

    // ── Disappearing messages ────────────────────────────────────────────────
    //
    // The three members below are one feature and are implemented together or
    // not at all: expiries that are never recorded read back empty, and an
    // empty set is never removed. A store that implements none of them simply
    // keeps every message forever, which is a client that cannot honour
    // `marmot.group.message-retention.v1` — degraded, not broken, and the same
    // shape of optionality as [recordEpoch].
    //
    // Expiry is pinned per message rather than recomputed: the component says
    // a message keeps the retention of its OWN source epoch, so a later change
    // must not re-time a message that already exists.

    /**
     * Remember when [innerEventId] stops being displayable.
     *
     * @param expiresAtSecs absolute Unix seconds, already `created_at + secs`.
     */
    suspend fun recordExpiry(
        nostrGroupId: String,
        innerEventId: String,
        expiresAtSecs: Long,
    ) = Unit

    /** Inner event id → its pinned expiry, for what was recorded. */
    suspend fun loadExpiries(nostrGroupId: String): Map<String, Long> = emptyMap()

    /**
     * Remember the retention this group required AT [epoch].
     *
     * Kept because a message pins the retention of its own source epoch, and
     * the source epoch is not always the current one: a kind:445 held back as a
     * retained candidate, or replayed after a restart, is decrypted under an
     * epoch the group has since moved past. Without this history such a message
     * would be pinned to whatever the setting happens to be at decrypt time —
     * which is the one thing the component says must not happen.
     *
     * Small and append-only: one entry per epoch that changed it, not one per
     * message.
     */
    suspend fun recordEpochRetention(
        nostrGroupId: String,
        epoch: Long,
        retentionSecs: Long,
    ) = Unit

    /** MLS epoch → the retention it required, for what was recorded. */
    suspend fun loadEpochRetentions(nostrGroupId: String): Map<Long, Long> = emptyMap()

    /**
     * Delete these messages, and any expiry recorded for them, permanently.
     *
     * The deletion is the feature: a disappearing message that is merely
     * hidden is still on disk, and this store is the only durable copy — the
     * MLS ratchet has long since moved past the ciphertext it came from.
     */
    suspend fun removeMessages(
        nostrGroupId: String,
        innerEventIds: Set<String>,
    ) = Unit
}
