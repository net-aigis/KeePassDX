/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Fail-closed *planning* for a true three-way merge of decrypted KDBX records.
 * A fingerprint MUST represent an entire canonical record, including protected
 * fields, attachments, history, group assignment and deletion state. Encrypted
 * KDBX blob hashes cannot be used as record fingerprints.
 *
 * This module NEVER mutates a database and NEVER publishes. The future KDBX
 * adapter must prove canonical completeness before using decisions to write.
 */
internal object ThreeWayEntryMergePlan {
    enum class Source { UNCHANGED, LOCAL, REMOTE, IDENTICAL, CONFLICT }
    data class Decision(val entryId: String, val source: Source)

    /** Missing UUID means a deletion. A remote-vs-local conflict includes
     * delete-vs-modify and two differing creations with the same UUID. */
    fun plan(
        base: Map<String, String>,
        local: Map<String, String>,
        remote: Map<String, String>
    ): List<Decision> {
        val ids = (base.keys + local.keys + remote.keys).toSortedSet()
        return ids.map { id ->
            val b = base[id]
            val l = local[id]
            val r = remote[id]
            val source = when {
                l == r -> if (l == b) Source.UNCHANGED else Source.IDENTICAL
                l == b -> Source.REMOTE
                r == b -> Source.LOCAL
                else -> Source.CONFLICT
            }
            Decision(id, source)
        }
    }
}
