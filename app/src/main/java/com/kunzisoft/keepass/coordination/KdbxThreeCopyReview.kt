/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import java.security.SecureRandom

/**
 * Read-only assessment of three decrypted KDBX copies. This is NOT a merge plan,
 * cannot grant write access, and intentionally does not return any record HMACs.
 * The caller must hold each model stable for the whole comparison.
 *
 * This reports selected database-wide metadata and custom-icon changes,
 * but cannot decide unknown KDBX extensions, binary-pool reconstruction,
 * credential handling or revision/lease safety. Those remain
 * mandatory before any later implementation may write or upload a merged KDBX.
 */
internal object KdbxThreeCopyReview {
    enum class Source { UNCHANGED, LOCAL, REMOTE, IDENTICAL, CONFLICT }

    data class Decision(val id: String, val source: Source)
    data class Report(
        val decisions: List<Decision>,
        val metadata: KdbxDatabaseMetadataReview.Report
    ) {
        val conflictIds: List<String> get() = decisions.filter { it.source == Source.CONFLICT }.map { it.id }
    }

    /**
     * Generates the ephemeral key internally, uses it for *all three* copies,
     * and zeroes it even if inventory creation or comparison fails.
     */
    fun read(base: DatabaseKDBX, local: DatabaseKDBX, remote: DatabaseKDBX): Report {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        try {
            return compare(
                KdbxRecordContentFingerprints.read(base, key),
                KdbxRecordContentFingerprints.read(local, key),
                KdbxRecordContentFingerprints.read(remote, key),
                KdbxDatabaseMetadataReview.compare(base, local, remote, key)
            )
        } finally {
            key.fill(0)
        }
    }

    /** Comparison of inventories created under one ephemeral key; never export them. */
    private fun compare(
        base: KdbxRecordContentFingerprints.Inventory,
        local: KdbxRecordContentFingerprints.Inventory,
        remote: KdbxRecordContentFingerprints.Inventory,
        metadata: KdbxDatabaseMetadataReview.Report
    ): Report {
        val all = listOf(base, local, remote)
        val root = base.model.rootGroupId
        require(root.isNotBlank() && all.all { it.model.rootGroupId == root }) {
            "KDBX root differs between three copies"
        }
        val macPattern = Regex("[0-9a-f]{64}")
        for (inventory in all) {
            val nodes = inventory.model.nodes
            val tombstones = inventory.model.tombstones
            require(nodes.keys == inventory.nodeHmacSha256.keys &&
                tombstones.keys == inventory.tombstoneHmacSha256.keys) {
                "Incomplete KDBX three-copy inventory"
            }
            require(nodes[root]?.kind == KdbxModelSnapshotReader.Kind.GROUP &&
                nodes[root]?.parentGroupId == null && root !in tombstones) {
                "KDBX root is missing, modified in type or marked deleted"
            }
            require(nodes.keys.intersect(tombstones.keys).isEmpty()) {
                "KDBX UUID occurs as both live node and DeletedObject"
            }
            require(inventory.nodeHmacSha256.values.all(macPattern::matches) &&
                inventory.tombstoneHmacSha256.values.all(macPattern::matches)) {
                "Malformed KDBX record fingerprint"
            }
        }

        val ids = all.flatMap { it.model.nodes.keys + it.model.tombstones.keys }.toSortedSet()
        val decisions = ArrayList<Decision>(ids.size)
        val selectedNodes = LinkedHashMap<String, KdbxModelSnapshotReader.Node>()
        var hasConflict = false
        for (id in ids) {
            val kinds = all.mapNotNull { it.model.nodes[id]?.kind }.distinct()
            require(kinds.size <= 1) { "KDBX UUID reused for another record kind: $id" }
            val b = state(base, id)
            val l = state(local, id)
            val r = state(remote, id)
            // A UUID already deleted in the common ancestor cannot silently
            // become a new live record with the same identity.
            require(b !is State.Deleted || (l !is State.Live && r !is State.Live)) {
                "KDBX previously deleted UUID reused as a live record: $id"
            }
            // A disappearing base record without an explicit DeletedObject is
            // not a verified deletion and may indicate truncated/corrupt input.
            if (b is State.Live) {
                require(l != null && r != null) {
                    "KDBX base record disappeared without a DeletedObject: $id"
                }
            }
            val source = when {
                l == r -> if (l == b) Source.UNCHANGED else Source.IDENTICAL
                l == b -> Source.REMOTE
                r == b -> Source.LOCAL
                else -> Source.CONFLICT
            }
            decisions.add(Decision(id, source))
            if (source == Source.CONFLICT) {
                hasConflict = true
            } else {
                // Keep the node metadata from the same inventory that produced
                // the HMAC-based decision, never reread mutable models here.
                val chosen = if (source == Source.REMOTE) remote else local
                chosen.model.nodes[id]?.let { selectedNodes[id] = it }
            }
        }
        // A conflict cannot be resolved by this review; therefore it has no
        // well-defined combined topology to validate. Preserve its decisions.
        if (!hasConflict) {
            KdbxSelectedTopologyPreflight.validate(root, selectedNodes)
        }
        return Report(decisions, metadata)
    }

    private sealed interface State {
        data class Live(val kind: KdbxModelSnapshotReader.Kind, val parent: String?, val hmac: String) : State
        data class Deleted(val hmac: String) : State
    }

    private fun state(inventory: KdbxRecordContentFingerprints.Inventory, id: String): State? {
        val node = inventory.model.nodes[id]
        if (node != null) return State.Live(node.kind, node.parentGroupId,
            inventory.nodeHmacSha256.getValue(id))
        val deleted = inventory.tombstoneHmacSha256[id]
        return if (deleted == null) null else State.Deleted(deleted)
    }
}
