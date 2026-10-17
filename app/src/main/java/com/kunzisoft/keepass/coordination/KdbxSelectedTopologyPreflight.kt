/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Verifies only the links of an in-memory, read-only candidate KDBX node tree.
 * The candidate must already have been selected from three complete, immutable,
 * fingerprinted inventories. A successful check MUST NOT authorize merging,
 * serialization, write access or publication: database-wide metadata, binary
 * pools, and coordinator revision/lease checks remain independent obligations.
 */
internal object KdbxSelectedTopologyPreflight {
    fun validate(
        rootId: String,
        selectedNodes: Map<String, KdbxModelSnapshotReader.Node>
    ) {
        require(rootId.isNotBlank()) { "Empty KDBX root UUID" }
        val root = selectedNodes[rootId]
        require(root?.kind == KdbxModelSnapshotReader.Kind.GROUP && root.parentGroupId == null) {
            "Selected KDBX root is missing, is not a group, or has a parent"
        }
        for ((id, node) in selectedNodes) {
            require(id.isNotBlank() && id == node.id) { "Selected KDBX node UUID mismatch" }
            if (id == rootId) continue
            require(node.parentGroupId != null && node.parentGroupId != id) {
                "Selected KDBX node has no parent or references itself: $id"
            }
            val parent = selectedNodes[node.parentGroupId]
            require(parent?.kind == KdbxModelSnapshotReader.Kind.GROUP) {
                "Selected KDBX node has a missing/non-group parent: $id"
            }
        }

        // Iterative traversal avoids stack overflows on adversarial deep trees.
        val verified = HashSet<String>()
        verified.add(rootId)
        for ((id, node) in selectedNodes) {
            if (node.kind != KdbxModelSnapshotReader.Kind.GROUP || id in verified) continue
            val path = LinkedHashSet<String>()
            var current = id
            while (current !in verified) {
                require(path.add(current)) { "Selected KDBX group ancestry cycle: $id" }
                current = selectedNodes.getValue(current).parentGroupId
                    ?: throw IllegalArgumentException("Detached selected KDBX group: $id")
            }
            verified.addAll(path)
        }
    }
}
