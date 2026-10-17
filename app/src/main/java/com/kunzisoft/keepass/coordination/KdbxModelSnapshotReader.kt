/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import java.util.ArrayDeque
import java.util.IdentityHashMap

/**
 * Reads the actual decrypted KDBX model without modifying it or retaining field values.
 *
 * This is an inventory of node identity, parent links, history/attachment presence,
 * and DeletedObjects. It deliberately does NOT produce a ThreeWayKdbxTreePlan.Snapshot:
 * no whole-record fingerprint (including binary bytes and database metadata) has
 * been certified, so this inventory is NOT authorization to merge or publish.
 */
internal object KdbxModelSnapshotReader {
    enum class Kind { GROUP, ENTRY }

    data class Node(
        val id: String,
        val kind: Kind,
        val parentGroupId: String?,
        val historyVersions: Int = 0,
        val attachmentReferences: Int = 0,
        // Null is reserved for the root and for older synthetic test inventories.
        // Real KDBX children always carry their position in the parent group.
        val indexInParent: Int? = null
    )

    data class Tombstone(
        val id: String,
        val deletionTimeMillis: Long,
        val deletionTimeType: String
    )

    data class Inventory(
        val rootGroupId: String,
        val nodes: Map<String, Node>,
        val tombstones: Map<String, Tombstone>
    )

    fun read(database: DatabaseKDBX): Inventory {
        val root = requireNotNull(database.rootGroup) { "KDBX has no root group" }
        require(root.parent == null) { "KDBX root group has a parent" }

        val nodes = LinkedHashMap<String, Node>()
        val visitedGroups = IdentityHashMap<GroupKDBX, Boolean>()
        val pending = ArrayDeque<GroupKDBX>()
        pending.add(root)

        while (pending.isNotEmpty()) {
            val group = pending.removeFirst()
            require(visitedGroups.put(group, true) == null) {
                "KDBX group appears repeatedly or forms a cycle"
            }
            val id = group.id.toString()
            require(id !in nodes) { "Duplicate KDBX node UUID: $id" }
            nodes[id] = Node(
                id, Kind.GROUP, group.parent?.id?.toString(),
                indexInParent = if (group.parent == null) null else group.indexInParent
            )

            for (child in group.getChildGroups()) {
                require(child.parent === group) {
                    "KDBX group parent pointer disagrees with containment: ${child.id}"
                }
                pending.addLast(child)
            }
            for (entry in group.getChildEntries()) {
                require(entry.parent === group) {
                    "KDBX entry parent pointer disagrees with containment: ${entry.id}"
                }
                val entryId = entry.id.toString()
                require(entryId !in nodes) { "Duplicate KDBX node UUID: $entryId" }
                nodes[entryId] = Node(
                    id = entryId,
                    kind = Kind.ENTRY,
                    parentGroupId = id,
                    historyVersions = entry.history.size,
                    attachmentReferences = entry.binaries.size,
                    indexInParent = entry.indexInParent
                )
            }
        }

        // DeletedObjects are independent of the live tree and must not be dropped.
        // A live UUID matching a tombstone is preserved for a future conflict check;
        // the reader does not reinterpret that ambiguity or remove either record.
        val tombstones = linkedMapOf<String, Tombstone>()
        for (deleted in database.deletedObjects.sortedBy { it.uuid.toString() }) {
            val id = deleted.uuid.toString()
            require(id !in tombstones) { "Duplicate KDBX DeletedObject UUID: $id" }
            tombstones[id] = Tombstone(
                id = id,
                deletionTimeMillis = deleted.deletionTime.instant.millis,
                deletionTimeType = deleted.deletionTime.type.name
            )
        }
        return Inventory(root.id.toString(), nodes.toMap(), tombstones.toMap())
    }
}
