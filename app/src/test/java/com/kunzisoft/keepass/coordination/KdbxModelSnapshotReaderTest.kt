/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

class KdbxModelSnapshotReaderTest {
    private fun database(): Pair<DatabaseKDBX, GroupKDBX> {
        val root = GroupKDBX()
        val db = DatabaseKDBX()
        db.rootGroup = root
        return db to root
    }

    private fun addGroup(parent: GroupKDBX): GroupKDBX = GroupKDBX().also {
        it.parent = parent
        parent.addChildGroup(it)
    }

    private fun addEntry(parent: GroupKDBX): EntryKDBX = EntryKDBX().also {
        it.parent = parent
        parent.addChildEntry(it)
    }

    private fun rejected(block: () -> Unit) {
        try {
            block()
            fail("Expected malformed KDBX model to be rejected")
        } catch (_: IllegalArgumentException) {
            // expected, and no write operation was attempted
        }
    }

    @Test fun `reads actual nested KDBX groups and entries`() {
        val (db, root) = database()
        val child = addGroup(root)
        val entry = addEntry(child)
        val result = KdbxModelSnapshotReader.read(db)
        assertEquals(root.id.toString(), result.rootGroupId)
        assertEquals(3, result.nodes.size)
        assertEquals(root.id.toString(), result.nodes[child.id.toString()]?.parentGroupId)
        assertEquals(child.id.toString(), result.nodes[entry.id.toString()]?.parentGroupId)
        assertEquals(KdbxModelSnapshotReader.Kind.ENTRY, result.nodes[entry.id.toString()]?.kind)
    }

    @Test fun `tracks histories and binary references without retaining secrets`() {
        val (db, root) = database()
        val entry = addEntry(root)
        entry.password = "top secret".toCharArray()
        entry.history.add(EntryKDBX())
        entry.binaries["attachment"] = 7
        val result = KdbxModelSnapshotReader.read(db)
        val node = result.nodes.getValue(entry.id.toString())
        assertEquals(1, node.historyVersions)
        assertEquals(1, node.attachmentReferences)
        assertTrue(result.toString().contains("top secret").not())
    }

    @Test fun `retains deleted object identities and timestamps`() {
        val (db, _) = database()
        val uuid = UUID.randomUUID()
        db.deletedObjects.add(DeletedObject(uuid))
        val result = KdbxModelSnapshotReader.read(db)
        assertEquals(uuid.toString(), result.tombstones.getValue(uuid.toString()).id)
        assertTrue(result.tombstones.getValue(uuid.toString()).deletionTimeMillis > 0)
    }

    @Test fun `does not discard a tombstone when UUID also exists in live tree`() {
        val (db, root) = database()
        val entry = addEntry(root)
        db.deletedObjects.add(DeletedObject(entry.id))
        val result = KdbxModelSnapshotReader.read(db)
        assertTrue(result.nodes.containsKey(entry.id.toString()))
        assertTrue(result.tombstones.containsKey(entry.id.toString()))
    }

    @Test fun `deep hierarchy is traversed without recursion`() {
        val (db, root) = database()
        var parent = root
        repeat(1200) { parent = addGroup(parent) }
        val result = KdbxModelSnapshotReader.read(db)
        assertEquals(1201, result.nodes.size)
    }

    @Test fun `rejects missing root`() {
        rejected { KdbxModelSnapshotReader.read(DatabaseKDBX()) }
    }

    @Test fun `rejects duplicate UUID between group and entry`() {
        val (db, root) = database()
        val group = addGroup(root)
        val entry = addEntry(root)
        entry.nodeId = NodeIdUUID(group.id)
        rejected { KdbxModelSnapshotReader.read(db) }
    }

    @Test fun `rejects duplicate child UUIDs`() {
        val (db, root) = database()
        val first = addEntry(root)
        val second = addEntry(root)
        second.nodeId = NodeIdUUID(first.id)
        rejected { KdbxModelSnapshotReader.read(db) }
    }

    @Test fun `rejects conflicting containment and parent reference`() {
        val (db, root) = database()
        val child = addGroup(root)
        val entry = addEntry(child)
        entry.parent = root
        rejected { KdbxModelSnapshotReader.read(db) }
    }

    @Test fun `rejects group with inconsistent parent reference`() {
        val (db, root) = database()
        val group = addGroup(root)
        group.parent = null
        rejected { KdbxModelSnapshotReader.read(db) }
    }

    @Test fun `rejects root assigned a parent`() {
        val (db, root) = database()
        root.parent = GroupKDBX()
        rejected { KdbxModelSnapshotReader.read(db) }
    }
}
