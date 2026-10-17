/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeIdUUID
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.joda.time.Instant
import java.util.UUID

class KdbxThreeCopyReviewTest {
    private val rootId = UUID.randomUUID()
    private val entryId = UUID.randomUUID()

    // Fingerprints include millisecond timestamps. Independent test copies must
    // represent identical persisted revisions, not freshly-created wall-clock instants.
    private fun fixedTime() = DateInstant(Instant(1_700_000_000_000L))

    private fun fixNodeTimes(node: NodeKDBXInterface) {
        node.creationTime = fixedTime()
        node.lastModificationTime = fixedTime()
        node.lastAccessTime = fixedTime()
        node.locationChanged = fixedTime()
    }

    private fun copy(password: String? = "unchanged"): DatabaseKDBX {
        val db = DatabaseKDBX()
        val root = GroupKDBX().also { it.nodeId = NodeIdUUID(rootId); fixNodeTimes(it) }
        db.rootGroup = root
        if (password != null) {
            val entry = EntryKDBX().also {
                it.nodeId = NodeIdUUID(entryId)
                fixNodeTimes(it)
                it.parent = root
                it.password = password.toCharArray()
            }
            root.addChildEntry(entry)
        } else {
            db.deletedObjects.add(DeletedObject(entryId, fixedTime()))
        }
        return db
    }

    private fun record(report: KdbxThreeCopyReview.Report) =
        report.decisions.single { it.id == entryId.toString() }.source

    private fun rejects(block: () -> Unit) {
        try { block(); fail("Expected rejection") }
        catch (_: IllegalArgumentException) { /* fail closed */ }
    }

    @Test fun `unchanged copies need no merge`() {
        assertEquals(KdbxThreeCopyReview.Source.UNCHANGED,
            record(KdbxThreeCopyReview.read(copy(), copy(), copy())))
    }

    @Test fun `local-only change is classified without exposing the password`() {
        val review = KdbxThreeCopyReview.read(copy(), copy("secret-new"), copy())
        assertEquals(KdbxThreeCopyReview.Source.LOCAL, record(review))
        assertFalse(review.toString().contains("secret-new"))
    }

    @Test fun `remote-only and equal parallel change classified`() {
        assertEquals(KdbxThreeCopyReview.Source.REMOTE,
            record(KdbxThreeCopyReview.read(copy(), copy(), copy("remote"))))
        assertEquals(KdbxThreeCopyReview.Source.IDENTICAL,
            record(KdbxThreeCopyReview.read(copy(), copy("both"), copy("both"))))
    }

    @Test fun `divergent edits reported as conflict`() {
        val result = KdbxThreeCopyReview.read(copy(), copy("local"), copy("remote"))
        assertEquals(KdbxThreeCopyReview.Source.CONFLICT, record(result))
        assertTrue(result.conflictIds.contains(entryId.toString()))
    }

    @Test fun `tombstone versus modification is a conflict`() {
        val result = KdbxThreeCopyReview.read(copy(), copy(null), copy("remote"))
        assertEquals(KdbxThreeCopyReview.Source.CONFLICT, record(result))
    }

    @Test fun `one-sided tombstone is visible as an edit but never grants write`() {
        assertEquals(KdbxThreeCopyReview.Source.LOCAL,
            record(KdbxThreeCopyReview.read(copy(), copy(null), copy())))
    }

    @Test fun `missing deleted object is rejected`() {
        val local = copy()
        val root = local.rootGroup!!
        val empty = DatabaseKDBX().also {
            it.rootGroup = GroupKDBX().also { g -> g.nodeId = NodeIdUUID(rootId); fixNodeTimes(g) }
        }
        rejects { KdbxThreeCopyReview.read(local, empty, copy()) }
        assertTrue(root.getChildEntries().isNotEmpty())
    }

    @Test fun `ambiguous live record and tombstone in same copy rejected`() {
        val local = copy()
        local.deletedObjects.add(DeletedObject(entryId))
        rejects { KdbxThreeCopyReview.read(copy(), local, copy()) }
    }

    @Test fun `mismatched roots are rejected`() {
        val bad = DatabaseKDBX()
        bad.rootGroup = GroupKDBX()
        rejects { KdbxThreeCopyReview.read(copy(), bad, copy()) }
    }

    @Test fun `reusing a previously deleted UUID is rejected`() {
        rejects { KdbxThreeCopyReview.read(copy(null), copy(), copy(null)) }
    }

    @Test fun `deletion on both branches with same tombstone is identical`() {
        assertEquals(KdbxThreeCopyReview.Source.IDENTICAL,
            record(KdbxThreeCopyReview.read(copy(), copy(null), copy(null))))
    }
}
