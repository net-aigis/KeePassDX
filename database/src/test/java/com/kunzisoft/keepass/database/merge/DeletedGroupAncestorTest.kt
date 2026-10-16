/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.database.merge

import com.kunzisoft.keepass.database.element.group.GroupKDBX
import junit.framework.TestCase
import java.io.IOException

class DeletedGroupAncestorTest : TestCase() {
    fun testImmediateSurvivingParent() {
        val root = GroupKDBX()
        assertSame(root, DeletedGroupAncestor.firstSurviving(root, emptySet()))
    }

    fun testSkipsMultipleDeletedAncestors() {
        val root = GroupKDBX()
        val outer = GroupKDBX().apply { parent = root }
        val inner = GroupKDBX().apply { parent = outer }
        assertSame(root, DeletedGroupAncestor.firstSurviving(
            inner, setOf(inner.nodeId.id, outer.nodeId.id)))
    }

    fun testDoesNotChooseDeletedRoot() {
        val root = GroupKDBX()
        val child = GroupKDBX().apply { parent = root }
        try {
            DeletedGroupAncestor.firstSurviving(child, setOf(child.nodeId.id, root.nodeId.id))
            fail("Expected fail-closed refusal when no parent survives")
        } catch (_: IOException) {
            // Expected: never relocate into a deleted group.
        }
    }

    fun testDetectsCyclicAncestry() {
        val first = GroupKDBX()
        val second = GroupKDBX()
        first.parent = second
        second.parent = first
        try {
            DeletedGroupAncestor.firstSurviving(first, setOf(first.nodeId.id, second.nodeId.id))
            fail("Expected cyclic ancestry to be rejected")
        } catch (_: IOException) {
            // Expected: no unbounded loop.
        }
    }
}
