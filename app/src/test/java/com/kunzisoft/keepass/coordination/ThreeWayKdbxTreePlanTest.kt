/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ThreeWayKdbxTreePlanTest {
    private val t = ThreeWayKdbxTreePlan
    private val root = "root"
    private fun hash(c: Char) = c.toString().repeat(64)
    private fun group(id: String, parent: String? = root, c: Char = 'a') =
        ThreeWayKdbxTreePlan.Node(id, ThreeWayKdbxTreePlan.Kind.GROUP, parent, hash(c))
    private fun entry(id: String, parent: String = root, c: Char = 'a') =
        ThreeWayKdbxTreePlan.Node(id, ThreeWayKdbxTreePlan.Kind.ENTRY, parent, hash(c))
    private fun snap(vararg nodes: ThreeWayKdbxTreePlan.Node) =
        ThreeWayKdbxTreePlan.Snapshot(root, (listOf(group(root, null)) + nodes).associateBy { it.id })
    private fun blocked(action: () -> Unit) {
        try { action(); fail("Unsafe KDBX topology must be rejected") }
        catch (_: IllegalArgumentException) { /* expected */ }
    }

    @Test fun `disjoint entry changes remain attached`() {
        val b = snap(entry("one"), entry("two"))
        val l = snap(entry("one", c = 'b'), entry("two"))
        val r = snap(entry("one"), entry("two", c = 'c'))
        val out = t.plan(b, l, r)
        assertEquals(hash('b'), out.nodes["one"]?.recordSha256)
        assertEquals(hash('c'), out.nodes["two"]?.recordSha256)
        assertEquals(3, out.nodes.size)
    }

    @Test fun `simultaneous different entry edits fail closed`() {
        blocked { t.plan(snap(entry("e")), snap(entry("e", c = 'b')),
            snap(entry("e", c = 'c'))) }
    }

    @Test fun `delete versus modification fails closed`() {
        blocked { t.plan(snap(entry("e")), snap(), snap(entry("e", c = 'b'))) }
    }

    @Test fun `same edit on both sides is accepted`() {
        val out = t.plan(snap(entry("e")), snap(entry("e", c = 'b')),
            snap(entry("e", c = 'b')))
        assertEquals(ThreeWayKdbxTreePlan.Source.IDENTICAL, out.decisions.single { it.id == "e" }.source)
    }

    @Test fun `deleted group cannot retain remotely created child`() {
        val b = snap(group("g"))
        val l = snap()
        val r = snap(group("g"), entry("new", "g"))
        blocked { t.plan(b, l, r) }
    }

    @Test fun `group deletion with child moved remotely is safe`() {
        val b = snap(group("g"), entry("e", "g"))
        val l = snap(entry("e")) // local deletes group and moves entry to root
        val r = snap(group("g"), entry("e", "g"))
        val out = t.plan(b, l, r)
        assertFalse(out.nodes.containsKey("g"))
        assertEquals(root, out.nodes["e"]?.parentGroupId)
    }

    @Test fun `orphaned entry in a source snapshot is rejected`() {
        blocked { t.plan(snap(), snap(entry("e", "missing")), snap()) }
    }

    @Test fun `group ancestry cycle in source is rejected`() {
        blocked { t.plan(snap(), snap(group("a", "b"), group("b", "a")), snap()) }
    }

    @Test fun `independent group moves forming combined cycle are rejected`() {
        val b = snap(group("a"), group("b"))
        val l = snap(group("a", "b"), group("b"))
        val r = snap(group("a"), group("b", "a"))
        blocked { t.plan(b, l, r) }
    }

    @Test fun `changing UUID from group to entry is rejected`() {
        blocked { t.plan(snap(group("x")), snap(entry("x")), snap(group("x"))) }
    }

    @Test fun `different root UUIDs are rejected`() {
        val base = snap()
        blocked { t.plan(base, base.copy(rootGroupId = "other"), base) }
    }

    @Test fun `root deletion is rejected`() {
        blocked { t.plan(snap(), ThreeWayKdbxTreePlan.Snapshot(root, emptyMap()), snap()) }
    }

    @Test fun `key UUID mismatch is rejected`() {
        val wrong = ThreeWayKdbxTreePlan.Snapshot(root,
            mapOf(root to group(root, null), "alias" to entry("actual")))
        blocked { t.plan(snap(), wrong, snap()) }
    }

    @Test fun `malformed fingerprint is rejected`() {
        blocked { t.plan(snap(), snap(entry("e").copy(recordSha256 = "a")), snap()) }
    }

    @Test fun `entry cannot be a parent group`() {
        blocked { t.plan(snap(), snap(entry("a"), entry("b", "a")), snap()) }
    }

    @Test fun `cross branch group removal cannot strand unchanged node`() {
        val b = snap(group("g"), entry("e", "g"))
        // An invalid local snapshot is rejected before candidate construction.
        blocked { t.plan(b, snap(entry("e", "g")), b) }
    }

    @Test fun `independent new entry and group are retained`() {
        val out = t.plan(snap(), snap(group("g")), snap(entry("e")))
        assertTrue(out.nodes.containsKey("g"))
        assertTrue(out.nodes.containsKey("e"))
    }
}
