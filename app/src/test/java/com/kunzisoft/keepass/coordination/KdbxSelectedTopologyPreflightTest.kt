/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class KdbxSelectedTopologyPreflightTest {
    private val t = KdbxSelectedTopologyPreflight
    private val root = KdbxModelSnapshotReader.Node("root", KdbxModelSnapshotReader.Kind.GROUP, null)

    private fun group(id: String, parent: String? = "root") =
        KdbxModelSnapshotReader.Node(id, KdbxModelSnapshotReader.Kind.GROUP, parent)

    private fun entry(id: String, parent: String? = "root") =
        KdbxModelSnapshotReader.Node(id, KdbxModelSnapshotReader.Kind.ENTRY, parent)

    private fun check(vararg nodes: KdbxModelSnapshotReader.Node) {
        val values = listOf(root) + nodes
        t.validate("root", values.associateBy { it.id })
    }

    private fun rejects(block: () -> Unit) {
        try { block(); fail("Invalid selected tree was accepted") }
        catch (_: IllegalArgumentException) { /* expected */ }
    }

    @Test fun `root with nested groups and entries is accepted`() {
        check(group("a"), group("b", "a"), entry("x", "b"), entry("y"))
    }

    @Test fun `entry left under removed parent is rejected`() {
        rejects { check(entry("x", "removed")) }
    }

    @Test fun `entry cannot be its own parent`() {
        rejects { check(entry("x", "x")) }
    }

    @Test fun `entry cannot contain another entry`() {
        rejects { check(entry("a"), entry("b", "a")) }
    }

    @Test fun `self referencing group is rejected`() {
        rejects { check(group("a", "a")) }
    }

    @Test fun `two groups in a cycle are rejected`() {
        rejects { check(group("a", "b"), group("b", "a")) }
    }

    @Test fun `group with missing parent is rejected`() {
        rejects { check(group("a", "missing")) }
    }

    @Test fun `non root group cannot be parentless`() {
        rejects { check(group("a", null)) }
    }

    @Test fun `missing selected root is rejected`() {
        rejects { t.validate("root", mapOf("a" to group("a"))) }
    }

    @Test fun `root with parent is rejected`() {
        rejects { t.validate("root", mapOf("root" to group("root", "a"), "a" to group("a"))) }
    }

    @Test fun `root may not change to an entry`() {
        rejects { t.validate("root", mapOf("root" to entry("root", null))) }
    }

    @Test fun `map key and node UUID must match`() {
        rejects { t.validate("root", mapOf("root" to root, "alias" to entry("actual"))) }
    }

    @Test fun `empty root UUID is rejected`() {
        rejects { t.validate("", mapOf("root" to root)) }
    }

    @Test fun `group removed after moving children is valid`() {
        check(entry("moved", "root"))
    }

    @Test fun `distinct indexed siblings are accepted`() {
        t.validate("root", mapOf(
            "root" to root,
            "a" to group("a").copy(indexInParent = 1),
            "x" to entry("x").copy(indexInParent = 2)
        ))
    }

    @Test fun `two selected siblings cannot share an index`() {
        rejects {
            t.validate("root", mapOf(
                "root" to root,
                "a" to group("a").copy(indexInParent = 1),
                "x" to entry("x").copy(indexInParent = 1)
            ))
        }
    }

    @Test fun `same sibling index is valid under different parent groups`() {
        t.validate("root", mapOf(
            "root" to root,
            "a" to group("a").copy(indexInParent = 1),
            "b" to group("b").copy(indexInParent = 2),
            "x" to entry("x", "a").copy(indexInParent = 1),
            "y" to entry("y", "b").copy(indexInParent = 1)
        ))
    }

    @Test fun `partially indexed combined tree fails closed`() {
        rejects {
            t.validate("root", mapOf(
                "root" to root,
                "a" to group("a").copy(indexInParent = 1),
                "x" to entry("x")
            ))
        }
    }

    @Test fun `negative sibling index is rejected`() {
        rejects {
            t.validate("root", mapOf(
                "root" to root,
                "x" to entry("x").copy(indexInParent = -1)
            ))
        }
    }

    @Test fun `root cannot carry a sibling index`() {
        rejects { t.validate("root", mapOf("root" to root.copy(indexInParent = 0))) }
    }

    @Test fun `deep hierarchy is checked without recursive stack usage`() {
        val nodes = linkedMapOf("root" to root)
        var parent = "root"
        for (index in 1..1200) {
            val child = "g$index"
            nodes[child] = group(child, parent)
            parent = child
        }
        nodes["deep-entry"] = entry("deep-entry", parent)
        t.validate("root", nodes)
        assertEquals(1202, nodes.size)
    }
}
