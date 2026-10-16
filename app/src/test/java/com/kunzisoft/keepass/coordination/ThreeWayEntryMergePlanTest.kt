/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertEquals
import org.junit.Test

class ThreeWayEntryMergePlanTest {
    private fun decision(base: String?, local: String?, remote: String?) =
        ThreeWayEntryMergePlan.plan(
            base?.let { mapOf("uuid-1" to it) } ?: emptyMap(),
            local?.let { mapOf("uuid-1" to it) } ?: emptyMap(),
            remote?.let { mapOf("uuid-1" to it) } ?: emptyMap()
        ).single().source

    @Test fun `unresolved conflict is rejected before applying plan`() {
        val plan = ThreeWayEntryMergePlan.plan(
            mapOf("entry" to "a"), mapOf("entry" to "b"), mapOf("entry" to "c")
        )
        try {
            ThreeWayEntryMergePlan.requireConflictFree(plan)
            org.junit.Assert.fail("Conflict must block writes")
        } catch (_: IllegalArgumentException) {
            // Expected: no merge may proceed with unresolved conflicts.
        }
    }
    @Test fun `conflict free plan passes preflight`() {
        val plan = ThreeWayEntryMergePlan.plan(
            mapOf("one" to "a", "two" to "b"),
            mapOf("one" to "A", "two" to "b"),
            mapOf("one" to "a", "two" to "B")
        )
        ThreeWayEntryMergePlan.requireConflictFree(plan)
    }
    @Test fun `duplicate record identities are rejected`() {
        val duplicated = listOf(
            ThreeWayEntryMergePlan.Decision("same", ThreeWayEntryMergePlan.Source.LOCAL),
            ThreeWayEntryMergePlan.Decision("same", ThreeWayEntryMergePlan.Source.REMOTE)
        )
        try {
            ThreeWayEntryMergePlan.requireConflictFree(duplicated)
            org.junit.Assert.fail("Duplicate IDs must block writes")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }
    @Test fun `local change only is eligible`() {
        assertEquals(ThreeWayEntryMergePlan.Source.LOCAL, decision("a", "b", "a"))
    }
    @Test fun `remote change only is eligible`() {
        assertEquals(ThreeWayEntryMergePlan.Source.REMOTE, decision("a", "a", "c"))
    }
    @Test fun `simultaneous different edits conflict`() {
        assertEquals(ThreeWayEntryMergePlan.Source.CONFLICT, decision("a", "b", "c"))
    }
    @Test fun `same change on both sides is identical`() {
        assertEquals(ThreeWayEntryMergePlan.Source.IDENTICAL, decision("a", "b", "b"))
    }
    @Test fun `delete against update conflicts`() {
        assertEquals(ThreeWayEntryMergePlan.Source.CONFLICT, decision("a", null, "b"))
        assertEquals(ThreeWayEntryMergePlan.Source.CONFLICT, decision("a", "b", null))
    }
    @Test fun `delete against unchanged is eligible`() {
        assertEquals(ThreeWayEntryMergePlan.Source.LOCAL, decision("a", null, "a"))
        assertEquals(ThreeWayEntryMergePlan.Source.REMOTE, decision("a", "a", null))
    }
    @Test fun `separate UUID changes are independent`() {
        val plan = ThreeWayEntryMergePlan.plan(
            mapOf("one" to "a", "two" to "b"),
            mapOf("one" to "A", "two" to "b"),
            mapOf("one" to "a", "two" to "B")
        ).associate { it.entryId to it.source }
        assertEquals(ThreeWayEntryMergePlan.Source.LOCAL, plan["one"])
        assertEquals(ThreeWayEntryMergePlan.Source.REMOTE, plan["two"])
    }
    @Test fun `conflicting independent creations fail closed`() {
        assertEquals(ThreeWayEntryMergePlan.Source.CONFLICT, decision(null, "a", "b"))
    }
}
