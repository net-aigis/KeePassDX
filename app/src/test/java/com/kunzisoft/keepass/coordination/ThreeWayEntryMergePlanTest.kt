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
