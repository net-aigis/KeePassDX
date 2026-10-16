/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RecoveryRetentionPolicyTest {
    private val a = "a".repeat(64)
    private val b = "b".repeat(64)
    private val c = "c".repeat(64)

    @Test fun `retry after lost acknowledgement retains latest save under same base`() {
        assertTrue(RecoveryRetentionPolicy.canReplace(a, b, a))
    }

    @Test fun `previously confirmed pending revision can advance base`() {
        assertTrue(RecoveryRetentionPolicy.canReplace(a, b, b))
    }

    @Test fun `unrelated base is never silently replaced`() {
        assertFalse(RecoveryRetentionPolicy.canReplace(a, b, c))
    }
}
