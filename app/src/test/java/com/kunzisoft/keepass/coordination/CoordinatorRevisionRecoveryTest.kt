/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

/** The durable recovery base must survive a lost lease, without permitting a PUT. */
class CoordinatorRevisionRecoveryTest {
    @Test fun `recovery remembers base revision after lease is lost`() {
        val client = KdbxCoordinatorClient("https://example.org", "demo", "z".repeat(32), "android")
        try {
            val revision = "a".repeat(64)
            val field = KdbxCoordinatorClient::class.java.getDeclaredField("revision")
            field.isAccessible = true
            field.set(client, revision)
            val lostField = KdbxCoordinatorClient::class.java.getDeclaredField("lost")
            lostField.isAccessible = true
            (lostField.get(client) as AtomicBoolean).set(true)

            assertEquals(revision, client.revisionForRecovery())
            assertFalse(client.hasLease())
            try {
                client.currentRevision()
                fail("A lost lease must not allow writes")
            } catch (_: KdbxCoordinatorClient.LostLeaseException) {
                // Recovery may inspect its base revision, but network writes remain forbidden.
            }
        } finally { client.close() }
    }

    @Test fun `recovery cannot create a base revision without a real lease`() {
        val client = KdbxCoordinatorClient("https://example.org", "demo", "z".repeat(32), "android")
        try {
            try {
                client.revisionForRecovery()
                fail("No revision must not be treated as revision zero")
            } catch (_: IOException) { }
        } finally { client.close() }
    }
}
