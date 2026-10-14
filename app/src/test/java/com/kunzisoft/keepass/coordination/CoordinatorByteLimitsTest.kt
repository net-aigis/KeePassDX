/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.ByteArrayInputStream
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class CoordinatorByteLimitsTest {
    private fun expectIoError(block: () -> Unit) {
        try {
            block()
            fail("Expected IOException")
        } catch (_: IOException) {
            // Correct: memory or network payload exceeded its bound.
        }
    }

    @Test fun `reads an exact-size response`() {
        val data = ByteArray(24) { it.toByte() }
        assertArrayEquals(data, CoordinatorByteLimits.readBounded(ByteArrayInputStream(data), 24))
    }

    @Test fun `rejects chunked responses beyond limit`() {
        expectIoError {
            CoordinatorByteLimits.readBounded(ByteArrayInputStream(ByteArray(25)), 24)
        }
    }

    @Test fun `rejects oversized declared content length`() {
        expectIoError {
            CoordinatorByteLimits.readBounded(ByteArrayInputStream(ByteArray(1)), 24, 25)
        }
    }

    @Test fun `bounds save serialization before unbounded expansion`() {
        val stream = BoundedKdbxOutputStream(24)
        stream.write(ByteArray(23))
        stream.write(1)
        assertEquals(24, stream.size())
        expectIoError { stream.write(1) }
        expectIoError { stream.write(ByteArray(2)) }
        assertEquals(24, stream.size())
    }
    @Test fun `rejects unencrypted endpoints and invalid bearer headers`() {
        try {
            KdbxCoordinatorClient("http://localhost:8765", "test", "z".repeat(32), "android")
            fail("Expected HTTPS-only validation")
        } catch (_: IllegalArgumentException) {
            // Only explicit protocol tests may use cleartext loopback.
        }
        try {
            KdbxCoordinatorClient("https://example.org", "test", "z".repeat(32) + "\n", "android")
            fail("Expected bearer-token validation")
        } catch (_: IllegalArgumentException) {
            // HTTP header injection and control characters are forbidden.
        }
    }
}
