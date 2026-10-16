/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLHandshakeException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineSnapshotPolicyTest {
    private val original = "a".repeat(64)
    private val published = "b".repeat(64)

    @Test fun `offline base follows verified cache when no changes exist`() {
        assertEquals(original, OfflineSnapshotPolicy.offlineBase(original, null, null))
    }
    @Test fun `offline pending continues its original edit chain`() {
        assertEquals(original, OfflineSnapshotPolicy.offlineBase(original, original, published))
    }
    @Test fun `acknowledged pending base advances to cached version`() {
        assertEquals(published, OfflineSnapshotPolicy.offlineBase(published, original, published))
    }
    @Test(expected = IOException::class)
    fun `unrelated cached and pending revisions must not be mixed`() {
        OfflineSnapshotPolicy.offlineBase(published, original, "c".repeat(64))
    }
    @Test fun `offline fallback requires transport error and does not ignore tls rejection`() {
        assertTrue(OfflineSnapshotPolicy.isTransportUnavailable(ConnectException("unreachable")))
        assertTrue(OfflineSnapshotPolicy.isTransportUnavailable(IOException("wrapped", SocketTimeoutException("timeout"))))
        assertFalse(OfflineSnapshotPolicy.isTransportUnavailable(IOException("HTTP 401")))
        assertFalse(OfflineSnapshotPolicy.isTransportUnavailable(KdbxCoordinatorClient.BusyException()))
        assertFalse(OfflineSnapshotPolicy.isTransportUnavailable(KdbxCoordinatorClient.StaleRevisionException()))
        assertFalse(OfflineSnapshotPolicy.isTransportUnavailable(SSLHandshakeException("invalid certificate")))
        assertFalse(OfflineSnapshotPolicy.isTransportUnavailable(IOException("checksum mismatch")))
    }
}
