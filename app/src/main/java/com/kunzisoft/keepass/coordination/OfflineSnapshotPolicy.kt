/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/** Fail closed on server errors, authentication failures and TLS problems. */
internal object OfflineSnapshotPolicy {
    fun isTransportUnavailable(error: Throwable): Boolean {
        var current: Throwable? = error
        while (current != null) {
            if (current is SSLException) return false
            current = current.cause
        }
        current = error
        while (current != null) {
            if (current is ConnectException || current is UnknownHostException ||
                current is NoRouteToHostException || current is SocketTimeoutException ||
                current is SocketException) return true
            current = current.cause
        }
        return false
    }

    /** Never treat two unrelated ciphertext revisions as the same edit history. */
    fun offlineBase(cacheRevision: String, pendingBase: String?, pendingHash: String?): String {
        if (pendingBase == null) return cacheRevision
        if (pendingHash == cacheRevision) return cacheRevision // upload succeeded; ack was lost
        if (pendingBase == cacheRevision) return pendingBase // unpublished local changes
        throw java.io.IOException("Local recovery and verified server cache diverge; manual recovery required")
    }
}
