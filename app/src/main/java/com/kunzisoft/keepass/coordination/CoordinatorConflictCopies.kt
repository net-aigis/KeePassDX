/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.File
import java.io.IOException
import java.security.MessageDigest

/** Non-destructive export of encrypted, unsynchronized KDBX bytes.
 * Never acknowledges, removes or publishes a pending recovery copy. */
internal object CoordinatorConflictCopies {
    data class LocalCopy(val bytes: ByteArray, val baseRevision: String, val revision: String)

    fun identity(config: CoordinatorConfiguration.Config): String =
        config.url.trimEnd('/') + "\u0000" + config.id

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    fun readLocal(directory: File, identity: String): LocalCopy = synchronized(AtomicRecoveryStore) {
        val pending = AtomicRecoveryStore.find(directory, identity)
            ?: throw IOException("No unsynchronized local KDBX recovery copy exists")
        val bytes = pending.file.inputStream().use {
            CoordinatorByteLimits.readBounded(it, CoordinatorByteLimits.MAX_KDBX_BYTES,
                pending.file.length())
        }
        if (bytes.isEmpty()) throw IOException("Refusing empty KDBX recovery copy")
        LocalCopy(bytes, pending.baseRevision, sha256(bytes))
    }
}
