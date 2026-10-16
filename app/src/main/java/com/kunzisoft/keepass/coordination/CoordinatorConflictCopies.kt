/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.File
import java.io.IOException
import java.security.MessageDigest

/** Non-destructive export of encrypted, unsynchronized KDBX bytes.
 * Never acknowledges, removes or publishes a pending recovery copy. */
internal object CoordinatorConflictCopies {
    data class LocalCopy(val bytes: ByteArray, val baseRevision: String, val revision: String)
    data class BaseCopy(val bytes: ByteArray, val revision: String)

    fun identity(config: CoordinatorConfiguration.Config): String =
        config.url.trimEnd('/') + "\u0000" + config.id

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /**
     * Return the exact common ancestor of the pending offline changes, not an arbitrary
     * offline cache revision. Without this ancestor a lossless three-way merge is
     * impossible. Do not create, delete, acknowledge, or publish any recovery data.
     */
    // Keep the same lock order as OfflineKdbxCache.readOffline(): cache first,
    // then recovery. This prevents a cross-thread lock-order inversion.
    fun readBase(directory: File, identity: String): BaseCopy = synchronized(OfflineKdbxCache) {
        synchronized(AtomicRecoveryStore) {
        val pending = AtomicRecoveryStore.find(directory, identity)
            ?: throw IOException("No pending offline changes; cannot determine common ancestor")
        if (pending.baseRevision == "0") {
            throw IOException("No previously published KDBX exists as a common ancestor")
        }
        val cached = OfflineKdbxCache.load(directory, identity)
            ?: throw IOException("Verified common-ancestor KDBX is missing; preserve local changes")
        if (cached.revision != pending.baseRevision) {
            throw IOException("Offline base revision differs from pending edits; unsafe to merge")
        }
        if (cached.bytes.isEmpty()) throw IOException("Empty common-ancestor KDBX")
        BaseCopy(cached.bytes, cached.revision)
        }
    }

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
