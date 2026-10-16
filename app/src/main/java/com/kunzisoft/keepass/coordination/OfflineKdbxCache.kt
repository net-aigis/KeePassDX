/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

/**
 * App-private cache of *already encrypted* KDBX bytes, never a decrypted database.
 * The content digest is the server's revision and is verified on every offline open.
 * A cache is not permission to publish: offline edits must pass the server revision
 * check after reconnecting.
 */
internal object OfflineKdbxCache {
    data class Snapshot(val revision: String, val bytes: ByteArray)
    data class OfflineContent(val bytes: ByteArray, val baseRevision: String)
    private val digest = Regex("[a-f0-9]{64}")

    private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun prefix(identity: String): String =
        "coordinated-kdbx-cache-${hash(identity.toByteArray(Charsets.UTF_8))}-"

    private fun syncDirectory(directory: File) {
        try {
            val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
            try { Os.fsync(fd) } finally { Os.close(fd) }
        } catch (e: Exception) {
            throw IOException("Could not sync offline cache directory", e)
        }
    }

    private fun inspect(directory: File, identity: String): List<File> {
        val files = directory.listFiles() ?: throw IOException("Cannot read cache directory")
        val prefix = prefix(identity)
        if (files.any { it.name.startsWith(prefix) && it.name.endsWith(".stage") }) {
            throw IOException("Incomplete offline cache staging; manual recovery required")
        }
        val matches = files.filter { it.name.startsWith(prefix) && it.name.endsWith(".kdbx") }
        if (matches.size > 1) throw IOException("Multiple offline cache revisions; manual recovery required")
        return matches
    }

    @Synchronized
    fun load(directory: File, identity: String): Snapshot? {
        val file = inspect(directory, identity).singleOrNull() ?: return null
        val revision = file.name.removePrefix(prefix(identity)).removeSuffix(".kdbx")
        if (!file.isFile || !digest.matches(revision)) throw IOException("Invalid offline cache filename")
        val bytes = file.inputStream().use {
            CoordinatorByteLimits.readBounded(it, CoordinatorByteLimits.MAX_KDBX_BYTES, file.length())
        }
        if (hash(bytes) != revision) throw IOException("Offline cache checksum mismatch")
        return Snapshot(revision, bytes)
    }

    /** A local unsynchronized revision takes precedence over the last online snapshot.
     * Both are validated before any caller receives ciphertext. */
    @Synchronized
    fun readOffline(directory: File, identity: String): OfflineContent? {
        val cached = load(directory, identity) ?: return null
        val pending = AtomicRecoveryStore.find(directory, identity)
        val local = if (pending != null) CoordinatorByteLimits.readBounded(
            pending.file.inputStream(), CoordinatorByteLimits.MAX_KDBX_BYTES, pending.file.length())
            else null
        val localHash = local?.let(::hash)
        val base = OfflineSnapshotPolicy.offlineBase(cached.revision, pending?.baseRevision, localHash)
        return OfflineContent(local ?: cached.bytes, base)
    }

    @Synchronized
    fun store(directory: File, identity: String, encryptedKdbx: ByteArray) {
        if (encryptedKdbx.isEmpty() || encryptedKdbx.size > CoordinatorByteLimits.MAX_KDBX_BYTES) {
            throw IOException("Refusing empty or oversized offline cache")
        }
        val revision = hash(encryptedKdbx)
        val prior = inspect(directory, identity).singleOrNull()
        if (prior != null && load(directory, identity)?.revision == revision) return
        val destination = File(directory, "${prefix(identity)}$revision.kdbx")
        val staged = File.createTempFile(prefix(identity), ".stage", directory)
        try {
            FileOutputStream(staged).use { output ->
                output.write(encryptedKdbx)
                output.fd.sync()
            }
            try { Os.rename(staged.absolutePath, destination.absolutePath) }
            catch (e: Exception) { throw IOException("Failed to install offline cache", e) }
            syncDirectory(directory)
            if (prior != null && prior.absolutePath != destination.absolutePath) {
                if (!prior.delete()) throw IOException("Old offline cache could not be removed")
                syncDirectory(directory)
            }
        } finally {
            staged.delete()
        }
    }
}
