/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import com.kunzisoft.keepass.BuildConfig
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/** Session is owned by the database's load/save lifecycle, not by a wrapper app. */
internal object CoordinatorSession {
    data class OpenResult(val input: InputStream, val readOnly: Boolean)
    private var active: KdbxCoordinatorClient? = null
    private var offlineBaseRevision: String? = null
    private var activeStorageIdentity: String? = null
    private var activeDocumentUri: String? = null
    private var databaseHash: String? = null

    // Recovery files must never be replayed onto a different coordinator
    // merely because its database ID happens to be identical.
    private fun recoveryIdentity(config: CoordinatorConfiguration.Config): String =
        config.url.trimEnd('/') + "\u0000" + config.id

    private fun notifyUser(context: Context, text: String) {
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(context.applicationContext, text, Toast.LENGTH_LONG).show()
        }
    }

    /** Can only fall back on actual transport failures, NEVER on HTTP or TLS errors. */
    private fun openCached(context: Context, uri: Uri, identity: String, requestWrite: Boolean): OpenResult {
        val cached = OfflineKdbxCache.readOffline(context.filesDir, identity)
            ?: throw IOException("Coordinator unavailable and no previously verified KDBX cache exists")
        activeStorageIdentity = if (requestWrite) identity else null
        activeDocumentUri = if (requestWrite) uri.toString() else null
        offlineBaseRevision = if (requestWrite) cached.baseRevision else null
        databaseHash = sha256(cached.bytes)
        notifyUser(context, "OFFLINE: Encrypted KDBX loaded from cache; changes will NOT synchronize until reconnect")
        return OpenResult(ByteArrayInputStream(cached.bytes), !requestWrite)
    }

    @Synchronized
    fun isOfflineEditing(): Boolean = offlineBaseRevision != null

    fun handles(uri: Uri?): Boolean = uri != null && uri.scheme == "content" &&
        uri.authority == "${BuildConfig.APPLICATION_ID}.coordinator"

    @Synchronized
    fun open(context: Context, uri: Uri, requestWrite: Boolean): OpenResult {
        require(handles(uri)) { "Not a coordinator URI" }
        close()
        val config = CoordinatorConfiguration.get(context)
            ?: throw IOException("Coordinator connection has not been configured")
        val client = KdbxCoordinatorClient(config.url, config.id, config.token, "android")
        var readOnly = !requestWrite
        try {
            if (requestWrite) {
                try { client.acquire() }
                catch (_: KdbxCoordinatorClient.BusyException) { readOnly = true }
            }
            // Reconcile durable encrypted changes BEFORE loading the remote database.
            // A save can reach the server while its acknowledgement gets lost. Never
            // overwrite a newer remote revision: only replay when the base matches.
            val pending = AtomicRecoveryStore.find(context.filesDir, recoveryIdentity(config))
            var data = if (readOnly) client.downloadReadOnly() else client.download()
            if (pending != null) {
                if (readOnly) {
                    throw IOException("Unsynchronized KDBX recovery copy exists; obtain the editing lock to recover it")
                }
                val remoteRevision = data?.let(::sha256) ?: "0"
                when (AtomicRecoveryStore.decide(pending, remoteRevision)) {
                    AtomicRecoveryStore.RecoveryAction.ALREADY_PUBLISHED -> {
                        AtomicRecoveryStore.acknowledge(context.filesDir, recoveryIdentity(config), remoteRevision)
                    }
                    AtomicRecoveryStore.RecoveryAction.PUBLISH -> {
                        val saved = CoordinatorByteLimits.readBounded(
                            pending.file.inputStream(), CoordinatorByteLimits.MAX_KDBX_BYTES,
                            pending.file.length())
                        val confirmedRevision = client.publish(saved)
                        AtomicRecoveryStore.acknowledge(context.filesDir, recoveryIdentity(config), confirmedRevision)
                        data = saved
                    }
                    AtomicRecoveryStore.RecoveryAction.CONFLICT -> {
                        throw IOException("Recovery copy conflicts with a newer remote revision; " +
                            "no automatic overwrite was attempted. Manual merge is required")
                    }
                }
            }
            if (data == null) throw IOException("No remote KDBX database exists yet")
            databaseHash = sha256(data)
            if (!readOnly) {
                active = client
                activeStorageIdentity = recoveryIdentity(config)
                activeDocumentUri = uri.toString()
            } else client.close()
            // Cache only after validating the response and completing any pending recovery.
            // A future offline open verifies these ciphertext bytes against their hash.
            if (config.enableOfflineCache)
                OfflineKdbxCache.store(context.filesDir, recoveryIdentity(config), data)
            return OpenResult(ByteArrayInputStream(data), readOnly)
        } catch (e: Exception) {
            runCatching { client.close() }
            if (config.enableOfflineCache && OfflineSnapshotPolicy.isTransportUnavailable(e)) {
                return openCached(context, uri, recoveryIdentity(config), requestWrite)
            }
            throw e
        }
    }

    /** Persist a recoverable encrypted copy and publish only under the same revision/lease. */
    @Synchronized
    fun persistAndPublish(context: Context, uri: Uri, encryptedKdbx: ByteArray) {
        if (!handles(uri)) throw IOException("Not a coordinator URI")
        // Keep the original document binding. Mutable settings must not redirect
        // recovery data to another coordinator while an editing session is open.
        if (activeDocumentUri != uri.toString()) {
            throw IOException("Coordinator document changed during editing")
        }
        val identity = activeStorageIdentity
            ?: throw IOException("No coordinator identity for this editing session")
        val client = active
        val localBase = offlineBaseRevision
        val base = localBase ?: client?.revisionForRecovery()
            ?: throw IOException("No valid coordinator editing session")
        // Retain ciphertext FIRST. Offline mode is not a lease and never authorizes a PUT.
        AtomicRecoveryStore.retain(context.filesDir, identity, base, encryptedKdbx)
        if (localBase != null) {
            notifyUser(context, "OFFLINE: Encrypted changes saved locally, NOT synchronized")
            return
        }
        // Only a live server-issued lease can publish.
        val config = CoordinatorConfiguration.get(context)
        if (config == null || recoveryIdentity(config) != identity) {
            throw IOException("Coordinator settings changed during editing; encrypted recovery copy retained")
        }
        if (client == null || !client.hasLease()) throw KdbxCoordinatorClient.LostLeaseException()
        val confirmedRevision = client.publish(encryptedKdbx)
        // A confirmed online save becomes the next verified offline base.
        // Retain the recovery ciphertext until the cache update is durable.
        if (config.enableOfflineCache) OfflineKdbxCache.store(context.filesDir, identity, encryptedKdbx)
        AtomicRecoveryStore.acknowledge(context.filesDir, identity, confirmedRevision)
        databaseHash = confirmedRevision
    }

    @Synchronized
    fun close() {
        val client = active
        active = null
        offlineBaseRevision = null
        activeStorageIdentity = null
        activeDocumentUri = null
        databaseHash = null
        if (client != null) runCatching { client.close() }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
