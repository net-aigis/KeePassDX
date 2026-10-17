/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.binary.BinaryData
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import java.util.TreeMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Read-only, session-keyed comparison of selected database-wide KDBX metadata.
 * No metadata values, MACs, decrypted fields or binary contents leave this API.
 *
 * NOT a complete serialization inventory and NOT merge/write authorization:
 * cipher/KDF parameters, public header variants, credential material, raw
 * binary-pool reconstruction and unknown KDBX extensions still need review.
 */
internal object KdbxDatabaseMetadataReview {
    private const val MAX_UNPACKED_ICON_BYTES = 64L * 1024L * 1024L

    enum class Source { UNCHANGED, LOCAL, REMOTE, IDENTICAL, CONFLICT }
    data class Decision(val key: String, val source: Source)
    data class Report(val decisions: List<Decision>) {
        val conflictKeys: List<String>
            get() = decisions.filter { it.source == Source.CONFLICT }.map { it.key }
    }

    fun compare(
        base: DatabaseKDBX,
        local: DatabaseKDBX,
        remote: DatabaseKDBX,
        sessionKey: ByteArray
    ): Report {
        require(sessionKey.size >= 32) { "KDBX metadata comparison needs a 256-bit session key" }
        val b = fingerprint(base, sessionKey)
        val l = fingerprint(local, sessionKey)
        val r = fingerprint(remote, sessionKey)
        val keys = (b.keys + l.keys + r.keys).toSortedSet()
        return Report(keys.map { key ->
            val bv = b[key]
            val lv = l[key]
            val rv = r[key]
            val source = when {
                lv == rv -> if (lv == bv) Source.UNCHANGED else Source.IDENTICAL
                lv == bv -> Source.REMOTE
                rv == bv -> Source.LOCAL
                else -> Source.CONFLICT
            }
            Decision(key, source)
        })
    }

    private fun fingerprint(db: DatabaseKDBX, key: ByteArray): Map<String, String> {
        val result = TreeMap<String, String>()
        fun add(name: String, data: Writer.() -> Unit) {
            require(!result.containsKey(name)) { "Duplicate KDBX metadata key" }
            result[name] = Writer(key, name).apply(data).finish()
        }

        add("database.version") { number(db.kdbxVersion.toLong()) }
        add("database.name") { text(db.name) }
        add("database.nameChanged") { instant(db.nameChanged) }
        add("database.description") { text(db.description) }
        add("database.descriptionChanged") { instant(db.descriptionChanged) }
        add("database.defaultUserName") { text(db.defaultUserName) }
        add("database.defaultUserNameChanged") { instant(db.defaultUserNameChanged) }
        add("database.settingsChanged") { instant(db.settingsChanged) }
        add("database.keyLastChanged") { instant(db.keyLastChanged) }
        add("database.keyChangeRecDays") { number(db.keyChangeRecDays) }
        add("database.keyChangeForceDays") { number(db.keyChangeForceDays) }
        add("database.keyChangeForceOnce") { bool(db.isKeyChangeForceOnce) }
        add("database.maintenanceHistoryDays") { number(db.maintenanceHistoryDays.toLong()) }
        add("database.color") { text(db.color) }
        add("database.recycleBinEnabled") { bool(db.isRecycleBinEnabled) }
        add("database.recycleBinUUID") { text(db.recycleBinUUID.toString()) }
        add("database.recycleBinChanged") { instant(db.recycleBinChanged) }
        add("database.entryTemplatesGroup") { text(db.entryTemplatesGroup.toString()) }
        add("database.entryTemplatesGroupChanged") { instant(db.entryTemplatesGroupChanged) }
        add("database.historyMaxItems") { number(db.historyMaxItems.toLong()) }
        add("database.historyMaxSize") { number(db.historyMaxSize.toLong()) }
        add("database.lastSelectedGroupUUID") { text(db.lastSelectedGroupUUID.toString()) }
        add("database.lastTopVisibleGroupUUID") { text(db.lastTopVisibleGroupUUID.toString()) }
        add("database.compressionAlgorithm") { text(db.compressionAlgorithm.name) }

        val protection = db.memoryProtection
        add("memory.protectTitle") { bool(protection.protectTitle) }
        add("memory.protectUserName") { bool(protection.protectUserName) }
        add("memory.protectPassword") { bool(protection.protectPassword) }
        add("memory.protectUrl") { bool(protection.protectUrl) }
        add("memory.protectNotes") { bool(protection.protectNotes) }
        add("memory.autoEnableVisualHiding") { bool(protection.autoEnableVisualHiding) }

        // Key length and domain separation prevent ambiguity in custom-data keys.
        val custom = mutableListOf<com.kunzisoft.keepass.database.element.CustomDataItem>()
        db.customData.doForEachItems(custom::add)
        custom.sortBy { it.key }
        require(custom.map { it.key }.distinct().size == custom.size) {
            "Duplicate database custom-data key"
        }
        for (item in custom) {
            add("database.customData/${item.key}") {
                text(item.key)
                text(item.value)
                instant(item.lastModificationTime)
            }
        }

        // Custom icons are database-wide resources, not entry-local metadata.
        // Hash actual decoded content; pool indices and object identities are not stable.
        db.iconsManager.doForEachCustomIcon { icon, iconBinary ->
            add("database.customIcon/${icon.uuid}") {
                text(icon.uuid.toString())
                text(icon.name)
                instant(icon.lastModificationTime)
                binary(iconBinary, db)
            }
        }
        return result
    }

    private class Writer(key: ByteArray, name: String) {
        private val mac: Mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key, "HmacSHA256"))
        }
        init {
            text("KEYSAFE-KDBX-METADATA-v1")
            text(name)
        }
        private fun length(value: Long) {
            for (shift in 56 downTo 0 step 8) mac.update((value ushr shift).toByte())
        }
        fun number(value: Long) = length(value)
        fun bool(value: Boolean) = number(if (value) 1L else 0L)
        fun text(value: String?) {
            if (value == null) { length(-1L); return }
            val bytes = value.toByteArray(Charsets.UTF_8)
            try {
                length(bytes.size.toLong())
                mac.update(bytes)
            } finally { bytes.fill(0) }
        }
        fun instant(value: DateInstant?) {
            bool(value != null)
            if (value != null) {
                number(value.instant.millis)
                text(value.type.name)
            }
        }
        fun binary(value: BinaryData, db: DatabaseKDBX) {
            require(!value.isCorrupted) { "Corrupted KDBX custom icon" }
            bool(value.isCompressed)
            bool(value.isProtected)
            var size = 0L
            // Stream bytes directly into the keyed MAC; never retain raw icon bytes.
            value.getUnGzipInputDataStream(db.binaryCache).use { input ->
                val buffer = ByteArray(16 * 1024)
                try {
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        require(n != 0) { "Custom icon input stream stalled" }
                        size = Math.addExact(size, n.toLong())
                        require(size <= MAX_UNPACKED_ICON_BYTES) {
                            "KDBX custom icon exceeds supported size"
                        }
                        mac.update(buffer, 0, n)
                    }
                } finally { buffer.fill(0) }
            }
            // Size is appended unambiguously after all content, inside the keyed MAC.
            number(size)
        }
        fun finish(): String {
            val digest = mac.doFinal()
            return try { digest.joinToString("") { "%02x".format(it) } }
            finally { digest.fill(0) }
        }
    }
}
