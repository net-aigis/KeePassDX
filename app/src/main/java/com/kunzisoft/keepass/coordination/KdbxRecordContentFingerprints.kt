/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.CustomData
import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.binary.BinaryData
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.node.NodeKDBXInterface
import com.kunzisoft.keepass.database.element.icon.IconImage
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Read-only, per-session HMAC-SHA256 of KDBX node content.
 *
 * A new random 32+ byte [sessionKey] MUST be used for each three-copy comparison;
 * the same key MUST be used for all three copies. Do not log, persist, or transmit
 * these MACs or the key. This is deliberately NOT a merge-authorizing snapshot:
 * database-level metadata, custom-icon image bytes, and atomic write/lease safety
 * still need separate verification. The current tree planner is NOT wired here.
 *
 * Call while the decrypted database has exclusive read access; concurrent edits
 * would make any multi-record inventory inconsistent.
 */
internal object KdbxRecordContentFingerprints {
    // Matches the currently documented in-memory KDBX cap; fail closed on gzip bombs.
    private const val MAX_UNPACKED_ATTACHMENT_BYTES = 64L * 1024L * 1024L

    data class Inventory(
        val model: KdbxModelSnapshotReader.Inventory,
        val nodeHmacSha256: Map<String, String>,
        val tombstoneHmacSha256: Map<String, String>
    )

    fun read(database: DatabaseKDBX, sessionKey: ByteArray): Inventory {
        require(sessionKey.size >= 32) { "KDBX comparison key must be at least 256 bits" }
        val model = KdbxModelSnapshotReader.read(database)
        val root = requireNotNull(database.rootGroup)
        val pending = java.util.ArrayDeque<GroupKDBX>()
        pending.add(root)
        val fingerprints = linkedMapOf<String, String>()
        while (pending.isNotEmpty()) {
            val group = pending.removeFirst()
            fingerprints[group.id.toString()] = MacWriter(sessionKey).apply {
                field("format", "KDBX-GROUP-CONTENT-v1")
                node(group, group.icon, group.id.toString(), group.parent?.id?.toString(), group.indexInParent)
                field("title", group.title)
                field("notes", group.notes)
                bool("expanded", group.isExpanded)
                optionalBool("search", group.enableSearching)
                optionalBool("autoType", group.enableAutoType)
                field("defaultAutoTypeSequence", group.defaultAutoTypeSequence)
                field("lastTopVisibleEntry", group.lastTopVisibleEntry.toString())
                val children = (group.getChildGroups().map { it.id.toString() to it.indexInParent } +
                    group.getChildEntries().map { it.id.toString() to it.indexInParent })
                    .sortedWith(compareBy<Pair<String, Int>> { it.second }.thenBy { it.first })
                number("childCount", children.size.toLong())
                children.forEach { (id, order) -> field("childId", id); number("childIndex", order.toLong()) }
            }.hex()
            for (entry in group.getChildEntries()) {
                fingerprints[entry.id.toString()] = MacWriter(sessionKey).apply {
                    field("format", "KDBX-ENTRY-CONTENT-v1")
                    entry(database, entry, includeHistory = true)
                }.hex()
            }
            group.getChildGroups().forEach(pending::addLast)
        }
        require(fingerprints.keys == model.nodes.keys) { "KDBX changed during content inventory" }
        val deletions = linkedMapOf<String, String>()
        for ((id, tombstone) in model.tombstones) {
            deletions[id] = MacWriter(sessionKey).apply {
                field("format", "KDBX-DELETED-OBJECT-v1")
                field("uuid", id)
                number("timestampMillis", tombstone.deletionTimeMillis)
                field("timestampType", tombstone.deletionTimeType)
            }.hex()
        }
        return Inventory(model, fingerprints.toMap(), deletions.toMap())
    }

    private class MacWriter(key: ByteArray) {
        private val mac: Mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key, "HmacSHA256"))
        }

        // Every item is length-delimited and labeled: neither concatenation nor
        // map ordering can accidentally make two different values hash alike.
        private fun bytes(value: ByteArray?) {
            if (value == null) {
                longRaw(-1L)
            } else {
                longRaw(value.size.toLong())
                mac.update(value)
            }
        }

        private fun longRaw(value: Long) {
            for (shift in 56 downTo 0 step 8) mac.update((value ushr shift).toByte())
        }

        fun field(name: String, value: String?) {
            textRaw(name)
            textRaw(value)
        }

        private fun textRaw(value: String?) {
            if (value == null) { bytes(null); return }
            val utf8 = value.toByteArray(Charsets.UTF_8)
            try { bytes(utf8) } finally { utf8.fill(0) }
        }

        fun binaryFingerprint(name: String, value: ByteArray) {
            textRaw(name)
            bytes(value)
        }

        fun number(name: String, value: Long) {
            textRaw(name)
            longRaw(value)
        }

        fun bool(name: String, value: Boolean) = number(name, if (value) 1 else 0)

        fun optionalBool(name: String, value: Boolean?) =
            number(name, when (value) { null -> -1; true -> 1; false -> 0 })

        // Hashes protected CharArray directly as UTF-16 code units. Never build
        // an immutable String holding a password, and never serialize its value.
        fun protectedChars(name: String, value: CharArray) {
            textRaw(name)
            longRaw(value.size.toLong())
            for (char in value) {
                mac.update((char.code ushr 8).toByte())
                mac.update(char.code.toByte())
            }
        }

        fun instant(name: String, value: DateInstant?) {
            bool("$name.present", value != null)
            if (value != null) {
                number("$name.ms", value.instant.millis)
                field("$name.type", value.type.name)
            }
        }

        fun custom(name: String, data: CustomData) {
            val items = mutableListOf<com.kunzisoft.keepass.database.element.CustomDataItem>()
            data.doForEachItems(items::add)
            items.sortBy { it.key }
            require(items.map { it.key }.distinct().size == items.size) { "Duplicate custom data item" }
            number("$name.count", items.size.toLong())
            items.forEach {
                field("$name.key", it.key)
                field("$name.value", it.value)
                instant("$name.updated", it.lastModificationTime)
            }
        }

        fun node(value: NodeKDBXInterface, icon: IconImage, id: String, parentId: String?, index: Int) {
            field("uuid", id)
            field("parent", parentId)
            number("position", index.toLong())
            number("icon.standard", icon.standard.id.toLong())
            field("icon.custom", icon.custom.uuid.toString())
            field("icon.custom.name", icon.custom.name)
            instant("icon.custom.modified", icon.custom.lastModificationTime)
            instant("created", value.creationTime)
            instant("modified", value.lastModificationTime)
            instant("accessed", value.lastAccessTime)
            instant("expiresAt", value.expiryTime)
            bool("expires", value.expires)
            number("usageCount", value.usageCount.toLong())
            instant("locationChanged", value.locationChanged)
            field("previousParent", value.previousParentGroup.toString())
            val tags = value.tags.toStringList().sorted()
            number("tags.count", tags.size.toLong())
            tags.forEach { field("tag", it) }
            custom("node.customData", value.customData)
        }

        fun entry(database: DatabaseKDBX, value: EntryKDBX, includeHistory: Boolean) {
            node(value, value.icon, value.id.toString(), value.parent?.id?.toString(), value.indexInParent)
            field("foreground", value.foregroundColor)
            field("background", value.backgroundColor)
            field("overrideUrl", value.overrideURL)
            bool("qualityCheck", value.qualityCheck)
            field("additional", value.additional)
            field("historyMainEntryId", value.historyMainEntryId?.toString())
            bool("autoType.enabled", value.autoType.enabled)
            number("autoType.obfuscation", value.autoType.obfuscationOptions.toLong())
            field("autoType.sequence", value.autoType.defaultSequence)
            val autoPairs = mutableListOf<Pair<String, String>>()
            value.autoType.doForEachAutoTypeItem { key, sequence -> autoPairs.add(key to sequence) }
            number("autoType.pairs", autoPairs.size.toLong())
            autoPairs.forEach { (key, sequence) -> field("autoType.key", key); field("autoType.seq", sequence) }

            val fields = value.getFields().sortedBy { it.name }
            require(fields.map { it.name }.distinct().size == fields.size) { "Duplicate entry field name" }
            number("fields.count", fields.size.toLong())
            fields.forEach {
                field("field.name", it.name)
                bool("field.protected", it.protectedValue.isProtected)
                protectedChars("field.value", it.protectedValue.charArrayValue)
            }
            val attachments = value.binaries.toSortedMap()
            number("attachments.count", attachments.size.toLong())
            for ((label, poolId) in attachments) {
                field("attachment.label", label)
                val binary = requireNotNull(database.attachmentPool[poolId]) {
                    "KDBX attachment is missing from binary pool"
                }
                attachment(binary, database)
            }

            if (includeHistory) {
                number("history.count", value.history.size.toLong())
                val seenHistory = java.util.IdentityHashMap<EntryKDBX, Boolean>()
                value.history.forEach { historyEntry ->
                    require(seenHistory.put(historyEntry, true) == null) {
                        "Repeated KDBX history object is unsupported"
                    }
                    require(historyEntry !== value && historyEntry.history.isEmpty()) {
                        "Nested or cyclic KDBX history is unsupported"
                    }
                    // Store the complete history record, not just its timestamp.
                    field("history.version", "v1")
                    entry(database, historyEntry, includeHistory = false)
                }
            } else {
                require(value.history.isEmpty()) { "Nested KDBX history is unsupported" }
            }
        }

        private fun attachment(binary: BinaryData, database: DatabaseKDBX) {
            require(!binary.isCorrupted) { "Corrupted KDBX attachment" }
            bool("attachment.protected", binary.isProtected)
            bool("attachment.compressed", binary.isCompressed)
            // Pool IDs are not stable across KDBX copies. Hash actual unpacked bytes.
            val sha = MessageDigest.getInstance("SHA-256")
            var readBytes = 0L
            binary.getUnGzipInputDataStream(database.binaryCache).use { stream ->
                val buf = ByteArray(16 * 1024)
                try {
                    while (true) {
                        val n = stream.read(buf)
                        if (n < 0) break
                        require(n > 0) { "KDBX attachment stream made no progress" }
                        readBytes = Math.addExact(readBytes, n.toLong())
                        require(readBytes <= MAX_UNPACKED_ATTACHMENT_BYTES) {
                            "Uncompressed KDBX attachment exceeds supported size"
                        }
                        sha.update(buf, 0, n)
                    }
                } finally { buf.fill(0) }
            }
            number("attachment.size", readBytes)
            val fingerprint = sha.digest()
            try { binaryFingerprint("attachment.bytesSha256", fingerprint) }
            finally { fingerprint.fill(0) }
        }

        fun hex(): String {
            val value = mac.doFinal()
            return try { value.joinToString("") { "%02x".format(it) } }
            finally { value.fill(0) }
        }
    }
}
