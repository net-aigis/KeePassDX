/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.CustomDataItem
import com.kunzisoft.keepass.database.element.DeletedObject
import com.kunzisoft.keepass.database.element.binary.BinaryData
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import com.kunzisoft.keepass.database.element.entry.EntryKDBX
import com.kunzisoft.keepass.database.element.group.GroupKDBX
import com.kunzisoft.keepass.database.element.security.ProtectedString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID
import java.io.InputStream

class KdbxRecordContentFingerprintsTest {
    private val key = ByteArray(32) { (it + 1).toByte() }

    private fun sample(): Triple<DatabaseKDBX, GroupKDBX, EntryKDBX> {
        val database = DatabaseKDBX()
        val root = GroupKDBX()
        val entry = EntryKDBX()
        database.rootGroup = root
        entry.parent = root
        root.addChildEntry(entry)
        entry.password = "first-secret".toCharArray()
        return Triple(database, root, entry)
    }

    private fun fingerprint(db: DatabaseKDBX, entry: EntryKDBX): String =
        KdbxRecordContentFingerprints.read(db, key).nodeHmacSha256.getValue(entry.id.toString())

    private fun rejected(block: () -> Unit) {
        try { block(); fail("Expected KDBX content fingerprint rejection") }
        catch (_: IllegalArgumentException) { /* safe failure */ }
    }

    @Test fun `stable across repeated inventory reads`() {
        val (db, _, entry) = sample()
        assertEquals(fingerprint(db, entry), fingerprint(db, entry))
    }

    @Test fun `protected password change changes HMAC and never appears in output`() {
        val (db, _, entry) = sample()
        val old = fingerprint(db, entry)
        entry.password = "second-secret".toCharArray()
        val current = KdbxRecordContentFingerprints.read(db, key)
        assertNotEquals(old, current.nodeHmacSha256.getValue(entry.id.toString()))
        assertTrue(!current.toString().contains("second-secret"))
    }

    @Test fun `protect flag is semantically included`() {
        val (db, _, entry) = sample()
        val old = fingerprint(db, entry)
        entry.fields["Password"] = ProtectedString(false, "first-secret".toCharArray())
        assertNotEquals(old, fingerprint(db, entry))
    }

    @Test fun `field insertion order does not alter result`() {
        val (db, _, entry) = sample()
        entry.fields["B"] = ProtectedString(false, charArrayOf('2'))
        entry.fields["A"] = ProtectedString(false, charArrayOf('1'))
        val first = fingerprint(db, entry)
        val one = entry.fields.remove("A")!!
        entry.fields["A"] = one
        assertEquals(first, fingerprint(db, entry))
    }

    @Test fun `custom data values are included`() {
        val (db, _, entry) = sample()
        entry.customData.put(CustomDataItem("X", "one"))
        val first = fingerprint(db, entry)
        entry.customData.put(CustomDataItem("X", "two"))
        assertNotEquals(first, fingerprint(db, entry))
    }

    @Test fun `complete history record content changes HMAC`() {
        val (db, _, entry) = sample()
        val history = EntryKDBX()
        history.password = "old-credential".toCharArray()
        entry.history.add(history)
        val first = fingerprint(db, entry)
        history.password = "older-credential".toCharArray()
        assertNotEquals(first, fingerprint(db, entry))
    }

    @Test fun `nested historical records fail closed`() {
        val (db, _, entry) = sample()
        val history = EntryKDBX()
        history.history.add(EntryKDBX())
        entry.history.add(history)
        rejected { fingerprint(db, entry) }
    }

    @Test fun `attachment bytes matter and binary pool ID does not`() {
        val (db, _, entry) = sample()
        db.attachmentPool[7] = BinaryData("payload1".toByteArray())
        entry.binaries["doc"] = 7
        val first = fingerprint(db, entry)
        db.attachmentPool[8] = BinaryData("payload1".toByteArray())
        entry.binaries["doc"] = 8
        assertEquals(first, fingerprint(db, entry))
        db.attachmentPool[8] = BinaryData("payload2".toByteArray())
        assertNotEquals(first, fingerprint(db, entry))
    }

    @Test fun `missing binary fails closed instead of silently skipping attachment`() {
        val (db, _, entry) = sample()
        entry.binaries["missing"] = 173
        rejected { fingerprint(db, entry) }
    }

    @Test fun `corrupted binary fails closed`() {
        val (db, _, entry) = sample()
        entry.binaries["broken"] = 7
        db.attachmentPool[7] = BinaryData(byteArrayOf(1), isCorrupted=true)
        rejected { fingerprint(db, entry) }
    }

    @Test fun `different per-session keys produce different HMAC`() {
        val (db, _, entry) = sample()
        assertNotEquals(fingerprint(db, entry), KdbxRecordContentFingerprints.read(db, ByteArray(32) { 44 }).nodeHmacSha256.getValue(entry.id.toString()))
    }


    @Test fun `duplicate history object fails closed`() {
        val (db, _, entry) = sample()
        val old = EntryKDBX()
        entry.history.add(old)
        entry.history.add(old)
        rejected { fingerprint(db, entry) }
    }

    @Test fun `overlarge uncompressed attachment fails closed without buffering contents`() {
        val (db, _, entry) = sample()
        entry.binaries["huge"] = 7
        db.attachmentPool[7] = object : BinaryData(byteArrayOf()) {
            override fun getUnGzipInputDataStream(cache: com.kunzisoft.keepass.database.element.binary.BinaryCache): InputStream =
                object : InputStream() {
                    var emitted = 0L
                    override fun read(): Int = if (emitted++ < 65L * 1024 * 1024) 0 else -1
                    override fun read(buf: ByteArray, off: Int, len: Int): Int {
                        if (emitted >= 65L * 1024 * 1024) return -1
                        val n = minOf(len.toLong(), 65L * 1024 * 1024 - emitted).toInt()
                        java.util.Arrays.fill(buf, off, off+n, 0.toByte())
                        emitted += n
                        return n
                    }
                }
        }
        rejected { fingerprint(db, entry) }
    }

    @Test fun `short key rejected`() {
        val (db, _, _) = sample()
        rejected { KdbxRecordContentFingerprints.read(db, ByteArray(31)) }
    }

    @Test fun `group content is tracked`() {
        val (db, root, _) = sample()
        val old = KdbxRecordContentFingerprints.read(db, key).nodeHmacSha256.getValue(root.id.toString())
        root.notes = "changed"
        assertNotEquals(old, KdbxRecordContentFingerprints.read(db, key).nodeHmacSha256.getValue(root.id.toString()))
    }

    @Test fun `deletion timestamps remain distinct and fingerprinted`() {
        val (db, _, _) = sample()
        val deleted = DeletedObject(UUID.randomUUID())
        db.deletedObjects.add(deleted)
        val result = KdbxRecordContentFingerprints.read(db, key)
        assertTrue(result.tombstoneHmacSha256.containsKey(deleted.uuid.toString()))
        val old = result.tombstoneHmacSha256.getValue(deleted.uuid.toString())
        deleted.deletionTime.instant.millis += 1
        assertNotEquals(old, KdbxRecordContentFingerprints.read(db, key).tombstoneHmacSha256.getValue(deleted.uuid.toString()))
    }
}
