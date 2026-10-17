/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.kunzisoft.keepass.database.element.CustomDataItem
import com.kunzisoft.keepass.database.element.DateInstant
import com.kunzisoft.keepass.database.element.binary.BinaryCache
import com.kunzisoft.keepass.database.element.binary.BinaryData
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import com.kunzisoft.keepass.database.element.database.DatabaseKDBX
import org.joda.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

class KdbxDatabaseMetadataReviewTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val iconId = UUID.fromString("12345678-1234-1234-1234-1234567890ab")
    private fun time() = DateInstant(Instant(1_700_000_000_000L))
    private fun db(): DatabaseKDBX = DatabaseKDBX().apply {
        nameChanged = time()
        descriptionChanged = time()
        defaultUserNameChanged = time()
        settingsChanged = time()
        keyLastChanged = time()
        recycleBinChanged = time()
        entryTemplatesGroupChanged = time()
    }
    private fun report(b: DatabaseKDBX, l: DatabaseKDBX, r: DatabaseKDBX) =
        KdbxDatabaseMetadataReview.compare(b, l, r, key)
    private fun source(report: KdbxDatabaseMetadataReview.Report, key: String) =
        report.decisions.single { it.key == key }.source
    private fun addIcon(
        db: DatabaseKDBX,
        name: String,
        bytes: ByteArray = byteArrayOf(1, 2, 3),
        corrupted: Boolean = false
    ) {
        db.iconsManager.addCustomIcon(iconId, name, null,
            builder = { _ -> object : BinaryData() {
                override fun getInputDataStream(binaryCache: BinaryCache): InputStream =
                    ByteArrayInputStream(bytes)
                override fun getOutputDataStream(binaryCache: BinaryCache): OutputStream =
                    ByteArrayOutputStream()
                override fun compress(binaryCache: BinaryCache) {}
                override fun decompress(binaryCache: BinaryCache) {}
                override fun clear(binaryCache: BinaryCache) {}
            }.also { it.isCorrupted = corrupted } },
            result = { _, _ -> })
    }
    private fun rejects(block: () -> Unit) {
        try { block(); fail("Invalid metadata accepted") }
        catch (_: IllegalArgumentException) { /* expected */ }
    }

    @Test fun `unchanged copies report no conflicts`() {
        val result = report(db(), db(), db())
        assertTrue(result.conflictKeys.isEmpty())
        assertTrue(result.decisions.all { it.source == KdbxDatabaseMetadataReview.Source.UNCHANGED })
    }

    @Test fun `local only setting change remains visible`() {
        val local = db().apply { name = "the-private-name" }
        assertEquals(KdbxDatabaseMetadataReview.Source.LOCAL,
            source(report(db(), local, db()), "database.name"))
    }

    @Test fun `remote only setting change remains visible`() {
        val remote = db().apply { historyMaxItems = 12 }
        assertEquals(KdbxDatabaseMetadataReview.Source.REMOTE,
            source(report(db(), db(), remote), "database.historyMaxItems"))
    }

    @Test fun `identical parallel setting change is recognized`() {
        val local = db().apply { description = "shared" }
        val remote = db().apply { description = "shared" }
        assertEquals(KdbxDatabaseMetadataReview.Source.IDENTICAL,
            source(report(db(), local, remote), "database.description"))
    }

    @Test fun `different edits to the same setting cause conflict`() {
        val local = db().apply { defaultUserName = "secret-A" }
        val remote = db().apply { defaultUserName = "secret-B" }
        val result = report(db(), local, remote)
        assertTrue("database.defaultUserName" in result.conflictKeys)
        assertFalse(result.toString().contains("secret-A")) // key names do not contain the changed value
        assertFalse(result.toString().contains("secret-B"))
    }

    @Test fun `database custom values and deletion are compared`() {
        val base = db().apply { customData.put(CustomDataItem("x", "base", time())) }
        val local = db().apply { customData.put(CustomDataItem("x", "changed", time())) }
        val result = report(base, local, db())
        assertEquals(KdbxDatabaseMetadataReview.Source.CONFLICT,
            source(result, "database.customData/x"))
    }

    @Test fun `memory-protection settings are reviewed`() {
        val local = db().apply { memoryProtection.protectPassword = false }
        assertEquals(KdbxDatabaseMetadataReview.Source.LOCAL,
            source(report(db(), local, db()), "memory.protectPassword"))
    }

    @Test fun `new custom icon detected as a one-sided change`() {
        val local = db().apply { addIcon(this, "logo") }
        assertEquals(KdbxDatabaseMetadataReview.Source.LOCAL,
            source(report(db(), local, db()), "database.customIcon/$iconId"))
    }

    @Test fun `divergent custom icon metadata conflicts`() {
        val base = db().apply { addIcon(this, "original") }
        val local = db().apply { addIcon(this, "left") }
        val remote = db().apply { addIcon(this, "right") }
        val result = report(base, local, remote)
        assertTrue("database.customIcon/$iconId" in result.conflictKeys)
    }

    @Test fun `actual icon content changes are detected under the same UUID`() {
        val base = db().apply { addIcon(this, "same", byteArrayOf(1, 2, 3)) }
        val local = db().apply { addIcon(this, "same", byteArrayOf(1, 2, 4)) }
        val remote = db().apply { addIcon(this, "same", byteArrayOf(1, 2, 5)) }
        assertEquals(KdbxDatabaseMetadataReview.Source.CONFLICT,
            source(report(base, local, remote), "database.customIcon/$iconId"))
    }

    @Test fun `corrupted custom icon fails closed`() {
        val local = db().apply { addIcon(this, "bad", corrupted = true) }
        rejects { report(db(), local, db()) }
    }

    @Test fun `short or absent session key is rejected`() {
        rejects { KdbxDatabaseMetadataReview.compare(db(), db(), db(), ByteArray(0)) }
        rejects { KdbxDatabaseMetadataReview.compare(db(), db(), db(), ByteArray(31)) }
    }
}
