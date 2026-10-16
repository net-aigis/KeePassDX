/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.nio.file.Files

class CoordinatorConflictCopiesTest {
    private val base = "a".repeat(64)
    private val identity = "https://example.invalid\u0000vault"

    @Test fun `local export reads ciphertext without deleting recovery copy`() {
        val dir = Files.createTempDirectory("keysafe-export-test").toFile()
        try {
            val bytes = byteArrayOf(3, 7, 11, 42)
            val file = writePending(dir, bytes)
            val export = CoordinatorConflictCopies.readLocal(dir, identity)
            assertArrayEquals(bytes, export.bytes)
            assertEquals(base, export.baseRevision)
            assertEquals(CoordinatorConflictCopies.sha256(bytes), export.revision)
            assertTrue(file.exists())
            assertArrayEquals(bytes, file.readBytes())
        } finally { dir.deleteRecursively() }
    }

    @Test(expected = IOException::class)
    fun `missing local recovery is not substituted with an online cache`() {
        val dir = Files.createTempDirectory("keysafe-export-empty").toFile()
        try { CoordinatorConflictCopies.readLocal(dir, identity) }
        finally { dir.deleteRecursively() }
    }

    @Test fun `base export is exactly the revision pending edits descended from`() {
        val dir = Files.createTempDirectory("keysafe-base-export").toFile()
        try {
            val original = byteArrayOf(1, 2, 3, 4, 5)
            val revision = CoordinatorConflictCopies.sha256(original)
            val cache = writeCached(dir, original, revision)
            val pending = writePendingWithBase(dir, byteArrayOf(8, 9), revision)
            val exported = CoordinatorConflictCopies.readBase(dir, identity)
            assertEquals(revision, exported.revision)
            assertArrayEquals(original, exported.bytes)
            assertTrue(cache.exists())
            assertTrue(pending.exists())
        } finally { dir.deleteRecursively() }
    }

    @Test(expected = IOException::class)
    fun `base export refuses unrelated verified cache`() {
        val dir = Files.createTempDirectory("keysafe-wrong-base").toFile()
        try {
            val original = byteArrayOf(1, 2, 3)
            writeCached(dir, original, CoordinatorConflictCopies.sha256(original))
            writePending(dir, byteArrayOf(4, 5, 6))
            CoordinatorConflictCopies.readBase(dir, identity)
        } finally { dir.deleteRecursively() }
    }

    @Test(expected = IOException::class)
    fun `base export refuses missing cache instead of guessing`() {
        val dir = Files.createTempDirectory("keysafe-missing-base").toFile()
        try {
            writePending(dir, byteArrayOf(4, 5, 6))
            CoordinatorConflictCopies.readBase(dir, identity)
        } finally { dir.deleteRecursively() }
    }

    @Test(expected = IOException::class)
    fun `base export refuses corrupted cached bytes`() {
        val dir = Files.createTempDirectory("keysafe-corrupt-base").toFile()
        try {
            val original = byteArrayOf(1, 2, 3)
            val revision = CoordinatorConflictCopies.sha256(original)
            writeCached(dir, byteArrayOf(1, 2, 4), revision)
            writePendingWithBase(dir, byteArrayOf(5, 6), revision)
            CoordinatorConflictCopies.readBase(dir, identity)
        } finally { dir.deleteRecursively() }
    }

    private fun writeCached(dir: File, bytes: ByteArray, revision: String): File {
        val prefix = "coordinated-kdbx-cache-${CoordinatorConflictCopies.sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$revision.kdbx").also { it.writeBytes(bytes) }
    }

    private fun writePendingWithBase(dir: File, bytes: ByteArray, baseRevision: String): File {
        val prefix = "coordinated-kdbx-${CoordinatorConflictCopies.sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$baseRevision-pending.kdbx").also { it.writeBytes(bytes) }
    }

    private fun writePending(dir: File, bytes: ByteArray): File {
        val prefix = "coordinated-kdbx-${CoordinatorConflictCopies.sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$base-pending.kdbx").also { it.writeBytes(bytes) }
    }
}
