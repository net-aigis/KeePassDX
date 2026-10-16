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

    private fun writePending(dir: File, bytes: ByteArray): File {
        val prefix = "coordinated-kdbx-${CoordinatorConflictCopies.sha256(identity.toByteArray())}-"
        return File(dir, "$prefix$base-pending.kdbx").also { it.writeBytes(bytes) }
    }
}
