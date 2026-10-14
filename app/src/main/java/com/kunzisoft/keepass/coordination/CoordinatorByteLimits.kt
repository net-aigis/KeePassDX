/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

/** Bounds both network and in-memory KDBX handling to avoid uncontrolled allocations. */
internal object CoordinatorByteLimits {
    // The current Android integration buffers a complete encrypted KDBX in memory.
    // Larger databases require a streaming implementation, not a larger arbitrary limit.
    const val MAX_KDBX_BYTES = 64 * 1024 * 1024
    const val MAX_CONTROL_BYTES = 16 * 1024

    fun readBounded(stream: InputStream, maxBytes: Int, declaredLength: Long = -1): ByteArray {
        if (declaredLength > maxBytes) throw IOException("Coordinator response exceeds permitted size")
        return stream.use { input ->
            val output = BoundedKdbxOutputStream(maxBytes)
            val buffer = ByteArray(8192)
            while (true) {
                val size = input.read(buffer)
                if (size < 0) break
                if (size > 0) output.write(buffer, 0, size)
            }
            output.toByteArray()
        }
    }
}

/** Rejects oversized saves before an in-memory serialization buffer can grow without bound. */
internal class BoundedKdbxOutputStream(private val maxBytes: Int = CoordinatorByteLimits.MAX_KDBX_BYTES) : ByteArrayOutputStream() {
    override fun write(value: Int) {
        if (count >= maxBytes) throw IOException("KDBX exceeds permitted in-memory size")
        super.write(value)
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset > bytes.size - length) {
            throw IndexOutOfBoundsException()
        }
        if (length > maxBytes - count) throw IOException("KDBX exceeds permitted in-memory size")
        super.write(bytes, offset, length)
    }
}
