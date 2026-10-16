/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.database.merge

import com.kunzisoft.keepass.database.element.group.GroupKDBX
import java.io.IOException
import java.util.UUID

/**
 * Find an existing group that survives the incoming KDBX deletion set.
 * A deleted ancestor must never receive a moved entry or group.
 * A malformed or cyclic hierarchy must fail before tree mutation.
 */
internal object DeletedGroupAncestor {
    @Throws(IOException::class)
    fun firstSurviving(parent: GroupKDBX?, deletedIds: Set<UUID>): GroupKDBX {
        val visited = HashSet<UUID>()
        var current = parent
        while (current != null) {
            val id = current.nodeId.id
            if (!visited.add(id)) {
                throw IOException("Cyclic KDBX group ancestry while applying deletion")
            }
            if (id !in deletedIds) return current
            current = current.parent
        }
        throw IOException("No surviving KDBX parent for deletion recovery")
    }
}
