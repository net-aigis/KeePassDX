/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/** Allows replacing a recovery snapshot only within the same logical edit chain. */
internal object RecoveryRetentionPolicy {
    fun canReplace(previousBase: String, previousContentHash: String, newBase: String): Boolean =
        previousBase == newBase || previousContentHash == newBase
}
