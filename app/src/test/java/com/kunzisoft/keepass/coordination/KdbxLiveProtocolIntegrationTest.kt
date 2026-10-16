/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in for local unit tests; CI verifies it ran and was never skipped. */
class KdbxLiveProtocolIntegrationTest {
    @Test fun `Kotlin client and real Go coordinator reject unsafe concurrent edits`() {
        val url = System.getenv("KEYSAFE_INTEGRATION_URL")
        assumeTrue("Live coordinator not configured", !url.isNullOrBlank())
        KdbxLiveProtocolScenarios.runAll(url!!)
    }
}
