/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Exercises the actual Android network client against the running Go coordinator.
 * Only dummy encrypted-blob placeholders are used: NO real passwords or KDBX files. */
internal object KdbxLiveProtocolScenarios {
    private const val TOKEN = "integration-test-only-secret-0123456789abcdef"
    private fun id() = "test" + UUID.randomUUID().toString().replace("-", "")
    private fun bytes(value: String) = "dummy-encrypted-$value".toByteArray(StandardCharsets.UTF_8)
    private fun client(url: String, id: String, owner: String) =
        KdbxCoordinatorClient(url, id, TOKEN, owner, allowInsecureLoopbackForTests = true)

    private inline fun <reified T : Throwable> mustThrow(noinline call: () -> Unit) {
        try { call() } catch (e: Throwable) {
            if (e is T) return
            throw AssertionError("Expected ${T::class.java.simpleName}, got ${e.javaClass.simpleName}: ${e.message}", e)
        }
        throw AssertionError("Expected ${T::class.java.simpleName} but call succeeded")
    }
    private fun same(expected: ByteArray, actual: ByteArray?) {
        check(actual != null && expected.contentEquals(actual)) { "Committed bytes differ" }
    }

    fun runAll(server: String) {
        check(URI(server).host in listOf("127.0.0.1", "localhost")) { "Integration tests must use loopback" }
        exclusiveEditingAndTransfer(server)
        concurrentClientAcquisition(server)
        revokedLeaseCannotOverwrite(server)
        acknowledgedRemotelyButResponseLost(server)
        interruptedBeforePublishMayRetry(server)
    }

    /** One editor at a time, readers get committed bytes, and ownership transfers. */
    private fun exclusiveEditingAndTransfer(server: String) {
        val database = id()
        client(server, database, "alpha").use { a ->
            a.acquire()
            client(server, database, "beta").use { b ->
                mustThrow<KdbxCoordinatorClient.BusyException> { b.acquire() }
                check(b.downloadReadOnly() == null)
                val first = bytes("first")
                check(a.publish(first).length == 64)
                same(first, b.downloadReadOnly())
                val second = bytes("second")
                check(a.publish(second).length == 64)
                same(second, b.downloadReadOnly())
            }
        }
        client(server, database, "beta").use { b ->
            b.acquire()
            same(bytes("second"), b.download())
            val latest = bytes("beta-update")
            b.publish(latest)
            same(latest, b.downloadReadOnly())
        }
    }

    /** Real concurrent Kotlin clients race for the same live Go lock. */
    private fun concurrentClientAcquisition(server: String) {
        val database = id()
        val ready = CountDownLatch(8)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(8)
        val success = AtomicInteger(0)
        val busy = AtomicInteger(0)
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val holders = java.util.concurrent.ConcurrentLinkedQueue<KdbxCoordinatorClient>()
        try {
            val futures = (1..8).map { index ->
                pool.submit {
                    val c = client(server, database, "user$index")
                    try {
                        ready.countDown()
                        check(start.await(5, TimeUnit.SECONDS))
                        try {
                            c.acquire()
                            holders.add(c) // Keep lock held until every competitor finished.
                            success.incrementAndGet()
                        } catch (_: KdbxCoordinatorClient.BusyException) {
                            busy.incrementAndGet()
                            c.close()
                        }
                    } catch (t: Throwable) {
                        errors.add(t)
                        runCatching { c.close() }
                    }
                }
            }
            check(ready.await(5, TimeUnit.SECONDS)) { "Clients did not start" }
            start.countDown()
            futures.forEach { it.get(25, TimeUnit.SECONDS) }
            check(errors.isEmpty()) { "Unexpected client failure: ${errors.peek()}" }
            check(success.get() == 1 && busy.get() == 7) {
                "Exclusive lock violation: successful=${success.get()} busy=${busy.get()}"
            }
        } finally {
            holders.forEach { runCatching { it.close() } }
            pool.shutdownNow()
        }
    }

    /** A revoked, stale Android lease cannot overwrite the new owner's work. */
    private fun revokedLeaseCannotOverwrite(server: String) {
        val database = id()
        val old = client(server, database, "old")
        try {
            old.acquire()
            // This test-only reflection simulates a lease revoked externally.
            // Production code cannot take over someone else's lease without its token.
            val field = KdbxCoordinatorClient::class.java.getDeclaredField("lease")
            field.isAccessible = true
            val oldLease = field.get(old) as String
            val endpoint = "$server/v1/databases/$database/lock"
            val connection = URI(endpoint).toURL().openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "DELETE"
                connection.setRequestProperty("Authorization", "Bearer $TOKEN")
                connection.setRequestProperty("X-KDBX-Lease", oldLease)
                check(connection.responseCode == 204) { "Could not revoke lease" }
            } finally { connection.disconnect() }
            client(server, database, "new").use { current ->
                current.acquire()
                val desired = bytes("winner")
                current.publish(desired)
                mustThrow<KdbxCoordinatorClient.LostLeaseException> { old.publish(bytes("stale")) }
                same(desired, current.downloadReadOnly())
            }
        } finally { runCatching { old.close() } }
    }

    /** The real Go server commits, but a proxy discards the successful reply.
     * Simulates an ambiguous acknowledgement: the local client must report failure,
     * while a fresh client sees the committed content and its valid ETag. */
    private fun acknowledgedRemotelyButResponseLost(server: String) {
        val database = id()
        val attempts = AtomicInteger(0)
        FaultProxy(server, interceptPut = { _, _ ->
            if (attempts.getAndIncrement() == 0) FaultProxy.Mode.ACK_LOST else FaultProxy.Mode.NORMAL
        }).use { proxy ->
            client(proxy.url, database, "ambiguous").use { writer ->
                writer.acquire()
                val content = bytes("already-published")
                mustThrow<IOException> { writer.publish(content) }
                // Server did commit, even though the Android client did not get 200.
                client(server, database, "observer").use { observer ->
                    same(content, observer.downloadReadOnly())
                }
                // Replaying the same old revision cannot silently publish a second write.
                mustThrow<KdbxCoordinatorClient.StaleRevisionException> { writer.publish(bytes("stale-retry")) }
            }
        }
    }

    /** A failed upload that never reaches the server cannot change revision;
     * the same client may retry a newer full copy under the same valid lease. */
    private fun interruptedBeforePublishMayRetry(server: String) {
        val database = id()
        val attempts = AtomicInteger(0)
        FaultProxy(server, interceptPut = { _, _ ->
            if (attempts.getAndIncrement() == 0) FaultProxy.Mode.REJECT_BEFORE_FORWARD
            else FaultProxy.Mode.NORMAL
        }).use { proxy ->
            client(proxy.url, database, "retry").use { writer ->
                writer.acquire()
                mustThrow<IOException> { writer.publish(bytes("not-published")) }
                client(server, database, "observer").use { observer ->
                    check(observer.downloadReadOnly() == null) { "Rejected upload changed server" }
                }
                val newest = bytes("latest-full-save")
                writer.publish(newest)
                client(server, database, "observer").use { observer ->
                    same(newest, observer.downloadReadOnly())
                }
            }
        }
    }

    private class FaultProxy(
        private val backend: String,
        private val interceptPut: (String, ByteArray) -> Mode
    ) : AutoCloseable {
        enum class Mode { NORMAL, REJECT_BEFORE_FORWARD, ACK_LOST }
        private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        private val executor = Executors.newCachedThreadPool()
        val url: String get() = "http://127.0.0.1:${server.address.port}"

        init {
            server.executor = executor
            server.createContext("/") { exchange ->
                try { serve(exchange) } catch (e: Throwable) {
                    runCatching { exchange.sendResponseHeaders(502, -1) }
                } finally { exchange.close() }
            }
            server.start()
        }
        private fun serve(exchange: HttpExchange) {
            val body = exchange.requestBody.use { it.readBytes() }
            val mode = if (exchange.requestMethod == "PUT") interceptPut(exchange.requestURI.path, body) else Mode.NORMAL
            if (mode == Mode.REJECT_BEFORE_FORWARD) {
                exchange.sendResponseHeaders(503, -1)
                return
            }
            val connection = URI(backend + exchange.requestURI.toString()).toURL().openConnection() as HttpURLConnection
            try {
                connection.instanceFollowRedirects = false
                connection.requestMethod = exchange.requestMethod
                for (key in listOf("Authorization", "X-KDBX-Lease", "If-Match")) {
                    exchange.requestHeaders.getFirst(key)?.let { connection.setRequestProperty(key, it) }
                }
                if (exchange.requestMethod in listOf("PUT", "POST")) {
                    connection.doOutput = true
                    connection.setFixedLengthStreamingMode(body.size)
                    connection.outputStream.use { it.write(body) }
                }
                val status = connection.responseCode
                val reply = (if (status in 200..299) connection.inputStream else connection.errorStream)
                    ?.use { it.readBytes() } ?: byteArrayOf()
                if (mode == Mode.ACK_LOST) {
                    check(status == 200) { "Backend did not commit before simulated lost acknowledgement" }
                    // Terminate the HTTP connection without returning the 200 acknowledgement.
                    exchange.close()
                    return
                }
                connection.getHeaderField("ETag")?.let { exchange.responseHeaders.set("ETag", it) }
                if (status == 204 || reply.isEmpty()) {
                    exchange.sendResponseHeaders(status, -1)
                } else {
                    exchange.sendResponseHeaders(status, reply.size.toLong())
                    exchange.responseBody.use { it.write(reply) }
                }
            } finally { connection.disconnect() }
        }
        override fun close() {
            server.stop(0)
            executor.shutdownNow()
        }
    }
}

/** Standalone Kotlin/JVM executable for offline development testing (same client sources). */
fun main(args: Array<String>) {
    require(args.size == 1) { "Usage: KdbxLiveProtocolScenariosKt http://127.0.0.1:8765" }
    KdbxLiveProtocolScenarios.runAll(args[0])
    println("PASS: five Android-client-to-Go live protocol scenarios")
}
