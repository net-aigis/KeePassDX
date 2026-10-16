# NetAigis KeySafe integration-test coordinator (Go)

This directory contains the existing Go reference coordinator used by the
Android/Kotlin HTTP integration tests. It runs on **127.0.0.1:8765 only**
with a disposable test token and a temporary database directory.

The GitHub Actions workflow builds this Go source and runs the real
`KdbxCoordinatorClient` against it. **It is a development test fixture**,
not a production-approved multi-user hosting package.

Go checks: `go test -race -count=10 ./...` in this directory.
Android/JVM integration checks: `KdbxLiveProtocolIntegrationTest` using
`KEYSAFE_INTEGRATION_URL=http://127.0.0.1:8765`.

The HTTP loopback exception is test-only and is never enabled for the
shipping Android configuration. The tests use dummy encrypted-blob
placeholders, not actual user databases.

Do not deploy this binary directly on the Internet. Production requires a
verified HTTPS reverse proxy, authentication hardening, persistence/disaster
recovery verification, and independent security review.
