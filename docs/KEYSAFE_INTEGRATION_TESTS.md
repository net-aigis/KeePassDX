# NetAigis KeySafe: live Kotlin ↔ Go integration checks

GitHub Actions builds `tests/integration/coordinator` and starts it with
**only loopback HTTP**, disposable storage, and a fixed TEST-ONLY bearer token.
The normal `:app:testLibreDebugUnitTest` task then runs the actual Android
network client (`KdbxCoordinatorClient`) over HTTP to the Go implementation.
All other Android unit tests and `:app:assembleLibreDebug` still run.

## Covered

1. Exclusive writer, read-only observer, two successive writes, and lock handoff.
2. Eight concurrent Kotlin clients: one successful editing lease.
3. External lease revocation: old client cannot overwrite new writer.
4. Go server commits a PUT but proxy **closes the connection before the
   successful HTTP acknowledgement**. Client sees an error; a new client
   verifies the committed content; stale retry is rejected.
5. Proxy blocks first PUT before contacting Go. Existing remote version remains
   unchanged; subsequent valid save succeeds.
6. Existing Go reference tests cover concurrent same-revision writes, a
   streaming body failure, expired leases during upload, backups, and renewal.
   They run under Go's race detector.

## Reproduce

The `.github/workflows/coordinated-kdbx-build.yml` workflow is the canonical
reproducer. It provides `KEYSAFE_INTEGRATION_URL`, starts/stops the fixture and
runs the Gradle test task without installing the coordinator on user machines.
`KdbxLiveProtocolIntegrationTest` skips when manually running normal unit
checks without a coordinator. The CI step sets the URL **and checks its JUnit
XML report**, rejecting missing/skipped integration coverage.

## Not proved by these tests

- Android device lifecycle, process death, filesystem durability, or recovery
  persistence under power loss.
- Actual KDBX cryptographic parsing/encryption, large KDBX streaming, or TLS
  certificate verification by Android (test traffic is loopback-only).
- Real two-device/desktop interoperation, distributed deployments or server
  restart persistence. In particular, Go lease state is process-local.
- Universal data-loss prevention. Do not use production password databases yet.
