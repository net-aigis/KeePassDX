# Contributing to NetAigis KeySafe

NetAigis KeySafe is an independently developed, GPL-licensed fork of KeePassDX.
Our focus is a local-first password manager with **optional coordinated use** of
one encrypted KDBX database by multiple users or devices. Offline-only use must
continue to work without an account or network connection.

## Scope and upstream

- Propose changes against this project's repository:
  https://github.com/net-aigis/NetAigis-KeySafe
- Changes from KeePassDX upstream are evaluated and incorporated selectively;
  upstream commits are never automatically merged into a release.
- Original authorship, copyright notices, and GPL obligations remain intact.
  The original upstream contribution policy is archived (whitespace normalized) in
  `docs/UPSTREAM_CONTRIBUTING.md` for historical reference; it is **not**
  NetAigis KeySafe's current architecture policy.

## Security requirements

- HTTPS coordination is **opt-in**. Normal offline KDBX handling must not depend
  on the coordinator or on any external service.
- Do not log secrets, KDBX plaintext, access tokens, encryption keys, or
  session credentials. Do not commit signing keys or credentials.
- A successful build is not a security audit. For changes to editing leases,
  revisions, saves, recovery, credential storage, or transport, describe the
  threat model and failure modes and provide regression tests.
- Concurrent editing and recovery are **experimental** until real-device,
  multi-user, network-failure, and crash-recovery tests are completed.
- Review authentication, least privilege, certificate verification, and error
  handling for any new network, exported Android, or provider functionality.
- Keep independent signing and release processes; do not reuse upstream keys.

## Contributions and releases

- Explain the problem, design and tests in the PR. Keep changes focused and
  independently reviewable; include tests for changed behaviour.
- CI checks build and unit tests but cannot substitute for manual testing.
- Follow `docs/KEYSAFE_RELEASE_CHECKLIST.md` before any official release.
- Contributors must have the right to license their work under GPLv3 or a
  compatible license; keep original third-party attributions.
