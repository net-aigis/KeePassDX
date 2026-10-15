# NetAigis KeySafe

**Independent NetAigis Android password manager fork of KeePassDX.**

This fork preserves KDBX support and adds an experimental HTTPS coordination feature
for shared encrypted databases. It is **not yet suitable for production password data**:
end-to-end concurrency, crash/recovery and security checks are still outstanding.

## Android application identity

- Display name: **NetAigis KeySafe**
- Gradle project: `NetAigis-KeySafe`
- Android `applicationId`: `de.netaigis.keysafe`
- Libre flavor: `de.netaigis.keysafe.libre`
- Free flavor: `de.netaigis.keysafe.free`
- Version: `0.1.0-dev` (independent of KeePassDX's version scheme)
- Coordination protocol: retained from the NetAigis fork, subject to validation

The original internal source namespaces (`com.kunzisoft.keepass`) are retained
intentionally for compatibility. They are **not** the installed Android package ID.
Changing them does not improve user-visible independence and requires a separate,
large-scale refactor with tests.

## Source, testing, distribution

Planned repository name after GitHub rename: https://github.com/net-aigis/NetAigis-KeySafe

CI: `.github/workflows/coordinated-kdbx-build.yml`; run Android unit tests and
build the Libre APK in GitHub Actions. Debug APKs have a debug signing certificate
and must not be treated as official releases. Configure a **new NetAigis-owned
release signing key** in an approved secure release pipeline. Never use original
KeePassDX certificates or original Google Play backup API keys.

Before publication update app assets, translations, store screenshots, privacy
statement, signing, release notes, and repository URLs according to
`docs/KEYSAFE_RELEASE_CHECKLIST.md`.

## Upstream and licenses

This software is derived from **KeePassDX**, originally developed by
**Jeremy Jamet / Kunzisoft** and other contributors:
https://github.com/Kunzisoft/KeePassDX

Original copyright notices and the GPL-3.0-or-later license apply. Changes in this
fork are distributed under the compatible GPL license. See `LICENSE`, `LICENSES`,
`CONTRIBUTING.md` (upstream history), and `docs/KEYSAFE_FORK_NOTICES.md`.

The repository is a fork; it is not affiliated with or endorsed by the upstream
KeePassDX maintainers.
