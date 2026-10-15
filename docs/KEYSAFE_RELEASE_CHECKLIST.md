# NetAigis KeySafe — release checklist

Not production-ready until all checklist items are completed.

- [x] Independent display name and Android application identifiers per flavor
- [x] New project version and product name in build metadata
- [x] HTTPS coordinator preserved (the protocol is NOT certified secure)
- [x] Replace upstream in-app donation/Pro ownership identification
- [x] Preserve upstream copyright/license notices and credit
- [x] Update displayed text in translation resources (brand only)
- [x] Remove incorrect offline-only statement from all languages
- [x] Update GitHub Actions display/artifact names (workflow file unchanged)
- [x] Replace app launcher icons for Libre and Free, adaptive and legacy densities
- [ ] CI Android app build + unit tests on NetAigis branch
- [ ] Check all Android manifest placeholders, provider authorities and autofill/IME registration on-device
- [ ] End-to-end tests with real Android device(s), parallel edits and network partitions
- [ ] Complete threat model, penetration tests, data-loss and recovery tests
- [ ] Independent release signing keystore and secure signing pipeline
- [ ] Verify application install and update behavior, Android backup/restore
- [ ] Review all translations for meaning after automated product-name replacements
- [ ] Replace all upstream screenshots and legacy changelogs before store distribution
- [ ] Review/remove upstream-only wiki/donation/Pro links that still appear in screens
- [ ] Rename GitHub repository from net-aigis/KeePassDX to net-aigis/NetAigis-KeySafe and update local origin URL
- [ ] Publish project-specific privacy policy and release notes
- [ ] Ensure no upstream secrets/API credentials in shipped manifests/assets
- [ ] Validate GPL corresponding-source availability and third-party notices

Note: Existing Kotlin/Java namespaces (`com.kunzisoft.keepass`) intentionally remain.
They are not Android `applicationId` values. This avoids needless source refactors.
