# NetAigis KeySafe – offline use of coordinated KDBX (initial implementation)

This opt-in *database type* uses server coordination while reachable. Ordinary local KDBX files retain their original offline behavior and are not affected.

## Behavior

- Explicitly enable **Allow encrypted offline cache** in the coordinator settings (disabled by default), then open a coordinated KDBX successfully **online at least once**. Only the already-encrypted KDBX bytes are stored in app-private storage. The SHA-256 checksum in the cache filename is checked before offline use.
- If the coordinator is **unreachable due to a network transport failure**, KeySafe can open the verified cache and, when requested, allow offline editing. Authentication failures, HTTP errors, TLS failures, changed database revisions, or an occupied edit lease do **not** permit offline fallback.
- An offline save writes the **encrypted** KDBX using the existing crash-recovery mechanism. The app shows a warning; the database remains flagged as **not synchronized**. It does not acquire a lease or send a PUT while offline.
- On the next **online reopen** the client first acquires the server lease, reads and checks the current server revision, and only publishes pending ciphertext if the retained base revision still matches (or acknowledges already-published bytes).
- If another client changed the remote database, **no automatic overwrite or merge occurs**. The encrypted local copy is kept. Manual recovery/merge must be implemented before this can be presented as full conflict-free offline synchronization.

## Safety properties and limitations

- Encryption: cache and recovery contain ciphertext-only KDBX bytes; no decrypted credential database or master password is cached by the coordinator feature. The user's KDBX master credential is still needed to unlock the database.
- The server is authoritative for versions. Offline cache possession never grants a server-side write lease.
- If an offline cached copy cannot be authenticated by hash, or diverges from the pending recovery base, opening fails closed.
- Disabling the offline option stops new caching and fallback but does not erase existing ciphertext automatically; unsynchronized revisions must not be deleted accidentally. Local ciphertext remains in app-private storage when the coordinator session is closed. Removing app data removes these copies. Back up unsynchronized content before removing the application.
- The existing 64 MiB in-memory KDBX limit remains; streaming is future work.
- This initial implementation does **not** reconnect automatically in the background, merge conflicting offline changes, or guarantee availability after the app is uninstalled or its data is cleared.
- Full Android-device tests, process-kill/power-loss durability tests and HTTPS end-to-end tests remain mandatory before production use.

## Conflict recovery export (phase 2A)

If the server revision differs from an offline edit's base revision, automatic publication stays blocked. In **Coordinator Settings**, choose **Export unsynchronized local KDBX** to save the pending encrypted edits and **Export current server KDBX** to save the server's latest encrypted version to two DIFFERENT, private destinations. The latter always downloads from the server; it cannot silently export a cached file. Neither export clears the app-private pending KDBX, unlocks the server, or merges entries.

Open and compare both exported KDBX files with appropriate credentials, retaining both originals. KeePassDX's existing database merge uses modification timestamps and is **not** guaranteed to detect conflicting changes to the same entry. Do not assume it is a lossless three-way merge. KeySafe intentionally provides no 'force publish' or 'discard pending' shortcut in this phase. The final merge-and-publish workflow requires a separate, reviewed change that verifies the current server revision under an exclusive lease.

Exports are user-selected files and may be backed up or synchronized by the chosen document provider; store them securely. Do not uninstall the app, clear app data, or overwrite either export while recovery is incomplete.

## Three-way merge prerequisites (phase 2B foundation)

Export **three** encrypted, independent KDBX files when a conflict exists: **original base** (the common ancestor), **unsynchronized local** and **current server**. The original base export only succeeds when the encrypted cached snapshot's SHA-256 revision exactly matches the pending changes' recorded base revision. A missing, corrupted or different cached base stops the export; the app never guesses an ancestor. The pending recovery data is not removed by any export.

`ThreeWayEntryMergePlan` is a **non-mutating** decision helper for whole-record changes indexed by stable KDBX UUID. It handles unchanged, one-sided modification, identical two-sided modification, and conflicts (including delete-vs-update). It cannot be given raw encrypted KDBX hashes as entry fingerprints. A future credential-aware KDBX adapter must hash the complete decrypted logical record, preserve history, attachments, links, deletions and group metadata, and verify the remote revision under an exclusive lease before a merged write. **No automatic merge or upload is enabled by this patch.** A timestamp-based upstream merge is not a safe substitute for this adapter.

## Three-way structural preflight (phase 2C; no automatic write)

`ThreeWayKdbxTreePlan` checks **complete, already-decrypted and canonicalized**
UUID-indexed entry/group snapshots supplied by a future KDBX adapter. It treats
parent movement as a record change, rejects double edits, and verifies that
all chosen nodes form an attached, acyclic group hierarchy. This prevents
independent, individually valid edits from silently creating a cycle or
leaving an entry under a group deleted by the other editor. It also rejects
root mismatches, UUID type changes and malformed SHA-256 record fingerprints.

**This is a pure preflight, not a KDBX adapter**: it does not read/unlock KDBX
files, prove fingerprint completeness, merge global database settings,
custom icons or deleted-object tombstones, preserve binary pools, serialize
results, or publish a revision. It must not be wired to the timestamp-based
`DatabaseKDBXMerger` as if that constituted a safe merge. Conflict exports and
the local pending recovery are unchanged; no automatic conflict resolution
or upload is enabled. A verified credential-aware adapter and lease-protected
revision revalidation are still required before any merge may be written.

## Decrypted KDBX model inventory (phase 2D; no merge authorization)

`KdbxModelSnapshotReader.read(DatabaseKDBX)` traverses the **actual KeePassDX
KDBX model**, not synthetic UUID maps. It reads live groups and entries,
validates containment against the parent pointers, rejects repeated UUIDs,
records whether each entry has history versions and attachment references,
and preserves `DeletedObjects` identities and their deletion timestamps.
The traversal is iterative and does not save any decrypted field values or
modify the database. Tombstones and live nodes remain distinct data sets.

**Do not treat the inventory as a mergeable fingerprinted snapshot.** Entry
attachment pool IDs do not identify attachment contents across database copies,
and history data, custom fields, icons, protected fields, group metadata,
and database-wide metadata are not fingerprinted here. The reader deliberately
cannot be passed to `ThreeWayKdbxTreePlan.plan` as a complete snapshot. A future
adapter must canonicalize those values, verify binary bytes, and implement a
reviewed atomic writer and lease-protected revision check before any merge or
publish path can be enabled.
