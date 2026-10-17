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

## Session-scoped KDBX content fingerprints (phase 2E; still read-only)

`KdbxRecordContentFingerprints.read(DatabaseKDBX, sessionKey)` verifies the
existing model inventory and creates session-keyed HMAC-SHA256 comparisons for
individual groups, entries, history versions and `DeletedObjects`. It reads
protected `CharArray` values directly (without constructing plaintext strings)
and streams the **actual uncompressed attachment bytes**, not database-specific
binary-pool IDs. Variable-length fields are framed and custom maps are sorted.
A missing or corrupted binary, duplicate/nested history object, or an
uncompressed attachment exceeding the current 64 MiB in-memory limit fails closed.

The caller MUST generate a fresh random key of at least 32 bytes for each
base/local/remote comparison and use that same key for all three copies.
These MACs and the key are sensitive **in-memory-only** comparison material;
never store, log, export or send them to the coordinator. The caller must also
prevent concurrent mutation of the decrypted model during inventory creation.

**Not a merge authorization:** database-wide settings, custom-icon image
bytes, cross-copy deleted-object reconciliation, binary-pool reconstruction,
and the atomic writer/remote lease recheck are NOT implemented. These HMACs
are intentionally not passed to `ThreeWayKdbxTreePlan` and do not enable
merging, saving or publishing. Existing encrypted recovery is unchanged.

## Ephemeral three-copy KDBX comparison (phase 2F; review only)

`KdbxThreeCopyReview.read(base, local, remote)` reads three already-decrypted,
**stable** `DatabaseKDBX` models with one fresh random 256-bit in-memory HMAC
key. The key is zeroed after comparison; neither it nor the per-record HMACs
are returned. Results contain only UUIDs and classifications: unchanged,
local-only, remote-only, identical edit, or conflict. Divergent edits and
modification-vs-deletion are visible as conflicts. A deletion in one branch
requires an explicit `DeletedObject`; missing base records without a tombstone,
live/tombstone UUID overlap, incompatible node kinds, deleted UUID reuse, and
incompatible root groups fail closed.

**This is NOT a writable merge plan or a safe-to-publish indicator.** A result
with no reported conflict does not validate cross-record merged topology,
database-wide metadata, custom-icon image bytes, binary-pool reconstruction,
credentials, revision revalidation under an exclusive lease, atomic KDBX
writing, or recovery retention. It does not read or write files itself, modify
any model, enable automatic merge, or transmit HMACs to the coordinator.

## Selected combined KDBX topology preflight (phase 2G; still read-only)

After `KdbxThreeCopyReview` has classified **all** UUIDs, a result without
record conflicts now validates the combined group/entry topology **using the
same already-read inventories**, without reopening or mutating the KDBX models.
`KdbxSelectedTopologyPreflight` rejects missing or non-group parents, UUID-map
mismatches, detached groups, missing/incorrect roots and cyclic group ancestry;
the traversal is iterative. If there are unresolved record conflicts, the
three-copy review still reports them without pretending a selected tree exists.

Passing this guard is **NOT merge authorization**. The check validates
selected parent pointers but does **not** reconstruct a group's child lists,
ordering or content fingerprint for the eventual combined model. It also does
not reconcile database-level settings, custom icons, binary pools, credential
changes, revision/lease validity, or atomic writes. It must not be wired to a writer or
interpreted as proof that all KDBX information was merged without loss.

## Database-wide three-copy metadata review (phase 2H; read-only)

`KdbxDatabaseMetadataReview.compare(base, local, remote, key)` classifies changes
in database-level settings, timestamps, password-field protection preferences,
custom database properties, and **decoded custom-icon content**. Each property
and each icon is compared with a domain-separated HMAC-SHA256 under the same
fresh session key used for the entry/group review. The result contains only
property identifiers and change/conflict classifications, never values or
fingerprints. Corrupted custom-icon data and oversized expanded icons fail
closed. `KdbxThreeCopyReview.Report.metadata` exposes these classifications;
The caller must separately inspect `conflictIds` and `metadata.conflictKeys`;
no combined success/authorization flag exists.

**Still no merge/write permission.** KDF/cipher settings, key material, public
header variants, unknown extensions, attachment-pool reconstruction, and
serialization have NOT yet been proven safe for automatic merging. Even a
conflict-free report is NOT a writable candidate. The decrypted source models
must remain stable throughout comparison, and a separate credential-aware,
lease-protected, atomic writer remains necessary.

## Cipher and KDF work-factor review (phase 2I; read-only)

The metadata comparison now also classifies the encryption cipher UUID, KDF engine
UUID and effective iteration, memory and parallelism settings. These properties
are compared using the same ephemeral session-keyed HMACs as other metadata:
no key material, work factors, fingerprints or master credentials are returned.
A missing KDF engine or algorithm UUID fails closed. Cipher/KDF setting changes
are reported but never automatically accepted or applied to a merged database.

This is **not** a complete cryptographic-header comparison. Random KDF salts,
unknown KDF parameters, public and inner-header extensions, key-file or other
credential material, and all serialization/re-encryption guarantees remain
outside the inspected surface. No result authorizes merge, save or upload.

## Combined sibling-order collision preflight (phase 2J; still read-only)

`KdbxModelSnapshotReader` now records each real non-root KDBX node's
`indexInParent` alongside UUID and parent identity. When a conflict-free
three-copy review selects a combined tree, the topology preflight rejects
duplicate positions among siblings, negative positions and partially indexed
inventories. Nodes under different parents may use the same index; the root
must not have a sibling index. Legacy synthetic test snapshots without
positions remain supported, but real KDBX inventories supply positions.

Independent offline additions can choose the same position. The guard
**reports an unresolved ordering collision** rather than silently
reassigning positions or dropping a child. It does not validate a final
serialized order, resolve simultaneous insertions, reconstruct group child
lists or approve any write. Group-content fingerprints still include
child membership and ordering and may conservatively report conflicts
for otherwise independent additions. All such cases require a separate
reviewed merge strategy. No automatic merge, save or publication is enabled.
