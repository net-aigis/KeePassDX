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
