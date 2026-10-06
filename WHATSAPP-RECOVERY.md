# Android WhatsApp recovery — release 9

The current recovery implementation is described in **WHATSAPP-CRYPT-RELEASE.md**. It combines original .crypt and CRYPT5/7/8/9/10/11/12/14/15 recovery with modern non-SQLite payloads, safe ZIP expansion, registered derived working copies before parsing, verified reads across the finalized acquisition boundary and a runnable 12-check synthetic case. Unsupported CRYPT extensions remain explicitly blocked. Original .crypt uses its historical public format key; CRYPT5 accepts a 24-byte/48-hex key or its original Google account. Historical unauthenticated output is labeled accordingly. CRYPT14 still needs a matching key acquired or supplied separately. The earlier recovery details and release-3 verification below remain historical context.

This update fixes failures in acquisition, backup decoding, deleted-text carving and chat browsing. The earlier message about an unreadable crypt14-only dump is replaced by the status of each collected backup and actionable recovery routes. The software can decode a backup with its matching key; it cannot derive that secret from ciphertext, turn an ADB error into a key, or reconstruct bytes absent from the acquisition.

## Changes included

- Private acquisition streams binary files and checks the command's exit status before accepting them. A `run-as` denial or invalid key payload cannot become a successful key file. Remote paths are quoted correctly, including spaces, Unicode and newlines.
- Already available root access, or an app installation for which Android already permits `run-as`, collects private app files and SQLite companions. Android user profiles, device-encrypted app directories and WhatsApp Business are included. The acquisition does not root, downgrade, unlock or modify the app to gain access.
- All valid collected keys and the Case Intake key are tried against every backup. An invalid first key no longer hides a matching key from another profile or installation.
- crypt12, crypt14 and crypt15 parsing supports actual Java-serialized key envelopes, protobuf IV fields and the optional feature flag. AES-GCM authentication and any MD5 footer must pass before plaintext is accepted. The cryptography fallback handles the 16-byte IV used by these formats.
- Parsed backup messages, media references, contacts and available call records retain the encrypted source path/hash and historical state. Recovered messages now appear in the main WhatsApp chat view, with SQL pagination and complete counts instead of an 8,000-record window.
- The broken deleted-text carver call is corrected. SQLite freelist trunk **and leaf** pages are inspected after decryption. Candidates carry plaintext byte offsets, page numbers and the decrypted database hash. A fragment is not asserted to be a complete deleted row, and retained date text is not asserted to be a deletion timestamp.
- TXT chat exports support Android/bracketed formats, UTF-8/UTF-16, multiline messages, local timestamps, system messages, URLs and attachment references. Full bodies reach RAG without the earlier per-field/text truncation. Exact media links are resolved when the acquired filename/path identifies one file; ambiguous matches remain candidates.
- **Reprocess mobile evidence** now restarts derived serial processing for an idle job. Saving a valid key and reprocessing updates the existing backup-status record. Running work is protected; paused jobs remain paused.

The previous release's Disk/Mobile priority evidence, image/video Suspicious Activity observations, source hashes, report observations, text-only RAG and **2,500-character chunks with 800-character overlap** are retained.

## Required source material

| Source | Required material | Expected result |
| --- | --- | --- |
| Plaintext Android database | `msgstore.db`, preferably with matching `-wal` / `-journal`; `wa.db` and app media when available | Supported live rows, participants, available media/call data and retained recovery evidence |
| Plaintext iOS database | `ChatStorage.sqlite` and available companions/media | Supported acquired chat records |
| crypt12 / crypt14 | Matching installation's `files/key`, typically a 158-byte Java-serialized key file; supported raw key material is also accepted | Authenticated historical database and its supported records |
| crypt15 | Matching `files/encrypted_backup.key`, commonly a 59-byte Java-serialized or 32-byte raw root key, or the owner's 64-character hexadecimal backup key | Authenticated historical database and its supported records |
| Owner-provided chat export | WhatsApp TXT export and the corresponding exported media | The history actually included in that export, with source line numbers and available attachment links |

Private Android paths include `/data/user/<user-id>/com.whatsapp/`, `/data/user_de/<user-id>/com.whatsapp/` and the legacy `/data/data/com.whatsapp/` alias. WhatsApp Business uses `com.whatsapp.w4b`. Keys must match the backup's installation; a valid-looking key from another installation can still fail authentication. A backup password alone is not the local crypt15 key.

Ordinary shared-storage ADB/MTP pulls cannot read a production app's private sandbox. If the owner's phone can open WhatsApp, use WhatsApp's **Export chat** operation for each required chat, include media when offered, and import the TXT/media evidence folder or ZIP. Exports do not establish complete history or recover already deleted messages. A private filesystem acquisition may contain plaintext databases or matching keys when that access was actually available. Selecting a collection label alone does not guarantee those files were acquired.

## Apply and reprocess existing cases

1. Keep the existing deployment as a rollback copy. Pause active jobs before updating a bind-mounted project. Merge this archive's code while preserving deployment credentials, evidence volumes and drive overlays. See `DISK-MOBILE-SERIAL-RELEASE.md` for model and environment settings.
2. From PowerShell in the updated project root, preview and apply to the existing products:

```powershell
.\scripts\Apply-Disk-Mobile-Serial.ps1 -Products @("forensic", "mobile-android", "mobile-ios") -DryRun
.\scripts\Apply-Disk-Mobile-Serial.ps1 -Products @("forensic", "mobile-android", "mobile-ios") -ReprocessReady
```

Select only products deployed on the host. Supply `-ForensicProjectName` and `-ComposeOverrides` when the existing deployment requires them. `-PrepareVisionModel` is available when the image/video observation model still needs preparation.

3. For a case with encrypted backups, open **Case Intake → Decrypt keys**, enter the valid matching hexadecimal key and save. Do not paste an ADB error or a backup password into that field. Collected binary key files are discovered automatically when imported with the evidence.
4. Once the job is idle, select **Reprocess mobile evidence**. Resume a paused job explicitly. Open **WhatsApp Encrypted Backups** to check each source's authentication result, then **WhatsApp chats/messages**, deleted/recovery evidence and Priority evidence.
5. If the matching key/private database was not acquired, import additional acquired evidence or an owner-provided export. Reprocessing the same keyless ciphertext does not make it readable.

## Local backup recovery utility

The utility reads acquired sources and writes derived SQLite/provenance files into a separate output directory. Run it with Python 3.11+ and the backend's existing dependencies, including an AES provider. No additional wa-crypt-tools runtime dependency is introduced.

```powershell
python .\scripts\recover-whatsapp.py --source "C:\Case\acquired" --key "C:\Case\keys\key" --out "C:\Case\derived"
```

`--source` accepts an acquired directory or a single `msgstore` crypt12/14/15 file. Repeat `--key` for other installations; key files inside the source directory are also discovered. A hex-text file can supply the 64-character backup key. Keys are passed by file path, not exposed on the command line.

Read `whatsapp_recovery_manifest.json` for per-backup status, source hashes, decrypted hashes and selected key-source paths. Derived databases are placed under `whatsapp_decrypted/`; identical plaintext databases are deduplicated. Import the derived evidence into the case if using this standalone route. Preserve the manifest and original encrypted files to retain provenance. Exit code 0 means available backups decoded; exit code 2 indicates a blocked, partial or non-applicable result. Missing AES providers are reported distinctly from wrong keys. Key bytes/hex are not written to recovery diagnostics.

## Reading recovery results

Authenticated backups and owner exports are **historical**, rather than proof of the current device state. A revoked/tombstoned database row can support a deletion status. Retained quoted/index text is assessed with its actual source. Freelist/WAL text alone is a **candidate**: it may be partial, and WAL content can also belong to live transactions. Validate its source and offset before using it in observations. Do not infer sender, deletion time or complete message content from an isolated string.

Overwritten bytes, securely erased pages, unavailable app-private files and media never included in the dump cannot be restored by adding a parser. Browser URLs, photos, audio, videos and documents still depend on the acquired files/private databases. Priority evidence and coverage exceptions expose those gaps. APK/DEX/ART code remains excluded from chat counts.

## Verification

- Focused WhatsApp/acquisition/browse/serial/priority run: **148 passed**. This includes 39 new recovery cases using independently generated wa-crypt-tools 0.1.0 crypt12/14/15 vectors, actual Java key envelopes, corrupt ciphertext/tag/checksum rejection, multiple keys, the cryptography fallback, exports and acquisition error handling.
- Real SQLite deletion fixtures retain text in free leaf pages and produce candidates with exact byte offsets. Secure-delete fixtures produce no invented content. Corrupt freelist cycles/pointers are bounded. A decrypted backup is tested through the actual parser and carver.
- PostgreSQL/WASM checks pass for blocked-to-decrypted status updates, eleven-key discovery, persisted visible messages, an 8,104-record thread, page 41, complete counts, media links, state filters and source hashes. Serial/RAG/media checks also pass, including 2500/800 windows, complete parsed/OCR text, reprocessing, pause preservation and resume deduplication. External storage, GPU lease and vision inference are mocked in those checks.
- The standalone CLI decodes independent crypt12/14/15 inputs, skips a wrong key, writes manifests and readable SQLite, preserves original hashes, and returns a blocked status without producing a database when the key is absent.
- TypeScript and forensic, unified, Android and iOS production builds pass. Existing bundle-size/dynamic-import warnings remain. Python 3.11 syntax, new-module lint and changed PowerShell grammar checks pass.
- A broader 33-file mobile/forensic regression run reports **294 passed, 14 failures**. All 14 failures reproduce in the original upload. They concern old deployment/source assertions, the mobile filename recognizer, capability label, inventory queue name and an objective-procedure wording expectation. They remain documented rather than being represented as passing.

No user handset or real acquisition was provided for this follow-up. Live Android/Windows PowerShell, Docker services and real vision/GPU acceptance remain pending on the central host. The package is tested code, not a claim that the user's encrypted dump has already been recovered or the deployment updated.

Primary format references: [wa-crypt-tools](https://github.com/ElDavoo/wa-crypt-tools), [SQLite file format](https://sqlite.org/fileformat2.html), [Android app backup access](https://developer.android.com/identity/data/autobackup).
