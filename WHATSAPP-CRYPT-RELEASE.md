# WhatsApp keyed recovery during mobile extraction — release 9

Encrypted WhatsApp sources are now decoded into registered working copies before native artifact parsing. The pipeline tries all valid acquired and Intake key candidates, keeps original ciphertext and hashes, verifies derived-file ownership and hashes, and sends supported plaintext content through artifact parsing, chat browsing, text-only RAG and report evidence. Identical decrypted SQLite snapshots reuse one working database to prevent duplicate chats. Failed sources retain an explicit per-file reason.

A CRYPT14 backup **cannot provide its own decryption key**. The classic 158-byte WhatsApp `files/key` supplies the 32-byte secret at zero-based bytes 126–157 (`[126:158]`), rendered as 64 hexadecimal characters. A matching key is specific to its installation/backup; it cannot decrypt every WhatsApp backup or other encrypted application. Existing permitted private-path acquisition and key validation remain active, including `/data/data/com.whatsapp/files/key`, Android profiles and WhatsApp Business. An ADB denial/error is never accepted as a key. This release does not obtain otherwise inaccessible private phone data.

## Supported formats

| Input | Required material | Acceptance and integrity |
| --- | --- | --- |
| Original `.crypt` | Historical public format key | AES-192-ECB; complete SQLite layout and `quick_check`; authenticity unverified |
| CRYPT5 | Already-derived 24-byte / 48-hex key, or exact original Android Google account email supplied in Intake | Historical AES-192-CBC account derivation; complete SQLite layout and `quick_check`; no authentication tag |
| CRYPT7 / CRYPT8 | Matching classic `files/key`, raw 32 bytes or valid hexadecimal secret | AES-256-CBC; CRYPT8 gzip; complete SQLite layout and `quick_check`; no authentication tag |
| CRYPT9 / CRYPT10 / CRYPT11 | Matching classic key material | GCM tags verified where present; historical tagless streams accepted only at exact compressed EOF with complete SQLite checks; failed tags never discarded |
| CRYPT12 / CRYPT14 | Matching installation key material | AES-GCM authentication and any MD5 footer; bounded payload expansion |
| CRYPT15 | Matching `encrypted_backup.key` or owner's 64-character hexadecimal root key | HKDF-SHA256 and AES-GCM authentication; any MD5 footer validated |
| Other CRYPT extensions | No validated decoder provided | Retained as encrypted evidence with `unsupported_crypt_version`; never silently treated as a supported version |

Legacy ECB/CBC and tagless-stream structural checks do not prove authenticity. Derived legacy chat records include `legacy_no_authentication_tag`, an explicit integrity label and a medium confidence ceiling. Modern authentication failure, truncated sources, corrupt footers, absent AES providers and size limits have distinct diagnostics. Plaintext SQLite in a backup-named file is explicitly classified as plaintext.

## Content and artifact flow

1. Finalize acquisition and register original files with source provenance. Capture permitted private keys into Intake or accept supplied matching key files/secrets. CRYPT5 also accepts its optional original Google account field. Original `.crypt` uses the historical public format key.
2. During materialization, detect WhatsApp CRYPT sources and try the matching-format candidates. Authenticate modern formats or structurally validate supported legacy databases. A declared filename alone does not establish payload type.
3. Register job-owned derived SQLite, JSON, ZIP, image or binary payloads. Expand safe, CRC-verified ZIP members with explicit member/count/size limits. Unsafe, duplicate, symlink, separately encrypted and oversized members remain in the retained archive with coverage warnings.
4. Native parsers read only verified registered derivations across the sealed-source boundary. Supported messages, email/EML, documents and pictures enter the existing artifact, OCR/media, recovery, RAG and report stages. Binary content is retained as such; unknown JSON changesets are not assumed to be complete chats or silently replayed into a base database.
5. Store encrypted source paths/hashes, derived hashes and integrity labels on recovered records. Surviving deletion flags and retained residual candidates preserve their actual evidence state. Existing Suspicious Activity media review and examiner observations can use recovered evidence with source-linked descriptions.

Text-only RAG retains **2,500-character chunks and 800-character overlap**. No GPU embedding stage or additional supervisory agent is introduced. Cache keys include source hash, decoder version and supplied/acquired key set, so new matching keys trigger a retry while completed derivations are reused. Explicit rollback before a retryable database deadlock prevents stale transaction state from interrupting processing.

Recovery depends on acquired bytes. It cannot restore overwritten/deleted material, fetch missing media from an encrypted database alone, unlock Android file-based encryption, decode arbitrary other encrypted apps, or infer unavailable chats. Modern generic payload support does not implement every incremental backup schema.

## Apply to new and existing cases

Use the existing deployment/update procedure in `DISK-MOBILE-SERIAL-RELEASE.md`; retain credentials and evidence volumes. The Windows Docker startup/caching/TLS files and canonical Laptop Scanner remain byte-identical to the current supplied project. The combined release preserves its expanded CRYPT-family decoder, per-file Intake results, private plaintext export option and Test-Crypt/Test-Crypt14 commands. The prior CRYPT_FAMILY_GUIDE and CRYPT14_MOBILE_DECRYPTION PDFs are preserved historical snapshots; this document and the process-flow PDFs describe the current behavior.

For new cases, recovery runs before native parsing. For an existing idle case, open **Case Intake → Decrypt keys**, save matching material (and the original Google account for CRYPT5 if required), then select **Reprocess mobile evidence**. Explicitly resume a paused case. Inspect **WhatsApp Encrypted Backups**, chats/deleted evidence, files and report observations for the actual recovered content and remaining gaps.

## Runnable synthetic test

```powershell
python scripts/test-whatsapp-decryption.py --out C:/Aetheris-QA/whatsapp-case-1
```

Python 3.11+ and the updated backend dependencies are required. Use a new empty folder. Expected output: `status=passed`, **12 checks**, original synthetic files, derived working copies and `whatsapp_synthetic_test_results.json`. The test includes a matching 158-byte key and a CRYPT14 backup; it extracts the known secret from the key file, verifies the three expected chat rows, tests all ten supported layouts and fourteen encrypted files and rejects the same CRYPT14 source without a key. It does not recover a key from ciphertext.

Prebuilt public fixtures are in `tests/fixtures/whatsapp_crypt`. The separate **WhatsApp-CRYPT-Test-Cases.zip** contains those inputs, an independently runnable QA subset, dependency pins, a Windows launcher and positive/negative recovery commands. Test encoder fixtures use independent cryptography primitives instead of the decoder's fixture helper. The known synthetic secrets are intentionally public; production decryption diagnostics never publish key bytes.

For a supplied fixture file:

```powershell
python scripts/recover-whatsapp.py --source tests/fixtures/whatsapp_crypt/WhatsApp/Databases/msgstore.db.crypt14 --key tests/fixtures/whatsapp_crypt/data/data/com.whatsapp/files/key --out C:/Aetheris-QA/decoded-crypt14
```

The output directory must be outside the source evidence directory. Repeat `--key` for other installations. Directory recovery discovers key files and accepts `--legacy-account` for CRYPT5. `whatsapp_recovery_manifest.json` records per-file outcomes and original/derived hashes; it never emits raw keys. Exit 0 means all considered files decoded; exit 2 means blocked, partial or non-applicable.

## Verification and limits

- **319 focused regression tests passed**, including ten-layout recovery, mismatched/missing keys, corrupt tags/footers, unknown versions, decompression/ZIP limits, derived-file integrity, private acquisition, chat/deleted views, artifact parsing, RAG, Suspicious Activity and report checks.
- **20 PostgreSQL-compatible integration checks passed** with real service SQL and controlled local case-object storage. They cover acquired/Intake key handling, eight sources with six decoded and two explicitly blocked, persisted Intake authentication outcomes, native parsing, email/picture artifacts, chat/deleted browsing, RAG, cache reuse, unchanged originals, cross-case/tampered derivation rejection and pause handling. This is not live phone, production database or MinIO acceptance.
- The **12-check standalone synthetic case passed**, also with PyCryptodome deliberately unavailable, using the cryptography fallback. CLI positive CRYPT14, keyless rejection and all-format recovery were exercised on the supplied packet.
- The preserved **Test-Crypt.ps1** case command passed under PowerShell 7.4.13 on Linux: 11 supplied demo backups decoded, with 7 authenticated and 4 marked legacy/unverified. Optional key export contains the already-collected matching key; it does not derive a key from ciphertext.
- Unified, Android and iOS frontend production builds passed. Changed Python sources pass Python 3.11 grammar checks, compile checks and Ruff F/E9.
- **Mobile-Process-Flows.pdf: 32 pages**; **WhatsApp-Decryption-Test-Cases.pdf: 11 pages**. Vector geometry and representative pages, including the contents and command tables, were inspected.

Live phone/GPU, native Windows acquisition, real user backup/key compatibility and deployment acceptance remain pending. No user-provided encrypted backup was recovered in this editing environment.

Primary format references: [Andriller legacy decoder](https://github.com/den4uk/andriller/blob/master/andriller/decrypts.py); [wa-crypt-tools](https://github.com/ElDavoo/wa-crypt-tools); legacy author [CRYPT5](https://github.com/andreas-mausch/whatsapp-viewer/blob/master/source/WhatsApp/Crypt5.cpp), [CRYPT7](https://github.com/andreas-mausch/whatsapp-viewer/blob/master/source/WhatsApp/Crypt7.cpp), [CRYPT8](https://github.com/andreas-mausch/whatsapp-viewer/blob/master/source/WhatsApp/Crypt8.cpp).
