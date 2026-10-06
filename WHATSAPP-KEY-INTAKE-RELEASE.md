# WhatsApp key capture and huddle cleanup — release 7

The live Android acquisition reads already-accessible WhatsApp key files before large media copies. A collected 158-byte `files/key` supplies `key_file[126:158].hex()` — exactly 64 hexadecimal characters — to job Intake. The complete original key file remains available, including the header material needed for crypt12. Uploading a previously acquired key file is also supported directly in Intake.

## Capture and use

1. Acquire with the updated Windows host helper or Android adapter. The helper reads `/data/data/com.whatsapp/files/key`, equivalent `/data/user/<profile>/com.whatsapp/files/key` paths, WhatsApp Business and supported backup-key files when existing root/su or permitted app run-as access is available. It performs no rooting, unlocking or app replacement.
2. Key-only collection now runs before large shared-media transfers on the Windows host and Android Logical/Advanced Logical/Backup routes. File System routes prioritize key reads before recursive app listing. Each key read has a 30-second timeout; the host's early key step has a 180-second overall limit. Missing access and interrupted reads remain visible gaps.
3. Materialization automatically captures usable WhatsApp key candidates into Intake. Sources include the file path, complete-file SHA-256, length, key format, byte offset and capture time. Existing examiner-entered keys are preserved. Multiple acquired candidates remain available for authenticated decryption.
4. In **Job → Intake → Captured WhatsApp key file**, choose **Capture key from case evidence** or **Upload acquired key file**. Capture searches registered materialized evidence first. Before extraction is finalized, it can search only the registered case directory, without following symlinks, within an eight-second/50,000-file discovery budget. After finalization, separately added key files must use the explicit upload action so parsing never falls back to the original source tree.
5. The 64-character key is stored with Intake, with presence/provenance shown in the UI. Raw key values are excluded from job metadata API responses, logs and reports. Full attached-file bytes are stored under the owning job and verified against their SHA-256 before reuse. ADB error text, oversized files, truncated unsupported files and corrupt stored attachments are rejected.
6. Once a key is saved, use **Reprocess mobile evidence** for an idle job, then recreate the report. Key-format acceptance alone does not prove a matching backup. Actual crypt12/14/15 decryption must authenticate and pass the existing SQLite/integrity checks; the encrypted-backup artifact records the decryption outcome. A crypt15 backup has its own key derivation and is not blindly decrypted with the classic offset rule.

## One coordinator

`progressAgent` remains the sole outside-process Disk/Mobile coordinator. It examines missing useful progress after 60 seconds, distinguishes valid pauses/dependencies from stuck work, and recovers only owned work within the retry budget.

Observe, Performance and Repair are absent from the active roster and Beat schedules. Legacy huddle and supervisor deliveries now return `retired` and perform no monitoring or dispatch. Routine `[Agent huddle] Observe`, `Performance` and `Repair` messages are rejected on write and omitted from job, activity and unified console queries. Historical database records are retained. Processing/evidence logs and shared thermal/performance helpers remain available.

The deployment script removes known retired `observe_agent.py`, `performance_agent.py` and `repair_agent.py` files left by archive overlays, and named obsolete monitoring containers within the selected product's exact Compose project. It does not remove evidence, database/Redis volumes or processing workers.

## Apply on the Windows central host

Merge this archive into the existing `H:\GIT\polaron` deployment, retaining local `.env`, tokens, drive overlays and evidence. Pause active Disk/Mobile jobs before updating the bind-mounted source. The script builds without cache, recreates the selected services, installs the existing serial schema/index migration, and preserves volumes.

```powershell
Set-Location H:\GIT\polaron
.\scripts\Apply-Disk-Mobile-Serial.ps1
```

With no `-Products` argument the script selects currently running Disk/Mobile product projects. For other project names or Compose overlays, use the existing script parameters and deployment-specific settings. There are no Laptop Vulnerability Scanner changes in release 7; the prior 1.5.3 scanner update remains included.

## Verification

- 181 focused tests passed: acquired key-to-Intake-to-authenticated-backup parsing, key-file errors and size limits, matching source hashes, full-file candidate preference, profile/Business reads, key-before-listing ordering, Logical route ordering, legacy delivery retirement, log filtering, serial materialization, progressAgent and mobile acceptance fixtures.
- PostgreSQL-compatible PGlite checks passed for actual row-lock/JSONB statements, key-source updates, examiner key preservation, repeat capture and historical console filtering. This is not a production database load test.
- Unified and Android frontend TypeScript/Vite builds passed. Python source is compatible with the Python 3.11 grammar. PowerShell grammar checks passed after normalizing size-literal suffixes unsupported by the parser; native Windows execution remains pending.
- Updated Disk PDF: 24 pages. Updated Mobile PDF: 29 pages, with a dedicated key capture-to-Intake flow. Bounds, bookmarks, TOC links and the new flow page were reviewed.
- No connected phone, live GPU or native Windows/ADB execution was available. Existing acquisition privileges and an actual matching backup key must be verified on the target device. No missing/overwritten phone data or successful physical capture is claimed by these fixture tests.

Reference sources: [Android Device Explorer access limitations](https://developer.android.com/studio/debug/device-file-explorer), [wa-crypt-tools key parser](https://github.com/ElDavoo/wa-crypt-tools/blob/main/src/wa_crypt_tools/lib/key/key14.py). Runtime decryption uses the project's authenticated parser and independent synthetic format vectors; these links do not add an external runtime dependency.
