# Polaron V35 — Email, MIME, Cloud and Social Artifact Completeness

Date: 2026-09-27

## Problems fixed

1. Outlook/EML evidence could be counted but the examiner could not reliably open the actual message body and MIME attachments.
2. Extensionless or placeholder-named evidence could remain `application/octet-stream`/generic even when the bytes identify a real format.
3. The Disk Artifact tree only surfaced the endpoint AXIOM platform, so the separate AXIOM `Cloud` catalog (OneDrive, Google Drive, Dropbox, Box, iCloud, Mega, AWS, Azure, etc.) was absent.
4. Generic path-token matching produced false Social Networking results. The observed `Google+ Chat = 2054` was caused by Chrome `.../Google/Chrome/.../Cache_Data/f_*` paths rather than Google+ chat evidence.
5. Existing jobs retained stale Social/Cloud counts from the old generic matcher.
6. EML count domains mixed regular EML/EMLX messages and extensionless RFC messages, which could lead to incorrect totals.

## V35 behavior

### Complete artifact tree

For Windows disk jobs the explorer now merges the relevant AXIOM catalogs:

- Windows
- Cloud
- Windows Memory

Every official definition is retained even when its count is zero. Exact duplicate labels are folded only once for display. Report-scope checkboxes do not control whether an artifact definition is inventoried or visible.

Key sections (Email and Calendar, Media, Cloud Storage, Social Networking) are expanded automatically. Each row carries the AXIOM source platform in metadata/tooltips.

### Cloud drives

Cloud Storage now uses strict provider signals and exposes both endpoint and cloud definitions, including OneDrive, Google Drive, Dropbox, Box, iCloud, Mega, Amazon/AWS, Azure, Samsung Cloud, Carbonite, Flickr and Android cloud-backup definitions. Files are accepted only from provider sync roots; browser/system cache noise is excluded. Web-only activity is based on provider domains/history records.

### Social Networking

Social counts no longer use generic artifact-name token matching. Provider domains/app stores are used instead. Chrome cache files containing the word `Google` cannot count as `Google+ Chat`. Message-specific Facebook/LinkedIn artifacts may use the chat-store parser; activity/media artifacts use provider-specific evidence.

Old provider counts are marked stale unless their query snapshot identifies the V35 `social_cloud_inventory` collector. Existing jobs are therefore recounted automatically without E01 download, copying or extraction.

### Email and attachments

- EML/EMLX: RFC/MIME body, HTML/plain text and attachments are parsed and displayed.
- MSG: V35 adds `extract-msg`; message headers/body/HTML and attachments are exposed in the same email preview. Each attachment is MIME-resolved and can be opened/downloaded independently.
- Real `.msg`/`.eml` Outlook evidence rows are listed before PST/OST metadata-only rows so the examiner reaches the content-bearing message first.
- PST/OST remains preserved as the original mailbox container. With `pst-utils/readpst` available, V35 creates derived RFC822 `.eml` message artifacts from the mailbox (`readpst -e -D`) without changing the source mailbox. Those derived messages use the same MIME preview, so bodies and attachments can be opened/downloaded. If mailbox conversion fails, the bounded metadata-only PST/OST fallback remains available instead of inventing content.
- Webmail catalog rows display deterministic browser-history access evidence instead of unrelated cache blobs.

### MIME/type normalization

The original evidence bytes and original hash are never rewritten. V35 creates a derived examiner-facing filename/type from:

1. forensic/manual byte signatures,
2. libmagic (`python-magic` + `libmagic1`),
3. special forensic names/paths,
4. parser/extractor MIME metadata,
5. declared extension,
6. structured-text detection.

Recognizable extensionless objects are therefore served with the correct MIME and normalized extension. Unknown evidence remains `application/x-forensic-data`; it is not falsely labeled as a document/image.

### EML count correctness

Regular EML/EMLX messages and extensionless RFC messages are now disjoint count domains and are combined once. This removes the previous double-count ambiguity while retaining extensionless email evidence.

## Deployment

Because V35 adds OS and Python dependencies, rebuild the backend containers rather than only restarting them:

```powershell
docker compose up -d --build api worker-disk worker-parse worker-rag-gpu worker-agent frontend
```

Then hard-refresh the browser with `Ctrl+Shift+R`.

## Validation

- Python application compilation: passed.
- Focused artifact/email/catalog regression suite: 76 passed.
- Modified TypeScript/TSX syntax transpilation with TypeScript 5.8.3: passed.
- Bundled AXIOM catalog: Windows + Cloud + Windows Memory = 819 raw definitions / 817 unique display definitions; zero-count definitions retained.
