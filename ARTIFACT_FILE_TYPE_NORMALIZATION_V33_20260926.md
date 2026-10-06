# Polaron V33 - Artifact file-type normalization

Date: 2026-09-26

## Problem

The Artifact preview/properties UI could show `Type: application/octet-stream` for extensionless or forensic system files such as `$AttrDef`, `$MFT`, `$Bitmap`, `$Boot`, `$ObjId`, `$Quota`, `$Reparse`, `$Repair`, `$Tops`, registry hives, carved files, email attachments, and files with misleading/generic extensions.

`application/octet-stream` is only a generic transport fallback. It does not tell an examiner what the evidence object actually is and can also cause the browser to download a file with an incorrect `.bin` name.

## V33 behavior

V33 adds one central deterministic forensic type resolver. Type resolution uses, in priority order:

1. strong file signatures/magic from the evidence bytes;
2. known forensic/system filenames and paths;
3. parser/extractor MIME metadata;
4. declared file extension;
5. bounded text/JSON/XML/CSV detection;
6. an explicit `Forensic data file (unrecognized format)` fallback.

The Artifact UI no longer presents artifact evidence as `application/octet-stream`.

### Normalized download/view names

Original evidence is NEVER renamed or modified on disk. Polaron derives a presentation/download name only.

Examples:

- extensionless `%PDF` bytes -> `recovered-file.pdf`, `application/pdf`
- `report.bin` with PDF signature -> `report.pdf`, `application/pdf`
- extensionless SQLite -> `History.db`, `application/vnd.sqlite3`
- extensionless EVTX -> `event-data.evtx`, `application/x-ms-evtx`
- `$MFT` -> `$MFT.mft`, `application/x-ntfs-mft`
- `$AttrDef` -> `$AttrDef.ntfs-attrdef`, `application/x-ntfs-attrdef`
- MIME `application/pdf` + filename `attachment` -> `attachment.pdf`
- MIME Word OOXML + filename `attachment` -> `attachment.docx`

For a truly unrecognized object, the original bytes remain available but the UI describes it as `Forensic data file (unrecognized format)` rather than calling it a binary or displaying raw byte/hex data.

## Forensic integrity

This is a presentation/type-normalization layer. It does not modify source evidence, E01/EWF contents, extracted bytes, SHA-256 values, timestamps, or source paths. A normalized extension is used only for examiner display/download so forensic hashes remain valid.

## Coverage

Built-in signatures/path mappings include PDF, Office OOXML/OLE, Outlook MSG/PST/OST, SQLite, Registry hives, EVTX, LNK, Prefetch, NTFS metadata, ZIP/RAR/7Z/GZIP/TAR/XZ/BZIP2, JPEG/PNG/GIF/BMP/TIFF/WebP/HEIC/AVIF, MP4/MOV/MKV/WebM/AVI, MP3/M4A/WAV/FLAC/Ogg, PE/ELF/DEX/Java, E01/EWF, VHDX, QCOW2, raw/disk image extensions, plist, JSON/XML/HTML/CSV/text, APK/JAR/EPUB and common forensic formats.

## Existing jobs

Existing jobs do not require extraction or RAG processing again. File type is resolved dynamically when artifact rows/properties/content are requested. When artifact bytes are subsequently materialized, the resolved type metadata is persisted for reuse. New materialized artifacts receive normalized type metadata immediately.

## UI changes

Artifact properties now show:

- Type: human-readable type name
- MIME: resolved MIME type
- Detected extension
- Open/download as: normalized filename when it differs from the source filename

## Validation

- 71 focused backend regression tests passed across V30/V31/V32 artifact and zero-copy areas plus the new V33 type resolver.
- 12 V33 type resolver/property tests passed.
- Backend Python compileall passed.
- Modified TypeScript/TSX files passed TypeScript 5.8.3 syntax transpilation.

Known pre-existing tests in the V32 baseline (`test_axiom_inventory_queue.py` and one email count fallback test) still fail unchanged in the baseline and were not introduced by V33.
