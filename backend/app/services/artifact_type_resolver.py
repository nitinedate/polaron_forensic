"""Deterministic forensic file-type resolution.

The forensic UI must never present evidence as the meaningless browser fallback
``application/octet-stream`` when the filename, metadata or file signature can
identify the actual format.  This module resolves a stable examiner-facing type
without modifying the evidence bytes.

Original evidence remains byte-for-byte unchanged.  ``normalized_filename`` is
only a derived download/view name used when the source is extensionless or has a
generic placeholder extension.
"""

from __future__ import annotations

import json
import mimetypes
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

GENERIC_MIME_TYPES = frozenset({"", "application/octet-stream", "binary/octet-stream", "application/binary"})
FORENSIC_DATA_MIME = "application/x-forensic-data"
TYPE_SNIFF_BYTES = 256 * 1024


@dataclass(frozen=True)
class ResolvedArtifactType:
    content_type: str
    extension: str | None
    label: str
    kind: str
    source: str
    confidence: str
    original_filename: str
    normalized_filename: str


# Explicit extensions used by forensic evidence that Python's mimetypes either
# does not know or maps too generically.
_EXTENSION_TYPES: dict[str, tuple[str, str, str]] = {
    # Documents / office
    ".pdf": ("application/pdf", "PDF document", "document"),
    ".doc": ("application/msword", "Microsoft Word document", "document"),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Microsoft Word document", "document"),
    ".xls": ("application/vnd.ms-excel", "Microsoft Excel workbook", "document"),
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Microsoft Excel workbook", "document"),
    ".ppt": ("application/vnd.ms-powerpoint", "Microsoft PowerPoint presentation", "document"),
    ".pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "Microsoft PowerPoint presentation", "document"),
    ".rtf": ("application/rtf", "Rich Text Format document", "document"),
    ".odt": ("application/vnd.oasis.opendocument.text", "OpenDocument text", "document"),
    ".ods": ("application/vnd.oasis.opendocument.spreadsheet", "OpenDocument spreadsheet", "document"),
    ".odp": ("application/vnd.oasis.opendocument.presentation", "OpenDocument presentation", "document"),
    ".epub": ("application/epub+zip", "EPUB document", "document"),
    # Text / structured text
    ".txt": ("text/plain", "Text file", "text"),
    ".log": ("text/plain", "Log file", "text"),
    ".csv": ("text/csv", "CSV data", "text"),
    ".tsv": ("text/tab-separated-values", "Tab-separated data", "text"),
    ".json": ("application/json", "JSON data", "structured"),
    ".xml": ("application/xml", "XML data", "structured"),
    ".html": ("text/html", "HTML document", "document"),
    ".htm": ("text/html", "HTML document", "document"),
    ".md": ("text/markdown", "Markdown document", "text"),
    ".ini": ("text/plain", "Configuration file", "text"),
    ".cfg": ("text/plain", "Configuration file", "text"),
    ".yaml": ("application/yaml", "YAML data", "structured"),
    ".yml": ("application/yaml", "YAML data", "structured"),
    ".sql": ("application/sql", "SQL script", "text"),
    ".ps1": ("text/x-powershell", "PowerShell script", "script"),
    ".bat": ("application/x-bat", "Windows batch script", "script"),
    ".cmd": ("application/x-bat", "Windows command script", "script"),
    ".sh": ("application/x-sh", "Shell script", "script"),
    ".js": ("text/javascript", "JavaScript file", "script"),
    ".css": ("text/css", "CSS stylesheet", "text"),
    # Mail / messaging
    ".eml": ("message/rfc822", "Email message", "email"),
    ".emlx": ("message/rfc822", "Apple Mail message", "email"),
    ".msg": ("application/vnd.ms-outlook", "Outlook message", "email"),
    ".pst": ("application/vnd.ms-outlook-pst", "Outlook PST mailbox", "email"),
    ".ost": ("application/vnd.ms-outlook-ost", "Outlook OST mailbox", "email"),
    ".mbox": ("application/mbox", "Mailbox file", "email"),
    # Databases
    ".db": ("application/vnd.sqlite3", "SQLite database", "database"),
    ".sqlite": ("application/vnd.sqlite3", "SQLite database", "database"),
    ".sqlite3": ("application/vnd.sqlite3", "SQLite database", "database"),
    ".sqlitedb": ("application/vnd.sqlite3", "SQLite database", "database"),
    ".db-wal": ("application/x-sqlite-wal", "SQLite WAL", "database"),
    ".db-shm": ("application/x-sqlite-shm", "SQLite shared-memory file", "database"),
    # Windows forensic formats
    ".evtx": ("application/x-ms-evtx", "Windows Event Log", "forensic"),
    ".evt": ("application/x-ms-eventlog", "Windows Event Log", "forensic"),
    ".etl": ("application/x-ms-etl", "Windows Event Trace Log", "forensic"),
    ".pf": ("application/x-windows-prefetch", "Windows Prefetch file", "forensic"),
    ".lnk": ("application/x-ms-shortcut", "Windows shortcut", "forensic"),
    ".automaticdestinations-ms": ("application/x-windows-jumplist", "Windows Jump List", "forensic"),
    ".customdestinations-ms": ("application/x-windows-jumplist", "Windows Jump List", "forensic"),
    ".blf": ("application/x-windows-clfs", "Windows Common Log File System file", "forensic"),
    ".reg": ("text/x-windows-registry", "Windows Registry export", "forensic"),
    ".hiv": ("application/x-windows-registry", "Windows Registry hive", "forensic"),
    ".hive": ("application/x-windows-registry", "Windows Registry hive", "forensic"),
    # Archives / packages
    ".zip": ("application/zip", "ZIP archive", "archive"),
    ".rar": ("application/vnd.rar", "RAR archive", "archive"),
    ".7z": ("application/x-7z-compressed", "7-Zip archive", "archive"),
    ".gz": ("application/gzip", "Gzip archive", "archive"),
    ".tgz": ("application/gzip", "Tar/Gzip archive", "archive"),
    ".tar": ("application/x-tar", "TAR archive", "archive"),
    ".bz2": ("application/x-bzip2", "Bzip2 archive", "archive"),
    ".xz": ("application/x-xz", "XZ archive", "archive"),
    ".apk": ("application/vnd.android.package-archive", "Android application package", "package"),
    ".ipa": ("application/x-ios-app", "iOS application package", "package"),
    ".jar": ("application/java-archive", "Java archive", "package"),
    # Images
    ".jpg": ("image/jpeg", "JPEG image", "image"),
    ".jpeg": ("image/jpeg", "JPEG image", "image"),
    ".png": ("image/png", "PNG image", "image"),
    ".gif": ("image/gif", "GIF image", "image"),
    ".bmp": ("image/bmp", "Bitmap image", "image"),
    ".webp": ("image/webp", "WebP image", "image"),
    ".tif": ("image/tiff", "TIFF image", "image"),
    ".tiff": ("image/tiff", "TIFF image", "image"),
    ".ico": ("image/x-icon", "Icon image", "image"),
    ".heic": ("image/heic", "HEIC image", "image"),
    ".heif": ("image/heif", "HEIF image", "image"),
    ".avif": ("image/avif", "AVIF image", "image"),
    # Video / audio
    ".mp4": ("video/mp4", "MP4 video", "video"),
    ".m4v": ("video/x-m4v", "M4V video", "video"),
    ".mov": ("video/quicktime", "QuickTime video", "video"),
    ".mkv": ("video/x-matroska", "Matroska video", "video"),
    ".webm": ("video/webm", "WebM video", "video"),
    ".avi": ("video/x-msvideo", "AVI video", "video"),
    ".wmv": ("video/x-ms-wmv", "Windows Media video", "video"),
    ".3gp": ("video/3gpp", "3GPP video", "video"),
    ".mp3": ("audio/mpeg", "MP3 audio", "audio"),
    ".m4a": ("audio/mp4", "M4A audio", "audio"),
    ".aac": ("audio/aac", "AAC audio", "audio"),
    ".wav": ("audio/wav", "WAV audio", "audio"),
    ".flac": ("audio/flac", "FLAC audio", "audio"),
    ".ogg": ("audio/ogg", "Ogg audio", "audio"),
    ".opus": ("audio/opus", "Opus audio", "audio"),
    ".amr": ("audio/amr", "AMR audio", "audio"),
    # Executables / runtime
    ".exe": ("application/vnd.microsoft.portable-executable", "Windows executable", "executable"),
    ".dll": ("application/vnd.microsoft.portable-executable", "Windows dynamic-link library", "executable"),
    ".sys": ("application/vnd.microsoft.portable-executable", "Windows driver", "executable"),
    ".msi": ("application/x-msi", "Windows Installer package", "package"),
    ".so": ("application/x-elf", "ELF shared library", "executable"),
    ".elf": ("application/x-elf", "ELF executable", "executable"),
    ".dex": ("application/x-android-dex", "Android DEX bytecode", "executable"),
    ".class": ("application/java-vm", "Java class file", "executable"),
    # Disk / forensic images
    ".e01": ("application/x-ewf", "Expert Witness Format image", "disk-image"),
    ".ex01": ("application/x-ewf", "Expert Witness Format image", "disk-image"),
    ".l01": ("application/x-ewf-logical", "EWF logical evidence image", "disk-image"),
    ".dd": ("application/x-raw-disk-image", "Raw disk image", "disk-image"),
    ".raw": ("application/x-raw-disk-image", "Raw disk image", "disk-image"),
    ".img": ("application/x-raw-disk-image", "Disk image", "disk-image"),
    ".iso": ("application/x-iso9660-image", "ISO disk image", "disk-image"),
    ".vhd": ("application/x-vhd", "Virtual Hard Disk", "disk-image"),
    ".vhdx": ("application/x-vhdx", "Virtual Hard Disk v2", "disk-image"),
    ".vmdk": ("application/x-vmdk", "VMware virtual disk", "disk-image"),
    ".vdi": ("application/x-vdi", "VirtualBox virtual disk", "disk-image"),
    ".qcow2": ("application/x-qcow2", "QCOW2 virtual disk", "disk-image"),
    ".aff": ("application/x-aff", "Advanced Forensic Format image", "disk-image"),
    ".aff4": ("application/x-aff4", "AFF4 forensic image", "disk-image"),
    ".dmg": ("application/x-apple-diskimage", "Apple disk image", "disk-image"),
    # Apple / mobile structured data
    ".plist": ("application/x-apple-plist", "Apple property list", "structured"),
    ".mobileprovision": ("application/x-apple-aspen-config", "Apple provisioning profile", "structured"),
    ".svg": ("image/svg+xml", "SVG image", "image"),
    ".webmanifest": ("application/manifest+json", "Web application manifest", "structured"),
    ".wasm": ("application/wasm", "WebAssembly module", "executable"),
    ".zlib": ("application/zlib", "Zlib-compressed data", "archive"),
    ".woff": ("font/woff", "WOFF font", "font"),
    ".woff2": ("font/woff2", "WOFF2 font", "font"),
}


_NTFS_SPECIAL: dict[str, tuple[str, str, str, str]] = {
    "$mft": ("application/x-ntfs-mft", ".mft", "NTFS Master File Table", "filesystem"),
    "$attrdef": ("application/x-ntfs-attrdef", ".ntfs-attrdef", "NTFS Attribute Definitions", "filesystem"),
    "$badclus": ("application/x-ntfs-badclus", ".ntfs-badclus", "NTFS Bad Cluster file", "filesystem"),
    "$bitmap": ("application/x-ntfs-bitmap", ".ntfs-bitmap", "NTFS Allocation Bitmap", "filesystem"),
    "$boot": ("application/x-ntfs-boot", ".ntfs-boot", "NTFS Boot metadata", "filesystem"),
    "$logfile": ("application/x-ntfs-logfile", ".ntfs-log", "NTFS Transaction Log", "filesystem"),
    "$objid": ("application/x-ntfs-objid", ".ntfs-objid", "NTFS Object ID metadata", "filesystem"),
    "$quota": ("application/x-ntfs-quota", ".ntfs-quota", "NTFS Quota metadata", "filesystem"),
    "$reparse": ("application/x-ntfs-reparse", ".ntfs-reparse", "NTFS Reparse metadata", "filesystem"),
    "$repair": ("application/x-ntfs-repair", ".ntfs-repair", "NTFS Repair metadata", "filesystem"),
    "$tops": ("application/x-ntfs-tops", ".ntfs-tops", "NTFS Transaction metadata", "filesystem"),
    "$secure": ("application/x-ntfs-secure", ".ntfs-secure", "NTFS Security metadata", "filesystem"),
    "$upcase": ("application/x-ntfs-upcase", ".ntfs-upcase", "NTFS UpCase table", "filesystem"),
    "$volume": ("application/x-ntfs-volume", ".ntfs-volume", "NTFS Volume metadata", "filesystem"),
    "$usnjrnl": ("application/x-ntfs-usn-journal", ".usnjrnl", "NTFS USN Journal", "filesystem"),
    "$extend": ("application/x-ntfs-extend", ".ntfs-extend", "NTFS Extend metadata", "filesystem"),
}

_REGISTRY_HIVE_NAMES = frozenset({"sam", "security", "software", "system", "default", "ntuser.dat", "usrclass.dat", "bcd"})
_GENERIC_EXTENSIONS = frozenset({".bin", ".blob", ".binary", ".tmp", ".unknown", ".file"})


def is_generic_content_type(content_type: str | None) -> bool:
    return (content_type or "").split(";", 1)[0].strip().lower() in GENERIC_MIME_TYPES | {FORENSIC_DATA_MIME}


def _norm_ext(value: Any) -> str:
    ext = str(value or "").strip().lower()
    if ext in {"", ".", "none", "null", "(none)"}:
        return ""
    return ext if ext.startswith(".") else f".{ext}"


def _filename_for_row(row: dict[str, Any]) -> tuple[str, str]:
    path = str(row.get("file_path") or row.get("source_path") or "")
    name = str(row.get("file_name") or row.get("title") or PurePosixPath(path.replace("\\", "/")).name or "artifact")
    return path, name


def _from_extension(ext: str) -> tuple[str, str, str] | None:
    if not ext:
        return None
    explicit = _EXTENSION_TYPES.get(ext)
    if explicit:
        return explicit
    guessed, _ = mimetypes.guess_type(f"x{ext}")
    if guessed and guessed.lower() not in GENERIC_MIME_TYPES:
        label = guessed.split("/", 1)[-1].replace("x-", "").replace("vnd.", "").replace("-", " ").title()
        kind = guessed.split("/", 1)[0] if "/" in guessed else "file"
        return guessed, label, kind
    return None


_PREFERRED_MIME_EXTENSIONS: dict[str, str] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/tiff": ".tif",
    "image/heic": ".heic",
    "image/heif": ".heif",
    "image/avif": ".avif",
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.sqlite3": ".db",
    "application/json": ".json",
    "application/xml": ".xml",
    "text/html": ".html",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/tab-separated-values": ".tsv",
    "message/rfc822": ".eml",
    "application/vnd.ms-outlook": ".msg",
    "application/vnd.ms-outlook-pst": ".pst",
    "application/vnd.ms-outlook-ost": ".ost",
    "application/zip": ".zip",
    "application/vnd.rar": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/gzip": ".gz",
    "application/x-tar": ".tar",
    "application/vnd.android.package-archive": ".apk",
    "application/java-archive": ".jar",
    "video/mp4": ".mp4",
    "video/quicktime": ".mov",
    "video/x-matroska": ".mkv",
    "video/webm": ".webm",
    "audio/mpeg": ".mp3",
    "audio/mp4": ".m4a",
    "audio/wav": ".wav",
    "audio/flac": ".flac",
    "audio/ogg": ".ogg",
    "application/x-ms-evtx": ".evtx",
    "application/x-windows-prefetch": ".pf",
    "application/x-ms-shortcut": ".lnk",
    "application/x-windows-registry": ".hive",
    "application/x-ewf": ".e01",
    "application/x-sqlite3": ".db",
    "application/zlib": ".zlib",
    "image/svg+xml": ".svg",
    "application/wasm": ".wasm",
    "font/woff": ".woff",
    "font/woff2": ".woff2",
}


def _from_mime(mime: str) -> tuple[str | None, str, str]:
    clean = (mime or "").split(";", 1)[0].strip().lower()
    preferred = _PREFERRED_MIME_EXTENSIONS.get(clean)
    if preferred:
        mapped = _from_extension(preferred)
        if mapped:
            return preferred, mapped[1], mapped[2]
    for ext, (candidate, label, kind) in _EXTENSION_TYPES.items():
        if candidate.lower() == clean:
            return ext, label, kind
    guessed = mimetypes.guess_extension(clean, strict=False) if clean else None
    if guessed:
        mapped = _from_extension(guessed)
        if mapped:
            return guessed, mapped[1], mapped[2]
    label = clean.split("/", 1)[-1].replace("x-", "").replace("vnd.", "").replace("-", " ").title() if clean else "File"
    kind = clean.split("/", 1)[0] if "/" in clean else "file"
    return None, label, kind


def _special_path_type(path: str, name: str) -> tuple[str, str | None, str, str] | None:
    low_name = name.lower()
    low_path = path.replace("\\", "/").lower()
    if low_name in _NTFS_SPECIAL:
        return _NTFS_SPECIAL[low_name]
    # $UsnJrnl:$J / $UsnJrnl:$Max and other named streams.
    for special, entry in _NTFS_SPECIAL.items():
        if low_name.startswith(special + ":") or f"/{special}:" in low_path:
            return entry
    if low_name == "$txflog.blf" or "$txflog" in low_path:
        return "application/x-windows-clfs", ".blf", "Windows Transaction Log (CLFS)", "forensic"
    if low_name in _REGISTRY_HIVE_NAMES and (
        low_name in {"ntuser.dat", "usrclass.dat"}
        or "/windows/system32/config/" in low_path
        or "/boot/" in low_path
    ):
        return "application/x-windows-registry", None, "Windows Registry hive", "forensic"
    if low_name == "hiberfil.sys":
        return "application/x-windows-hibernation", None, "Windows hibernation file", "memory"
    if low_name == "pagefile.sys":
        return "application/x-windows-pagefile", None, "Windows pagefile", "memory"
    if low_name == "swapfile.sys":
        return "application/x-windows-swapfile", None, "Windows swap file", "memory"
    if low_name in {"thumbcache_idx.db"} or low_name.startswith("thumbcache_"):
        return "application/x-windows-thumbcache", None, "Windows Thumbnail Cache", "forensic"
    if low_name.startswith("iconcache_") or low_name == "iconcache.db":
        return "application/x-windows-iconcache", None, "Windows Icon Cache", "forensic"
    if low_name == "webcachev01.dat":
        return "application/x-esent-database", None, "Windows WebCache ESE database", "database"
    if low_name.endswith(".edb"):
        return "application/x-esent-database", ".edb", "Extensible Storage Engine database", "database"
    return None


def _printable_text(data: bytes) -> str | None:
    if not data:
        return None
    sample = data[: min(len(data), 65536)]
    if b"\x00" in sample[:4096]:
        # UTF-16 text normally has a BOM or a clear alternating-NUL pattern.
        # Do not decode arbitrary binary pairs as printable Unicode.
        probe = sample[:4096]
        has_bom = probe.startswith((b"\xff\xfe", b"\xfe\xff"))
        even = probe[0::2]
        odd = probe[1::2]
        even_zero = (even.count(0) / max(len(even), 1))
        odd_zero = (odd.count(0) / max(len(odd), 1))
        if not has_bom and max(even_zero, odd_zero) < 0.25:
            return None
        enc = "utf-16" if has_bom else ("utf-16-le" if odd_zero >= even_zero else "utf-16-be")
        try:
            text = sample.decode(enc)
        except UnicodeDecodeError:
            return None
    else:
        try:
            text = sample.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not text:
        return None
    probe = text[:8000]
    printable = sum(1 for c in probe if c.isprintable() or c in "\r\n\t")
    return text if printable / max(len(probe), 1) >= 0.94 else None


def _zip_subtype(data: bytes) -> tuple[str, str, str, str] | None:
    # OOXML/ODF package paths are normally present near the start of the local
    # ZIP entries, so a bounded evidence head is enough for classification.
    probe = data[:TYPE_SNIFF_BYTES]
    low = probe.lower()
    if b"word/document.xml" in low or b"word/_rels" in low:
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx", "Microsoft Word document", "document"
    if b"xl/workbook.xml" in low or b"xl/worksheets/" in low:
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx", "Microsoft Excel workbook", "document"
    if b"ppt/presentation.xml" in low or b"ppt/slides/" in low:
        return "application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx", "Microsoft PowerPoint presentation", "document"
    if b"androidmanifest.xml" in low:
        return "application/vnd.android.package-archive", ".apk", "Android application package", "package"
    if b"meta-inf/manifest.mf" in low:
        return "application/java-archive", ".jar", "Java archive", "package"
    if b"meta-inf/container.xml" in low and b"application/epub+zip" in low:
        return "application/epub+zip", ".epub", "EPUB document", "document"
    if b"mimetypeapplication/vnd.oasis.opendocument.text" in low:
        return "application/vnd.oasis.opendocument.text", ".odt", "OpenDocument text", "document"
    if b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet" in low:
        return "application/vnd.oasis.opendocument.spreadsheet", ".ods", "OpenDocument spreadsheet", "document"
    if b"mimetypeapplication/vnd.oasis.opendocument.presentation" in low:
        return "application/vnd.oasis.opendocument.presentation", ".odp", "OpenDocument presentation", "document"
    return None


def _libmagic_sniff(data: bytes) -> tuple[str, str | None, str, str] | None:
    """Use libmagic as a second independent signature detector when available.

    Manual forensic signatures stay first because they are more specific for
    NTFS/EWF/Windows artifacts.  libmagic is especially useful for browser-cache
    objects with extensionless names such as ``f_000009``.
    """
    if not data:
        return None
    try:
        import magic  # type: ignore

        mime = str(magic.from_buffer(data[:TYPE_SNIFF_BYTES], mime=True) or "").split(";", 1)[0].strip().lower()
    except Exception:
        return None
    aliases = {
        "application/x-sqlite3": "application/vnd.sqlite3",
        "application/x-gzip": "application/gzip",
        "application/x-rar": "application/vnd.rar",
        "application/x-dosexec": "application/vnd.microsoft.portable-executable",
    }
    mime = aliases.get(mime, mime)
    if not mime or mime in GENERIC_MIME_TYPES or mime in {FORENSIC_DATA_MIME, "application/x-empty", "inode/x-empty"}:
        return None
    ext, label, kind = _from_mime(mime)
    if mime == "application/vnd.microsoft.portable-executable":
        ext, label, kind = ".exe", "Windows executable", "executable"
    elif mime == "application/zlib":
        ext, label, kind = ".zlib", "Zlib-compressed data", "archive"
    return mime, ext, label, kind


def sniff_bytes(data: bytes, *, path: str = "", extension_hint: str = "") -> tuple[str, str | None, str, str] | None:
    """Return ``(mime, extension, label, kind)`` when bytes identify a format."""
    if not data:
        return None
    b = data[:TYPE_SNIFF_BYTES]
    ext = _norm_ext(extension_hint)

    # Common media/doc signatures.
    if b.startswith(b"%PDF"):
        return "application/pdf", ".pdf", "PDF document", "document"
    if b.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg", "JPEG image", "image"
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png", "PNG image", "image"
    if b.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", ".gif", "GIF image", "image"
    if b.startswith(b"BM"):
        return "image/bmp", ".bmp", "Bitmap image", "image"
    if b.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff", ".tif", "TIFF image", "image"
    if b.startswith(b"RIFF") and len(b) >= 12:
        tag = b[8:12]
        if tag == b"WEBP":
            return "image/webp", ".webp", "WebP image", "image"
        if tag == b"WAVE":
            return "audio/wav", ".wav", "WAV audio", "audio"
        if tag == b"AVI ":
            return "video/x-msvideo", ".avi", "AVI video", "video"
    if b.startswith(b"fLaC"):
        return "audio/flac", ".flac", "FLAC audio", "audio"
    if b.startswith(b"OggS"):
        return "audio/ogg", ".ogg", "Ogg media", "audio"
    if b.startswith(b"ID3") or (len(b) >= 2 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0):
        return "audio/mpeg", ".mp3", "MP3 audio", "audio"
    if b.startswith(b"\x1aE\xdf\xa3"):
        return "video/x-matroska", ".mkv", "Matroska/WebM media", "video"
    if len(b) >= 12 and b[4:8] == b"ftyp":
        brand = b[8:12].lower()
        if brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}:
            return "image/heic", ".heic", "HEIC image", "image"
        if brand in {b"avif", b"avis"}:
            return "image/avif", ".avif", "AVIF image", "image"
        if brand in {b"qt  "}:
            return "video/quicktime", ".mov", "QuickTime video", "video"
        if brand in {b"m4a ", b"m4b ", b"f4a "}:
            return "audio/mp4", ".m4a", "M4A audio", "audio"
        return "video/mp4", ".mp4", "MP4 media", "video"

    # Structured / forensic signatures.
    if b.startswith(b"SQLite format 3\x00"):
        return "application/vnd.sqlite3", ".db", "SQLite database", "database"
    if b.startswith(b"regf"):
        return "application/x-windows-registry", ".hive", "Windows Registry hive", "forensic"
    if b.startswith(b"ElfFile\x00"):
        return "application/x-ms-evtx", ".evtx", "Windows Event Log", "forensic"
    if b.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "application/x-ms-shortcut", ".lnk", "Windows shortcut", "forensic"
    if b.startswith(b"!BDN"):
        return "application/vnd.ms-outlook-pst", ".pst", "Outlook PST/OST mailbox", "email"
    if b.startswith(b"bplist00"):
        return "application/x-apple-binary-plist", ".plist", "Apple binary property list", "structured"
    if b.startswith(b"dex\n"):
        return "application/x-android-dex", ".dex", "Android DEX bytecode", "executable"
    if b.startswith(b"\x7fELF"):
        return "application/x-elf", ".elf", "ELF executable/object", "executable"
    if b.startswith(b"MZ"):
        # Respect a declared DLL/SYS extension if present.
        out_ext = ext if ext in {".exe", ".dll", ".sys", ".scr", ".cpl"} else ".exe"
        label = {".dll": "Windows dynamic-link library", ".sys": "Windows driver"}.get(out_ext, "Windows executable")
        return "application/vnd.microsoft.portable-executable", out_ext, label, "executable"
    if b.startswith(b"\xca\xfe\xba\xbe"):
        return "application/java-vm", ".class", "Java class file", "executable"
    if b.startswith(b"EVF\x09\x0d\x0a\xff\x00") or b.startswith(b"LVF\x09\x0d\x0a\xff\x00"):
        return "application/x-ewf", ".e01", "Expert Witness Format image", "disk-image"
    if b.startswith(b"vhdxfile"):
        return "application/x-vhdx", ".vhdx", "Virtual Hard Disk v2", "disk-image"
    if b.startswith(b"QFI\xfb"):
        return "application/x-qcow2", ".qcow2", "QCOW2 virtual disk", "disk-image"
    if b.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed", ".7z", "7-Zip archive", "archive"
    if b.startswith(b"Rar!\x1a\x07"):
        return "application/vnd.rar", ".rar", "RAR archive", "archive"
    if b.startswith(b"\x1f\x8b"):
        return "application/gzip", ".gz", "Gzip archive", "archive"
    if b.startswith(b"BZh"):
        return "application/x-bzip2", ".bz2", "Bzip2 archive", "archive"
    if b.startswith(b"\xfd7zXZ\x00"):
        return "application/x-xz", ".xz", "XZ archive", "archive"
    if len(b) > 262 and b[257:262] == b"ustar":
        return "application/x-tar", ".tar", "TAR archive", "archive"
    if b.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        subtype = _zip_subtype(b)
        if subtype:
            return subtype
        # Preserve a known office/package extension when supplied.
        known = _from_extension(ext)
        if known and known[2] in {"document", "package"}:
            return known[0], ext, known[1], known[2]
        return "application/zip", ".zip", "ZIP archive", "archive"
    if b.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        low = b.lower()
        # Compound File Binary containers: use stream names when available.
        if b"__substg1.0" in low or b"__properties_version1.0" in low:
            return "application/vnd.ms-outlook", ".msg", "Outlook message", "email"
        if b"worddocument" in low:
            return "application/msword", ".doc", "Microsoft Word document", "document"
        if b"workbook" in low or b"book" in low:
            return "application/vnd.ms-excel", ".xls", "Microsoft Excel workbook", "document"
        if b"powerpoint document" in low:
            return "application/vnd.ms-powerpoint", ".ppt", "Microsoft PowerPoint presentation", "document"
        known = _from_extension(ext)
        if known and ext in {".doc", ".xls", ".ppt", ".msg", ".msi"}:
            return known[0], ext, known[1], known[2]
        return "application/x-ole-storage", ".ole", "OLE Compound File", "container"

    # RFC822/MIME messages are frequently extensionless in mail stores, browser
    # caches and carved pagefile fragments. Detect the structured header block
    # before libmagic can downgrade it to generic text/plain.
    header_probe = b[: min(len(b), 64 * 1024)]
    try:
        header_text = header_probe.decode("utf-8", errors="replace")
    except Exception:
        header_text = ""
    if header_text:
        header_hits = sum(
            1
            for key in ("From:", "To:", "Subject:", "Date:", "Message-ID:", "MIME-Version:", "Content-Type:", "Received:")
            if re.search(rf"(?im)^{re.escape(key)}\s*", header_text)
        )
        if header_hits >= 3:
            return "message/rfc822", ".eml", "Email message", "email"

    # libmagic recognises many extensionless browser-cache payloads, fonts,
    # compressed resources and uncommon media formats not practical to hard-code.
    libmagic = _libmagic_sniff(b)
    if libmagic:
        return libmagic

    # Text-like structured content.
    text = _printable_text(b)
    if text is not None:
        stripped = text.lstrip("\ufeff \r\n\t")
        low_text = stripped[:1024].lower()
        if stripped.startswith(("{", "[")):
            try:
                json.loads(stripped)
                return "application/json", ".json", "JSON data", "structured"
            except Exception:
                pass
        if low_text.startswith("<?xml") or low_text.startswith("<plist"):
            if "<plist" in low_text:
                return "application/x-apple-plist", ".plist", "Apple property list", "structured"
            return "application/xml", ".xml", "XML data", "structured"
        if low_text.startswith(("<!doctype html", "<html", "<head", "<body")):
            return "text/html", ".html", "HTML document", "document"
        if stripped.startswith("Windows Registry Editor Version"):
            return "text/x-windows-registry", ".reg", "Windows Registry export", "forensic"
        if stripped.startswith("#!"):
            return "application/x-sh", ".sh", "Shell script", "script"
        # CSV heuristic: at least two lines with the same delimiter count.
        lines = [ln for ln in stripped.splitlines()[:5] if ln.strip()]
        if len(lines) >= 2:
            for delim in (",", "\t", ";"):
                counts = [ln.count(delim) for ln in lines[:3]]
                if counts and min(counts) > 0 and max(counts) == min(counts):
                    if delim == "\t":
                        return "text/tab-separated-values", ".tsv", "Tab-separated data", "text"
                    return "text/csv", ".csv", "CSV data", "text"
        return "text/plain", ".txt", "Text file", "text"
    return None


def _normalize_filename(name: str, detected_ext: str | None, *, source: str, preserve_name: bool = False) -> str:
    safe = re.sub(r'["\r\n]+', "_", name or "artifact")[:180] or "artifact"
    if preserve_name or not detected_ext:
        return safe
    suffix = _norm_ext(PurePosixPath(safe).suffix)
    if not suffix:
        return f"{safe}{detected_ext}"
    # Only replace explicit placeholder extensions on strong content detection.
    if source == "magic" and suffix in _GENERIC_EXTENSIONS and suffix != detected_ext:
        return f"{safe[: -len(suffix)]}{detected_ext}"
    return safe


def resolve_artifact_type(row: dict[str, Any] | None, *, data: bytes | None = None) -> ResolvedArtifactType:
    row = dict(row or {})
    path, name = _filename_for_row(row)
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    ext = _norm_ext(row.get("extension") or PurePosixPath(name).suffix)

    # 1. Strong signatures are authoritative. Text heuristics are intentionally
    # weaker than a known filename/extension because short printable byte
    # sequences can occur inside otherwise structured evidence.
    magic = sniff_bytes(data or b"", path=path, extension_hint=ext) if data else None
    weak_magic = bool(
        magic
        and (
            magic[0].startswith("text/")
            or magic[0] in {"application/json", "application/xml", "application/yaml", "application/sql"}
        )
    )
    if magic and not weak_magic:
        mime, detected_ext, label, kind = magic
        normalized = _normalize_filename(name, detected_ext, source="magic")
        return ResolvedArtifactType(mime, detected_ext, label, kind, "magic", "high", name, normalized)

    # 2. Special forensic filenames are deterministic even when extensionless.
    special = _special_path_type(path, name)
    if special:
        mime, detected_ext, label, kind = special
        normalized = _normalize_filename(name, detected_ext, source="path", preserve_name=bool(PurePosixPath(name).suffix))
        return ResolvedArtifactType(mime, detected_ext or ext or None, label, kind, "path", "high", name, normalized)

    # 3. Parser/extractor metadata can be more specific than a generic extension.
    for key in (
        "resolved_content_type",
        "detected_mime_type",
        "mime_type",
        "content_type",
        "media_mime_type",
        "mimetype",
    ):
        raw = metadata.get(key)
        if raw:
            mime = str(raw).split(";", 1)[0].strip().lower()
            if mime and mime not in GENERIC_MIME_TYPES and mime != FORENSIC_DATA_MIME:
                mime_ext, mime_label, mime_kind = _from_mime(mime)
                detected_ext = _norm_ext(metadata.get("detected_extension") or ext or mime_ext) or None
                label = str(metadata.get("type_label") or metadata.get("format") or mime_label)
                kind = str(metadata.get("detected_kind") or metadata.get("file_kind") or mime_kind)
                normalized = _normalize_filename(name, detected_ext, source="metadata")
                return ResolvedArtifactType(mime, detected_ext, label, kind, "metadata", "high", name, normalized)

    # 4. Declared extension.
    ext_type = _from_extension(ext)
    if ext_type:
        mime, label, kind = ext_type
        normalized = _normalize_filename(name, ext, source="extension")
        return ResolvedArtifactType(mime, ext or None, label, kind, "extension", "medium", name, normalized)

    # 5. Weak textual detection is useful only when path/metadata/extension did
    # not already identify the format.
    if magic:
        mime, detected_ext, label, kind = magic
        normalized = _normalize_filename(name, detected_ext, source="magic")
        return ResolvedArtifactType(mime, detected_ext, label, kind, "magic", "medium", name, normalized)

    # 6. Unknown evidence remains a real forensic data object, not a browser
    # octet-stream placeholder.  We deliberately do not invent a document type.
    fallback_ext = ext or ".dat"
    normalized = _normalize_filename(name, fallback_ext if not ext else None, source="fallback")
    return ResolvedArtifactType(
        FORENSIC_DATA_MIME,
        ext or None,
        "Forensic data file (unrecognized format)",
        "forensic-data",
        "fallback",
        "low",
        name,
        normalized,
    )
