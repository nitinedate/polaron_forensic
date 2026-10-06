"""Media, document, download, archive and generic-file artifact parser."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext

_IMAGE = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff",
    ".dng", ".raw", ".cr2", ".nef", ".avif",
}
_VIDEO = {
    ".mp4", ".mkv", ".3gp", ".3gpp", ".mov", ".avi", ".m4v", ".webm", ".mpeg", ".mpg", ".ts",
}
_AUDIO = {
    ".mp3", ".m4a", ".aac", ".opus", ".wav", ".amr", ".ogg", ".oga", ".flac", ".3ga", ".caf",
}
_DOC = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf", ".odt",
    ".ods", ".odp", ".pages", ".numbers", ".key", ".epub", ".md", ".html", ".htm", ".xml", ".json",
}
_ARCHIVE = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
_DOC |= {".docm", ".dot", ".dotx", ".dotm", ".xlsm", ".xlsb", ".xlt", ".xltx", ".xltm", ".pptm", ".pps", ".ppsx", ".ppsm", ".pot", ".potx", ".potm", ".log", ".tsv", ".yaml", ".yml", ".ini", ".cfg", ".tex", ".mobi", ".azw", ".azw3", ".fb2", ".wps", ".wpd", ".one", ".eml", ".emlx", ".msg", ".mbox", ".vcard", ".vcf"}


def file_extension(item):
    ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
    return ext if ext.startswith(".") or not ext else "." + ext


def file_kind(item):
    ext = file_extension(item)
    mime = str(item.mime_hint or (item.meta or {}).get("detected_mime") or "").lower()
    if ext in _IMAGE or mime.startswith("image/"):
        return "image"
    if ext in _VIDEO or mime.startswith("video/"):
        return "video"
    if ext in _AUDIO or mime.startswith("audio/"):
        return "audio"
    if ext in _ARCHIVE:
        return "archive"
    if ext in _DOC or mime.startswith("text/") or any(x in mime for x in ("pdf", "document", "word", "excel", "spreadsheet", "presentation", "opendocument", "epub", "rtf")):
        return "document"
    return None


def _path_markers(path: str) -> dict[str, object]:
    p = path.lower().replace("\\", "/")
    app = None
    if "whatsapp" in p or "com.whatsapp" in p or "net.whatsapp" in p:
        app = "whatsapp_business" if "w4b" in p or "whatsapp business" in p or "smb" in p else "whatsapp"
    elif "telegram" in p or "org.telegram" in p:
        app = "telegram"
    elif "signal" in p or "org.thoughtcrime.securesms" in p:
        app = "signal"
    elif "instagram" in p or "com.instagram" in p:
        app = "instagram"
    elif "facebook" in p or "com.facebook" in p:
        app = "facebook_messenger"

    source_bucket = "filesystem"
    if any(x in p for x in ("/download/", "/downloads/", "sdcard_download")):
        source_bucket = "download"
    elif any(x in p for x in ("/dcim/", "/camera/", "camera roll", "/photos/")):
        source_bucket = "camera"
    elif any(x in p for x in ("voice notes", "voicenotes", "ptt-", "/recordings/", "sound_recorder")):
        source_bucket = "voice_note"
    elif app:
        source_bucket = "application_media"

    deleted_marker = any(
        x in p
        for x in (
            ".trashed-", "/.trash", "/trash/", "deleted_recovery", "$recycle.bin", "/recently deleted/",
            "/.thumbnails/deleted/",
        )
    )
    cache_marker = any(x in p for x in ("/cache/", "/caches/", "/thumbnails/", "/.thumbnails/"))
    return {
        "application": app,
        "source_bucket": source_bucket,
        "deleted_marker": deleted_marker,
        "cache_marker": cache_marker,
    }


class FilesMediaParser(ArtifactParser):
    name = "files_media_parser"
    version = "2.0.0"
    domains = ("media", "files")

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        return file_kind(item) is not None

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        ext = file_extension(item)
        kind = file_kind(item)
        markers = _path_markers(item.path)
        if kind == "image":
            atype, domain, media_kind = "photo", "media", "image"
        elif kind == "video":
            atype, domain, media_kind = "video", "media", "video"
        elif kind == "audio":
            atype, domain, media_kind = "audio", "media", "audio"
        elif kind == "archive":
            atype, domain, media_kind = "archive", "files", None
        else:
            atype, domain, media_kind = "document", "files", None

        state = "allocated"
        recovery_source = "live_file"
        if bool(markers["deleted_marker"]) or (item.meta or {}).get("is_deleted") is True:
            state = "filesystem_recovered"
            recovery_source = "trash_or_deleted_path"
        elif bool(markers["cache_marker"]):
            state = "cache_derived"
            recovery_source = "application_cache"

        application = markers["application"]
        source_bucket = str(markers["source_bucket"])
        data = {
            "path": item.path,
            "name": PurePosixPath(item.path).name,
            "mime": item.mime_hint,
            "size": item.size,
            "sha256": item.sha256,
            "extension": ext,
            "media_kind": media_kind,
            "application": application,
            "source_bucket": source_bucket,
            "is_download": source_bucket == "download",
            "is_messaging_media": bool(application),
            "artifact_family": {"image": "pictures", "video": "videos", "audio": "audio", "document": "documents"}.get(kind, "archives"),
            "deleted_at": (item.meta or {}).get("deleted_at"),
        }
        if application == "whatsapp" or application == "whatsapp_business":
            data["artifact_family"] = "whatsapp_media"
            low = item.path.lower()
            if "whatsapp images" in low:
                data["whatsapp_media_type"] = "image"
            elif "whatsapp video" in low:
                data["whatsapp_media_type"] = "video"
            elif "whatsapp audio" in low:
                data["whatsapp_media_type"] = "audio"
            elif "voice notes" in low:
                data["whatsapp_media_type"] = "voice_note"
            elif "whatsapp documents" in low:
                data["whatsapp_media_type"] = "document"
            elif "stickers" in low:
                data["whatsapp_media_type"] = "sticker"
            elif ".statuses" in low:
                data["whatsapp_media_type"] = "status"

        record = NormalizedArtifact.create(
            artifact_type=atype,
            source_domain=domain,
            data=data,
            state=state,  # type: ignore[arg-type]
            recovery_source=recovery_source,
            source_path=item.path,
            source_sha256=item.sha256,
            parser=self.name,
            parser_version=self.version,
            job_id=context.job_id,
            source_id=context.source_id,
        )
        from app.services.mobile_forensic.models import attach_decryption_provenance
        yield attach_decryption_provenance(record, item)
