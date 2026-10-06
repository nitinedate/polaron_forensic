"""Evidence-file media properties for examiner artifact views.

The artifact browser must report the properties of the actual evidence object,
not a web thumbnail.  Image dimensions prefer the persisted image-RAG census and
fall back to Pillow.  Audio/video metadata prefers persisted extraction metadata
and falls back to ffprobe against a temporary streamed copy.
"""

from __future__ import annotations

import json
import mimetypes
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchone
from app.services.artifact_file_forensics import classify_file_row, kind_from_ext
from app.services.artifact_preview import _artifact_filename_and_type, _load_artifact_row, iter_artifact_content


def _int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _metadata_value(meta: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = meta.get(key)
        if value not in (None, ""):
            return value
    return None


def _stream_to_temp(db: Session, job_id: str, row: dict[str, Any], suffix: str) -> str:
    max_bytes = int(os.environ.get("ARTIFACT_MEDIA_PROBE_MAX_BYTES", str(20 * 1024**3)))
    size = _int(row.get("size_bytes"))
    if size is not None and size > max_bytes:
        raise ValueError(f"media object is {size} bytes; probe ceiling is {max_bytes} bytes")
    tmp = tempfile.NamedTemporaryFile(prefix="aetheris-media-", suffix=suffix[:16], delete=False)
    written = 0
    try:
        for chunk in iter_artifact_content(db, job_id, row, max_bytes=max_bytes):
            if not chunk:
                continue
            tmp.write(chunk)
            written += len(chunk)
            if written > max_bytes:
                raise ValueError("media probe ceiling exceeded")
        tmp.flush()
        os.fsync(tmp.fileno())
        return tmp.name
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    finally:
        tmp.close()


def _image_probe(path: str) -> dict[str, Any]:
    try:
        from app.services.artifact_preview import _ensure_heif_support
        from PIL import Image

        _ensure_heif_support()
        with Image.open(path) as image:
            width, height = image.size
            return {
                "width": int(width),
                "height": int(height),
                "format": str(image.format or "") or None,
                "mode": str(image.mode or "") or None,
                "frames": int(getattr(image, "n_frames", 1) or 1),
            }
    except Exception as exc:
        return {"probe_error": str(exc)}


def _ffprobe(path: str) -> dict[str, Any]:
    executable = shutil.which("ffprobe")
    if not executable:
        return {"probe_error": "ffprobe unavailable"}
    try:
        raw = subprocess.run(
            [
                executable,
                "-v",
                "error",
                "-show_entries",
                "format=format_name,duration:stream=codec_type,codec_name,width,height,duration,sample_rate,channels",
                "-of",
                "json",
                path,
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if raw.returncode != 0:
            return {"probe_error": (raw.stderr or "ffprobe failed").strip()[:500]}
        payload = json.loads(raw.stdout or "{}")
        streams = payload.get("streams") if isinstance(payload, dict) else []
        fmt = payload.get("format") if isinstance(payload, dict) else {}
        streams = streams if isinstance(streams, list) else []
        fmt = fmt if isinstance(fmt, dict) else {}
        video = next((s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"), {})
        audio = next((s for s in streams if isinstance(s, dict) and s.get("codec_type") == "audio"), {})
        duration = _float(video.get("duration")) or _float(audio.get("duration")) or _float(fmt.get("duration"))
        return {
            "width": _int(video.get("width")),
            "height": _int(video.get("height")),
            "duration_seconds": duration,
            "video_codec": video.get("codec_name"),
            "audio_codec": audio.get("codec_name"),
            "sample_rate": _int(audio.get("sample_rate")),
            "channels": _int(audio.get("channels")),
            "format": fmt.get("format_name"),
        }
    except Exception as exc:
        return {"probe_error": str(exc)}


def get_artifact_media_properties(db: Session, job_id: str, artifact_id: str) -> dict[str, Any]:
    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise LookupError("Artifact not found")
    row = dict(row)
    meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    classified = classify_file_row({
        **row,
        "source_path": row.get("file_path"),
        "title": row.get("file_name"),
    })
    forensic = classified.get("metadata") if isinstance(classified.get("metadata"), dict) else {}
    ext = str(row.get("extension") or Path(str(row.get("file_name") or "")).suffix or "").lower()
    kind = str(forensic.get("file_kind") or kind_from_ext(ext) or "other")
    filename, content_type = _artifact_filename_and_type(row)

    width = _int(_metadata_value(meta, "width", "pixel_width", "image_width", "video_width"))
    height = _int(_metadata_value(meta, "height", "pixel_height", "image_height", "video_height"))
    duration = _float(_metadata_value(meta, "duration_seconds", "duration", "media_duration"))
    fmt = _metadata_value(meta, "format", "media_format")
    orientation = _int(_metadata_value(meta, "orientation"))
    source = "metadata" if any(v is not None for v in (width, height, duration, fmt)) else None

    # Image-RAG keeps authoritative dimensions from the actual evidence image.
    table = fetchone(db, "SELECT to_regclass('rag_image_assets')::text AS table_name", {})
    if table and table.get("table_name"):
        image = fetchone(
            db,
            """SELECT file_size, mime_type, format, width, height, orientation,
                      filesystem_mtime, exif_taken_at, gps_lat, gps_lon,
                      ocr_text, ocr_confidence, ai_description
               FROM rag_image_assets
               WHERE job_id=:jid AND job_artifact_id=:aid
               ORDER BY updated_at DESC LIMIT 1""",
            {"jid": job_id, "aid": artifact_id},
        )
    else:
        image = None
    if image:
        width = _int(image.get("width")) or width
        height = _int(image.get("height")) or height
        orientation = _int(image.get("orientation")) or orientation
        fmt = image.get("format") or fmt
        content_type = image.get("mime_type") or content_type
        source = "image_index"
    else:
        image = {}

    probe: dict[str, Any] = {}
    need_image_probe = kind == "image" and (not width or not height)
    need_av_probe = kind in {"video", "audio"} and (
        (kind == "video" and (not width or not height)) or duration is None
    )
    if need_image_probe or need_av_probe:
        temp_path = None
        try:
            temp_path = _stream_to_temp(db, job_id, row, ext or ".bin")
            probe = _image_probe(temp_path) if need_image_probe else _ffprobe(temp_path)
            width = _int(probe.get("width")) or width
            height = _int(probe.get("height")) or height
            duration = _float(probe.get("duration_seconds")) or duration
            fmt = probe.get("format") or fmt
            source = "evidence_probe"
        except Exception as exc:
            probe = {"probe_error": str(exc)}
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    if not content_type or content_type == "application/octet-stream":
        content_type = mimetypes.guess_type(filename)[0] or content_type

    return {
        "artifact_id": str(row.get("id")),
        "job_id": str(row.get("job_id")),
        "file_name": filename,
        "source_path": row.get("file_path"),
        "sha256": row.get("sha256"),
        "size_bytes": _int(row.get("size_bytes")),
        "content_type": content_type,
        "kind": kind,
        "extension": ext or None,
        "width": width,
        "height": height,
        "pixels": (width * height) if width and height else None,
        "duration_seconds": duration,
        "format": fmt,
        "orientation": orientation,
        "video_codec": probe.get("video_codec"),
        "audio_codec": probe.get("audio_codec"),
        "sample_rate": probe.get("sample_rate"),
        "channels": probe.get("channels"),
        "is_deleted": bool(forensic.get("is_deleted") or meta.get("is_deleted") or meta.get("deleted_at")),
        "deleted_at": forensic.get("deleted_at") or meta.get("deleted_at"),
        "probe_source": source,
        "probe_error": probe.get("probe_error"),
        "gps": {
            "lat": image.get("gps_lat"),
            "lon": image.get("gps_lon"),
        } if image and (image.get("gps_lat") is not None or image.get("gps_lon") is not None) else None,
        "ocr_text_available": bool(image.get("ocr_text")) if image else False,
        "ai_description_available": bool(image.get("ai_description")) if image else False,
        "downloadable": True,
        "content_url": f"/api/jobs/{job_id}/artifacts/{artifact_id}/content?download=1",
    }
