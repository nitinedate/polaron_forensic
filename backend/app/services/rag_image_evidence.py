"""Image Evidence selection + job start helpers (feeds frozen agentic pipeline)."""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.rag_processing_profiles import get_profile, list_profiles, normalize_profile

log = logging.getLogger("rag_image_evidence")

IMAGE_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".heif",
})
DOC_EXTS = frozenset({".pdf"})
ELIGIBLE_EXTS = IMAGE_EXTS | DOC_EXTS


def ensure_schema(db: Session, schema_name: str) -> None:
    """Best-effort apply image-evidence DDL for this firm schema.

    Skip ALTER TABLE when columns already exist. PostgreSQL still takes
    AccessExclusiveLock for ``ADD COLUMN IF NOT EXISTS``, which queues every
    jobs SELECT/UPDATE behind it during a live extract.
    """
    try:
        row = fetchone(
            db,
            """SELECT 1 AS ok
               FROM information_schema.columns
               WHERE table_schema = :s
                 AND table_name = 'jobs'
                 AND column_name = 'rag_selection_session_id'""",
            {"s": schema_name},
        )
        if row:
            return
        with db.begin_nested():
            db.execute(
                __import__("sqlalchemy", fromlist=["text"]).text(
                    "SELECT public.apply_firm_rag_image_evidence(:s)"
                ),
                {"s": schema_name},
            )
    except Exception as exc:
        log.warning("apply_firm_rag_image_evidence failed for %s: %s", schema_name, exc)


def is_image_evidence_job(db: Session, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT coalesce(job_kind, 'forensic') AS job_kind,
                  coalesce(rag_processing_profile, '') AS profile,
                  disk_source
           FROM jobs WHERE id=:jid""",
        {"jid": job_id},
    )
    if not row:
        return False
    if str(row.get("job_kind") or "").lower() == "image_evidence":
        return True
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if isinstance(ds, dict) and str(ds.get("job_kind") or "").lower() == "image_evidence":
        return True
    return False


def evidence_roots() -> list[Path]:
    """Deprecated — image evidence uses host_evidence.browse (any mounted drive/path)."""
    return []


def list_repository_children(
    parent: str | None = None,
    *,
    drive: str = "",
    browse_path: str = "",
    host_path: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Browse any host path the container can see (Windows drives, /Volumes, USB, SSD, etc.).

    Reuses the same host_evidence.browse stack as Disk Jobs — no RAG_EVIDENCE_ROOTS allowlist.
    """
    from app.services.host_evidence import browse as host_browse, resolve_host_path

    limit = max(1, min(int(limit or 500), 2000))

    # Prefer explicit host_path (paste any absolute path) or drive/browse_path.
    hp = (host_path or parent or "").strip() or None
    result = host_browse(
        drive=drive or "",
        browse_path=browse_path or "",
        host_path=hp,
        source_type="disk",
    )
    if result.get("error") and not result.get("entries"):
        return {
            "nodes": [],
            "error": result.get("error"),
            "mount_hint": result.get("mount_hint"),
            "display_path": result.get("display_path"),
            "drive_root": result.get("drive_root"),
            "current_path": result.get("current_path"),
            "drives": result.get("drives") or [],
        }

    nodes: list[dict[str, Any]] = []
    display = str(result.get("display_path") or "")
    drive_root = str(result.get("drive_root") or drive or "")
    current = str(result.get("current_path") or browse_path or "")

    for entry in result.get("entries") or []:
        if len(nodes) >= limit:
            break
        kind = str(entry.get("kind") or "")
        name = str(entry.get("name") or "")
        if kind == "drive":
            key = str(entry.get("drive_key") or name)
            nodes.append(
                {
                    "node_id": f"drive:{key}",
                    "parent_node_id": None,
                    "node_type": "folder",
                    "root_label": name,
                    "relative_path": "",
                    "name": name,
                    "absolute_path": None,
                    "drive": key,
                    "browse_path": "",
                    "size_bytes": None,
                    "mime_type": None,
                    "eligible": bool(entry.get("mounted", True)),
                    "mounted": bool(entry.get("mounted", True)),
                }
            )
            continue

        # Resolve absolute path for files/folders under current browse location
        abs_path = None
        child_browse = "/".join(p for p in [current.strip("/"), name] if p)
        try:
            if hp:
                base = resolve_host_path(hp)
                candidate = base / name if base.is_dir() else base.parent / name
            elif drive_root:
                candidate = resolve_host_path(None, drive=drive_root, browse_path=child_browse)
            else:
                candidate = None
            if candidate is not None and candidate.exists():
                abs_path = str(candidate)
        except Exception:
            abs_path = None

        is_dir = kind in ("dir", "folder", "directory") or bool(entry.get("is_dir"))
        # host_evidence uses kind "dir" / "file" typically
        if kind in ("dir", "folder", "directory") or (not kind and entry.get("selectable") is False):
            is_dir = True
        if kind == "file":
            is_dir = False

        if is_dir:
            nodes.append(
                {
                    "node_id": f"dir:{drive_root}:{child_browse}",
                    "parent_node_id": f"dir:{drive_root}:{current}" if current else f"drive:{drive_root}",
                    "node_type": "folder",
                    "root_label": display or drive_root or "host",
                    "relative_path": child_browse,
                    "name": name,
                    "absolute_path": abs_path,
                    "drive": drive_root,
                    "browse_path": child_browse,
                    "host_path": abs_path,
                    "size_bytes": None,
                    "mime_type": None,
                    "eligible": True,
                }
            )
            continue

        ext = Path(name).suffix.lower()
        if ext not in ELIGIBLE_EXTS:
            # Still show other files as non-selectable so investigator sees full folder contents
            nodes.append(
                {
                    "node_id": f"skip:{drive_root}:{child_browse}",
                    "parent_node_id": f"dir:{drive_root}:{current}" if current else f"drive:{drive_root}",
                    "node_type": "other",
                    "root_label": display or drive_root or "host",
                    "relative_path": child_browse,
                    "name": name,
                    "absolute_path": abs_path,
                    "drive": drive_root,
                    "browse_path": child_browse,
                    "host_path": abs_path,
                    "size_bytes": entry.get("size_bytes"),
                    "mime_type": None,
                    "eligible": False,
                }
            )
            continue

        mime, _ = mimetypes.guess_type(name)
        nodes.append(
            {
                "node_id": f"file:{drive_root}:{child_browse}",
                "parent_node_id": f"dir:{drive_root}:{current}" if current else f"drive:{drive_root}",
                "node_type": "image" if ext in IMAGE_EXTS else "document",
                "root_label": display or drive_root or "host",
                "relative_path": child_browse,
                "name": name,
                "absolute_path": abs_path,
                "drive": drive_root,
                "browse_path": child_browse,
                "host_path": abs_path,
                "size_bytes": entry.get("size_bytes"),
                "mime_type": mime,
                "eligible": True,
            }
        )

    return {
        "nodes": nodes,
        "error": result.get("error"),
        "mount_hint": result.get("mount_hint"),
        "display_path": display,
        "drive_root": drive_root,
        "current_path": current,
        "parent_path": result.get("parent_path"),
        "drives": result.get("drives") or [],
    }


def list_repository_files(
    *,
    drive: str = "",
    browse_path: str = "",
    host_path: str | None = None,
    max_files: int = 50_000,
    max_depth: int = 32,
) -> dict[str, Any]:
    """Recursively list eligible image/PDF files under a host folder (multi-folder inventory)."""
    from app.services.host_evidence import resolve_host_path

    max_files = max(1, min(int(max_files or 50_000), 50_000))
    max_depth = max(1, min(int(max_depth or 32), 64))
    hp = (host_path or "").strip() or None
    error: str | None = None
    root: Path | None = None
    drive_root = (drive or "").strip()
    current = (browse_path or "").strip().replace("\\", "/").strip("/")

    try:
        if hp:
            root = resolve_host_path(hp, strict=False)
        elif drive_root:
            root = resolve_host_path(None, drive=drive_root, browse_path=current, strict=False)
        else:
            error = "Provide host_path or drive (+ optional path)"
    except Exception as exc:
        error = str(exc)
        root = None

    if root is None or error:
        return {
            "files": [],
            "truncated": False,
            "error": error or "Path not found",
            "root_label": hp or f"{drive_root}:/{current}",
            "root_absolute_path": None,
            "drive_root": drive_root,
            "browse_path": current,
        }

    if not root.exists():
        return {
            "files": [],
            "truncated": False,
            "error": f"Path does not exist: {root}",
            "root_label": str(root),
            "root_absolute_path": str(root),
            "drive_root": drive_root,
            "browse_path": current,
        }

    if root.is_file():
        # Single file — return if eligible
        ext = root.suffix.lower()
        if ext not in ELIGIBLE_EXTS:
            return {
                "files": [],
                "truncated": False,
                "error": f"Not an eligible image/PDF: {root.name}",
                "root_label": str(root),
                "root_absolute_path": str(root),
                "drive_root": drive_root,
                "browse_path": current,
            }
        mime, _ = mimetypes.guess_type(root.name)
        try:
            size = root.stat().st_size
        except OSError:
            size = None
        node_id = f"file:{drive_root}:{current}" if drive_root else f"file:abs:{root}"
        return {
            "files": [
                {
                    "node_id": node_id,
                    "parent_node_id": None,
                    "node_type": "image" if ext in IMAGE_EXTS else "document",
                    "root_label": str(root.parent),
                    "relative_path": root.name,
                    "name": root.name,
                    "absolute_path": str(root),
                    "host_path": str(root),
                    "drive": drive_root,
                    "browse_path": current or root.name,
                    "size_bytes": size,
                    "mime_type": mime,
                    "eligible": True,
                }
            ],
            "truncated": False,
            "error": None,
            "root_label": str(root.parent),
            "root_absolute_path": str(root.parent),
            "drive_root": drive_root,
            "browse_path": current,
        }

    files: list[dict[str, Any]] = []
    truncated = False
    root_label = str(root)
    root_resolved = root.resolve()

    def _rel(p: Path) -> str:
        try:
            return p.resolve().relative_to(root_resolved).as_posix()
        except Exception:
            return p.name

    # os.walk is faster than Path.rglob on large trees
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = Path(dirpath).resolve().relative_to(root_resolved).parts if Path(dirpath).resolve() != root_resolved else ()
        if len(depth) >= max_depth:
            dirnames[:] = []
            continue
        # Skip heavy/system dirs
        dirnames[:] = [
            d
            for d in dirnames
            if d.lower() not in {"$recycle.bin", "system volume information", ".git", "node_modules", "__pycache__"}
        ]
        for name in filenames:
            if len(files) >= max_files:
                truncated = True
                break
            ext = Path(name).suffix.lower()
            if ext not in ELIGIBLE_EXTS:
                continue
            full = Path(dirpath) / name
            rel = _rel(full)
            child_browse = "/".join(p for p in [current, rel] if p) if drive_root else rel
            mime, _ = mimetypes.guess_type(name)
            try:
                size = full.stat().st_size
            except OSError:
                size = None
            abs_s = str(full)
            node_id = f"file:{drive_root}:{child_browse}" if drive_root else f"file:abs:{abs_s}"
            files.append(
                {
                    "node_id": node_id,
                    "parent_node_id": f"dir:{drive_root}:{current}" if drive_root else f"dir:abs:{root_label}",
                    "node_type": "image" if ext in IMAGE_EXTS else "document",
                    "root_label": root_label,
                    "relative_path": rel,
                    "name": name,
                    "absolute_path": abs_s,
                    "host_path": abs_s,
                    "drive": drive_root,
                    "browse_path": child_browse,
                    "size_bytes": size,
                    "mime_type": mime,
                    "eligible": True,
                }
            )
        if truncated:
            break

    return {
        "files": files,
        "truncated": truncated,
        "error": None,
        "root_label": root_label,
        "root_absolute_path": str(root_resolved),
        "drive_root": drive_root,
        "browse_path": current,
        "total": len(files),
    }


def create_session(
    db: Session,
    *,
    created_by: str | None,
    case_id: str | None,
    profile: str | None,
) -> dict[str, Any]:
    profile_id = normalize_profile(profile or get_settings().rag_default_processing_profile)
    row = fetchone(
        db,
        """INSERT INTO rag_selection_sessions (case_id, created_by, status, processing_profile)
           VALUES (:case_id, :created_by, 'open', :profile)
           RETURNING *""",
        {"case_id": case_id, "created_by": created_by, "profile": profile_id},
    )
    return dict(row or {})


def get_session(db: Session, session_id: str) -> dict[str, Any] | None:
    row = fetchone(db, "SELECT * FROM rag_selection_sessions WHERE id=:id", {"id": session_id})
    return dict(row) if row else None


def put_manifest(
    db: Session,
    session_id: str,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    session = get_session(db, session_id)
    if not session:
        raise ValueError("selection session not found")
    if session.get("status") not in ("open", "committed"):
        raise ValueError(f"session status {session.get('status')} cannot update manifest")

    execute(db, "DELETE FROM rag_selection_manifest_items WHERE session_id=:sid", {"sid": session_id})
    selected_count = 0
    selected_bytes = 0
    root_labels: set[str] = set()

    for raw in items:
        node_id = str(raw.get("node_id") or "").strip()
        if not node_id:
            continue
        node_type = str(raw.get("node_type") or "image").strip().lower()
        selected = bool(raw.get("selected"))
        size_bytes = raw.get("size_bytes")
        try:
            size_i = int(size_bytes) if size_bytes is not None else None
        except (TypeError, ValueError):
            size_i = None
        root_label = raw.get("root_label")
        if root_label:
            root_labels.add(str(root_label))
        if selected and node_type in ("image", "document", "file"):
            selected_count += 1
            if size_i:
                selected_bytes += size_i
        execute(
            db,
            """INSERT INTO rag_selection_manifest_items (
                 session_id, node_id, parent_node_id, node_type, root_label, relative_path,
                 name, selected, selection_state, size_bytes, mime_type, metadata
               ) VALUES (
                 :sid, :node_id, :parent, :node_type, :root_label, :rel,
                 :name, :selected, :sel_state, :size_bytes, :mime, CAST(:meta AS jsonb)
               )""",
            {
                "sid": session_id,
                "node_id": node_id,
                "parent": raw.get("parent_node_id"),
                "node_type": node_type,
                "root_label": root_label,
                "rel": str(raw.get("relative_path") or raw.get("name") or node_id),
                "name": str(raw.get("name") or Path(str(raw.get("relative_path") or node_id)).name),
                "selected": selected,
                "sel_state": str(raw.get("selection_state") or ("checked" if selected else "unchecked")),
                "size_bytes": size_i,
                "mime": raw.get("mime_type"),
                "meta": json.dumps(raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}),
            },
        )

    row = fetchone(
        db,
        """UPDATE rag_selection_sessions SET
             selected_count=:sc, selected_bytes=:sb,
             root_labels=CAST(:roots AS jsonb),
             processing_profile=coalesce(:profile, processing_profile),
             updated_at=NOW()
           WHERE id=:sid RETURNING *""",
        {
            "sid": session_id,
            "sc": selected_count,
            "sb": selected_bytes,
            "roots": json.dumps(sorted(root_labels)),
            "profile": None,
        },
    )
    return {
        "session": dict(row or session),
        "selected_count": selected_count,
        "selected_bytes": selected_bytes,
        "item_count": len(items),
    }


def append_uploaded_items(
    db: Session,
    session_id: str,
    staged_files: list[dict[str, Any]],
) -> dict[str, Any]:
    """Append browser-uploaded images/PDFs without wiping the existing manifest."""
    session = get_session(db, session_id)
    if not session:
        raise ValueError("selection session not found")
    if session.get("status") not in ("open", "committed"):
        raise ValueError(f"session status {session.get('status')} cannot update manifest")

    added: list[dict[str, Any]] = []
    skipped: list[str] = []
    for staged in staged_files:
        name = str(staged.get("name") or "unnamed")
        rel = str(staged.get("relative_path") or name)
        ext = Path(name).suffix.lower() or Path(rel).suffix.lower()
        if ext not in ELIGIBLE_EXTS:
            skipped.append(rel)
            continue
        digest = str(staged.get("sha256") or uuid.uuid4().hex)
        node_id = f"upload:{digest[:16]}:{rel}"
        node_type = "document" if ext == ".pdf" else "image"
        meta = {
            "source_absolute_path": staged.get("local_path"),
            "source_object_uri": staged.get("storage_uri"),
            "intake": "browser_upload",
        }
        row = fetchone(
            db,
            """INSERT INTO rag_selection_manifest_items (
                 session_id, node_id, node_type, root_label, relative_path,
                 name, selected, selection_state, size_bytes, mime_type,
                 ingest_status, sha256, source_object_uri, metadata
               ) VALUES (
                 :sid, :node_id, :node_type, :root, :rel,
                 :name, TRUE, 'checked', :size, :mime,
                 'uploaded', :sha, :uri, CAST(:meta AS jsonb)
               )
               ON CONFLICT (session_id, node_id) DO UPDATE SET
                 selected = TRUE,
                 selection_state = 'checked',
                 size_bytes = EXCLUDED.size_bytes,
                 source_object_uri = EXCLUDED.source_object_uri,
                 metadata = EXCLUDED.metadata,
                 updated_at = NOW()
               RETURNING *""",
            {
                "sid": session_id,
                "node_id": node_id,
                "node_type": node_type,
                "root": "This computer",
                "rel": rel,
                "name": name,
                "size": staged.get("size_bytes"),
                "mime": staged.get("mime_type"),
                "sha": digest,
                "uri": staged.get("storage_uri"),
                "meta": json.dumps(meta),
            },
        )
        if row:
            added.append(dict(row))

    counts = fetchone(
        db,
        """SELECT
             count(*) FILTER (
               WHERE selected AND node_type IN ('image', 'document', 'file')
             )::int AS sc,
             coalesce(sum(size_bytes) FILTER (
               WHERE selected AND node_type IN ('image', 'document', 'file')
             ), 0)::bigint AS sb
           FROM rag_selection_manifest_items
           WHERE session_id=:sid""",
        {"sid": session_id},
    ) or {}
    labels = fetchall(
        db,
        """SELECT DISTINCT root_label FROM rag_selection_manifest_items
           WHERE session_id=:sid AND root_label IS NOT NULL
           ORDER BY 1""",
        {"sid": session_id},
    )
    updated = fetchone(
        db,
        """UPDATE rag_selection_sessions SET
             selected_count=:sc, selected_bytes=:sb,
             root_labels=CAST(:roots AS jsonb),
             updated_at=NOW()
           WHERE id=:sid RETURNING *""",
        {
            "sid": session_id,
            "sc": int(counts.get("sc") or 0),
            "sb": int(counts.get("sb") or 0),
            "roots": json.dumps([str(r.get("root_label")) for r in labels if r.get("root_label")]),
        },
    )
    return {
        "session": dict(updated or session),
        "items": added,
        "skipped": skipped,
        "selected_count": int(counts.get("sc") or 0),
        "selected_bytes": int(counts.get("sb") or 0),
    }


def list_selected_items(db: Session, session_id: str) -> list[dict[str, Any]]:
    return fetchall(
        db,
        """SELECT * FROM rag_selection_manifest_items
           WHERE session_id=:sid AND selected = TRUE
             AND node_type IN ('image', 'document', 'file')
           ORDER BY root_label, relative_path""",
        {"sid": session_id},
    )


def start_processing_job(
    db: Session,
    *,
    session_id: str,
    schema_name: str,
    created_by: str | None,
    case_id: str | None = None,
    profile: str | None = None,
    source_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create image_evidence job and register selected files as job_artifacts.

    Feeds the same agentic supervisor path; artifacts are pre-materialized from
    the selection manifest so OCR/parse/RAG can run immediately.
    """
    session = get_session(db, session_id)
    if not session:
        raise ValueError("selection session not found")
    items = list_selected_items(db, session_id)
    if not items:
        raise ValueError("no selected images/documents in manifest")

    profile_id = normalize_profile(profile or session.get("processing_profile"))
    profile_cfg = get_profile(profile_id)
    case = case_id or session.get("case_id")
    path_map = source_paths or {}

    from app.services.host_evidence import resolve_host_path

    def _item_meta(item: dict[str, Any]) -> dict[str, Any]:
        raw = item.get("metadata")
        return raw if isinstance(raw, dict) else {}

    def _resolve_item_bytes(item: dict[str, Any]) -> tuple[bytes | None, str | None, str | None]:
        """Return (bytes, local_path, storage_uri) from upload or host path."""
        meta = _item_meta(item)
        uri = str(
            meta.get("source_object_uri")
            or item.get("source_object_uri")
            or ""
        ).strip()
        if uri.startswith(("s3://", "file://")):
            from app.services.storage import get_bytes

            data = get_bytes(uri)
            if data:
                local = str(meta.get("source_absolute_path") or "")
                return data, local or None, uri
        for key in (
            path_map.get(str(item.get("node_id") or "")),
            path_map.get(str(item.get("relative_path") or "")),
            meta.get("source_absolute_path"),
            item.get("source_object_uri"),
        ):
            raw = (key or "").strip()
            if not raw:
                continue
            if raw.startswith(("s3://", "file://")):
                from app.services.storage import get_bytes

                data = get_bytes(raw)
                if data:
                    return data, None, raw
            try:
                p = resolve_host_path(raw, strict=False)
                if p.is_file():
                    return p.read_bytes(), str(p), uri or None
            except Exception:
                p2 = Path(raw)
                if p2.is_file():
                    return p2.read_bytes(), str(p2), uri or None
        drive = str(meta.get("drive") or "").strip()
        browse = str(meta.get("browse_path") or item.get("relative_path") or "").strip()
        if drive and browse:
            try:
                p = resolve_host_path(None, drive=drive, browse_path=browse, strict=False)
                if p.is_file():
                    return p.read_bytes(), str(p), uri or None
            except Exception:
                pass
        return None, None, uri or None

    disk_source = {
        "job_kind": "image_evidence",
        "selection_session_id": session_id,
        "processing_profile": profile_id,
        "selected_count": len(items),
        "profile": profile_cfg,
        "intake": "selection_manifest",
    }

    job = None
    try:
        with db.begin_nested():
            job = fetchone(
                db,
                """INSERT INTO jobs(
                     type, domain_pack, case_id, created_by, status, disk_source,
                     job_kind, rag_selection_session_id, rag_processing_profile
                   ) VALUES (
                     'image_evidence', 'forensic', :case_id, :created_by, 'created',
                     CAST(:ds AS jsonb), 'image_evidence', :sid, :profile
                   ) RETURNING *""",
                {
                    "case_id": case,
                    "created_by": created_by,
                    "ds": json.dumps(disk_source),
                    "sid": session_id,
                    "profile": profile_id,
                },
            )
    except Exception as exc:
        log.warning("jobs insert with job_kind columns failed, falling back: %s", exc)
        job = None
    if not job:
        job = fetchone(
            db,
            """INSERT INTO jobs(type, domain_pack, case_id, created_by, status, disk_source)
               VALUES ('image_evidence', 'forensic', :case_id, :created_by, 'created', CAST(:ds AS jsonb))
               RETURNING *""",
            {"case_id": case, "created_by": created_by, "ds": json.dumps(disk_source)},
        )
    if not job:
        raise ValueError("failed to create job")
    job_id = str(job["id"])

    registered = 0
    for item in items:
        data, abs_path, storage_uri = _resolve_item_bytes(item)
        if not data:
            execute(
                db,
                """UPDATE rag_selection_manifest_items
                   SET ingest_status='failed', updated_at=NOW(),
                       metadata = coalesce(metadata, '{}'::jsonb) || '{"error":"source file not found"}'::jsonb
                   WHERE id=:id""",
                {"id": str(item["id"])},
            )
            continue

        display_name = str(item.get("name") or Path(abs_path or item.get("relative_path") or "image").name)
        path_obj = Path(abs_path) if abs_path else Path(display_name)
        sha = hashlib.sha256(data).hexdigest()
        size = len(data)

        ext = Path(display_name).suffix.lower() or path_obj.suffix.lower()
        mime, _ = mimetypes.guess_type(display_name)
        file_path = f"{item.get('root_label') or 'selection'}/{item.get('relative_path') or display_name}".replace("\\", "/")

        art = fetchone(
            db,
            """INSERT INTO job_artifacts (
                 job_id, file_path, file_name, extension, size_bytes, sha256,
                 mime_type, ocr_status, parse_status, metadata
               ) VALUES (
                 :jid, :path, :name, :ext, :size, :sha, :mime, 'pending', 'pending',
                 CAST(:meta AS jsonb)
               ) RETURNING id""",
            {
                "jid": job_id,
                "path": file_path,
                "name": display_name,
                "ext": ext,
                "size": size,
                "sha": sha,
                "mime": mime or item.get("mime_type"),
                "meta": json.dumps(
                    {
                        "job_kind": "image_evidence",
                        "selection_session_id": session_id,
                        "node_id": item.get("node_id"),
                        "source_absolute_path": abs_path,
                        "source_object_uri": storage_uri,
                        "retain_smallest": True,
                    }
                ),
            },
        )
        if not art:
            art = fetchone(
                db,
                "SELECT id FROM job_artifacts WHERE job_id=:jid AND file_path=:path",
                {"jid": job_id, "path": file_path},
            )
        asset = None
        try:
            with db.begin_nested():
                asset = fetchone(
                    db,
                    """INSERT INTO rag_image_assets (
                         case_id, job_id, selection_session_id, job_artifact_id,
                         root_label, relative_path, folder_path, filename, extension,
                         sha256, file_size, source_object_uri, mime_type, format,
                         ocr_status, stage_status, metadata
                       ) VALUES (
                         :case_id, :jid, :sid, :aid,
                         :root, :rel, :folder, :fname, :ext,
                         :sha, :size, :uri, :mime, :fmt,
                         'pending', 'registered', CAST(:meta AS jsonb)
                       ) RETURNING id""",
                    {
                        "case_id": case,
                        "jid": job_id,
                        "sid": session_id,
                        "aid": str(art["id"]) if art else None,
                        "root": item.get("root_label"),
                        "rel": item.get("relative_path"),
                        "folder": str(Path(str(item.get("relative_path") or ".")).parent).replace("\\", "/"),
                        "fname": display_name,
                        "ext": ext,
                        "sha": sha,
                        "size": size,
                        "uri": storage_uri or abs_path,
                        "mime": mime or item.get("mime_type"),
                        "fmt": ext.lstrip("."),
                        "meta": json.dumps({"node_id": item.get("node_id")}),
                    },
                )
        except Exception as exc:
            log.warning("rag_image_assets insert failed: %s", exc)

        execute(
            db,
            """UPDATE rag_selection_manifest_items
               SET ingest_status='registered', sha256=:sha, source_object_uri=:uri,
                   image_asset_id=:aid, updated_at=NOW()
               WHERE id=:id""",
            {
                "id": str(item["id"]),
                "sha": sha,
                "uri": storage_uri or abs_path,
                "aid": str(asset["id"]) if asset else None,
            },
        )
        registered += 1

    execute(
        db,
        """UPDATE rag_selection_sessions
           SET status='committed', job_id=:jid, committed_at=NOW(),
               processing_profile=:profile, updated_at=NOW()
           WHERE id=:sid""",
        {"sid": session_id, "jid": job_id, "profile": profile_id},
    )
    execute(db, "UPDATE jobs SET status='processing' WHERE id=:jid", {"jid": job_id})

    try:
        from app.tasks import ocr_drain_task, parse_drain_task

        # Strict GPU XOR: OCR (+ CPU parse) first; rag_append enqueued when OCR drain finishes.
        ocr_drain_task.delay(schema_name, job_id)
        parse_drain_task.delay(schema_name, job_id)
    except Exception as exc:
        log.warning("enqueue pipeline tasks failed for %s: %s", job_id, exc)

    return {
        "job_id": job_id,
        "session_id": session_id,
        "profile": profile_id,
        "registered": registered,
        "selected": len(items),
        "job": dict(job),
    }


def mark_image_evidence_searchable(
    db: Session,
    job_id: str,
    *,
    label: str = "Searchable — embedding continuing safely",
) -> None:
    """Early Q&A / FTS readiness for image-evidence without waiting for full corpus embed."""
    import json as _json

    from app.services.disk_build_log import write_disk_log

    done_row = fetchone(
        db,
        """SELECT
             (SELECT count(*)::int FROM rag_image_assets WHERE job_id=CAST(:jid AS uuid) AND ocr_status='done') AS ocr_done,
             (SELECT count(*)::int FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence') AS chunks
        """,
        {"jid": job_id},
    )
    ocr_done = int((done_row or {}).get("ocr_done") or 0)
    chunks = int((done_row or {}).get("chunks") or 0)
    if ocr_done <= 0 and chunks <= 0:
        return

    execute(
        db,
        """UPDATE rag_image_assets
           SET stage_status = CASE
                 WHEN ocr_status = 'done' AND stage_status IN ('registered', 'ocr_done') THEN 'searchable'
                 ELSE stage_status
               END,
               updated_at = NOW()
           WHERE job_id = CAST(:jid AS uuid) AND ocr_status = 'done'""",
        {"jid": job_id},
    )
    execute(
        db,
        """UPDATE jobs SET
             status = CASE
               WHEN status IN ('created', 'processing', 'indexing') THEN 'indexed'
               ELSE status
             END,
             pipeline_progress = coalesce(pipeline_progress, '{}'::jsonb) || CAST(:pp AS jsonb),
             updated_at = NOW()
           WHERE id = :jid""",
        {
            "jid": job_id,
            "pp": _json.dumps(
                {
                    "phase": "rag",
                    "label": label,
                    "searchable": True,
                    "baseline_complete": True,
                    "ocr_done": ocr_done,
                    "rag_chunks": chunks,
                    "completed": max(ocr_done, chunks),
                    "total": max(ocr_done, chunks, 1),
                }
            ),
        },
    )
    write_disk_log(db, job_id, label, stage="rag_index")


def session_artifacts(db: Session, session_id: str) -> list[dict[str, Any]]:
    return fetchall(
        db,
        """SELECT m.*, a.id AS asset_id, a.ocr_status AS asset_ocr_status,
                  a.ocr_confidence, a.stage_status, a.thumbnail_uri,
                  left(coalesce(a.ocr_text, ''), 240) AS ocr_snippet
           FROM rag_selection_manifest_items m
           LEFT JOIN rag_image_assets a ON a.id = m.image_asset_id
           WHERE m.session_id=:sid AND m.selected = TRUE
           ORDER BY m.root_label, m.relative_path""",
        {"sid": session_id},
    )


def profiles_payload() -> list[dict[str, Any]]:
    return list_profiles()
