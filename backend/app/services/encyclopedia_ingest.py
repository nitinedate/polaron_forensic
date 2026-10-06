"""Load encyclopedia JSONL into public tables."""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session


def encyclopedia_jsonl_path() -> Path:
    """Resolve artifacts.jsonl across host repo, Docker /app, and DATA_ROOT mounts.

    ``Path(__file__).parents[3]`` is the repo on the host (backend/app/services)
    but the filesystem root inside Docker (/app/app/services → /). Always try
    parents[2] (/app or backend) plus explicit /app/data before giving up.
    """
    here = Path(__file__).resolve()
    candidates: list[Path] = []
    try:
        from app.config import get_settings

        candidates.append(Path(get_settings().data_root) / "encyclopedia" / "artifacts.jsonl")
    except Exception:
        pass
    for n in (2, 3, 4):
        if n < len(here.parents):
            candidates.append(here.parents[n] / "data" / "encyclopedia" / "artifacts.jsonl")
    candidates.extend(
        (
            here.parents[1] / "catalogs" / "encyclopedia" / "artifacts.jsonl",
            Path("/app/data/encyclopedia/artifacts.jsonl"),
            Path("/app/app/catalogs/encyclopedia/artifacts.jsonl"),
            Path("/data/encyclopedia/artifacts.jsonl"),
        )
    )
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return candidate
    return candidates[0] if candidates else Path("/app/data/encyclopedia/artifacts.jsonl")


def _encyclopedia_records(path: Path) -> list[dict]:
    records: list[dict] = []
    if path.is_file():
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
        return records
    from app.catalogs.encyclopedia_seed import ENCYCLOPEDIA_RECORDS

    return list(ENCYCLOPEDIA_RECORDS)


def load_encyclopedia_from_jsonl(db: Session, *, force: bool = False) -> dict:
    path = encyclopedia_jsonl_path()
    records = _encyclopedia_records(path)
    if not records:
        return {"loaded": 0, "error": f"Missing {path}"}

    if not force:
        row = db.execute(text("SELECT count(*) c FROM public.encyclopedia_artifacts")).mappings().first()
        if row and int(row["c"]) > 0:
            return {"loaded": int(row["c"]), "skipped": True, "source": str(path) if path.is_file() else "builtin"}

    artifacts = 0
    fields = 0
    source = str(path) if path.is_file() else "builtin"
    for rec in records:
        if rec.get("chunk_type") == "field_row":
            db.execute(
                text(
                    """INSERT INTO public.encyclopedia_field_rows
                       (artifact_id, supplement, field_name, where_found, source_artifact, notes, search_text)
                       VALUES (:aid, :sup, :field, :where, :src, :notes, :search)
                       ON CONFLICT (supplement, artifact_id, field_name) DO UPDATE SET
                         where_found=EXCLUDED.where_found,
                         source_artifact=EXCLUDED.source_artifact,
                         notes=EXCLUDED.notes,
                         search_text=EXCLUDED.search_text"""
                ),
                {
                    "aid": rec.get("artifact_id"),
                    "sup": rec.get("supplement"),
                    "field": rec.get("field_name"),
                    "where": rec.get("where_found"),
                    "src": rec.get("source_artifact"),
                    "notes": rec.get("notes"),
                    "search": rec.get("search_text"),
                },
            )
            fields += 1
        else:
            db.execute(
                text(
                    """INSERT INTO public.encyclopedia_artifacts
                       (artifact_id, artifact_name, volume, section, category, operating_system,
                        default_paths, file_extensions, evidence_value, search_text, raw_row)
                       VALUES (:aid, :name, :vol, :sec, :cat, :os, :paths, :ext, :ev, :search,
                               CAST(:raw AS jsonb))
                       ON CONFLICT (artifact_id) DO UPDATE SET
                         artifact_name=EXCLUDED.artifact_name,
                         search_text=EXCLUDED.search_text,
                         updated_at=NOW()"""
                ),
                {
                    "aid": rec["artifact_id"],
                    "name": rec.get("artifact_name", ""),
                    "vol": rec.get("volume"),
                    "sec": rec.get("section"),
                    "cat": rec.get("category"),
                    "os": rec.get("operating_system"),
                    "paths": rec.get("default_paths"),
                    "ext": rec.get("file_extensions"),
                    "ev": rec.get("evidence_value"),
                    "search": rec.get("search_text"),
                    "raw": json.dumps(rec.get("raw_row") or []),
                },
            )
            artifacts += 1
    db.commit()
    return {
        "loaded": artifacts,
        "loaded_artifacts": artifacts,
        "loaded_field_rows": fields,
        "source": source,
    }


def search_encyclopedia(
    db: Session,
    *,
    q: str | None = None,
    os: str | None = None,
    category: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    sql = """SELECT artifact_id, artifact_name, volume, category, operating_system,
                    default_paths, evidence_value, search_text
             FROM public.encyclopedia_artifacts WHERE 1=1"""
    params: dict = {"limit": limit, "offset": offset}
    if q:
        sql += " AND (artifact_id ILIKE :q OR search_text ILIKE :q OR artifact_name ILIKE :q)"
        params["q"] = f"%{q}%"
    if os:
        sql += " AND operating_system ILIKE :os"
        params["os"] = f"%{os}%"
    if category:
        sql += " AND category ILIKE :cat"
        params["cat"] = f"%{category}%"
    sql += " ORDER BY artifact_id LIMIT :limit OFFSET :offset"
    rows = db.execute(text(sql), params).mappings().all()
    return [dict(r) for r in rows]


def get_artifact_catalog(db: Session) -> dict:
    rows = db.execute(
        text(
            """SELECT category, count(*) c FROM public.encyclopedia_artifacts
               GROUP BY category ORDER BY category"""
        )
    ).mappings().all()
    sections = []
    for r in rows:
        cat = r["category"] or "Other"
        subs = db.execute(
            text(
                """SELECT volume as key, count(*) as cnt FROM public.encyclopedia_artifacts
                   WHERE category=:cat GROUP BY volume ORDER BY volume"""
            ),
            {"cat": cat},
        ).mappings().all()
        sections.append({
            "title": cat,
            "count": int(r["c"]),
            "subcategories": [
                {"key": s["key"] or "general", "label": s["key"] or "General", "critical": True, "count": int(s["cnt"])}
                for s in subs
            ],
        })
    return {"sections": sections}
