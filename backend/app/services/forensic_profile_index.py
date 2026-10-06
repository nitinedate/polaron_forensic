"""Derive forensic profile facts (Windows users, last logon, password changes) into RAG chunks."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.embedding_gpu import embed_texts

log = logging.getLogger("forensic_profile_index")


def _write_serial_fact_chunks(db, job_id, path, content, artifact_id, metadata):
    """Keep full derived facts within the same text-only forensic chunk policy."""
    from psycopg2.extras import execute_values

    from app.services.dual_rag_index import _chunk_text
    from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_POLICY, CHUNK_SIZE

    execute(db, "DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=:path AND chunk_type='evidence'",
            {"jid": job_id, "path": path})
    meta = json.dumps({**metadata, "serial_pipeline": True, "chunk_policy": CHUNK_POLICY}, default=str)
    values = [(job_id, path, index, chunk, artifact_id, meta)
              for index, chunk in enumerate(_chunk_text(content, CHUNK_SIZE, CHUNK_OVERLAP))]
    if values:
        with db.connection().connection.cursor() as cur:
            execute_values(cur, """INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,artifact_id,chunk_type,metadata)
                VALUES %s""", values, template="(%s,%s,%s,%s,%s,'evidence',%s::jsonb)", page_size=500)
    return len(values)


_USER_RE = re.compile(r"^Users/([^/]+)/", re.I)
_SKIP_PROFILES = frozenset(
    {
        "default",
        "defaultuser0",
        "public",
        "all users",
        "default user",
    }
)
_SERVICE_ACCOUNT_RE = re.compile(r"^(DWM|UMFD|Font Driver Host|Window Manager)-\d+$", re.I)
_SKIP_ACCOUNTS = frozenset(
    {
        "system",
        "local service",
        "network service",
        "anonymous logon",
        "defaultaccount",
        "wdagutilityaccount",
        "guest",
        "ksnproxy",
    }
)

from app.services.critical_forensic_paths import CRITICAL_PATH_SQL as _CRITICAL_PATH_SQL


def discover_windows_users(db, job_id: str) -> list[str]:
    rows = fetchall(
        db,
        """SELECT DISTINCT file_path FROM job_artifacts
           WHERE job_id=:jid AND file_path ILIKE 'Users/%'
           UNION
           SELECT DISTINCT file_path FROM rag_chunks
           WHERE job_id=:jid AND file_path ILIKE 'Users/%'
           LIMIT 5000""",
        {"jid": job_id},
    )
    users: set[str] = set()
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        m = _USER_RE.match(path)
        if not m:
            continue
        name = m.group(1).strip()
        if not name or name.lower() in _SKIP_PROFILES:
            continue
        users.add(name)
    return sorted(users, key=str.lower)


def _normalize_user(name: str | None) -> str | None:
    if not name or not isinstance(name, str):
        return None
    name = name.strip()
    if not name or name.lower() in _SKIP_PROFILES:
        return None
    if name.endswith("$"):
        return None
    if name.upper() in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}:
        return None
    if name.lower() in _SKIP_ACCOUNTS or _SERVICE_ACCOUNT_RE.match(name):
        return None
    return name


def _normalize_iso(value: str | None) -> str | None:
    if not value or not isinstance(value, str):
        return None
    v = value.strip().replace(" ", "T")
    v = v.replace("+00:00Z", "Z").replace("+00:00", "Z")
    if v.endswith("Z"):
        return v
    if re.search(r"[+-]\d{2}:\d{2}$", v):
        return v
    return v + "Z" if "T" in v else v


def _merge_ts(bucket: dict[str, Any], field: str, value: str | None, source: str) -> None:
    value = _normalize_iso(value)
    if not value:
        return
    prev = bucket.get(field)
    prev_at = prev.get("at") if isinstance(prev, dict) else prev
    # Prefer later timestamps for last_* fields
    if not prev_at or str(value) > str(prev_at):
        bucket[field] = {"at": value, "source": source}


def collect_account_timeline(db, job_id: str) -> dict[str, dict[str, Any]]:
    """Build per-username facts from parsed SAM / ProfileList / EVTX / NTUSER records."""
    rows = fetchall(
        db,
        f"""SELECT ja.file_path, apr.normalized
            FROM job_artifacts ja
            JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
            WHERE ja.job_id=:jid AND ({_CRITICAL_PATH_SQL})
            ORDER BY apr.created_at DESC""",
        {"jid": job_id},
    )
    by_user: dict[str, dict[str, Any]] = {}

    def bucket(username: str) -> dict[str, Any]:
        key = username
        if key not in by_user:
            by_user[key] = {"username": username}
        return by_user[key]

    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict):
                continue
            rtype = rec.get("record_type")
            user = _normalize_user(rec.get("username"))
            if rtype == "sam_user" and user:
                b = bucket(user)
                if rec.get("rid") is not None:
                    b["rid"] = rec["rid"]
                _merge_ts(b, "last_logon", rec.get("last_logon"), path)
                _merge_ts(b, "password_last_set", rec.get("password_last_set"), path)
                _merge_ts(b, "last_logoff", rec.get("last_logoff"), path)
            elif rtype == "profile_list" and user:
                b = bucket(user)
                if rec.get("sid"):
                    b["sid"] = rec["sid"]
                if rec.get("profile_image_path"):
                    b["profile_path"] = rec["profile_image_path"]
                _merge_ts(b, "profile_key_last_write", rec.get("profile_key_last_write"), path)
            elif rtype == "ntuser_hive" and user:
                b = bucket(user)
                _merge_ts(b, "ntuser_last_write", rec.get("ntuser_last_write"), path)
            elif rtype == "security_event" and user:
                b = bucket(user)
                kind = rec.get("event_kind") or ""
                when = rec.get("event_time")
                if kind == "logon_success":
                    _merge_ts(b, "last_logon", when, path)
                    # keep recent logon events sample
                    evs = b.setdefault("logon_events", [])
                    if isinstance(evs, list) and len(evs) < 5 and when:
                        evs.append({"at": when, "logon_type": rec.get("logon_type"), "source": path})
                elif kind in ("password_change", "password_reset"):
                    _merge_ts(b, "password_last_set", when, path)
                    b["password_change_event"] = kind

    # Prefer SAM last_logon; fall back to Security.evtx then NTUSER/ProfileList
    for b in by_user.values():
        if not b.get("last_logon"):
            for alt in ("ntuser_last_write", "profile_key_last_write"):
                if b.get(alt):
                    b["last_logon"] = {**b[alt], "approx": True, "note": alt}
                    break
    return by_user


def _has_account_timeline_parsed(db, job_id: str) -> bool:
    row = fetchone(
        db,
        f"""SELECT 1 AS ok FROM artifact_parse_results apr
            JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
            WHERE ja.job_id=:jid AND ({_CRITICAL_PATH_SQL})
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(
                  CASE WHEN jsonb_typeof(apr.normalized) = 'array' THEN apr.normalized ELSE '[]'::jsonb END
                ) e
                WHERE e->>'record_type' IN (
                  'sam_user', 'security_event', 'ntuser_hive', 'profile_list'
                )
                OR e ? 'password_last_set'
                OR e ? 'last_logon'
              )
            LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)


def _software_hive_materialized(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 AS ok FROM job_artifacts
           WHERE job_id=:jid AND file_path ILIKE '%/config/SOFTWARE' LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)


def _software_os_parsed(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 AS ok FROM artifact_parse_results apr
           JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
           WHERE ja.job_id=:jid
             AND ja.file_path ILIKE '%/config/SOFTWARE'
             AND EXISTS (
               SELECT 1 FROM jsonb_array_elements(
                 CASE WHEN jsonb_typeof(apr.normalized) = 'array' THEN apr.normalized ELSE '[]'::jsonb END
               ) e
               WHERE e->>'record_type' = 'windows_os'
             )
           LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)


def ensure_critical_account_artifacts(db, job_id: str) -> dict[str, Any]:
    """Rematerialize + reparse SAM/SOFTWARE/NTUSER/Security.evtx if missing from job_artifacts."""
    needs_software = not _software_hive_materialized(db, job_id) or not _software_os_parsed(db, job_id)
    if _has_account_timeline_parsed(db, job_id) and not needs_software:
        return {"materialize": {"skipped": True}, "parse": {"parsed": 0, "skipped": 0}, "skipped_reparse": True}

    from app.services.artifact_materialize import materialize_critical_forensic_paths
    from app.services.artifact_parse import parse_job_artifacts_for_paths
    from app.services.disk_manifest import build_index_map

    mat = materialize_critical_forensic_paths(db, job_id)

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except Exception:
            manifest = {}
    index_map = build_index_map(manifest or {})

    # Force re-parse of critical paths (even if previously string-scanned)
    critical = fetchall(
        db,
        f"""SELECT id, file_path FROM job_artifacts
            WHERE job_id=:jid AND ({_CRITICAL_PATH_SQL})""",
        {"jid": job_id},
    )
    paths = [r["file_path"] for r in critical]
    if paths:
        execute(
            db,
            f"""UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
                WHERE job_id=:jid AND ({_CRITICAL_PATH_SQL})""",
            {"jid": job_id},
        )
        # Drop stale parse rows so new SAM/EVTX fields replace old hive_scan stubs
        execute(
            db,
            f"""DELETE FROM artifact_parse_results
                WHERE job_artifact_id IN (
                  SELECT id FROM job_artifacts WHERE job_id=:jid AND ({_CRITICAL_PATH_SQL})
                )""",
            {"jid": job_id},
        )
        db.flush()
        pr = parse_job_artifacts_for_paths(
            db, job_id, paths=paths, index_map=index_map, update_status=False,
        )
    else:
        pr = {"parsed": 0, "skipped": 0}

    return {"materialize": mat, "parse": pr, "critical_paths": paths}


def _fmt_ts(val: Any) -> str | None:
    if isinstance(val, dict):
        at = val.get("at")
        if not at:
            return None
        note = " (approximate)" if val.get("approx") else ""
        src = val.get("source")
        src_bit = f" [{src}]" if src else ""
        return f"{at}{note}{src_bit}"
    if isinstance(val, str) and val:
        return val
    return None


def profile_chunk_has_accounts(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 AS ok FROM rag_chunks
           WHERE job_id=:jid AND file_path='__forensic__/windows_user_profiles'
             AND (
               metadata ? 'accounts'
               OR content ILIKE '%Account timeline for%'
             )
           LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)


def ensure_profile_fact_chunks(db, job_id: str, *, refresh_critical: bool = False) -> int:
    """Insert/refresh synthetic evidence chunks for OS user profiles + account timeline."""
    if not refresh_critical and profile_chunk_has_accounts(db, job_id):
        return 0
    if refresh_critical:
        try:
            ensure_critical_account_artifacts(db, job_id)
        except Exception as exc:
            log.warning("Critical account artifact refresh failed: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass

    users = discover_windows_users(db, job_id)
    timeline = collect_account_timeline(db, job_id)
    # Keep primary list = profile folders only. Timeline may include extra domain logons.
    users = sorted(set(users), key=str.lower)
    if not users:
        # Fall back to SAM/ProfileList names if profiles were not extracted
        users = sorted(
            (u for u in timeline if _normalize_user(u)),
            key=str.lower,
        )
    if not users:
        return 0

    extra_logons = sorted(
        (
            u for u in timeline
            if _normalize_user(u) and u.lower() not in {x.lower() for x in users}
        ),
        key=str.lower,
    )

    lines = [
        "Windows local user profiles discovered on this disk image.",
        f"User count: {len(users)}",
        f"Users who used this laptop / workstation: {', '.join(users)}",
    ]
    account_facts: list[dict[str, Any]] = []
    for u in users:
        lines.append(f"- User profile: Users/{u}/")
        facts = timeline.get(u) or timeline.get(next((k for k in timeline if k.lower() == u.lower()), "")) or {"username": u}
        # case-insensitive timeline lookup
        if facts.get("username") != u:
            for k, v in timeline.items():
                if k.lower() == u.lower():
                    facts = v
                    break
        account_facts.append(facts)
        ll = _fmt_ts(facts.get("last_logon"))
        pw = _fmt_ts(facts.get("password_last_set"))
        detail = []
        if ll:
            detail.append(f"last logon: {ll}")
        if pw:
            detail.append(f"password last changed: {pw}")
        if detail:
            lines.append(f"  Account timeline for {u}: " + "; ".join(detail))
        else:
            lines.append(
                f"  Account timeline for {u}: last logon and password-change times not found "
                f"in parsed SAM / Security.evtx / NTUSER evidence yet."
            )

    if extra_logons:
        lines.append(
            "Additional accounts seen in Security.evtx / SAM (no Users\\ profile folder on this image): "
            + ", ".join(extra_logons[:20])
        )
        for u in extra_logons[:20]:
            facts = timeline[u]
            ll = _fmt_ts(facts.get("last_logon"))
            pw = _fmt_ts(facts.get("password_last_set"))
            bits = [b for b in (f"last logon {ll}" if ll else None, f"password last changed {pw}" if pw else None) if b]
            if bits:
                lines.append(f"  - {u}: " + "; ".join(bits))
            account_facts.append(facts)

    lines.append(
        "These profile folders under Users\\ indicate accounts that logged onto the system. "
        "Last logon and password-change times come from SAM F values, Security.evtx "
        "(4624/4723/4724), ProfileList, and NTUSER.DAT last-write when available."
    )
    content = "\n".join(lines)
    path = "__forensic__/windows_user_profiles"
    meta = json.dumps({
        "kind": "windows_users",
        "users": users,
        "accounts": account_facts,
    }, default=str)
    from app.services.forensic_serial_policy import serial_enabled
    if serial_enabled():
        return _write_serial_fact_chunks(db, job_id, path, content, "USR-WIN-0001", json.loads(meta))
    params = {"content": content[:12000], "meta": meta}
    existing = fetchone(
        db,
        """SELECT id FROM rag_chunks
           WHERE job_id=:jid AND file_path=:path AND chunk_type='evidence' LIMIT 1""",
        {"jid": job_id, "path": path},
    )
    settings = get_settings()
    emb = None
    # Synthetic profile chunks: always embed on CPU so Q&A does not load GPU / block on E01 I/O.
    embed_device = "cpu"
    if (embed_device or "").lower() in ("cuda", "gpu", "auto"):
        try:
            vectors = embed_texts(
                [content],
                model_name=settings.rag_embedding_model,
                device=embed_device,
                batch_size=1,
            )
            if vectors and vectors[0]:
                emb = "[" + ",".join(f"{v:.8f}" for v in vectors[0]) + "]"
        except Exception as exc:
            log.warning("Profile chunk embedding skipped: %s", exc)

    if existing:
        if emb:
            execute(
                db,
                """UPDATE rag_chunks SET content=:content, metadata=CAST(:meta AS jsonb),
                   embedding_v2=CAST(:emb AS vector) WHERE id=:id""",
                {**params, "emb": emb, "id": existing["id"]},
            )
        else:
            execute(
                db,
                """UPDATE rag_chunks SET content=:content, metadata=CAST(:meta AS jsonb) WHERE id=:id""",
                {**params, "id": existing["id"]},
            )
        return 1

    if emb:
        execute(
            db,
            """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
               artifact_id, chunk_type, metadata)
               VALUES (:jid, :path, 0, :content, NULL, CAST(:emb AS vector),
               'USR-WIN-0001', 'evidence', CAST(:meta AS jsonb))""",
            {"jid": job_id, "path": path, "emb": emb, **params},
        )
    else:
        execute(
            db,
            """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
               artifact_id, chunk_type, metadata)
               VALUES (:jid, :path, 0, :content, NULL, NULL,
               'USR-WIN-0001', 'evidence', CAST(:meta AS jsonb))""",
            {"jid": job_id, "path": path, **params},
        )
    return 1


def collect_os_facts(db, job_id: str) -> dict[str, Any]:
    """Collect OS / computer identity from parsed SOFTWARE + SYSTEM hives."""
    rows = fetchall(
        db,
        """SELECT ja.file_path, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
             WHERE ja.job_id=:jid AND (
               ja.file_path ILIKE '%/config/SOFTWARE'
               OR ja.file_path ILIKE '%/config/SYSTEM'
             )
           ORDER BY apr.created_at DESC""",
        {"jid": job_id},
    )
    facts: dict[str, Any] = {}
    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict):
                continue
            rtype = rec.get("record_type")
            if rtype == "windows_os":
                for key in (
                    "product_name", "display_version", "version_number", "current_version",
                    "current_build", "ubr", "edition_id", "composition_edition_id",
                    "install_date", "install_time", "product_id", "product_key", "product_key_alt",
                    "build_lab", "build_branch", "registered_owner", "registered_organization",
                    "installation_type", "system_root", "path_name", "source",
                ):
                    val = rec.get(key)
                    if not val:
                        continue
                    prev = facts.get(key)
                    if not prev or (isinstance(prev, str) and prev.startswith("%") and not str(val).startswith("%")):
                        facts[key] = val
            elif rtype == "computer_name" and rec.get("computer_name"):
                facts["computer_name"] = rec["computer_name"]
            elif rtype == "system_root" and rec.get("system_root"):
                root = rec["system_root"]
                prev = facts.get("system_root")
                if not prev or (str(prev).startswith("%") and not str(root).startswith("%")):
                    facts["system_root"] = root
            elif rtype == "last_shutdown" and rec.get("last_shutdown"):
                facts["last_shutdown"] = rec["last_shutdown"]
            elif rtype == "system_path" and rec.get("path"):
                facts["path"] = rec["path"]
            elif rtype == "system_directory" and rec.get("system_directory"):
                facts["system_directory"] = rec["system_directory"]
            elif rtype == "system_environment":
                for key in ("os_env", "windir", "processor_architecture", "processor_identifier", "number_of_processors"):
                    if rec.get(key) and not facts.get(key):
                        facts[key] = rec[key]
    return {k: v for k, v in facts.items() if v}


def ensure_os_hive_parsed(db, job_id: str) -> dict[str, Any]:
    """Reparse SOFTWARE/SYSTEM when windows_os facts from SOFTWARE are missing."""
    if _software_os_parsed(db, job_id):
        return {"skipped": True}

    from app.services.artifact_materialize import (
        materialize_critical_forensic_paths,
        materialize_missing_critical_from_disk,
    )
    from app.services.artifact_parse import parse_job_artifacts_for_paths
    from app.services.disk_manifest import build_index_map

    materialize_critical_forensic_paths(db, job_id)
    materialize_missing_critical_from_disk(db, job_id)
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except Exception:
            manifest = {}
    index_map = build_index_map(manifest or {})
    paths = [
        r["file_path"]
        for r in fetchall(
            db,
            """SELECT file_path FROM job_artifacts
               WHERE job_id=:jid AND (
                 file_path ILIKE '%/config/SOFTWARE'
                 OR file_path ILIKE '%/config/SYSTEM'
               )""",
            {"jid": job_id},
        )
    ]
    if not paths:
        return {"parsed": 0, "paths": []}
    execute(
        db,
        """UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
           WHERE job_id=:jid AND (
             file_path ILIKE '%/config/SOFTWARE'
             OR file_path ILIKE '%/config/SYSTEM'
           )""",
        {"jid": job_id},
    )
    execute(
        db,
        """DELETE FROM artifact_parse_results
           WHERE job_artifact_id IN (
             SELECT id FROM job_artifacts WHERE job_id=:jid AND (
               file_path ILIKE '%/config/SOFTWARE'
               OR file_path ILIKE '%/config/SYSTEM'
             )
           )""",
        {"jid": job_id},
    )
    db.flush()
    pr = parse_job_artifacts_for_paths(
        db, job_id, paths=paths, index_map=index_map, update_status=False,
    )
    return {"parse": pr, "paths": paths}


def ensure_os_fact_chunks(db, job_id: str, *, refresh_hives: bool = False) -> int:
    """Insert/refresh synthetic OS evidence chunk from SOFTWARE/SYSTEM parse results."""
    if refresh_hives:
        try:
            ensure_os_hive_parsed(db, job_id)
        except Exception as exc:
            log.warning("OS hive refresh failed: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass

    facts = collect_os_facts(db, job_id)
    if not facts.get("product_name") and not facts.get("computer_name"):
        return 0

    build = facts.get("current_build")
    if build and facts.get("ubr"):
        build = f"{build}.{facts['ubr']}"

    # Labeled inventory matching common forensic OS report fields
    field_rows = [
        ("Operating System", facts.get("product_name")),
        ("Version Number", facts.get("version_number") or facts.get("display_version")),
        ("Installed/Updated Date/Time", facts.get("install_time") or facts.get("install_date")),
        ("Product Key", facts.get("product_key") or facts.get("product_key_alt")),
        ("Computer Name", facts.get("computer_name")),
        ("Operating System Version", facts.get("current_version")),
        ("Build Number", build),
        ("Product ID", facts.get("product_id")),
        ("Last Shutdown Date/Time", facts.get("last_shutdown")),
        ("System Root", facts.get("system_root") or facts.get("path_name")),
        ("Path", facts.get("path")),
        ("Display Version", facts.get("display_version")),
        ("Edition", facts.get("edition_id")),
        ("Installation Type", facts.get("installation_type")),
        ("Build Lab", facts.get("build_lab")),
        ("Registered Owner", facts.get("registered_owner")),
        ("Processor", facts.get("processor_identifier")),
        ("Architecture", facts.get("processor_architecture")),
        ("CPU Count", facts.get("number_of_processors")),
    ]
    lines = [
        "Windows operating system details recovered from registry hives on this disk image.",
        "",
    ]
    for label, value in field_rows:
        if value:
            lines.append(f"{label}: {value}")
    lines.append("")
    lines.append(
        "Source: SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion and SYSTEM "
        "(ComputerName, ShutdownTime, Environment\\Path)."
    )
    content = "\n".join(lines)
    path = "__forensic__/windows_os"
    from app.services.forensic_serial_policy import serial_enabled
    if serial_enabled():
        return _write_serial_fact_chunks(db, job_id, path, content, "SYS-WIN-OS01", {"kind": "windows_os", **facts})
    existing = fetchone(
        db,
        """SELECT id FROM rag_chunks
           WHERE job_id=:jid AND file_path=:path AND chunk_type='evidence' LIMIT 1""",
        {"jid": job_id, "path": path},
    )
    meta = json.dumps({"kind": "windows_os", **facts}, default=str)
    params = {"content": content[:8000], "meta": meta}
    if existing:
        execute(
            db,
            """UPDATE rag_chunks SET content=:content, metadata=CAST(:meta AS jsonb) WHERE id=:id""",
            {**params, "id": existing["id"]},
        )
        return 1
    execute(
        db,
        """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
           artifact_id, chunk_type, metadata)
           VALUES (:jid, :path, 0, :content, NULL, NULL,
           'SYS-WIN-OS01', 'evidence', CAST(:meta AS jsonb))""",
        {"jid": job_id, "path": path, **params},
    )
    return 1


def profile_chunk_has_os(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 AS ok FROM rag_chunks
           WHERE job_id=:jid AND (
             file_path = '__forensic__/windows_os'
             OR metadata->>'kind' = 'windows_os'
             OR content ILIKE '%ProductName:%'
           )
           LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)
