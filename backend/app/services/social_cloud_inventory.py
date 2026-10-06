"""Strict Social Networking and Cloud Storage evidence inventory.

The AXIOM catalogue contains many provider-specific artifacts.  Generic path-token
matching is unsafe for these categories: e.g. ``Google+ Chat`` used to match every
Chrome cache path containing ``Google``.  This module only accepts explicit provider
hosts, sync-root paths, or provider application stores.

Counts are evidence occurrences, not guesses.  If no deterministic provider signal is
present the artifact remains visible with count 0.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from typing import Any
from urllib.parse import urlparse

from app.db.sql_helpers import fetchall

_CACHE_LOCK = threading.Lock()
_PROVIDER_FILE_CACHE: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = {}
_CACHE_TTL = 900.0


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _host_matches(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


_SOCIAL: dict[str, dict[str, Any]] = {
    "facebook": {
        "terms": ("facebook", "messenger"),
        "domains": ("facebook.com", "messenger.com"),
        "paths": ("/com.facebook.orca/", "/com.facebook.katana/", "/facebook/", "/messenger/"),
    },
    "instagram": {
        "terms": ("instagram",),
        "domains": ("instagram.com",),
        "paths": ("/com.instagram.android/", "/instagram/"),
    },
    "twitter": {
        "terms": ("twitter", "x.com"),
        "domains": ("twitter.com", "x.com"),
        "paths": ("/com.twitter.android/", "/twitter/"),
    },
    "linkedin": {
        "terms": ("linkedin",),
        "domains": ("linkedin.com",),
        "paths": ("/com.linkedin.android/", "/linkedin/"),
    },
    "google_plus": {
        "terms": ("google+", "google plus"),
        "domains": ("plus.google.com", "hangouts.google.com", "chat.google.com"),
        "paths": ("/com.google.android.talk/", "/hangouts/", "/google/chat/"),
    },
    "myspace": {
        "terms": ("myspace",),
        "domains": ("myspace.com",),
        "paths": ("/myspace/",),
    },
    "bebo": {
        "terms": ("bebo",),
        "domains": ("bebo.com",),
        "paths": ("/bebo/",),
    },
    "weibo": {
        "terms": ("weibo", "sina"),
        "domains": ("weibo.com", "weibo.cn", "sina.com.cn"),
        "paths": ("/com.sina.weibo/", "/weibo/"),
    },
    "vk": {
        "terms": ("vk ", "vk.com", "vkontakte"),
        "domains": ("vk.com",),
        "paths": ("/com.vkontakte.android/", "/vkontakte/", "/vk/"),
    },
}

_CLOUD: dict[str, dict[str, Any]] = {
    "onedrive": {
        "terms": ("onedrive", "one drive", "skydrive", "microsoft unified audit"),
        "domains": ("onedrive.live.com", "1drv.ms", "sharepoint.com", "office.com"),
        "paths": ("/onedrive/", "/onedrive - ", "/microsoft/onedrive/", "/skydrive/"),
    },
    "google_drive": {
        "terms": ("google drive", "google workspace", "gdrive"),
        "domains": ("drive.google.com", "docs.google.com", "workspace.google.com"),
        "paths": ("/google drive/", "/my drive/", "/drivefs/", "/google/drive/"),
    },
    "dropbox": {
        "terms": ("dropbox",),
        "domains": ("dropbox.com", "dropboxapi.com"),
        "paths": ("/dropbox/", "/dropbox - ", "/com.dropbox.android/"),
    },
    "box": {
        "terms": ("box.com", "box enterprise", "cloud box", "box files", "box user"),
        "domains": ("box.com", "box.net"),
        "paths": ("/box drive/", "/box sync/", "/box/"),
    },
    "icloud": {
        "terms": ("icloud", "cloudkit"),
        "domains": ("icloud.com", "icloud-content.com"),
        "paths": ("/icloud drive/", "/icloud photos/", "/mobile documents/", "/clouddocs/"),
    },
    "mega": {
        "terms": ("mega files", "mega cloud", "megasync"),
        "domains": ("mega.nz", "mega.io"),
        "paths": ("/megasync/", "/mega/"),
    },
    "amazon": {
        "terms": ("amazon cloud", "amazon s3", "cloudtrail", "aws ", "s3 "),
        "domains": ("amazonaws.com", "aws.amazon.com"),
        "paths": ("/amazon drive/", "/aws/", "/s3/"),
    },
    "azure": {
        "terms": ("azure",),
        "domains": ("azure.com", "windows.net", "blob.core.windows.net"),
        "paths": ("/azure/",),
    },
    "samsung": {
        "terms": ("samsung cloud",),
        "domains": ("samsungcloud.com", "samsung.com"),
        "paths": ("/samsung cloud/",),
    },
    "carbonite": {
        "terms": ("carbonite",),
        "domains": ("carbonite.com",),
        "paths": ("/carbonite/",),
    },
    "flickr": {
        "terms": ("flickr",),
        "domains": ("flickr.com", "staticflickr.com"),
        "paths": ("/flickr/",),
    },
    "android_backup": {
        "terms": ("cloud android backups", "android backups"),
        "domains": ("googleapis.com", "googleusercontent.com"),
        "paths": ("/android/backup/", "/android backups/", "/backup/"),
    },
}


def _provider_for(name: str, specs: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    n = _norm(name)
    for key, spec in specs.items():
        if any(term in n for term in spec["terms"]):
            return key, spec
    return None


def _url_records(db, job_id: str, domains: tuple[str, ...], *, artifact_name: str = "") -> list[dict[str, Any]]:
    from app.services.browser_url_inventory import collect_job_browser_url_records

    name = _norm(artifact_name)
    out: list[dict[str, Any]] = []
    for rec in collect_job_browser_url_records(db, job_id):
        url = str(rec.get("url") or "")
        host = _host(url)
        if not host or not _host_matches(host, domains):
            continue
        origin = str(rec.get("record_origin") or "")
        # Never turn random message/cache strings into browser activity counts.
        if origin not in {"browser_history", "browser_history_recovered", "internet_shortcut", "recovered_url"}:
            continue
        low_url = url.lower()
        # Message/chat-specific catalogue rows need a message-oriented URL signal.
        if any(t in name for t in (" chat", "messages", "web messages", "inbox", "email")):
            if "google+" in name or "google plus" in name:
                if host not in {"chat.google.com", "hangouts.google.com"} and not any(x in low_url for x in ("/chat", "/hangout", "/messages")):
                    continue
            elif "facebook" in name:
                if host != "messenger.com" and not any(x in low_url for x in ("/messages", "/messenger", "/inbox")):
                    continue
            elif not any(x in low_url for x in ("/messages", "/message", "/messaging", "/chat", "/inbox", "/dm/", "/direct/", "/im")):
                continue
        if any(t in name for t in ("status", "wall post", "posts", "microblogs")):
            if not any(x in low_url for x in ("/status", "/posts", "/post/", "/wall", "/p/")):
                continue
        out.append(rec)
    return out


def _provider_files(db, job_id: str, provider: str, paths: tuple[str, ...], *, social: bool) -> list[dict[str, Any]]:
    cache_key = (str(job_id), f"{'social' if social else 'cloud'}:{provider}")
    now = time.monotonic()
    with _CACHE_LOCK:
        hit = _PROVIDER_FILE_CACHE.get(cache_key)
        if hit and now - hit[0] < _CACHE_TTL:
            return list(hit[1])

    clauses: list[str] = []
    params: dict[str, Any] = {"j": job_id}
    for idx, marker in enumerate(paths):
        key = f"p{idx}"
        clauses.append(f"lower(replace(file_path, '\\\\', '/')) LIKE :{key}")
        params[key] = f"%{marker.lower()}%"
    if not clauses:
        return []

    extra = ""
    if social:
        # Social-network rows must be app stores/messages, never Chrome/Edge cache blobs.
        extra = """
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/cache/%'
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/code cache/%'
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/gpucache/%'
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/browser cache/%'
          AND (
            lower(coalesce(extension,'')) IN ('.db','.sqlite','.sqlite3','.json','.xml','.eml','.msg')
            OR lower(file_name) LIKE '%message%'
            OR lower(file_name) LIKE '%thread%'
            OR lower(file_name) LIKE '%chat%'
          )
        """
    else:
        extra = """
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/program files/%'
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/windows/winsxs/%'
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/cache/cache_data/%'
          AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/code cache/%'
        """

    rows = fetchall(
        db,
        f"""SELECT id, file_path, file_name, extension, size_bytes, minio_uri, metadata, created_at
             FROM job_artifacts
             WHERE job_id=:j AND ({' OR '.join(clauses)})
             {extra}
             ORDER BY file_path
             LIMIT 20000""",
        params,
    )
    result = [dict(r) for r in rows]
    with _CACHE_LOCK:
        _PROVIDER_FILE_CACHE[cache_key] = (now, result)
    return result


def _virtual_url_row(job_id: str, *, provider: str, label: str, rec: dict[str, Any], kind: str) -> dict[str, Any]:
    url = str(rec.get("url") or "")
    source = str(rec.get("source") or "")
    key = hashlib.sha1(f"{kind}|{provider}|{source}|{url}".encode("utf-8", errors="ignore")).hexdigest()[:20]
    title = str(rec.get("title") or url or label)
    visits = max(int(rec.get("visit_count") or 0), 1)
    return {
        "id": f"ev-{kind}-{key}",
        "job_id": job_id,
        "file_id": None,
        "parent_artifact_id": None,
        "artifact_type": kind,
        "axiom_category": kind,
        "axiom_category_label": label,
        "axiom_sub_category": provider,
        "title": title[:240],
        "source_path": source or url,
        "artifact_datetime": rec.get("last_visit"),
        "preview_uri": None,
        "storage_uri": None,
        "metadata": {
            "evidence_kind": kind,
            "provider": provider,
            "url": url,
            "browser": rec.get("browser"),
            "visit_count": visits,
            "record_origin": rec.get("record_origin"),
            "preview_body": (
                f"{label}\n\nURL: {url}\nVisits: {visits}\n"
                f"Browser: {rec.get('browser') or 'Browser'}\n"
                f"Last visit: {rec.get('last_visit') or '—'}\n"
                f"Source: {source or '—'}"
            ),
        },
        "tags": [kind, provider],
        "created_at": "",
    }


def _actual_file_row(job_id: str, *, provider: str, label: str, row: dict[str, Any], kind: str) -> dict[str, Any]:
    meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    return {
        "id": str(row.get("id") or ""),
        "job_id": job_id,
        "file_id": None,
        "parent_artifact_id": None,
        "artifact_type": str(row.get("extension") or kind).lstrip(".") or kind,
        "axiom_category": kind,
        "axiom_category_label": label,
        "axiom_sub_category": provider,
        "title": str(row.get("file_name") or str(row.get("file_path") or "").rsplit("/", 1)[-1] or label),
        "source_path": row.get("file_path"),
        "artifact_datetime": None,
        "preview_uri": None,
        "storage_uri": row.get("minio_uri"),
        "size_bytes": row.get("size_bytes"),
        "file_name": row.get("file_name"),
        "metadata": {**meta, "provider": provider, "catalog_label": label},
        "tags": [kind, provider],
        "created_at": row.get("created_at").isoformat() if hasattr(row.get("created_at"), "isoformat") else str(row.get("created_at") or ""),
    }


def social_artifact_evidence(db, job_id: str, artifact_name: str) -> dict[str, Any]:
    match = _provider_for(artifact_name, _SOCIAL)
    if not match:
        return {"count": 0, "rows": [], "provider": None, "count_domain": "social_activity"}
    provider, spec = match
    urls = _url_records(db, job_id, tuple(spec["domains"]), artifact_name=artifact_name)
    files = _provider_files(db, job_id, provider, tuple(spec["paths"]), social=True)

    url_rows = [_virtual_url_row(job_id, provider=provider, label=artifact_name, rec=r, kind="social_activity") for r in urls]
    file_rows = [_actual_file_row(job_id, provider=provider, label=artifact_name, row=r, kind="social_store") for r in files]
    # History visit occurrences are the only universal record-level signal.  App
    # database containers are browseable corroboration and are not added as messages.
    count = sum(max(int(r.get("visit_count") or 0), 1) for r in urls)
    return {
        "count": count,
        "rows": url_rows + file_rows,
        "provider": provider,
        "url_occurrences": count,
        "store_files": len(files),
        "count_domain": "web_activity_occurrence",
    }


def cloud_artifact_evidence(db, job_id: str, artifact_name: str) -> dict[str, Any]:
    match = _provider_for(artifact_name, _CLOUD)
    if not match:
        return {"count": 0, "rows": [], "provider": None, "count_domain": "cloud_occurrence"}
    provider, spec = match
    urls = _url_records(db, job_id, tuple(spec["domains"]), artifact_name=artifact_name)
    files = _provider_files(db, job_id, provider, tuple(spec["paths"]), social=False)
    name = _norm(artifact_name)

    if "media" in name:
        media_exts = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".m4a", ".flac"}
        selected_files = [r for r in files if (str(r.get("extension") or "").lower() in media_exts)]
    elif any(k in name for k in ("account", "root")):
        selected_files = files[:1]
    elif any(k in name for k in ("activity", "events", "audit", "version history")):
        selected_files = []
    else:
        selected_files = files

    file_rows = [_actual_file_row(job_id, provider=provider, label=artifact_name, row=r, kind="cloud_file") for r in selected_files]
    url_rows = [_virtual_url_row(job_id, provider=provider, label=artifact_name, rec=r, kind="cloud_activity") for r in urls]

    if any(k in name for k in ("activity", "events", "audit", "version history")):
        count = sum(max(int(r.get("visit_count") or 0), 1) for r in urls)
        domain = "cloud_activity_occurrence"
    elif any(k in name for k in ("account", "root")):
        count = 1 if (files or urls) else 0
        domain = "cloud_account_occurrence"
    else:
        count = len(selected_files)
        # If this is web-only cloud evidence, keep a deterministic non-zero signal.
        if count == 0 and urls:
            count = sum(max(int(r.get("visit_count") or 0), 1) for r in urls)
            domain = "cloud_web_occurrence"
        else:
            domain = "file_occurrence"
    return {
        "count": count,
        "rows": file_rows + url_rows,
        "provider": provider,
        "file_occurrences": len(selected_files),
        "url_occurrences": sum(max(int(r.get("visit_count") or 0), 1) for r in urls),
        "count_domain": domain,
    }


def count_social_artifact(db, job_id: str, artifact_name: str) -> int:
    return int(social_artifact_evidence(db, job_id, artifact_name).get("count") or 0)


def count_cloud_artifact(db, job_id: str, artifact_name: str) -> int:
    return int(cloud_artifact_evidence(db, job_id, artifact_name).get("count") or 0)


def list_social_evidence(db, job_id: str, artifact_name: str) -> list[dict[str, Any]]:
    return list(social_artifact_evidence(db, job_id, artifact_name).get("rows") or [])


def list_cloud_evidence(db, job_id: str, artifact_name: str) -> list[dict[str, Any]]:
    return list(cloud_artifact_evidence(db, job_id, artifact_name).get("rows") or [])
