"""Complete acquired browser records; saved URLs and visits remain distinct."""

from __future__ import annotations

import json
import plistlib
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import (
    column_name_map,
    open_sqlite_bytes,
    table_names,
)
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext
from app.services.mobile_forensic.storage import _json_safe

BROWSER_NAMES = {
    "history",
    "history.db",
    "history.sqlite",
    "history.plist",
    "browser.db",
    "browser2.db",
    "browserstate.db",
    "bookmarks",
    "bookmarks.db",
    "bookmarks.plist",
    "places.sqlite",
    "cookies",
    "cookies.sqlite",
    "login data",
    "web data",
    "favicons",
    "top sites",
    "searchhistory.db",
    "downloads.db",
}
TABLE_TYPES = {
    "urls": ("browser_url", "browser_history"),
    "visits": ("browser_visit", "browser_history"),
    "history": ("browser_visit", "browser_history"),
    "history_items": ("browser_url", "browser_history"),
    "history_visits": ("browser_visit", "browser_history"),
    "moz_places": ("browser_url", "browser_history"),
    "moz_historyvisits": ("browser_visit", "browser_history"),
    "bookmarks": ("browser_bookmark", "browser_bookmarks"),
    "moz_bookmarks": ("browser_bookmark", "browser_bookmarks"),
    "downloads": ("browser_download", "browser_downloads"),
    "downloads_url_chains": ("browser_download_url", "browser_downloads"),
    "moz_annos": ("browser_annotation", "browser_downloads"),
    "cookies": ("browser_cookie", "browser_cookies"),
    "moz_cookies": ("browser_cookie", "browser_cookies"),
    "logins": ("browser_login", "browser_logins"),
    "autofill": ("browser_autofill", "browser_autofill"),
    "keyword_search_terms": ("browser_search", "browser_searches"),
    "searches": ("browser_search", "browser_searches"),
    "searchhistory": ("browser_search", "browser_searches"),
    "tabs": ("browser_tab", "browser_sessions"),
    "thumbnails": ("browser_thumbnail", "browser_cache"),
    "top_sites": ("browser_site", "browser_history"),
    "icon_mapping": ("browser_icon", "browser_cache"),
}


def _q(name):
    return '"' + name.replace('"', '""') + '"'


def _rows(conn, sql):
    """Stream full tables; unreadable pages remain an explicit parse exception."""
    cursor = conn.execute(sql)
    while batch := cursor.fetchmany(1000):
        for row in batch:
            yield dict(row)


def _timestamp(value, *, chromium=False, safari=False):
    try:
        n = float(value)
        if chromium and n > 10_000_000_000_000:
            n = n / 1_000_000 - 11644473600
        elif safari:
            n += 978307200
        elif n > 100_000_000_000_000:  # Firefox microseconds since Unix epoch.
            n /= 1_000_000
        elif n > 100_000_000_000:  # Android milliseconds since Unix epoch.
            n /= 1000
        return datetime.fromtimestamp(n, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _bookmark_rows(value, location="root"):
    if isinstance(value, dict):
        url = value.get("url") or value.get("URLString")
        if url:
            yield (
                location,
                {
                    "url": url,
                    "title": value.get("name")
                    or value.get("title")
                    or (value.get("URIDictionary") or {}).get("title"),
                    "raw": _json_safe(value),
                },
            )
        for key, child in value.items():
            if isinstance(child, (dict, list)) and key != "URIDictionary":
                yield from _bookmark_rows(child, f"{location}/{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _bookmark_rows(child, f"{location}/{i}")


class BrowserHistoryParser(ArtifactParser):
    name = "browser_parser"
    version = "3.0.0"
    domains = ("browser",)

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name
        if name.endswith(("-wal", "-journal", "-shm")):
            return False
        return name in BROWSER_NAMES or (
            any(x in p for x in ("safari", "sbrowser", "browser", "chrome", "firefox"))
            and name.endswith((".db", ".sqlite", ".sqlite3"))
        )

    def parse(
        self, item: InventoryItem, context: ParseContext
    ) -> Iterator[NormalizedArtifact]:
        blob = context.read_artifact_bytes(item.path)
        if not blob:
            raise ValueError("Acquired browser source could not be read")
        name = PurePosixPath(item.path).name.lower()

        def record(kind, family, data, table, rid, timestamp=None):
            url = str(data.get("url") or "")
            if url.startswith(("http://", "https://")):
                from urllib.parse import urlsplit

                try:
                    host = (urlsplit(url).hostname or "").lower()
                except ValueError:
                    host = ""
                if (
                    host == "whatsapp.com"
                    or host.endswith(".whatsapp.com")
                    or host == "wa.me"
                ):
                    data.update(application="whatsapp_web", whatsapp_link=True)
            return NormalizedArtifact.create(
                # Retain v2 identities when changing URL-summary labels, so an
                # upgraded acquisition updates records rather than duplicating them.
                artifact_id=NormalizedArtifact.make_stable_id(
                    job_id=context.job_id,
                    artifact_type="browser_visit" if table.lower() == "urls" else kind,
                    source_path=item.path,
                    source_table=table,
                    source_row_id=str(rid),
                    data={} if table.lower() == "history" else data,
                ),
                artifact_type=kind,
                source_domain="browser",
                data={"artifact_family": family, **data},
                timestamp_utc=timestamp,
                state="database_deleted"
                if data.get("raw", {}).get("is_deleted") in (1, True, "1")
                else "allocated",
                source_path=item.path,
                source_table=table,
                source_row_id=str(rid),
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                job_id=context.job_id,
                source_id=context.source_id,
            )

        if name in {"bookmarks", "bookmarks.plist", "history.plist"}:
            payload = (
                plistlib.loads(blob) if name.endswith(".plist") else json.loads(blob)
            )
            family = (
                "browser_history" if name == "history.plist" else "browser_bookmarks"
            )
            for rid, data in _bookmark_rows(payload):
                yield record(
                    "browser_url"
                    if family == "browser_history"
                    else "browser_bookmark",
                    family,
                    data,
                    "document",
                    rid,
                )
            return
        with open_sqlite_bytes(blob) as conn:
            if not conn:
                raise ValueError("Browser source is not a readable SQLite database")
            names = {n.lower(): n for n in table_names(conn)}
            url_maps = {}
            for key in ("urls", "moz_places", "history_items"):
                if key in names:
                    url_maps[key] = {
                        str(r.get("id") or r.get("_id") or ""): r
                        for r in _rows(conn, f"SELECT * FROM {_q(names[key])}")
                    }
            for key, (kind, family) in TABLE_TYPES.items():
                table = names.get(key)
                if not table:
                    continue
                cols = column_name_map(conn, table)
                definition = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE name=?", (table,)
                ).fetchone()[0]
                without_rowid = "WITHOUT ROWID" in (definition or "").upper()
                primary_keys = [
                    r[1]
                    for r in conn.execute(f"PRAGMA table_info({_q(table)})")
                    if r[5]
                ]
                select = "*" if without_rowid else "rowid AS __row_id, *"
                for r in _rows(conn, f"SELECT {select} FROM {_q(table)}"):
                    row_id = (
                        r.get("__row_id")
                        if not without_rowid
                        else json.dumps([r.get(k) for k in primary_keys], default=str)
                    )
                    data = {
                        "raw": _json_safe(
                            {k: v for k, v in r.items() if k != "__row_id"}
                        )
                    }
                    linked = {}
                    if key in {"visits", "keyword_search_terms"}:
                        linked = url_maps.get("urls", {}).get(
                            str(r.get("url_id") or r.get("url") or ""), {}
                        )
                    elif key in {"moz_historyvisits", "moz_bookmarks", "moz_annos"}:
                        linked = url_maps.get("moz_places", {}).get(
                            str(r.get("place_id") or r.get("fk") or ""), {}
                        )
                    elif key == "history_visits":
                        linked = url_maps.get("history_items", {}).get(
                            str(r.get("history_item") or ""), {}
                        )
                    data.update(
                        url=linked.get("url")
                        or r.get("url")
                        or r.get("origin_url")
                        or r.get("tab_url")
                        or r.get("source_url"),
                        title=r.get("title") or linked.get("title"),
                        visit_count=r.get("visit_count"),
                        target_path=r.get("target_path")
                        or r.get("current_path")
                        or r.get("_data"),
                        host=r.get("host_key") or r.get("host"),
                        username=r.get("username_value") or r.get("username"),
                        search_term=r.get("term") or r.get("search"),
                    )
                    if key == "logins":
                        data["encrypted_password_present"] = bool(
                            r.get("password_value")
                        )
                    ts = next(
                        (
                            r.get(c)
                            for c in (
                                "visit_time",
                                "last_visit_time",
                                "visit_date",
                                "date",
                                "date_added",
                                "start_time",
                                "creation_utc",
                            )
                            if c in cols
                        ),
                        None,
                    )
                    yield record(
                        kind,
                        family,
                        data,
                        table,
                        row_id,
                        _timestamp(
                            ts,
                            chromium=key
                            not in {
                                "moz_historyvisits",
                                "moz_places",
                                "moz_bookmarks",
                                "history",
                            },
                            safari=key == "history_visits",
                        ),
                    )
