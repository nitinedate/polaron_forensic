"""Calendar / notes / reminders parser."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import epoch_to_iso, iter_query, open_sqlite_bytes, table_names
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class CalendarNotesParser(ArtifactParser):
    name = "calendar_notes_parser"
    version = "2.0.0"
    domains = ("calendar_notes",)

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return any(m in p for m in ("calendar.db", "calender", "notes.sqlite", "notestore.sqlite", "reminders", "/com.android.providers.calendar/")) and name.endswith((".db", ".sqlite", ".sqlitedb"))

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        data = context.read_artifact_bytes(item.path)
        if not data:
            return
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            if "events" in tables:
                sql = "SELECT _id AS id, title, dtstart, dtend, eventLocation AS loc, description FROM events"
                for r in iter_query(conn, sql):
                    yield NormalizedArtifact.create(
                        artifact_type="calendar_event", source_domain="calendar_notes",
                        data={"artifact_family": "calendar", "title": r.get("title"), "location": r.get("loc"), "description": r.get("description"), "end_time": epoch_to_iso(r.get("dtend"))},
                        timestamp_utc=epoch_to_iso(r.get("dtstart")), state="allocated", source_path=item.path,
                        source_table="events", source_row_id=str(r.get("id") or ""), source_sha256=item.sha256,
                        parser=self.name, parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
                    )
            if "znote" in tables:
                for r in iter_query(conn, "SELECT Z_PK AS id, ZTITLE AS title, ZMODIFICATIONDATE AS ts FROM ZNOTE"):
                    yield NormalizedArtifact.create(
                        artifact_type="note", source_domain="calendar_notes",
                        data={"artifact_family": "notes", "title": r.get("title")},
                        timestamp_utc=epoch_to_iso(r.get("ts")), state="allocated", source_path=item.path,
                        source_table="ZNOTE", source_row_id=str(r.get("id") or ""), source_sha256=item.sha256,
                        parser=self.name, parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
                    )
