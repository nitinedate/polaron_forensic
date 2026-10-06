"""Location / navigation artifact parser."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import epoch_to_iso, iter_query, open_sqlite_bytes, table_names
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class LocationParser(ArtifactParser):
    name = "location_parser"
    version = "2.0.0"
    domains = ("location",)

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return any(m in p for m in ("consolidated.db", "cache.sqlite", "location", "fusedlocation", "places.sqlite", "routinetime")) and (name.endswith((".db", ".sqlite")) or "location" in name)

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        data = context.read_artifact_bytes(item.path)
        if not data:
            yield NormalizedArtifact.create(
                artifact_type="location_source", source_domain="location",
                data={"artifact_family": "location", "path": item.path}, state="unsupported",
                source_path=item.path, source_sha256=item.sha256, parser=self.name,
                parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
            )
            return
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            for table in ("celllocation", "wificocation", "location", "zrtcllocationmo"):
                if table not in tables:
                    continue
                for r in iter_query(conn, f'SELECT rowid AS __row_id, * FROM "{table}"'):
                    safe_raw = {str(k): v for k, v in list(r.items())[:30] if not isinstance(v, (bytes, bytearray))}
                    yield NormalizedArtifact.create(
                        artifact_type="location", source_domain="location",
                        data={"artifact_family": "location", "raw": safe_raw, "table": table},
                        timestamp_utc=epoch_to_iso(r.get("timestamp") or r.get("time") or r.get("ztimestamp")),
                        state="allocated", source_path=item.path, source_table=table,
                        source_row_id=str(r.get("__row_id") or ""), source_sha256=item.sha256,
                        parser=self.name, parser_version=self.version, job_id=context.job_id, source_id=context.source_id,
                    )
