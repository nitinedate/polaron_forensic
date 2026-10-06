"""SMS/MMS/RCS and native telephony call-log parsers."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import epoch_to_iso, iter_query, open_sqlite_bytes, table_names
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class SmsCallsParser(ArtifactParser):
    name = "sms_calls_parser"
    version = "2.0.0"
    domains = ("sms_mms_rcs", "telephony")

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return any(
            m in p or name == m
            for m in (
                "mmssms.db", "sms.db", "telephony.db", "calllog.db", "call_log",
                "callhistory.sqlite", "/com.android.providers.telephony/", "library/sms",
            )
        ) and name.endswith((".db", ".sqlite", ".sqlitedb"))

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        data = context.read_artifact_bytes(item.path)
        if not data:
            return
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            p = item.path.lower()

            if "sms" in tables:
                sql = "SELECT _id AS id, address, body, date, type, read FROM sms ORDER BY date DESC"
                for r in iter_query(conn, sql):
                    try:
                        msg_type = int(r.get("type") or 0)
                    except (TypeError, ValueError):
                        msg_type = 0
                    direction = "incoming" if msg_type in (1, 0) else "outgoing"
                    yield NormalizedArtifact.create(
                        artifact_type="sms",
                        source_domain="sms_mms_rcs",
                        data={
                            "artifact_family": "sms",
                            "address": r.get("address"),
                            "body": r.get("body"),
                            "direction": direction,
                            "read": r.get("read"),
                            "message_type": msg_type,
                        },
                        timestamp_utc=epoch_to_iso(r.get("date")),
                        state="allocated",
                        source_path=item.path,
                        source_table="sms",
                        source_row_id=str(r.get("id") or ""),
                        source_sha256=item.sha256,
                        parser=self.name,
                        parser_version=self.version,
                        job_id=context.job_id,
                        source_id=context.source_id,
                    )

            # Android MMS: preserve message metadata and relationship ids.
            if "pdu" in tables:
                for r in iter_query(conn, "SELECT * FROM pdu"):
                    rid = str(r.get("_id") or r.get("id") or "")
                    yield NormalizedArtifact.create(
                        artifact_type="mms",
                        source_domain="sms_mms_rcs",
                        data={"artifact_family": "mms", "raw": {str(k): v for k, v in list(r.items())[:30]}},
                        timestamp_utc=epoch_to_iso(r.get("date") or r.get("date_sent")),
                        state="allocated",
                        source_path=item.path,
                        source_table="pdu",
                        source_row_id=rid,
                        source_sha256=item.sha256,
                        parser=self.name,
                        parser_version=self.version,
                        job_id=context.job_id,
                        source_id=context.source_id,
                    )

            call_table = next((cand for cand in ("calls", "call_log", "calllog") if cand in tables), None)
            if call_table:
                sql = f'SELECT _id AS id, number, date, duration, type FROM "{call_table}" ORDER BY date DESC'
                for r in iter_query(conn, sql):
                    try:
                        t = int(r.get("type") or 0)
                    except (TypeError, ValueError):
                        t = 0
                    direction = {1: "incoming", 2: "outgoing", 3: "missed", 5: "rejected"}.get(t, "unknown")
                    yield NormalizedArtifact.create(
                        artifact_type="call",
                        source_domain="telephony",
                        data={
                            "artifact_family": "call_logs",
                            "peer_identity": r.get("number"),
                            "direction": direction,
                            "duration_seconds": r.get("duration"),
                            "type": "voice",
                        },
                        timestamp_utc=epoch_to_iso(r.get("date")),
                        state="allocated",
                        source_path=item.path,
                        source_table=call_table,
                        source_row_id=str(r.get("id") or ""),
                        source_sha256=item.sha256,
                        parser=self.name,
                        parser_version=self.version,
                        job_id=context.job_id,
                        source_id=context.source_id,
                    )

            if "zcallrecord" in tables or "callhistory" in p:
                sql = "SELECT Z_PK AS id, ZADDRESS AS number, ZDATE AS date, ZDURATION AS duration, ZCALLTYPE AS type FROM ZCALLRECORD"
                for r in iter_query(conn, sql):
                    yield NormalizedArtifact.create(
                        artifact_type="call",
                        source_domain="telephony",
                        data={
                            "artifact_family": "call_logs",
                            "peer_identity": r.get("number"),
                            "duration_seconds": r.get("duration"),
                            "type": "voice",
                            "raw_type": r.get("type"),
                        },
                        timestamp_utc=epoch_to_iso(r.get("date")),
                        state="allocated",
                        source_path=item.path,
                        source_table="ZCALLRECORD",
                        source_row_id=str(r.get("id") or ""),
                        source_sha256=item.sha256,
                        parser=self.name,
                        parser_version=self.version,
                        job_id=context.job_id,
                        source_id=context.source_id,
                    )
