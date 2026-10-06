"""Contacts / accounts parser (Android contacts2.db, iOS AddressBook)."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterator

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import epoch_to_iso, iter_query, open_sqlite_bytes, table_names
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext


class ContactsParser(ArtifactParser):
    name = "contacts_parser"
    version = "2.0.0"
    domains = ("accounts_contacts",)

    def supports(self, item: InventoryItem, context: ParseContext) -> bool:
        p = item.path.lower().replace("\\", "/")
        name = PurePosixPath(p).name.lower()
        return any(
            m in p or name == m
            for m in ("contacts2.db", "contacts.db", "addressbook.sqlitedb", "addressbook", "/com.android.providers.contacts/")
        ) and (name.endswith((".db", ".sqlite", ".sqlitedb")) or "addressbook" in name)

    def parse(self, item: InventoryItem, context: ParseContext) -> Iterator[NormalizedArtifact]:
        data = context.read_artifact_bytes(item.path)
        if not data:
            return
        with open_sqlite_bytes(data) as conn:
            if not conn:
                return
            tables = table_names(conn)
            if "view_contacts" in tables:
                rows = iter_query(conn, "SELECT _id AS id, display_name, last_time_contacted FROM view_contacts")
                source_table = "view_contacts"
            elif "raw_contacts" in tables:
                rows = iter_query(conn, "SELECT _id AS id, display_name FROM raw_contacts")
                source_table = "raw_contacts"
            elif "abperson" in tables:
                rows = iter_query(conn, "SELECT ROWID AS id, First AS first_name, Last AS last_name, Organization AS org FROM ABPerson")
                source_table = "ABPerson"
            else:
                return
            for r in rows:
                if "first_name" in r or "last_name" in r:
                    name = " ".join(x for x in (r.get("first_name"), r.get("last_name")) if x).strip() or r.get("org")
                else:
                    name = r.get("display_name")
                yield NormalizedArtifact.create(
                    artifact_type="contact",
                    source_domain="accounts_contacts",
                    data={"artifact_family": "contacts", "display_name": name, "contact_id": r.get("id")},
                    timestamp_utc=epoch_to_iso(r.get("last_time_contacted")),
                    state="allocated",
                    source_path=item.path,
                    source_table=source_table,
                    source_row_id=str(r.get("id") or ""),
                    source_sha256=item.sha256,
                    parser=self.name,
                    parser_version=self.version,
                    job_id=context.job_id,
                    source_id=context.source_id,
                )
