"""Android MediaStore references, including trash metadata and missing files.

A database reference cannot prove that original or deleted image bytes were
acquired. Reference artifacts therefore have a distinct type and coverage flag.
"""

from pathlib import PurePosixPath

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import (
    epoch_to_iso,
    iter_query,
    open_sqlite_bytes,
    table_names,
)
from app.services.mobile_forensic.plugins import ArtifactParser, ParseContext
from app.services.mobile_forensic.storage import _json_safe


class MediaStoreParser(ArtifactParser):
    name = "android_media_store_parser"
    version = "1.0.0"
    domains = ("media", "files")

    def supports(self, item: InventoryItem, context: ParseContext):
        name = PurePosixPath(item.path.lower()).name
        return name in {"external.db", "internal.db"} or (
            "providers.media" in item.path.lower() and name.endswith(".db")
        )

    def parse(self, item: InventoryItem, context: ParseContext):
        blob = context.read_artifact_bytes(item.path)
        if not blob:
            raise ValueError("Acquired MediaStore database could not be read")
        with open_sqlite_bytes(blob) as conn:
            if not conn:
                raise ValueError("MediaStore database could not be opened")
            for table in sorted(
                table_names(conn) & {"files", "images", "video", "audio"}
            ):
                for row in iter_query(
                    conn, f'SELECT rowid AS __row_id,* FROM "{table}"'
                ):
                    trashed = str(row.get("is_trashed") or "0") == "1"
                    data = {
                        "artifact_family": "deleted_media_references"
                        if trashed
                        else "media_references",
                        "path": row.get("_data"),
                        "name": row.get("_display_name"),
                        "mime": row.get("mime_type"),
                        "size": row.get("_size"),
                        "is_trashed": trashed,
                        "is_pending": row.get("is_pending"),
                        "reference_only": True,
                        "raw": _json_safe(row),
                    }
                    yield NormalizedArtifact.create(
                        artifact_type="media_reference",
                        source_domain="media",
                        data=data,
                        timestamp_utc=epoch_to_iso(
                            row.get("datetaken") or row.get("date_added")
                        ),
                        state="database_deleted" if trashed else "allocated",
                        recovery_source="media_store_trash_reference"
                        if trashed
                        else "media_store_reference",
                        source_path=item.path,
                        source_table=table,
                        source_row_id=str(row.get("__row_id")),
                        source_sha256=item.sha256,
                        parser=self.name,
                        parser_version=self.version,
                        job_id=context.job_id,
                        source_id=context.source_id,
                    )
