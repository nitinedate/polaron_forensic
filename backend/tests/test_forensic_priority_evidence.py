"""Priority evidence, text-only RAG and source-linked media behavior."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from app.services import forensic_media_review as media
from app.services import forensic_serial_stages as stages
from app.services.forensic_serial_pipeline import STAGES, StageWaiting
from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_SIZE
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.parsers._sqlite_util import SqliteEvidenceBytes
from app.services.mobile_forensic.parsers.browser import BrowserHistoryParser
from app.services.mobile_forensic.parsers.files_media import FilesMediaParser
from app.services.mobile_forensic.parsers.media_store import MediaStoreParser
from app.services.mobile_forensic.plugins import ParseContext, get_plugin_registry


def database(tmp_path, sql):
    path = tmp_path / "source.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(sql)
    return path.read_bytes()


def context(blob):
    return ParseContext(
        job_id="00000000-0000-0000-0000-000000000001",
        platform="Android",
        read_bytes=lambda *a, **kw: blob,
    )


def test_complete_evidence_chunks_have_fixed_windows_and_source_links(monkeypatch):
    monkeypatch.setattr(
        "app.services.embedding_gpu.embed_texts",
        lambda *a, **kw: pytest.fail("Embedding loaded"),
    )
    payload = "".join(f"record-{i:05d} नमस्ते\n" for i in range(1500)) + "EVIDENCE_TAIL"
    rows = [
        {
            "id": "source-id",
            "file_path": "data/WhatsApp/messages.db",
            "normalized": {"body": payload},
            "ocr_text": "OCR_TAIL",
        }
    ]
    output = stages._full_text_chunks(rows)
    assert CHUNK_SIZE == 2500 and CHUNK_OVERLAP == 800
    assert output[0][3].startswith("Evidence file data/WhatsApp/messages.db")
    assert all(len(row[3]) <= 2500 for row in output)
    assert all(a[3][-800:] == b[3][:800] for a, b in zip(output, output[1:]))
    assert "EVIDENCE_TAIL" in output[-1][3] and "OCR_TAIL" in output[-1][3]
    assert "embedding" not in {name for name, _, _ in STAGES}


def test_mobile_text_chunks_ignore_old_embedding_flag(monkeypatch):
    from app.services.mobile_forensic import mobile_rag

    monkeypatch.setattr(
        "app.services.embedding_gpu.embed_texts",
        lambda *a, **kw: pytest.fail("Embedding loaded"),
    )
    monkeypatch.setattr(
        mobile_rag,
        "_chunk_mobile_records",
        lambda db, jid, **kw: {"status": "ok", "embedding_enabled": False},
    )
    monkeypatch.setattr(
        "app.services.forensic_serial_policy.serial_enabled", lambda: True
    )
    assert (
        mobile_rag.index_mobile_artifacts_for_rag(object(), "job", embed=True)[
            "embedding_enabled"
        ]
        is False
    )


def test_android_chrome_urls_visits_downloads_cookies_and_logins(tmp_path):
    blob = database(
        tmp_path,
        """CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER,visit_count INTEGER);
        INSERT INTO urls VALUES(1,'https://web.whatsapp.com/','WhatsApp',13344473600000000,2);
        CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER); INSERT INTO visits VALUES(9,1,13344473600000000);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY,target_path TEXT,start_time INTEGER); INSERT INTO downloads VALUES(7,'/sdcard/Download/report.pdf',13344473600000000);
        CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT);INSERT INTO downloads_url_chains VALUES(7,0,'https://example.org/report.pdf');
        CREATE TABLE cookies(host_key TEXT,name TEXT,encrypted_value BLOB);INSERT INTO cookies VALUES('example.org','session',X'0102');
        CREATE TABLE logins(origin_url TEXT,username_value TEXT,password_value BLOB);INSERT INTO logins VALUES('https://example.org','user',X'1234');""",
    )
    parser = BrowserHistoryParser()
    item = InventoryItem(
        path="data/user/0/com.android.chrome/app_chrome/Default/History",
        size=len(blob),
        sha256=hashlib.sha256(blob).hexdigest(),
    )
    records = list(parser.parse(item, context(blob)))
    visit = next(a for a in records if a.artifact_type == "browser_visit")
    assert (
        visit.data["url"] == "https://web.whatsapp.com/" and visit.data["whatsapp_link"]
    )
    assert (
        visit.forensic["source_table"] == "visits"
        and visit.forensic["source_row_id"] == "9"
    )
    assert visit.timestamp_utc.startswith("2023")
    assert {a.artifact_type for a in records} >= {
        "browser_download",
        "browser_download_url",
        "browser_cookie",
        "browser_login",
    }
    login = next(a for a in records if a.artifact_type == "browser_login")
    assert login.data["encrypted_password_present"]
    assert login.data["raw"]["password_value"]["binary_length"] == 2


def test_android_firefox_visits_resolve_urls(tmp_path):
    blob = database(
        tmp_path,
        """CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT);INSERT INTO moz_places VALUES(2,'https://example.org','Example');
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,place_id INTEGER,visit_date INTEGER);INSERT INTO moz_historyvisits VALUES(3,2,1700000000000000);""",
    )
    item = InventoryItem(
        path="data/data/org.mozilla.firefox/files/profile/places.sqlite", size=len(blob)
    )
    parser = BrowserHistoryParser()
    assert parser.supports(item, context(blob))
    visits = [
        a
        for a in parser.parse(item, context(blob))
        if a.artifact_type == "browser_visit"
    ]
    assert len(visits) == 1 and visits[0].data["url"] == "https://example.org"


def test_browser_reads_acquired_wal_and_preserves_source_bytes(tmp_path):
    path = tmp_path / "History"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT)")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("INSERT INTO urls VALUES(1,'https://example.org/wal-only','Only WAL')")
    conn.commit()
    original = path.read_bytes()
    wal = Path(str(path) + "-wal").read_bytes()
    evidence = SqliteEvidenceBytes(original, {"-wal": wal})
    try:
        records = list(
            BrowserHistoryParser().parse(
                InventoryItem(path="app_chrome/Default/History", size=len(original)),
                context(evidence),
            )
        )
        assert any(a.data.get("url") == "https://example.org/wal-only" for a in records)
        assert (
            path.read_bytes() == original
            and Path(str(path) + "-wal").read_bytes() == wal
        )
    finally:
        conn.close()


def test_bookmark_parser_does_not_drop_tail_records():
    blob = json.dumps(
        {
            "roots": {
                "bookmark_bar": {
                    "children": [
                        {
                            "type": "url",
                            "name": f"item{i}",
                            "url": f"https://example.org/{i}",
                        }
                        for i in range(1201)
                    ]
                }
            }
        }
    ).encode()
    records = list(
        BrowserHistoryParser().parse(
            InventoryItem(path="User Data/Default/Bookmarks", size=len(blob)),
            context(blob),
        )
    )
    assert len(records) == 1201 and records[-1].data["url"].endswith("/1200")


def test_browser_rejects_unreadable_database_instead_of_claiming_zero_records():
    with pytest.raises(ValueError, match="SQLite"):
        list(
            BrowserHistoryParser().parse(
                InventoryItem(path="History", size=10), context(b"not SQLite")
            )
        )


@pytest.mark.parametrize(
    "extension,mime,kind",
    [
        ("jpg", "image/jpeg", "photo"),
        ("", "image/jpeg", "photo"),
        ("", "video/mp4", "video"),
        ("", "application/pdf", "document"),
        (".epub", "application/epub+zip", "document"),
        (".eml", "message/rfc822", "document"),
    ],
)
def test_media_and_documents_include_mime_and_extension_variants(extension, mime, kind):
    item = InventoryItem(
        path="storage/evidence",
        size=32,
        extension=extension,
        mime_hint=mime,
        meta={"is_deleted": True, "deleted_at": "2026-01-01"},
    )
    parser = FilesMediaParser()
    assert parser.supports(item, context(None))
    record = list(parser.parse(item, context(None)))[0]
    assert (
        record.artifact_type == kind
        and record.forensic["state"] == "filesystem_recovered"
    )
    assert record.data["deleted_at"] == "2026-01-01"


def test_media_store_trash_is_a_reference_not_recovered_image_bytes(tmp_path):
    blob = database(
        tmp_path,
        """CREATE TABLE files(_id INTEGER PRIMARY KEY,_data TEXT,_display_name TEXT,mime_type TEXT,is_trashed INTEGER,date_added INTEGER);
        INSERT INTO files VALUES(1,'/sdcard/DCIM/.trashed-photo.jpg','photo.jpg','image/jpeg',1,1700000000);""",
    )
    record = list(
        MediaStoreParser().parse(
            InventoryItem(
                path="data/user/0/com.android.providers.media/databases/external.db",
                size=len(blob),
            ),
            context(blob),
        )
    )[0]
    assert record.artifact_type == "media_reference" and record.data["reference_only"]
    assert record.forensic["state"] == "database_deleted"
    assert any(
        p.name == "android_media_store_parser" for p in get_plugin_registry().parsers
    )


def test_vision_model_missing_or_without_vision_holds_stage(monkeypatch):
    monkeypatch.setattr(
        "app.services.model_router._ollama_post",
        lambda *a, **kw: {"capabilities": ["completion"]},
    )
    with pytest.raises(StageWaiting, match="vision support"):
        media.check_model()


def test_frame_description_retains_review_basis_and_structured_request(monkeypatch):
    requests = []

    def respond(path, payload, **kw):
        requests.append((path, payload))
        return {
            "message": {
                "content": json.dumps(
                    {
                        "description": "A sheet shows a printed bank account number.",
                        "review_signals": [
                            {
                                "category": "financial_document",
                                "visible_detail": "Printed bank account number is visible.",
                            }
                        ],
                    }
                )
            }
        }

    monkeypatch.setattr("app.services.model_router._ollama_post", respond)
    result = media.describe_frame(b"png-test")
    assert (
        result["signals"][0]["examiner_status"] == "pending_review"
        and result["model_derived"]
    )
    assert (
        requests[0][0] == "/api/chat" and requests[0][1]["format"] == media.MODEL_SCHEMA
    )
    assert base64.b64decode(requests[0][1]["messages"][0]["images"][0]) == b"png-test"


def test_malformed_visual_findings_are_not_accepted(monkeypatch):
    monkeypatch.setattr(
        "app.services.model_router._ollama_post",
        lambda *a, **kw: {
            "message": {
                "content": '{"description":"Photo","review_signals":[{"category":"criminal","visible_detail":"Unknown person"}]}'
            }
        },
    )
    with pytest.raises(ValueError, match="ungrounded"):
        media.describe_frame(b"image")


def test_ocr_review_basis_is_an_actual_content_excerpt():
    signals = media.ocr_signals("This image says: password = abc123. Context follows.")
    assert len(signals) == 1 and "password = abc123" in signals[0]["detail"]
    assert media.ocr_signals("A landscape photograph with no text.") == []


def test_video_sampling_covers_tail_and_reports_budget():
    times, limited = media.video_sample_times(131, 10)
    assert times[0] == 0 and times[-1] == 130.9 and not limited
    times, limited = media.video_sample_times(131, 10, 3)
    assert times == [0, 65.45, 130.9] and limited


@pytest.mark.skipif(
    not shutil.which("ffmpeg") or not shutil.which("ffprobe"),
    reason="ffmpeg not installed",
)
def test_actual_video_frames_have_source_timestamps_and_tail(tmp_path, monkeypatch):
    path = tmp_path / "evidence.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=192x128:rate=10",
            "-t",
            "2.4",
            "-pix_fmt",
            "yuv420p",
            "-y",
            str(path),
        ],
        check=True,
    )
    monkeypatch.setenv("FORENSIC_VIDEO_SAMPLE_SECONDS", "1")
    frames = list(media.video_frames(str(path)))
    assert [round(stamp["timestamp_seconds"], 1) for _, stamp, _ in frames] == [
        0,
        1,
        2,
        2.3,
    ]
    assert all(
        blob.startswith(b"\x89PNG") and not coverage["all_frames_reviewed"]
        for blob, _, coverage in frames
    )


def test_report_observations_include_all_flagged_evidence_and_hashes(monkeypatch):
    rows = [
        {
            "job_artifact_id": str(i),
            "source_path": f"DCIM/image-{i}.jpg",
            "source_sha256": f"sourcehash{i}",
            "details": {
                "frames": [
                    {
                        "timestamp_seconds": None,
                        "frame_sha256": f"framehash{i}",
                        "description": f"Observed detail {i}",
                        "signals": [{"detail": "Visible document."}],
                    }
                ]
            },
        }
        for i in range(151)
    ]
    monkeypatch.setattr(
        media, "fetchone", lambda *a, **kw: {"name": "forensic_media_observations"}
    )
    monkeypatch.setattr(media, "fetchall", lambda *a, **kw: rows)
    report = media.build_media_observations_markdown(object(), "job")
    assert (
        "Suspicious Activity" in report
        and "sourcehash150" in report
        and "framehash150" in report
    )
    assert "Pending examiner review" in report and "sampled frames" in report


def test_media_description_is_in_full_text_rag_before_report():
    output = stages._full_text_chunks(
        [
            {
                "id": "image",
                "file_path": "DCIM/a.jpg",
                "normalized": None,
                "ocr_text": "",
                "media_review": {
                    "description": "A visible printed document needs review.",
                    "flagged": True,
                },
            }
        ]
    )
    assert "visible printed document" in output[0][3] and len(output[0][3]) <= 2500


def test_browser_timestamps_do_not_guess_apple_epoch():
    from app.services.mobile_forensic.parsers.browser import _timestamp

    assert _timestamp(946684800).startswith("2000-01-01")
    assert _timestamp(0, safari=True).startswith("2001-01-01")
    assert _timestamp(946684800000).startswith("2000-01-01")
    assert _timestamp(1700000000000000).startswith("2023")


def test_browser_without_rowid_tables_are_not_silently_skipped(tmp_path):
    blob = database(
        tmp_path,
        """CREATE TABLE cookies(host_key TEXT,name TEXT,value TEXT,
        PRIMARY KEY(host_key,name)) WITHOUT ROWID;
        INSERT INTO cookies VALUES('example.org','session','visible-cookie');""",
    )
    records = list(
        BrowserHistoryParser().parse(
            InventoryItem(path="Cookies", size=len(blob)), context(blob)
        )
    )
    assert len(records) == 1 and records[0].artifact_type == "browser_cookie"
    assert "example.org" in records[0].forensic["source_row_id"]


def test_old_stage_snapshot_excludes_embedding_and_requires_upgrade():
    from app.services.forensic_serial_pipeline import snapshot_from_rows

    rows = [
        {"stage": name, "status": "done"}
        for name, _, _ in STAGES
        if name != "media_review"
    ]
    rows.insert(9, {"stage": "embedding", "status": "waiting"})
    snapshot = snapshot_from_rows(rows)
    assert snapshot["upgrade_required"] and not snapshot["complete"]
    assert "embedding" not in [row["id"] for row in snapshot["stages"]]


def test_mobile_fallback_counts_do_not_invent_media_findings():
    from app.services.mobile_report_llm import plain_fallback_observations

    report = plain_fallback_observations(
        {"pictures": 10, "audio": 4, "whatsapp_messages": 5}
    )
    assert "10 pictures and images" in report
    assert "Nothing clearly malicious" not in report and "were reviewed" not in report
    assert "cannot be determined from inventory counts" in report
