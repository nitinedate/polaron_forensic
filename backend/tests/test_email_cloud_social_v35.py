from __future__ import annotations

import csv
import sys
import types
from pathlib import Path

from app.services.artifact_evidence_browse import evidence_browse_mode
from app.services.artifact_type_resolver import resolve_artifact_type
from app.services import social_cloud_inventory as sci

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _catalog_rows() -> list[dict[str, str]]:
    path = ROOT / "data" / "axiom" / "Magnet_AXIOM_10.2.0_All_Artifacts.csv"
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def test_composite_catalog_exposes_cloud_drives_and_zero_definitions() -> None:
    rows = _catalog_rows()
    names = {(r["platform"], r["category"], r["artifact_name"]) for r in rows}
    assert ("Windows", "Cloud Storage", "OneDrive") in names
    assert ("Windows", "Cloud Storage", "Google Drive") in names
    assert ("Windows", "Cloud Storage", "Dropbox") in names
    assert ("Cloud", "Cloud Storage", "Cloud OneDrive Files") in names
    assert ("Cloud", "Cloud Storage", "Cloud Google Drive Files") in names
    assert ("Cloud", "Cloud Storage", "Cloud Dropbox Files") in names
    assert ("Cloud", "Cloud Storage", "Cloud Box.com Files") in names
    assert ("Cloud", "Cloud Storage", "Cloud iCloud Drive Files") in names
    assert ("Cloud", "Cloud Storage", "Cloud Mega Files") in names

    selection = read("backend/app/services/artifact_selection_catalog.py")
    assert 'result.append("Cloud")' in selection
    assert 'result.append("Windows Memory")' in selection

    router = read("backend/app/routers/artifacts.py")
    block = router[
        router.index('@router.get("/{job_id}/artifacts/categories")'):
        router.index('@router.get("/{job_id}/artifacts/resolve-path")')
    ]
    assert "for catalog_platform in platforms:" in block
    assert '"catalog_platform"' in block
    assert "if count <= 0" not in block



def test_windows_composite_display_catalog_has_more_than_endpoint_only_definitions() -> None:
    rows = [r for r in _catalog_rows() if r["platform"] in {"Windows", "Cloud", "Windows Memory"}]
    seen: set[tuple[str, str]] = set()
    for row in rows:
        seen.add((row["category"].strip().lower(), row["artifact_name"].strip().lower()))
    assert len(rows) == 819
    assert len(seen) == 817


def test_all_windows_email_and_social_axiom_names_are_present_in_reference() -> None:
    rows = _catalog_rows()
    windows_email = [r for r in rows if r["platform"] == "Windows" and r["category"] == "Email and Calendar"]
    windows_social = [r for r in rows if r["platform"] == "Windows" and r["category"] == "Social Networking"]
    cloud_email = [r for r in rows if r["platform"] == "Cloud" and r["category"] == "Email and Calendar"]
    assert len(windows_email) == 34
    assert len(windows_social) == 19
    assert len(cloud_email) == 10
    social_names = {r["artifact_name"] for r in windows_social}
    assert {"Facebook Chat", "Google+ Chat", "Instagram Images", "Instagram Posts", "Twitter", "VK Web Messages"} <= social_names


def test_social_browse_does_not_treat_google_chrome_cache_as_google_plus_chat() -> None:
    # Provider-specific social rows are routed before generic path matching.
    assert evidence_browse_mode("Google+ Chat", "Social Networking") == "social_activity"
    assert evidence_browse_mode("Instagram Images", "Social Networking") == "social_activity"
    # Message-specific rows may use the dedicated chat DB parser.
    assert evidence_browse_mode("Facebook Chat", "Social Networking") == "chat_message"
    assert evidence_browse_mode("LinkedIn Emails", "Social Networking") == "chat_message"


def test_google_plus_count_uses_provider_activity_not_generic_store_files(monkeypatch) -> None:
    monkeypatch.setattr(
        sci,
        "_url_records",
        lambda *_a, **_k: [
            {"url": "https://chat.google.com/u/0/", "record_origin": "browser_history", "visit_count": 2},
            {"url": "https://hangouts.google.com/", "record_origin": "browser_history", "visit_count": 1},
        ],
    )
    monkeypatch.setattr(
        sci,
        "_provider_files",
        lambda *_a, **_k: [
            {"id": str(i), "file_path": f"/Chrome/Cache/Cache_Data/f_{i:06x}", "file_name": f"f_{i:06x}", "extension": ""}
            for i in range(2054)
        ],
    )
    result = sci.social_artifact_evidence(object(), "job", "Google+ Chat")
    assert result["count"] == 3
    assert result["url_occurrences"] == 3
    assert result["count"] != 2054


def test_cloud_browse_modes_cover_onedrive_and_other_clouds() -> None:
    for name in (
        "OneDrive",
        "Cloud OneDrive Files",
        "Google Drive",
        "Cloud Google Drive Files",
        "Dropbox",
        "Cloud Dropbox Files",
        "Cloud Box.com Files",
        "Cloud iCloud Drive Files",
        "Cloud Mega Files",
        "Carbonite Log File",
        "Flickr",
    ):
        assert evidence_browse_mode(name, "Cloud Storage") == "cloud_storage"


def test_old_provider_results_are_invalidated_for_recount() -> None:
    runner = read("backend/app/services/catalog_artifact_runner.py")
    assert 'snapshot.get("collector") != "social_cloud_inventory"' in runner
    router = read("backend/app/routers/artifacts.py")
    assert "stale_provider_count" in router
    assert '"pending" if stale_provider_count' in router


def test_extensionless_file_uses_libmagic_when_available(monkeypatch) -> None:
    fake_magic = types.SimpleNamespace(from_buffer=lambda *_a, **_k: "image/svg+xml")
    monkeypatch.setitem(sys.modules, "magic", fake_magic)
    resolved = resolve_artifact_type(
        {"file_name": "f_000009", "file_path": "/cache/f_000009", "extension": "", "metadata": {}},
        data=b"\x00\x01\x02opaque-content-that-manual-signatures-do-not-recognize",
    )
    assert resolved.content_type == "image/svg+xml"
    assert resolved.normalized_filename == "f_000009.svg"
    assert resolved.source == "magic"


def test_msg_email_preview_and_attachment_download_are_wired() -> None:
    parser = read("backend/app/parsers/outlook_msg_parser.py")
    preview = read("backend/app/services/artifact_preview.py")
    requirements = read("backend/requirements.txt")
    dockerfile = read("backend/Dockerfile")
    assert "extract_msg.Message" in parser
    assert "attachments" in parser
    assert "load_msg_attachment_bytes" in parser
    assert "if ext == \".msg\"" in preview
    assert "load_msg_attachment_bytes" in preview
    assert "extract-msg" in requirements
    assert "libmagic1" in dockerfile


def test_actual_outlook_files_are_listed_before_metadata_only_mailbox_rows() -> None:
    source = read("backend/app/services/pst_mailbox_inventory.py")
    assert "materialize_mailbox_messages" in source
    assert "direct = _direct_outlook_file_evidence" in source
    assert source.index("inv = scan_job_pst_mailboxes") < source.index("direct = _direct_outlook_file_evidence")
    assert "combined = direct + virtual" in source
    assert "Deliberately NOT evidence_kind=outlook_message" in source


def test_pst_mailbox_is_converted_to_derived_eml_without_changing_source_evidence() -> None:
    source = read("backend/app/services/pst_message_materializer.py")
    assert '[readpst, "-q", "-e", "-D", "-t", "e"' in source
    assert 'content_type="message/rfc822"' in source
    assert '"derived_mailbox_parent_id"' in source
    assert '"derived_tool": "readpst"' in source
    assert "iter_artifact_content" in source
    assert "UPDATE job_artifacts SET" not in source


def test_category_ui_keeps_zero_rows_and_auto_opens_key_families() -> None:
    source = read("frontend/src/components/forensic/ArtifactCategoryTree.tsx")
    assert "zero-count definitions remain visible" in source
    assert '"cloud storage"' in source
    assert '"social networking"' in source
    assert '"email and calendar"' in source
    assert ".filter((n) => n.count > 0)" not in source
