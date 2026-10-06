"""Captured key provenance, exact bytes, scope, and authenticated use."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, UploadFile

from app.services.mobile_forensic import key_intake as intake
from app.services.mobile_forensic import sqlite_counts as counts
from app.services.mobile_forensic.whatsapp_crypt import (
    WhatsAppKeyCandidate,
    decrypt_with_candidates,
)
from tests.test_whatsapp_recovery import SQLITE_SHA256, vector


@pytest.fixture
def case(monkeypatch):
    state = {"ds": {}, "objects": {}, "locks": [], "updates": 0}

    def get(_db, sql, params):
        if "FOR UPDATE" in sql:
            state["locks"].append(params["jid"])
        return {
            "id": "job-1",
            "disk_source": json.loads(json.dumps(state["ds"])),
            "extracted_disk_uri": state.get("extracted"),
        }

    def update(_db, _sql, params):
        state["ds"] = json.loads(params["ds"])
        state["updates"] += 1

    def put(key, material, **kwargs):
        state["objects"][key] = material
        return "s3://test/" + key

    def read(uri, *, max_bytes=None):
        material = state["objects"].get(uri.removeprefix("s3://test/"))
        return material[:max_bytes] if material else None

    monkeypatch.setattr(intake, "fetchone", get)
    monkeypatch.setattr(intake, "execute", update)
    monkeypatch.setattr(counts, "fetchone", get)
    monkeypatch.setattr(counts, "fetchall", lambda *args, **kwargs: [])
    monkeypatch.setattr("app.services.storage.put_bytes", put)
    monkeypatch.setattr("app.services.storage.get_bytes", read)
    return state


@pytest.mark.parametrize("version", ["crypt12", "crypt14", "crypt15"])
def test_uploaded_full_key_is_usable_after_intake_capture(case, version):
    backup, material = vector(version)
    result = intake.attach_key_file(object(), "job-1", material)
    ds = case["ds"]
    assert ds["whatsapp_key_hex"] == bytes(range(32)).hex()
    assert ds["case_intake"]["whatsapp_key_hex"] == bytes(range(32)).hex()
    assert len(ds["whatsapp_key_hex"]) == 64
    source = result["whatsapp_key_capture"]["sources"][0]
    assert source["sha256"] == hashlib.sha256(material).hexdigest()
    if len(material) == 158:
        assert source["key_offset"] == 126
        assert material[126:158].hex() == ds["whatsapp_key_hex"]
    public = json.dumps(result)
    assert material.hex() not in public and ds["whatsapp_key_hex"] not in public
    assert "storage_uri" not in public
    candidates = counts.discover_whatsapp_keys(object(), "job-1")
    assert len(candidates) == 1
    assert candidates[0].material == material
    plain = decrypt_with_candidates(backup, candidates, path="msgstore.db." + version)
    assert plain and hashlib.sha256(plain).hexdigest() == SQLITE_SHA256
    assert case["locks"] == ["job-1"]
    assert result["whatsapp_key_capture"]["backup_match_verified"] is False


def test_classic_non_serialized_key_uses_only_bytes_126_through_157(case):
    material = b"\xff" * 126 + bytes(range(32))
    result = intake.persist_captured_keys(
        object(),
        "job-1",
        [WhatsAppKeyCandidate(material, "data/data/com.whatsapp/files/key")],
    )
    assert case["ds"]["whatsapp_key_hex"] == material[126:158].hex()
    assert result["whatsapp_key_capture"]["sources"][0]["key_offset"] == 126


@pytest.mark.parametrize(
    "material",
    [
        b"",
        b"short",
        b"x" * 157,
        b"x" * 513,
        b"run-as: package not debuggable".ljust(158, b" "),
        b"cat: permission denied".ljust(158, b" "),
    ],
)
def test_invalid_capture_writes_neither_key_nor_object(case, material):
    with pytest.raises(ValueError, match="Invalid WhatsApp key"):
        intake.attach_key_file(object(), "job-1", material)
    assert case["ds"] == {} and case["objects"] == {} and not case["locks"]


def test_manual_key_preserved_and_multiple_user_keys_remain_available(case):
    case["ds"] = {
        "whatsapp_key_hex": "aa" * 32,
        "case_intake": {"signal_db_key_hex": "bb" * 32},
    }
    key = vector("crypt14")[1]
    intake.attach_key_file(object(), "job-1", key)
    result = intake.attach_key_file(object(), "job-1", b"C" * 126 + b"D" * 32)
    assert case["ds"]["whatsapp_key_hex"] == "aa" * 32
    assert case["ds"]["case_intake"]["signal_db_key_hex"] == "bb" * 32
    assert len(result["whatsapp_key_capture"]["sources"]) == 2
    assert len(counts.discover_whatsapp_keys(object(), "job-1")) == 3


def test_repeat_capture_does_not_duplicate_sources(case):
    material = vector("crypt14")[1]
    intake.attach_key_file(object(), "job-1", material)
    result = intake.attach_key_file(object(), "job-1", material)
    assert result["added"] == 0
    assert len(result["whatsapp_key_capture"]["sources"]) == 1
    assert case["updates"] == 1


def test_corrupt_stored_key_is_rejected_without_losing_manual_candidate(case):
    material = vector("crypt14")[1]
    intake.attach_key_file(object(), "job-1", material)
    reference = case["ds"]["case_intake"]["whatsapp_key_files"][0]
    case["objects"][reference["storage_uri"].removeprefix("s3://test/")] = b"x" * 158
    candidates = counts.discover_whatsapp_keys(object(), "job-1")
    assert len(candidates) == 1 and candidates[0].source == "case_intake"


def test_artifact_full_key_replaces_intake_hex_without_using_other_app_keys(
    case, monkeypatch
):
    material = vector("crypt12")[1]
    case["ds"]["whatsapp_key_hex"] = material[126:158].hex()
    rows = [
        {"file_path": path, "size_bytes": 158}
        for path in (
            "data/user/0/com.other.app/files/key",
            "data/user/10/com.whatsapp/files/key",
        )
    ]
    monkeypatch.setattr(counts, "fetchall", lambda *a, **kw: rows)
    reads = []

    def read(_db, _jid, path, **kwargs):
        reads.append(path)
        return material

    monkeypatch.setattr(counts, "_read_artifact_bytes", read)
    candidates = counts.discover_whatsapp_keys(object(), "job-1")
    assert reads == ["data/user/10/com.whatsapp/files/key"]
    assert len(candidates) == 1 and candidates[0].material == material


def test_registered_folder_capture_never_follows_outside_symlink(
    case, monkeypatch, tmp_path
):
    material = vector("crypt14")[1]
    folder = tmp_path / "case"
    folder.mkdir()
    (folder / "key").write_bytes(material)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "encrypted_backup.key").write_bytes(b"P" * 32)
    (folder / "com.whatsapp").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        "app.services.host_evidence.load_job_evidence_folder", lambda *a: str(folder)
    )
    monkeypatch.setattr(
        "app.services.host_evidence.resolve_host_path", lambda *a, **kw: folder
    )
    result = intake.capture_registered_keys(object(), "job-1", include_case_folder=True)
    assert result["added"] == 1
    assert result["whatsapp_key_capture"]["sources"][0]["source_path"] == "key"


def test_finalized_evidence_never_reopens_original_folder(case):
    case["extracted"] = "s3://test/extracted/manifest"
    with patch("app.services.host_evidence.load_job_evidence_folder") as folder:
        result = intake.capture_registered_keys(
            object(), "job-1", include_case_folder=True
        )
    assert result["status"] == "key_unavailable"
    folder.assert_not_called()


def test_job_metadata_redacts_keys_without_mutating_evidence(case):
    intake.attach_key_file(object(), "job-1", vector("crypt14")[1])
    public = intake.redact_forensic_keys(case["ds"])
    assert "whatsapp_key_hex" not in json.dumps(public)
    assert "storage_uri" not in json.dumps(public)
    assert case["ds"]["whatsapp_key_hex"] == bytes(range(32)).hex()


def test_upload_endpoint_rejects_oversized_file_before_storage(case, monkeypatch):
    from app.routers import report

    monkeypatch.setattr(report, "_ensure_job", lambda *a: {"id": "job-1"})
    monkeypatch.setattr(report, "apply_firm_search_path", lambda *a: None)
    db = MagicMock()
    file = UploadFile(filename="key", file=io.BytesIO(b"x" * 10_000))
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            report.upload_whatsapp_key_file(
                "job-1",
                file=file,
                db=db,
                current=SimpleNamespace(schema_name="firm_test"),
            )
        )
    assert error.value.status_code == 400 and not case["objects"]
    db.rollback.assert_called_once()


def test_intake_before_form_exists_still_shows_captured_status(case, monkeypatch):
    from app.routers import report

    intake.attach_key_file(object(), "job-1", vector("crypt14")[1])
    monkeypatch.setattr(
        report, "fetchone", lambda *a, **kw: {"disk_source": case["ds"]}
    )
    payload = report._intake_api(None, "job-1", db=object())
    assert payload["forensic_key_status"]["whatsapp_key_hex_set"] is True
    assert payload["whatsapp_key_capture"]["sources"][0]["key_offset"] == 126
    assert bytes(range(32)).hex() not in json.dumps(payload)


@pytest.mark.parametrize("mode", ["su", "run_as"])
def test_live_reader_captures_canonical_key_before_recursive_listing(
    monkeypatch, tmp_path, mode
):
    from app.services.mobile_acquire import privileged_app_pull as pull

    key = vector("crypt14")[1]
    events = []
    root = "/data/data/com.whatsapp"
    monkeypatch.setattr(pull, "_root_mode", lambda *a: "su")
    monkeypatch.setattr(pull, "_android_users", lambda *a: [0])
    monkeypatch.setattr(
        pull, "_run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=root)
    )
    monkeypatch.setattr(
        pull,
        "_remote_exists",
        lambda _a, _s, _m, path: path in {root, root + "/files/key"},
    )

    def read(_a, _s, _m, remote, dest):
        events.append("key")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(key)
        return True, ""

    def listing(*args):
        events.append("listing")
        return [root + "/files/key"]

    monkeypatch.setattr(pull, "_cat_file", read)
    monkeypatch.setattr(pull, "_list_files", listing)
    reader = (
        pull.pull_private_evidence if mode == "su" else pull.pull_debuggable_evidence
    )
    result = reader(
        adb="adb",
        serial="s",
        out=tmp_path,
        packages=["com.whatsapp"],
        include_system=False,
    )
    assert events == ["key", "listing"]
    assert result["files"] == 1
    assert (tmp_path / "data/data/com.whatsapp/files/key").read_bytes() == key
    assert result["whatsapp_key_files"][0]["key_offset"] == 126
    assert bytes(range(32)).hex() not in json.dumps(result)


def test_key_only_capture_never_walks_app_trees_and_uses_existing_run_as(
    monkeypatch, tmp_path
):
    from app.services.mobile_acquire import privileged_app_pull as pull

    key = vector("crypt14")[1]
    monkeypatch.setattr(pull, "_root_mode", lambda *a: None)
    monkeypatch.setattr(
        pull,
        "_run",
        lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout="/data/data/com.whatsapp"
        ),
    )
    monkeypatch.setattr(
        pull,
        "_remote_exists",
        lambda _a, _s, _m, path: path.endswith("com.whatsapp/files/key"),
    )

    def read(_a, _s, _m, remote, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(key)
        return True, ""

    monkeypatch.setattr(pull, "_cat_file", read)
    with patch.object(pull, "_list_files") as listing:
        result = pull.pull_whatsapp_key_evidence(adb="adb", serial="s", out=tmp_path)
    listing.assert_not_called()
    assert result["files"] == 1 and result["root_mode"] == "run_as"


def test_logical_adapter_attempts_keys_before_shared_media(monkeypatch, tmp_path):
    from app.services.mobile_acquire.adapters.android_adb import AndroidAdbAdapter
    from app.services.mobile_acquire.device_profile import DeviceProfile
    from app.services.mobile_acquire.methods import CollectionMethod

    adapter = AndroidAdbAdapter()
    events = []
    monkeypatch.setattr(adapter, "_collect_state", lambda *a: None)
    monkeypatch.setattr(adapter, "_pull_targets", lambda *a: events.append("shared"))

    def keys(**kwargs):
        events.append("keys")
        return {
            "bytes": 0,
            "whatsapp_key_files": [],
            "limitations": ["Private key inaccessible"],
            "errors": [],
        }

    monkeypatch.setattr(
        "app.services.mobile_acquire.privileged_app_pull.pull_whatsapp_key_evidence",
        keys,
    )
    result = adapter.acquire(
        profile=DeviceProfile(os_family="android", serial="s"),
        method=CollectionMethod.LOGICAL,
        destination=tmp_path,
    )
    assert events == ["keys", "shared"]
    assert "Private key inaccessible" in result.coverage_gaps
