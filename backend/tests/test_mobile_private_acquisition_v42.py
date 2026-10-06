from __future__ import annotations

from pathlib import Path


def test_privileged_pull_uses_existing_root_only(monkeypatch, tmp_path: Path) -> None:
    from app.services.mobile_acquire import privileged_app_pull as mod

    monkeypatch.setattr(mod, "_root_mode", lambda adb, serial: "su")
    monkeypatch.setattr(mod, "_remote_exists", lambda adb, serial, mode, root: root.endswith("com.whatsapp"))
    monkeypatch.setattr(
        mod,
        "_list_files",
        lambda adb, serial, mode, root: [
            "/data/user/0/com.whatsapp/files/key",
            "/data/user/0/com.whatsapp/databases/msgstore.db",
            "/data/user/0/com.whatsapp/databases/msgstore.db-wal",
        ],
    )

    def fake_cat(adb, serial, mode, remote, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"K" * 158 if remote.endswith("/key") else b"SQLite format 3\x00" + b"X" * 64)
        return True, ""

    monkeypatch.setattr(mod, "_cat_file", fake_cat)
    out = mod.pull_private_evidence(
        adb="adb",
        serial="SERIAL",
        out=tmp_path,
        packages=["com.whatsapp"],
        include_system=False,
    )
    assert out["ok"] is True
    assert out["root_mode"] == "su"
    assert out["files"] == 3
    assert (tmp_path / "data/user/0/com.whatsapp/files/key").is_file()
    assert (tmp_path / "data/user/0/com.whatsapp/databases/msgstore.db-wal").is_file()


def test_privileged_pull_does_not_attempt_bypass_without_root(monkeypatch, tmp_path: Path) -> None:
    from app.services.mobile_acquire import privileged_app_pull as mod

    monkeypatch.setattr(mod, "_root_mode", lambda adb, serial: None)
    out = mod.pull_private_evidence(adb="adb", serial="SERIAL", out=tmp_path)
    assert out["ok"] is False
    assert out["root_mode"] == "unavailable"
    assert any("No rooting or lock bypass was attempted" in x for x in out["limitations"])


def test_android_readable_reports_locked_whatsapp_when_key_missing(tmp_path: Path) -> None:
    from app.services.mobile_acquire.android_readable import materialize_android_readable_artifacts

    # Make it an Android tree and include an encrypted msgstore without a key.
    crypt = tmp_path / "filesystem/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/msgstore-2026-09-29.1.db.crypt14"
    crypt.parent.mkdir(parents=True, exist_ok=True)
    crypt.write_bytes(b"not-a-real-crypt-fixture" * 8)

    result = materialize_android_readable_artifacts(tmp_path)
    assert result["ok"] is True
    assert result["whatsapp_decryption_state"] == "key_unavailable"
    assert result["whatsapp_decrypted_backups"] == 0
    assert result["deleted_whatsapp_messages"] == 0


def test_mobile_job_enables_live_acquisition_and_existing_folder_fallback() -> None:
    root = Path(__file__).resolve().parents[2]
    page = (root / "frontend/src/pages/mobile/MobileCompactJobPage.tsx").read_text(encoding="utf-8")
    panel = (root / "frontend/src/components/forensic/HostEvidencePanel.tsx").read_text(encoding="utf-8")
    assert "allowLiveMobileAcquisition={true}" in page
    assert "Start extraction & create image" in panel
    assert "Select extraction directory" in panel
