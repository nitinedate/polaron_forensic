"""Tests for Phase 1-40 artifact scope filtering and parser join sidecars."""

from app.services.phase1_artifact_scope import (
    is_parser_join_sidecar,
    is_phase1_evidence_path,
    should_materialize_path,
)


def test_drops_winsxs_system_dll_noise() -> None:
    ok, reason = should_materialize_path(
        "Windows/WinSxS/amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.19041.1_none_deadbeef/kernel32.dll",
    )
    assert ok is False
    assert reason == "phase1_noise"


def test_keeps_browser_history_and_sidecars() -> None:
    history = "Users/Jane/AppData/Local/Google/Chrome/User Data/Default/History"
    assert is_phase1_evidence_path(history) is True
    assert should_materialize_path(history)[0] is True

    wal = history + "-wal"
    shm = history + "-shm"
    journal = history + "-journal"
    assert is_parser_join_sidecar(wal) is True
    assert is_parser_join_sidecar(shm) is True
    assert is_parser_join_sidecar(journal) is True
    assert should_materialize_path(wal)[0] is True
    assert should_materialize_path(shm)[0] is True


def test_keeps_leveldb_manifest_and_current() -> None:
    manifest = "Users/Jane/AppData/Local/Discord/app-1.0/Local Storage/leveldb/MANIFEST-000001"
    current = "Users/Jane/AppData/Local/Discord/app-1.0/Local Storage/leveldb/CURRENT"
    log = "Users/Jane/AppData/Local/Discord/app-1.0/Local Storage/leveldb/000003.log"
    assert is_parser_join_sidecar(manifest) is True
    assert is_parser_join_sidecar(current) is True
    assert is_parser_join_sidecar(log) is True
    assert should_materialize_path(manifest)[0] is True


def test_keeps_registry_transaction_logs() -> None:
    log1 = "Windows/System32/config/LOG1"
    log2 = "Windows/System32/config/LOG2"
    assert is_parser_join_sidecar(log1) is True
    assert is_parser_join_sidecar(log2) is True
    assert should_materialize_path(log1)[0] is True


def test_keeps_setupapi_and_recycle_bin_metadata() -> None:
    setup = "Windows/INF/setupapi.dev.log"
    recycle = "C/$Recycle.Bin/S-1-5-21-1234567890-123456789-123456789-1234/$IABC123.txt"
    assert is_phase1_evidence_path(setup) is True
    assert is_phase1_evidence_path(recycle) is True


def test_drops_chrome_disk_cache_blob() -> None:
    cache = "Users/Jane/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/f_000001"
    ok, reason = should_materialize_path(cache)
    assert ok is False
    assert reason == "phase1_noise"


def test_filter_disabled_materializes_everything() -> None:
    cache = "Users/Jane/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/f_000001"
    ok, reason = should_materialize_path(cache, enabled=False)
    assert ok is True
    assert reason is None


def test_keeps_critical_hives() -> None:
    sam = "Windows/System32/config/SAM"
    ntuser = "Users/Jane/NTUSER.DAT"
    assert should_materialize_path(sam)[0] is True
    assert should_materialize_path(ntuser)[0] is True


def test_keeps_handbook_maildir_extensionless() -> None:
    maildir = "Users/Jane/Maildir/cur/1234567890.abcdef"
    assert is_phase1_evidence_path(maildir) is True
    assert should_materialize_path(maildir)[0] is True


def test_keeps_handbook_container_extensions() -> None:
    pcap = "Users/Jane/Downloads/capture.pcapng"
    vmdk = "Evidence/vm-disk.vmdk"
    assert is_phase1_evidence_path(pcap) is True
    assert is_phase1_evidence_path(vmdk) is True
