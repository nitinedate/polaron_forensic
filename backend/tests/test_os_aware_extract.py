"""OS detection + forensic extract filter policy."""

from app.services.extract_filters import (
    matches_defensible_include,
    matches_forensic_include,
    resolve_skip_system_paths,
    should_extract_node,
)
from app.services.os_detect import detect_os_from_paths


def test_detect_windows_from_paths():
    nodes = [
        {"path": "Windows/System32/config/SOFTWARE"},
        {"path": "Windows/System32/config/SYSTEM"},
        {"path": "Windows/WinSxS/manifests/x86_foo"},
        {"path": "Program Files/WindowsApps/Microsoft.Foo/AppxManifest.xml"},
        {"path": "Users/Alice/AppData/Local/Temp/a.txt"},
        {"path": "pagefile.sys"},
    ]
    info = detect_os_from_paths(nodes)
    assert info["family"] == "windows"
    assert info["confidence"] in {"medium", "high"}


def test_detect_linux_from_paths():
    nodes = [
        {"path": "etc/passwd"},
        {"path": "etc/os-release"},
        {"path": "var/log/syslog"},
        {"path": "home/bob/.bashrc"},
        {"path": "boot/vmlinuz-6.1"},
    ]
    info = detect_os_from_paths(nodes)
    assert info["family"] == "linux"


def test_windows_full_keeps_critical_even_if_env_skip_true():
    skip, reason = resolve_skip_system_paths(
        mode="full",
        extract_skip_system_paths=True,
        os_family="windows",
    )
    assert skip is False
    assert reason == "windows_full_keep_system_paths"

    for path in (
        "Program Files/WindowsApps/Microsoft.ZuneMusic/foo.mp4",
        "Windows/WinSxS/amd64_microsoft/foo.dll",
        "Windows/System32/LogFiles/WMI/RtBackup/foo.etl",
        "Windows/System32/winevt/Logs/Application.evtx",
        "Users/Bob/Pictures/a.jpg",
    ):
        ok, reason = should_extract_node(
            path,
            1024,
            mode="full",
            max_file_bytes=0,
            skip_system_paths=False,
            os_family="windows",
        )
        assert ok, f"{path} skipped as {reason}"


def test_forensic_drops_winsxs_dll_keeps_media_and_evidence():
    skip, reason = resolve_skip_system_paths(
        mode="forensic",
        extract_skip_system_paths=False,
        os_family="windows",
    )
    assert reason == "forensic_mode_selective_include"

    assert matches_forensic_include("Users/Bob/Documents/report.pdf")
    assert matches_forensic_include("Windows/System32/winevt/Logs/Security.evtx")
    assert matches_forensic_include("Windows/System32/config/SOFTWARE")
    assert matches_forensic_include("Windows/Prefetch/NOTEPAD.EXE-12345678.pf")
    assert matches_forensic_include("Program Files/WindowsApps/Foo/photo.jpg")
    assert matches_forensic_include("Windows/WinSxS/amd64_foo/photo.png")

    assert not matches_forensic_include("Windows/WinSxS/amd64_microsoft/foo.dll")
    assert not matches_forensic_include("Windows/System32/driverstore/FileRepository/x/y.sys")
    assert not matches_forensic_include("Windows/Fonts/arial.ttf")

    ok, why = should_extract_node(
        "Windows/WinSxS/amd64_microsoft/foo.dll",
        4096,
        mode="forensic",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok is False and why == "forensic_filter"

    ok, why = should_extract_node(
        "Users/Bob/Desktop/notes.txt",
        100,
        mode="forensic",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok and why is None


def test_non_windows_can_still_broad_skip():
    skip, _ = resolve_skip_system_paths(
        mode="full",
        extract_skip_system_paths=True,
        os_family="linux",
    )
    assert skip is True
    ok, reason = should_extract_node(
        "Windows/WinSxS/amd64_microsoft/foo.dll",
        1024,
        mode="full",
        max_file_bytes=0,
        skip_system_paths=True,
        os_family="linux",
    )
    assert ok is False
    assert reason == "system_path"


def test_defensible_includes_uncertain_user_and_programdata_files():
    skip, reason = resolve_skip_system_paths(
        mode="defensible",
        extract_skip_system_paths=False,
        os_family="windows",
    )
    assert reason == "defensible_mode_selective_include"

    # Forensic skips WinSxS DLL; defensible still skips large system DLLs but keeps unknowns
    assert not matches_defensible_include(
        "Windows/WinSxS/amd64_microsoft/foo.dll", size_bytes=4096
    )
    assert matches_defensible_include(
        "Windows/WinSxS/amd64_microsoft/unknown_payload", size_bytes=2048
    )

    # User profile — extensionless / unknown always kept
    assert matches_defensible_include("Users/Bob/AppData/Local/Temp/unknown", size_bytes=512)
    assert matches_defensible_include("Users/Bob/AppData/Roaming/noext", size_bytes=100)

    # ProgramData — configs and small unknown binaries
    assert matches_defensible_include("ProgramData/Vendor/config", size_bytes=256)
    assert matches_defensible_include("ProgramData/Startup/suspicious.bin", size_bytes=65536)

    ok, why = should_extract_node(
        "Users/Bob/AppData/Local/Temp/unknown",
        512,
        mode="defensible",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok and why is None

    # Regenerable cache bodies are not evidence, including in defensible mode.
    ok, why = should_extract_node(
        "Users/Bob/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0",
        4096,
        mode="defensible",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok is False and why == "defensible_filter"
    ok, why = should_extract_node(
        "Users/Bob/AppData/Local/Microsoft/Windows/INetCache/IE/abc",
        4096,
        mode="defensible",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok is False and why == "defensible_filter"

    ok, why = should_extract_node(
        "Windows/WinSxS/amd64_microsoft/foo.dll",
        4096,
        mode="forensic",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok is False and why == "forensic_filter"


def test_minimal_skip_still_drops_extend():
    ok, reason = should_extract_node(
        "$Extend/$UsnJrnl:$J",
        1024,
        mode="full",
        max_file_bytes=0,
        skip_system_paths=False,
        os_family="windows",
    )
    assert ok is False
    assert reason == "system_path"


def test_forensic_keeps_browser_and_chat_evidence_not_cache():
    assert matches_forensic_include(
        "Users/Bob/AppData/Local/Google/Chrome/User Data/Profile 1/Favicons"
    )
    assert matches_forensic_include(
        "Users/Bob/AppData/Local/Google/Chrome/User Data/Profile 1/Top Sites"
    )
    assert matches_forensic_include(
        "Users/Bob/AppData/Roaming/discord/Local Storage/leveldb/000003.log"
    )
    assert matches_forensic_include(
        "Users/Bob/AppData/Roaming/Mozilla/Firefox/Profiles/abc123/places.sqlite"
    )

    ok, why = should_extract_node(
        "Users/Bob/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0",
        4096,
        mode="forensic",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok is False and why == "forensic_filter"

    ok, why = should_extract_node(
        "Users/Bob/AppData/Local/Mozilla/Firefox/Profiles/x.default/cache2/doomed/",
        4096,
        mode="forensic",
        max_file_bytes=0,
        os_family="windows",
    )
    assert ok is False and why == "forensic_filter"


def test_ios_image_hashed_file_survives_size_cap_and_forensic_filter():
    hashed = "ios_image/00008150-0002659C0CBB401C/7c/7c7fba66680ef796" + ("a" * 24)
    ok, why = should_extract_node(
        hashed,
        138_493_952,
        mode="forensic",
        max_file_bytes=100_000_000,
        os_family="ios",
    )
    assert ok is True and why is None
    ok, why = should_extract_node(
        "readable_artifacts/whatsapp/7c7fba66680ef796_ChatStorage.sqlite",
        138_493_952,
        mode="mobile",
        max_file_bytes=100_000_000,
        os_family="ios",
    )
    assert ok is True and why is None


def test_critical_files_sql_does_not_bind_zone_parameter():
    from sqlalchemy import text
    from sqlalchemy.sql.elements import BindParameter

    from app.services.artifact_file_forensics import critical_files_where_sql

    sql, binds = critical_files_where_sql()
    stmt = text(f"SELECT 1 FROM job_artifacts WHERE job_id=:jid {sql}")
    names = {
        getattr(el, "key", None)
        for el in stmt._bindparams.values()
        if isinstance(el, BindParameter)
    }
    assert "zone" not in names
    assert "jid" in names
    assert binds == {}
