#!/usr/bin/env python3
"""Regression proof for the artifact-coverage gap closure.

Every path below is an artifact an examiner would be asked about in court and
that the pre-patch pipeline discarded. The test asserts two things:

  1. the OS scope pack claims the path (matches_os_scope), and
  2. the real extraction gate keeps it (should_extract_node in forensic mode).

Run:  python scripts/artifact_gap_regression.py
Exit code 1 on any regression, so it can be wired into CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.extract_filters import should_extract_node  # noqa: E402
from app.services.os_artifact_scope import catalog_entry_for, matches_os_scope  # noqa: E402

CASES: list[tuple[str, str, str]] = [
    # ---------------- Windows ----------------
    ("windows", "$Extend/$UsnJrnl:$J", "USN change journal (was killed by the $extend skip prefix)"),
    ("windows", "Windows.old/Users/jdoe/NTUSER.DAT", "pre-upgrade user hive"),
    ("windows", "Windows.old/Windows/System32/config/SYSTEM", "pre-upgrade system hive"),
    ("windows", "ProgramData/Microsoft/Windows/AppRepository/StateRepository-Machine.srd",
     "installed app inventory"),
    ("windows", "ProgramData/Microsoft/Windows Defender/Quarantine/ResourceData/A1/A1B2C3D4",
     "quarantined malware body (extensionless)"),
    ("windows", "ProgramData/Microsoft/Windows Defender/Support/MPLog-20260701-120000.log",
     "Defender scan log"),
    ("windows", "Windows/SoftwareDistribution/DataStore/DataStore.edb", "update history"),
    ("windows", "Windows/System32/config/SYSTEM.LOG1", "dirty hive transaction log"),
    ("windows", "Windows/System32/config/RegBack/SOFTWARE", "registry backup"),
    ("windows", "Users/jdoe/AppData/Local/Comms/Unistore/data/3/s/0/00000001.dat",
     "Windows Mail unified store"),
    ("windows", "Users/jdoe/AppData/Local/Microsoft/Olk/LocalData/store.db", "new Outlook cache"),
    ("windows", "Windows/System32/SRU/SRUDB.jfm", "ESE sidecar for SRUM"),
    ("windows", "Users/jdoe/Desktop/evidence.E01", "nested forensic container"),
    ("windows", "Windows/System32/Tasks/Microsoft/Windows/UpdateOrchestrator/Reboot",
     "extensionless scheduled task"),
    ("windows", "Users/jdoe/Downloads/setup.exe:Zone.Identifier", "alternate data stream"),
    ("windows", "System Volume Information/{3808876b-c176-4e48-b7ae-04046e6cc752}",
     "volume shadow copy store"),

    # ---------------- Linux ----------------
    ("linux", "var/lib/plocate/plocate.db", "filenames of deleted files"),
    ("linux", "var/lib/systemd/wtmpdb/wtmp.db", "systemd 256+ session accounting"),
    ("linux", "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/17/fs/etc/passwd",
     "container filesystem"),
    ("linux", "var/lib/sss/db/cache_corp.example.com.ldb", "cached domain identities"),
    ("linux", "var/lib/NetworkManager/internal-1234-eth0.lease", "DHCP lease"),
    ("linux", "var/lib/bluetooth/AA:BB:CC:DD:EE:FF/info", "bluetooth pairing"),
    ("linux", "var/spool/cups/d00001-001", "print spool body"),
    ("linux", "var/lib/systemd/coredump/core.nginx.0.abc.1000.1719830400000000.zst", "core dump"),
    ("linux", "home/jdoe/.netrc", "cleartext credentials"),
    ("linux", "var/lib/php/sessions/sess_4f8a2b1c", "web shell session"),
    ("linux", "var/log/journal/9f1c/system.journal", "systemd journal"),

    # ---------------- macOS ----------------
    ("macos", "private/var/db/uuidtext/3A/1B2C3D4E5F", "unified log string catalogue"),
    ("macos", "private/var/db/biome/streams/public/App/local/1234567890", "Biome SEGB stream"),
    ("macos", "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL", "PowerLog"),
    ("macos", "private/var/db/dslocal/nodes/Default/users/jdoe.plist", "local account record"),
    ("macos", "private/var/db/lockdown/1a2b3c4d5e6f.plist", "paired iOS device"),
    ("macos", "Users/jdoe/Library/Application Support/com.apple.TCC/TCC.db", "privacy grants"),
    ("macos", "Users/jdoe/Library/Messages/chat.db-wal", "iMessage WAL sidecar"),
    ("macos", "Users/jdoe/Documents/report.docx.icloud", "evicted iCloud placeholder"),
    ("macos", "private/var/vm/sleepimage", "hibernation memory"),
    ("macos", "Users/jdoe/Library/Saved Application State/com.apple.Safari.savedState/data.data",
     "window contents at last quit"),

    # ---------------- iOS ----------------
    ("ios", "3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28", "backup hash bucket (extensionless)"),
    ("ios", "Manifest.db", "backup hash -> path map"),
    ("ios", "private/var/mobile/Library/Biome/streams/public/Notification/local/123456",
     "Biome behavioural stream"),
    ("ios", "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL", "PowerLog"),
    ("ios", "private/var/mobile/Library/SMS/sms.db-wal", "newest messages live in the WAL"),
    ("ios", "private/var/keybags/systembag.kb", "class keybag"),
    ("ios", "private/var/mobile/Library/Preferences/com.apple.commcenter.plist", "SIM history"),
    ("ios", "private/var/mobile/Library/DeviceActivity/screentime.sqlite", "Screen Time"),
    ("ios", "private/var/mobile/Library/Passes/passes23.sqlite", "Wallet / transit taps"),
    ("ios", "private/var/mobile/Library/Logs/CrashReporter/app-2026-07-01.ips", "crash report"),

    # ---------------- Android ----------------
    ("android", "data/user/10/com.whatsapp/databases/msgstore.db", "work-profile WhatsApp"),
    ("android", "data/user/150/com.samsung.knox.securefolder/databases/sdp.db", "Secure Folder"),
    ("android", "data/user_de/0/com.android.providers.settings/databases/settings.db",
     "device-encrypted store"),
    ("android", "mnt/expand/0a1b2c3d/user/0/com.telegram.messenger/files/cache4.db",
     "adopted SD card"),
    ("android", "data/data/com.google.android.apps.messaging/databases/bugle_db", "RCS chats"),
    ("android", "data/data/com.tencent.mm/mmkv/mmkv.default", "MMKV preference store"),
    ("android", "data/system/dropbox/system_server_crash@1719830400000.txt", "system DropBox"),
    ("android", "data/misc/user/0/cacerts-added/a1b2c3d4.0", "user-added CA (TLS intercept)"),
    ("android", "data/data/com.whatsapp/files/key", "WhatsApp crypt key (extensionless)"),
    ("android", "data/system/notification_history.db", "recalled message text"),
    ("android", "data/adb/magisk.db", "root indicator"),
    ("android", "data/misc/wifi/WifiConfigStore.xml", "saved SSIDs / BSSIDs"),
]


def main() -> int:
    failures: list[str] = []
    for family, path, why in CASES:
        in_scope = matches_os_scope(path, os_family=family)
        kept, reason = should_extract_node(
            path, size_bytes=4096, mode="forensic", max_file_bytes=0, os_family=family,
        )
        if not in_scope:
            failures.append(f"SCOPE  {family:8} {path}  ({why})")
        elif not kept:
            failures.append(f"FILTER {family:8} {path}  -> skipped as {reason}  ({why})")

    total = len(CASES)
    print(f"artifact gap regression: {total - len(failures)}/{total} paths retained")

    unattributed = [
        f"{fam}: {p}" for fam, p, _ in CASES if catalog_entry_for(p, os_family=fam) is None
    ]
    if unattributed:
        print(f"\n{len(unattributed)} path(s) retained without a catalog/provenance entry:")
        for u in unattributed:
            print(f"  - {u}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  {f}")
        return 1
    print("all gap-closure paths survive extraction")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
