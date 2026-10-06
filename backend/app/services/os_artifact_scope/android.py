"""Android artifact scope pack — AXIOM platform 'Android'.

Covers physical/full-filesystem dumps, ADB backups (.ab), Cellebrite/UFED and
Oxygen folder structures, and rooted app-data pulls. Closes gaps around
/data/user_de (direct-boot storage), /data/property, /data/misc/keystore,
/cache/recovery, vendor partitions and Knox/work profiles (/data/user/10+).
"""

from __future__ import annotations

import re

from .base import ArtifactScopePack, CatalogEntry

KEEP_PREFIXES: tuple[str, ...] = (
    # App and user data (all storage classes)
    "data/data/",
    "data/user/",
    "data/user_de/",
    "data/system/",
    "data/system_ce/",
    "data/system_de/",
    "data/misc/",
    "data/misc_ce/",
    "data/misc_de/",
    "data/vendor/",
    "data/property/",
    "data/local/",
    "data/adb/",
    "data/app/",
    "data/log/",
    "data/anr/",
    "data/tombstones/",
    "data/dalvik-cache/profiles/",
    "data/backup/",
    "data/bugreports/",
    "data/media/",
    "data/ss/",
    # External / shared storage
    "sdcard/",
    "storage/emulated/",
    "storage/self/",
    "mnt/sdcard/",
    "mnt/shell/",
    "android/data/",
    "android/obb/",
    "android/media/",
    # System partitions worth reading for config / persistence
    "system/etc/",
    "system/build.prop",
    "vendor/build.prop",
    "product/etc/",
    "persist/",
    "efs/",
    "metadata/",
    "cache/",
    "recovery/",
    # Vendor extraction wrappers
    "dump/",
    "ufeddump/",
    "extraction/",
    "physical/",
    "filesystem/",
    # --- gap closure -------------------------------------------------------
    "data/system_ce/0/",             # credential-encrypted per-user store
    "data/system_de/0/",             # device-encrypted (readable before first unlock)
    "data/misc_ce/0/",
    "data/misc_de/0/",
    "data/user/10/", "data/user/11/", "data/user/95/", "data/user/999/",
    "data/user_de/10/",              # work profile / secure folder / cloned apps
    "data/vendor_ce/", "data/vendor_de/",
    "data/system/users/",
    "data/system/sync/",
    "data/system/dropbox/",          # system crash + event snapshots
    "data/system/notification_log.db",
    "data/system/graphicsstats/",
    "data/system/shutdown-checkpoints/",
    "data/system/appops/",
    "data/system/job/",
    "data/system/deviceidle/",
    "data/system/procstats/",
    "data/system/usagestats/",
    "data/system/netstats/",
    "data/system/batterystats/",
    "data/system/install_sessions/",
    "data/system/package_cache/",
    "data/system/role/",
    "data/system/uiderrors.txt",
    "data/misc/apexdata/",
    "data/misc/emergencynumberdb/",
    "data/misc/location/",           # GNSS fix cache
    "data/misc/gcov/",
    "data/misc/network_watchlist/",
    "data/misc/carrierid/",
    "data/misc/wifi/",
    "data/misc/bluetooth/",
    "data/misc/bluedroid/",
    "data/misc/installd/",
    "data/misc/logd/",
    "data/misc/perfetto-traces/",
    "data/misc/profiles/",
    "data/misc/snapshots/",
    "data/misc/user/0/",             # cacerts-added: TLS interception evidence
    "data/misc/vold/",
    "data/misc/keychain/",
    "data/misc/keystore/",
    "data/apex/",
    "data/rollback/",
    "data/incremental/",
    "data/pkg_staging/",
    "data/nativetest/",
    "data/preloads/",
    "data/resource-cache/",
    "data/unencrypted/",             # FBE metadata
    "data/per_boot/",
    "mnt/expand/",                   # ADOPTED SD CARD — a second /data volume
    "mnt/media_rw/",
    "mnt/vendor/persist/",
    "sdcard/android/data/",
    "sdcard/download/",
    "sdcard/dcim/",
    "sdcard/whatsapp/",
    "sdcard/pictures/",
    "sdcard/movies/",
    "sdcard/documents/",
    "sdcard/tencent/",
    "sdcard/backups/",
    "storage/emulated/0/android/",
    "carrier/",
    "odm/etc/",
    "system_ext/etc/",
    "vendor/etc/",
    "modem/",
    "fsg/",
    "proc/",
)

KEEP_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.crypt[a-z0-9_-]*$", re.I),
    re.compile(r"/(databases|shared_prefs|files|cache|no_backup|app_webview|app_textures)/", re.I),
    re.compile(r"/data/user(_de)?/\d+/", re.I),          # multi-user + work profile
    re.compile(r"/com\.(whatsapp|android|google|facebook|instagram|snapchat|twitter|telegram|viber|signal|discord|tiktok|zhiliaoapp)", re.I),
    re.compile(r"/org\.(telegram|thoughtcrime|whispersystems)", re.I),
    re.compile(r"/data/misc/(wifi|bluedroid|bluetooth|keystore|apns|profiles|radio|user|vold|adb)/", re.I),
    re.compile(r"/data/system/(users|sync|dropbox|netstats|procstats|usagestats|appops|notification)", re.I),
    re.compile(r"/(tombstone|anr|bugreport|dumpstate|logcat|kmsg|last_kmsg|last_log)", re.I),
    re.compile(r"\.(ab|adb|backup)$", re.I),
    re.compile(r"\.(ufd|ufdx|pas)$", re.I),
    re.compile(r"installedappslist", re.I),
)

SPECIAL_BASENAMES: frozenset[str] = frozenset({
    # Package / account / settings state
    "packages.xml", "packages.list", "packages-stopped.xml", "packages-warnings.xml",
    "package-usage.list", "package-cstats.list", "packages.list.tmp",
    "settings_secure.xml", "settings_global.xml", "settings_system.xml", "settings_ssaid.xml",
    "accounts.db", "accounts_ce.db", "accounts_de.db", "users.xml", "userlist.xml",
    "appops.xml", "notification_policy.xml", "device_policies.xml",
    "build.prop", "default.prop", "local.prop", "persist.sys.timezone",
    # Telephony / messaging / contacts
    "mmssms.db", "telephony.db", "sms.db", "contacts2.db", "profile.db",
    "calllog.db", "calls.db", "msgstore.db", "wa.db", "axolotl.db",
    "chatsettings.db", "cache4.db", "logs.db", "threads_db2",
    # Media / location
    "external.db", "internal.db", "media.db", "gservices.db",
    "location.db", "cache.cell", "cache.wifi", "gnss.log",
    # Connectivity
    "wificonfigstore.xml", "wifiblobstore.bin", "wpa_supplicant.conf",
    "bt_config.conf", "bt_config.bak", "bt_config.xml", "btsnoop_hci.log",
    "netpolicy.xml", "netstats", "apns-conf.xml",
    # Usage / power / health
    "usage-history.xml", "batterystats.bin", "batterystats-checkin.bin",
    "appusage", "usagestats", "procstats", "job_pkg_history.xml",
    # Recovery / boot / root
    "last_log", "last_kmsg", "recovery.log", "last_install", "uncrypt_file",
    "magisk.db", "module.prop", "su.db", "supersu.db",
    # Keys and crypto
    "keystore", "user_0", "conscrypt", "certs-added.pem",
    # --- gap closure -------------------------------------------------------
    # Messaging / RCS / carrier
    "bugle_db", "rcs_message_store.db", "rcsprovider.db", "jibe.db",
    "message_store.db", "im.db", "carrier_services.db",
    "com.android.providers.telephony", "mmssms.db-wal", "mmssms.db-shm",
    "contacts2.db-wal", "contacts2.db-shm", "calllog.db-wal", "calllog.db-shm",
    "msgstore.db-wal", "msgstore.db-shm", "wa.db-wal", "wa.db-shm",
    "msgstore.db.crypt14", "msgstore.db.crypt15", "chatsettings.db-wal",
    "key", "encrypted_backup.key",     # WhatsApp crypt key (extensionless)
    # Accounts / identity
    "accounts.db-wal", "accounts.db-shm", "accounts_ce.db-wal", "accounts_de.db-wal",
    "sync_manager.db", "gservices.db-wal", "phenotype.db", "checkin.db",
    "gms_icing", "icing_mobile_application", "clientcontext.db",
    # Device / boot / integrity
    "misc_info.txt", "prop.default", "vendor_build.prop", "odm_build.prop",
    "product_build.prop", "system_ext_build.prop",
    "device_provisioned", "setup_wizard.xml", "flag.xml",
    "last_boot_reason", "boot_reason", "reboot_reason", "shutdown-checkpoints",
    "uiderrors.txt", "dropbox", "event_log", "system_server_crash",
    # Security / root / bypass indicators
    "cacerts-added", "cacerts-removed", "user_ca.crt",
    "adb_keys", "persistent_properties", "selinux_denials",
    "magisk", "magisk.img", "supolicy", "busybox", "xposed.prop",
    "frida-server", "lsposed.log",
    # Location / connectivity
    "gnss_log.txt", "location_manager_service.db", "gnss.db",
    "networkpolicy.xml", "netstats_uid.bin", "netstats_xt.bin",
    "wifi.db", "wifi_config_store.xml", "wifiblobstore.bin",
    "networkhistory.txt", "wpa_supplicant.log", "networkfactory.db",
    "bt_did.conf", "bt_stack.conf", "bt_remote_dev.db",
    # Usage / behaviour
    "notification_log.db", "notification_history.db",
    "appusagestats", "daily", "weekly", "monthly", "yearly",
    "package-usage.list.tmp", "package_cache", "appsearch",
    "job_pkg_history.xml", "jobs.xml", "alarms.xml",
    # Media / gallery
    "external.db-wal", "external.db-shm", "internal.db-wal",
    "localcache.db", "picasa.db", "gallery.db", "thumbnails.db",
    "filecache.db", "downloads.db", "download_manager.db",
    # Cloud / backup
    "backup_pw", "ancestral", "journal", "pending",
    "com.google.android.gms", "cloudbackup.db",
    # Vendor-specific stores (Samsung / Xiaomi / Huawei / OPPO / Vivo)
    "sec_container", "knox.db", "securefolder.db", "sdp.db",
    "samsung_notes.db", "smemo.db", "sbrowser", "logs_history.db",
    "miui.db", "cloudservice.db", "securitycenter.db", "xiaomi_account.db",
    "hwid.db", "hicloud.db", "hisuite.db",
    "coloros.db", "oppo_account.db", "vivo_account.db",
    "dualapp", "clone_app", "app_clone", "parallel_space",
})

BASENAME_PREFIXES: tuple[str, ...] = (
    "tombstone_", "anr_", "bugreport", "dumpstate", "logcat", "msgstore",
    "wa.db", "settings_", "packages", "batterystats", "usagestats",
    "1000_", "persist.", "ro.", "com.", "org.", "net.",
)

BASENAME_SUFFIXES: tuple[str, ...] = (
    ".db", ".db-wal", ".db-shm", ".db-journal",
    ".sqlite", ".sqlite-wal", ".sqlite-shm",
    ".xml", ".xml.bak", ".prop", ".conf", ".list", ".json", ".proto", ".pb",
    ".apk", ".xapk", ".apks", ".dex", ".odex", ".vdex", ".art",
    ".ab", ".adb", ".backup", ".crypt12", ".crypt14", ".crypt15", ".crypt",
    ".log", ".txt", ".bin", ".key", ".pem", ".nomedia",
    ".ufd", ".ufdx", ".pas",
)

EXTENSIONS: frozenset[str] = frozenset({
    ".db", ".db-wal", ".db-shm", ".db-journal",
    ".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlite3",
    ".xml", ".prop", ".conf", ".list", ".json", ".proto", ".pb", ".cfg",
    ".apk", ".xapk", ".apks", ".dex", ".odex", ".vdex", ".oat", ".art",
    ".ab", ".adb", ".backup", ".crypt", ".crypt12", ".crypt14", ".crypt15", ".mcrypt1",
    ".log", ".txt", ".bin", ".key", ".pem", ".jks", ".bks", ".keystore",
    ".ufd", ".ufdx", ".pas", ".nomedia", ".vcf", ".ics",
    ".jpg", ".jpeg", ".png", ".webp", ".heic", ".mp4", ".3gp", ".amr", ".opus", ".m4a",
    # --- gap closure ---
    ".realm", ".leveldb", ".ldb", ".sst", ".mmkv", ".mmap", ".ndb", ".idb",
    ".kv", ".hprof", ".pb.gz", ".pbtxt", ".binarypb", ".ab.gz", ".tar", ".tar.gz",
    ".7z", ".rar", ".zip", ".bz2", ".img", ".mbn", ".elf", ".ozip", ".new.dat",
    ".sig", ".sha1", ".md5", ".trace", ".perfetto-trace", ".pftrace",
    ".kmsg", ".dmesg", ".ser", ".idx", ".index", ".meta", ".journal",
    ".csv", ".tsv", ".html", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".odt", ".rtf", ".epub", ".gif", ".bmp", ".tiff", ".dng",
    ".svg", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".ts", ".m3u8",
    ".wav", ".flac", ".ogg", ".aac", ".awb", ".qcp", ".vcs", ".vcard",
    ".p12", ".pfx", ".cer", ".der", ".crt", ".kdbx", ".so", ".prof", ".profm",
    ".dd", ".e01",
})

EXTENSIONLESS_DIRS: tuple[str, ...] = (
    "data/data/",
    "data/user/",
    "data/user_de/",
    "data/system/",
    "data/system_ce/",
    "data/system_de/",
    "data/misc/",
    "data/property/",
    "data/adb/",
    "data/local/",
    "data/tombstones/",
    "data/anr/",
    "data/vendor/",
    "cache/recovery/",
    "persist/",
    "efs/",
    "metadata/",
    "/shared_prefs/",
    "/databases/",
    "/files/",
    "/no_backup/",
    "dump/",
    # --- gap closure ---
    "data/system_ce/",
    "data/system_de/",
    "data/misc_ce/",
    "data/misc_de/",
    "data/misc/keystore/",
    "data/misc/keychain/",
    "data/misc/vold/",
    "data/misc/user/",
    "data/misc/wifi/",
    "data/misc/bluedroid/",
    "data/misc/profiles/",
    "data/misc/apexdata/",
    "data/misc/location/",
    "data/system/dropbox/",
    "data/system/users/",
    "data/system/sync/",
    "data/system/usagestats/",
    "data/system/procstats/",
    "data/system/netstats/",
    "data/unencrypted/",
    "data/rollback/",
    "data/apex/",
    "data/per_boot/",
    "mnt/expand/",
    "mnt/media_rw/",
    "mnt/vendor/persist/",
    "/app_webview/",
    "/code_cache/",
    "/mmkv/",
    "/leveldb/",
    "/blob_storage/",
    "efs/",
    "metadata/",
    "fsg/",
    "modem/",
)

NOISE_PREFIXES: tuple[str, ...] = (
    "system/fonts/",
    "system/framework/",
    "system/app/",
    "system/priv-app/",
    "system/lib/",
    "system/lib64/",
    "vendor/lib/",
    "vendor/firmware/",
    "apex/",
    "data/dalvik-cache/arm",
    "data/dalvik-cache/arm64",
)

CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(r"data/user_de/", "Direct-boot (DE) app storage", "Application Usage",
                 "Android 7+ splits app data into credential-encrypted (/data/data) and "
                 "device-encrypted (/data/user_de). Telephony and dialer data often live in DE — "
                 "a filter that only knows /data/data misses SMS entirely on some devices.",
                 "sqlite", True),
    CatalogEntry(r"data/user/\d+/", "Multi-user / work profile", "Operating System",
                 "Profile 10+ = Knox / Android Work container: a second, separate evidence set on "
                 "the same handset.", "sqlite", True),
    CatalogEntry(r"(mmssms\.db|telephony\.db)", "SMS / MMS", "Communication",
                 "Message bodies, threads, delivery state.", "sqlite", True),
    CatalogEntry(r"msgstore\.db|wa\.db|\.crypt1[245]$", "WhatsApp", "Communication",
                 "Chats, contacts and the encrypted backup variants (crypt12/14/15) that require "
                 "the key file from /data/data/com.whatsapp/files/key.", "sqlite", True),
    CatalogEntry(r"contacts2\.db|calllog\.db", "Contacts / call log", "Communication",
                 "Contact identities and call records.", "sqlite", True),
    CatalogEntry(r"/shared_prefs/", "Shared preferences", "Application Usage",
                 "Per-app account identifiers, tokens, last-used timestamps, feature flags. "
                 "Small XML files that are frequently the only surviving account evidence.",
                 "xml", True),
    CatalogEntry(r"data/system/packages\.(xml|list)", "Installed packages", "Application Usage",
                 "Install source, first-install/last-update time, UID mapping, permissions — "
                 "including sideloaded packages.", "xml", True),
    CatalogEntry(r"settings_(secure|global|system)\.xml", "System settings", "Operating System",
                 "ANDROID_ID, ADB/unknown-sources state, device name, lock settings.", "xml", True),
    CatalogEntry(r"data/misc/wifi/|wificonfigstore", "Saved WiFi", "Connected Devices",
                 "SSID/BSSID history and PSKs — device geolocation and network attribution.",
                 "xml", True),
    CatalogEntry(r"bt_config|bluedroid", "Bluetooth pairings", "Connected Devices",
                 "MACs and names of paired devices (vehicles, headsets, other handsets).",
                 "conf", True),
    CatalogEntry(r"data/system/(usagestats|procstats|appops)", "Usage statistics", "Application Usage",
                 "Foreground time and last-used per package — behavioural timeline.", "proto", True),
    CatalogEntry(r"data/system/dropbox/", "DropBoxManager", "Operating System",
                 "System crash/ANR/wtf entries retained with timestamps.", "text"),
    CatalogEntry(r"data/(anr|tombstones)/", "ANR / tombstones", "Operating System",
                 "Native crash dumps naming every running process at the time.", "text"),
    CatalogEntry(r"data/adb/|magisk|supersu", "Root / Magisk artefacts", "Operating System",
                 "Root state materially affects evidential weight and must be reported.",
                 "text", True),
    CatalogEntry(r"data/misc/keystore/", "Android Keystore", "Encryption & Credentials",
                 "Hardware-backed key blobs referenced by app credential stores.", "blob", True),
    CatalogEntry(r"data/property/", "System properties", "Operating System",
                 "persist.* values: timezone, serial, first-boot, OEM unlock state.", "text"),
    CatalogEntry(r"cache/recovery/", "Recovery logs", "Operating System",
                 "Factory-reset and OTA history — anti-forensic wipe evidence.", "text", True),
    CatalogEntry(r"\.(ufd|ufdx|pas)$", "Vendor extraction metadata", "Operating System",
                 "Cellebrite acquisition provenance for chain of custody.", "vendor_meta", True),
)

CATALOG = CATALOG + (
    # --- gap closure -------------------------------------------------------
    CatalogEntry(r"/data/user(_de)?/(?!0/)\d+/", "Secondary user / work profile / cloned app",
                 "Additional Sources",
                 "User 0 is only the primary profile. Work profiles (user 10+), Samsung Secure "
                 "Folder (user 150), Xiaomi Second Space and app-cloning containers each hold a "
                 "SEPARATE copy of WhatsApp, Telegram and the browser. Collecting only "
                 "/data/data misses the profile a subject actually used to hide activity.",
                 "path_inventory", True),
    CatalogEntry(r"data/system_de/", "Device-encrypted store", "Operating System",
                 "Readable before first unlock (Direct Boot). Holds lock-screen metadata, "
                 "user list and last-unlock timestamps.", "path_inventory", True),
    CatalogEntry(r"^mnt/expand/", "Adopted SD card", "Additional Sources",
                 "An adopted card is an encrypted extension of /data carrying complete app "
                 "private directories — a second data volume that is routinely missed.",
                 "nested_source", True),
    CatalogEntry(r"(bugle_db|rcs_message_store|rcsprovider|jibe)", "RCS / Google Messages",
                 "Chat",
                 "RCS chats live in bugle_db, NOT in mmssms.db. A collector that grabs only the "
                 "telephony provider reports zero messages on a modern Android phone.",
                 "sqlite", True),
    CatalogEntry(r"/mmkv/|\.mmkv", "MMKV preference store", "Application Usage",
                 "Tencent MMKV memory-mapped store used by WeChat, QQ, TikTok and many SDKs "
                 "instead of shared_prefs XML. Extensionless/opaque and usually skipped.",
                 "mmkv", True),
    CatalogEntry(r"data/system/dropbox/", "System DropBox", "Operating System",
                 "Timestamped snapshots of crashes, ANRs, kernel events and system server "
                 "restarts — a de-facto system event log.", "dropbox", True),
    CatalogEntry(r"/misc/user/\d+/cacerts-added", "User-added CA certificates", "Network Activity",
                 "A user-installed root CA is the signature of TLS interception / MDM / "
                 "stalkerware traffic capture.", "cert", True),
    CatalogEntry(r"(magisk|frida-server|lsposed|xposed|supolicy|adb_keys)", "Root / instrumentation indicators",
                 "Operating System",
                 "Establishes whether the device was rooted or instrumented — directly affects "
                 "the reliability weight given to every other artifact.", "path_inventory", True),
    CatalogEntry(r"data/misc/(wifi|bluedroid|bluetooth)/", "WiFi + Bluetooth state", "Connections",
                 "Saved SSIDs with BSSIDs, and paired-device MAC addresses: geolocation by "
                 "wardriving lookup and proximity association.", "xml_prefs", True),
    CatalogEntry(r"notification_(log|history)\.db", "Notification history", "Chat",
                 "Retains the text of notifications from messaging apps even when the app's own "
                 "database has been cleared or the message was remotely deleted.", "sqlite", True),
    CatalogEntry(r"(encrypted_backup\.key|/files/key$)", "WhatsApp crypt key", "Encryption & Credentials",
                 "Extensionless key file required to decrypt msgstore.db.crypt14/15. Without it "
                 "the chat database is unreadable.", "whatsapp_crypt", True),
    CatalogEntry(r"data/system/(usagestats|procstats|netstats|batterystats)", "Usage accounting",
                 "Application Usage",
                 "Protobuf usage stats give per-app foreground time and last-used timestamps, "
                 "including for apps that have since been uninstalled.", "protobuf_usagestats", True),
    CatalogEntry(r"(sec_container|knox|securefolder|sdp\.db|miui|hicloud|coloros)", "Vendor secure containers",
                 "Additional Sources",
                 "Samsung Knox/Secure Folder, Xiaomi MIUI, Huawei and OPPO stores hold "
                 "separately encrypted user data outside the AOSP paths.", "path_inventory", True),
    CatalogEntry(r"data/misc/keystore/", "Android Keystore blobs", "Encryption & Credentials",
                 "Hardware-backed key blobs; needed to reason about what could and could not "
                 "be decrypted off-device.", "path_inventory"),
)

PACK = ArtifactScopePack(
    os_family="android",
    axiom_platform="Android",
    keep_prefixes=KEEP_PREFIXES,
    keep_regexes=KEEP_REGEXES,
    special_basenames=SPECIAL_BASENAMES,
    basename_prefixes=BASENAME_PREFIXES,
    basename_suffixes=BASENAME_SUFFIXES,
    extensions=EXTENSIONS,
    extensionless_dirs=EXTENSIONLESS_DIRS,
    noise_prefixes=NOISE_PREFIXES,
    catalog=CATALOG,
)
