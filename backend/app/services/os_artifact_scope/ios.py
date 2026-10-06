"""iOS / iPadOS artifact scope pack — AXIOM platform 'iOS'.

Handles three distinct acquisition shapes, which is why iOS needs its own agent:

  A. iTunes/Finder backup  — Manifest.db + 256 hash-named buckets (00..ff) of
     EXTENSIONLESS files. Without a rule for the buckets, the entire evidence
     body is dropped and only the manifests survive.
  B. Full filesystem (checkm8 / agent-based / GrayKey) — /private/var/mobile/...
  C. UFED / GrayKey logical or advanced-logical — vendor wrapper + payload tree.
"""

from __future__ import annotations

import re

from .base import ArtifactScopePack, CatalogEntry

KEEP_PREFIXES: tuple[str, ...] = (
    "private/var/mobile/",
    "private/var/root/",
    "private/var/wireless/",
    "private/var/keybags/",
    "private/var/keychains/",
    "private/var/db/",
    "private/var/logs/",
    "private/var/log/",
    "private/var/preferences/",
    "private/var/installd/",
    "private/var/containers/",
    "private/var/mobiledevicelogs/",
    "private/etc/",
    "var/mobile/",
    "var/wireless/",
    "var/keybags/",
    "var/keychains/",
    "var/db/",
    "var/logs/",
    "var/installd/",
    "var/containers/",
    "var/preferences/",
    "applications/",
    "system/library/caches/",
    # Backup shapes
    "backups/",
    "backup/",
    "mobilesync/",
    "itunes_control/",
    # Vendor extraction wrappers
    "filesystem1/",
    "filesystem2/",
    # --- gap closure -------------------------------------------------------
    "private/var/mobile/library/biome/",        # SEGB behavioural streams
    "private/var/db/powerlog/",                 # CurrentPowerlog.PLSQL
    "private/var/mobile/library/callhistorydb/",
    "private/var/mobile/library/coreduet/",
    "private/var/mobile/library/frontboard/",   # app launch history
    "private/var/mobile/library/springboard/",
    "private/var/mobile/library/carplay/",
    "private/var/mobile/library/suggestions/",
    "private/var/mobile/library/homekit/",
    "private/var/mobile/library/passes/",       # Wallet: transit + payment
    "private/var/mobile/library/shortcuts/",
    "private/var/mobile/library/deviceactivity/",   # Screen Time
    "private/var/mobile/library/duetexpertd/",
    "private/var/mobile/library/trial/",
    "private/var/mobile/library/spotlight/",
    "private/var/mobile/library/filepicker/",
    "private/var/mobile/library/mobile documents/", # iCloud Drive local cache
    "private/var/mobile/library/application support/com.apple.remotemanagement/",
    "private/var/containers/shared/systemgroup/",
    "private/var/containers/data/",
    "private/var/mobile/containers/data/",
    "private/var/mobile/containers/shared/",
    "private/var/mobile/media/",
    "private/var/root/library/",
    "private/var/preferences/logs/",
    "private/var/mobile/library/logs/crashreporter/",
    "private/var/tmp/",
    "sysdiagnose/",
    "logs/",
    "ufeddump/",
    "extraction/",
)

KEEP_REGEXES: tuple[re.Pattern[str], ...] = (
    # iTunes/Finder backup hash buckets: <2-hex>/<40-hex>
    re.compile(r"(^|/)[0-9a-f]{2}/[0-9a-f]{40}$", re.I),
    # Backup root manifests / metadata
    re.compile(r"(^|/)(manifest|info|status)\.(db|plist|mbdb|mbdx)$", re.I),
    # App containers (Data / Shared / Bundle)
    re.compile(r"/containers/(data|shared|bundle)/", re.I),
    re.compile(r"/appgroup/|/pluginkitplugin/|/systemgroup/", re.I),
    # High-value stores wherever they land
    re.compile(r"/(sms|callhistory|addressbook|notes|photos|healthdb|calendar|voicemail|safari|knowledgec)\b", re.I),
    re.compile(r"/library/(sms|mail|calendar|callhistorydb|voicemail|safari|caches|preferences|databases|cookies|accounts|keyboard|springboard|assistant|健康)/", re.I),
    re.compile(r"/media/(dcim|photodata|recordings|downloads|books|purchases)/", re.I),
    re.compile(r"/wireless/library/(databases|preferences)/", re.I),
    re.compile(r"/db/(diagnostics|uuidtext|analyticsd|lockdown|timezone)/", re.I),
    # Vendor report/metadata files that carry acquisition provenance
    re.compile(r"\.(ufd|ufdx|pas|bin\.xml)$", re.I),
)

SPECIAL_BASENAMES: frozenset[str] = frozenset({
    # Backup control files
    "manifest.db", "manifest.plist", "manifest.mbdb", "manifest.mbdx",
    "info.plist", "status.plist", "lockdown.plist",
    # Messaging / calls / contacts
    "sms.db", "chatstorage.sqlite", "callhistory.storedata", "call_history.db",
    "addressbook.sqlitedb", "addressbookimages.sqlitedb", "voicemail.db",
    "notes.sqlite", "notestore.sqlite", "calendar.sqlitedb", "reminders.sqlite",
    # Media / location / health
    "photos.sqlite", "photos.db", "assets.sqlite", "cache_encryptedb.db",
    "cache_encrypteda.db", "consolidated.db", "locationd.sqlite", "routined.db",
    "healthdb.sqlite", "healthdb_secure.sqlite", "cache.sqlite",
    # System / usage
    "knowledgec.db", "interactionc.db", "datausage.sqlite", "netusage.sqlite",
    "carrier_data.db", "com.apple.mobile.installation.plist",
    "lastlaunchservicesmap.plist", "applicationstate.db", "iconstate.plist",
    "com.apple.springboard.plist", "com.apple.preferences.datetime.plist",
    "com.apple.wifi.plist", "com.apple.wifi-networks.plist",
    "com.apple.mobilephone.speeddial.plist", "com.apple.accountsettings.plist",
    "accounts3.sqlite", "accounts4.sqlite", "keychain-2.db", "keychain-backup.plist",
    "systembag.kb", "escrowbag", "protectedbag",
    "safari/history.db", "history.db", "bookmarks.db", "cloudtabs.db",
    "browserstate.db", "recentlyclosedtabs.plist", "topsites.plist",
    "cookies.binarycookies",
    # --- gap closure -------------------------------------------------------
    "currentpowerlog.plsql", "powerlog.plsql",
    "callhistory.storedata-wal", "callhistory.storedata-shm",
    "sms.db-wal", "sms.db-shm", "chatstorage.sqlite-wal", "chatstorage.sqlite-shm",
    "contactsv2.db", "contacts.sqlite", "quickpath.db",
    "biome", "segb", "streams",
    "screentime.sqlite", "rmadmin.sqlite", "rmmodel.sqlite",
    "passes23.sqlite", "nanopasses.sqlite",           # Wallet / transit taps
    "healthdb_secure.sqlite-wal", "healthdb_secure.sqlite-shm",
    "com.apple.mobileslideshow.plist", "com.apple.camera.plist",
    "com.apple.mobiletimer.plist", "com.apple.mobilemail.plist",
    "com.apple.mobilesafari.plist", "com.apple.mobilesms.plist",
    "com.apple.purplebuddy.plist",                    # first-boot / activation time
    "com.apple.mobiledevice.plist", "com.apple.locationd.plist",
    "com.apple.networkextension.plist", "com.apple.mobilegestalt.plist",
    "com.apple.commcenter.plist", "com.apple.commcenter.callservices.plist",
    "com.apple.commcenter.device_specific_nobackup.plist",
    "com.apple.identityservices.idstatuscache.plist",
    "com.apple.imservice.ids.imessage.plist",
    "com.apple.mobilebackup.plist", "com.apple.mobile.ldbackup.plist",
    "com.apple.airtraffic.plist", "com.apple.airdrop.plist",
    "com.apple.sharingd.plist", "com.apple.proximityd.plist",
    "com.apple.bluetooth.plist", "com.apple.mobilewifi.plist",
    "com.apple.mobile.battery_health.plist",
    "com.apple.restrictionspassword.plist",
    "data_ark.plist", "activation_record.plist", "iokitstats.plist",
    "cache_encryptedb.db-wal", "cache_encryptedb.db-shm",
    "appconduit.db", "wireless_carrier.plist",
    "installedappslist.plist", "applicationstate.db-wal", "applicationstate.db-shm",
    "carrier_bundle.plist", "sim_history.plist",
    "cellularusage.db", "wireless.db", "dataaccess.sqlite",
    "notificationstore.db", "duetexpertd.db",
    "recents.db", "recents.storedata", "callhistorytemp.storedata",
    "envelope index", "protected index", "mailboxes.plist",
    "wallet.sqlite", "signature.sqlite",
    "mediaanalysis.db", "photos.sqlite-wal", "photos.sqlite-shm",
    "assetsd.db", "geodmapscache.db", "mapsync.db",
    "com.apple.maps.plist", "history.mapsdata", "geohistory.mapsdata",
    "systemversion.plist", "buildmanifest.plist", "restore.plist",
})

BASENAME_PREFIXES: tuple[str, ...] = (
    "manifest", "keychain", "systembag", "escrowbag", "com.apple.",
    "net.whatsapp", "ph.telegra", "org.whispersystems", "com.burbn.instagram",
    "com.facebook", "com.toyopagroup", "com.google", "com.snapchat",
)

BASENAME_SUFFIXES: tuple[str, ...] = (
    ".storedata", ".storedata-wal", ".storedata-shm",
    ".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlitedb", ".sqlitedb-wal", ".sqlitedb-shm",
    ".db", ".db-wal", ".db-shm", ".db-journal",
    ".plist", ".binarycookies", ".ips", ".synced", ".stub",
    ".tracev3", ".kb", ".pem", ".mobileprovision", ".mobileconfig",
    ".aae", ".heic", ".heif", ".mov", ".m4a", ".amr", ".caf", ".livephoto",
    ".ufd", ".ufdx", ".pas",
)

EXTENSIONS: frozenset[str] = frozenset({
    ".storedata", ".storedata-wal", ".storedata-shm",
    ".sqlite-wal", ".sqlite-shm", ".sqlitedb", ".sqlitedb-wal", ".sqlitedb-shm",
    ".db-wal", ".db-shm", ".db-journal",
    ".plist", ".binarycookies", ".ips", ".panic", ".synced", ".stub",
    ".tracev3", ".dsc", ".kb", ".mobileprovision", ".mobileconfig", ".pkpass",
    ".aae", ".livephoto", ".heic", ".heif", ".caf", ".amr", ".m4a",
    ".ufd", ".ufdx", ".pas", ".ipa", ".ipsw", ".shsh2",
    ".webarchive", ".emlx", ".vcf", ".ics",
    # --- gap closure -------------------------------------------------------
    ".segb", ".plsql", ".mapsdata", ".storedata-journal",
    ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".realm", ".realm.lock",
    ".protobuf", ".pb", ".pbdata", ".bplist", ".archive",
    ".itdb", ".itl", ".ithmb",                   # iTunes/photo thumbnail databases
    ".mddata", ".mdbackup", ".mbdb", ".mbdx",    # legacy backup formats
    ".shsh", ".blob", ".plist.bak",
    ".log", ".log.gz", ".ips.ca", ".ips.beta", ".crash", ".stacks",
    ".jpg", ".jpeg", ".png", ".gif", ".mov", ".mp4", ".m4v", ".hevc",
    ".pdf", ".docx", ".xlsx", ".pptx", ".pages", ".numbers", ".key",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".p12", ".pem", ".cer", ".der", ".mobilekey",
    ".tar.gz", ".sysdiagnose", ".gzip",
    ".dmg", ".e01", ".bin",
})

EXTENSIONLESS_DIRS: tuple[str, ...] = (
    "backups/",
    "backup/",
    "mobilesync/backup/",
    "private/var/keybags/",
    "var/keybags/",
    "private/var/mobile/library/",
    "var/mobile/library/",
    "/containers/data/",
    "/containers/shared/",
    "/appgroup/",
    "private/var/db/uuidtext/",
    "var/db/uuidtext/",
    "itunes_control/",
    "/library/caches/",
    "/library/cookies/",
    "/library/accounts/",
    "/keychains/",
    # --- gap closure ---
    "/library/biome/",
    "/db/powerlog/",
    "/library/coreduet/",
    "/library/frontboard/",
    "/library/springboard/",
    "/library/deviceactivity/",
    "/library/suggestions/",
    "/library/passes/",
    "/library/shortcuts/",
    "/library/homekit/",
    "/library/mobile documents/",
    "/library/logs/crashreporter/",
    "/containers/data/",
    "/containers/shared/",
    "/systemgroup/",
    "/media/dcim/",
    "/media/photodata/",
    "/media/recordings/",
    "var/preferences/",
    "var/wireless/library/",
    "sysdiagnose/",
)

NOISE_PREFIXES: tuple[str, ...] = (
    "system/library/frameworks/",
    "system/library/privateframeworks/",
    "system/library/fonts/",
    "usr/lib/",
    "usr/share/",
    "/library/caches/com.apple.dyld/",
    "/library/assets/",
)

CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(r"[0-9a-f]{2}/[0-9a-f]{40}$", "iOS backup content file", "Additional Sources",
                 "The backup payload itself. Filenames are SHA-1 of domain+relativePath and carry "
                 "no extension; Manifest.db maps them back to real names. Dropping these leaves "
                 "an empty case.", "ios_backup", True),
    CatalogEntry(r"manifest\.(db|plist|mbdb)", "iOS backup manifest", "Additional Sources",
                 "Maps hash filenames to domains/paths; also flags whether the backup is encrypted.",
                 "ios_backup", True),
    CatalogEntry(r"(sms\.db|chatstorage\.sqlite)", "Messages / WhatsApp", "Communication",
                 "Message bodies, attachments, participants, read receipts.", "sqlite", True),
    CatalogEntry(r"-wal$|-shm$|-journal$", "SQLite write-ahead sidecars", "Communication",
                 "Unflushed and recently-deleted rows live only in the WAL. Collecting the .db "
                 "without its -wal silently loses the newest messages.", "sqlite", True),
    CatalogEntry(r"callhistory\.storedata", "Call history", "Communication",
                 "Incoming/outgoing/FaceTime call records with durations.", "sqlite", True),
    CatalogEntry(r"knowledgec\.db", "KnowledgeC", "Application Usage",
                 "App usage, device lock/unlock, notifications, Now-Playing, battery — the richest "
                 "iOS behavioural timeline.", "sqlite", True),
    CatalogEntry(r"(cache_encrypted[ab]\.db|consolidated\.db|routined)", "Location", "Location and Travel",
                 "Significant locations, cell/WiFi fixes, visit clustering.", "sqlite", True),
    CatalogEntry(r"photos\.sqlite", "Photos library", "Media",
                 "Asset metadata, albums, faces, deleted-but-recoverable assets, original EXIF.",
                 "sqlite", True),
    CatalogEntry(r"datausage\.sqlite|netusage", "Data usage", "Application Usage",
                 "Per-process bytes in/out with first/last seen — proves app-level exfiltration.",
                 "sqlite"),
    CatalogEntry(r"(keychain-2\.db|systembag\.kb|escrowbag)", "Keychain / keybag", "Encryption & Credentials",
                 "Credential store and the class keys needed to decrypt protected items.",
                 "keychain", True),
    CatalogEntry(r"applicationstate\.db|lastlaunchservicesmap", "Installed apps", "Application Usage",
                 "Bundle IDs, container GUID mapping, install state — resolves opaque container paths.",
                 "sqlite", True),
    CatalogEntry(r"cookies\.binarycookies", "Safari cookies", "Web Related",
                 "Authenticated session evidence for web accounts.", "binarycookies"),
    CatalogEntry(r"\.(ufd|ufdx|pas)$", "Vendor extraction metadata", "Operating System",
                 "Cellebrite acquisition provenance — device IMEI/serial, method, examiner, hashes. "
                 "Required for the chain-of-custody section.", "vendor_meta", True),
)

CATALOG = CATALOG + (
    # --- gap closure -------------------------------------------------------
    CatalogEntry(r"(^|/)[0-9a-f]{2}/[0-9a-f]{40}$", "iTunes/Finder backup hash bucket",
                 "Additional Sources",
                 "Every file in an iOS backup is stored extensionless under a two-character "
                 "directory as a 40-char SHA-1 name. A collector that filters by extension "
                 "collects NOTHING from an iOS backup. Manifest.db maps hash -> real path.",
                 "ios_backup_manifest", True),
    CatalogEntry(r"/library/biome/", "Biome / SEGB streams", "Application Usage",
                 "iOS 15+ behavioural streams: app launch/close, notifications, device "
                 "lock/unlock, Bluetooth pairing, location. Replaced much of KnowledgeC and "
                 "is the highest-value modern iOS timeline source.", "segb", True),
    CatalogEntry(r"powerlog", "PowerLog", "Application Usage",
                 "Per-app usage, network bytes, location fixes and battery events for roughly "
                 "the last 30 days — survives app deletion.", "sqlite", True),
    CatalogEntry(r"/library/deviceactivity/", "Screen Time", "Application Usage",
                 "Per-app and per-website usage duration by day, including web categories.",
                 "sqlite"),
    CatalogEntry(r"/library/passes/", "Wallet passes", "Financial",
                 "Transit taps and payment passes place the device at a location and time.",
                 "sqlite"),
    CatalogEntry(r"\.storedata|\.sqlite|\.db($|-)", "SQLite + WAL/SHM sidecars", "Chat",
                 "The -wal file holds committed-but-unflushed rows. On a live-seized phone the "
                 "newest messages are in the WAL, not the main database. Collect all three.",
                 "sqlite", True),
    CatalogEntry(r"/keybags/|systembag\.kb|escrowbag", "Keybags", "Encryption & Credentials",
                 "Class-key material required to decrypt protected files and the keychain.",
                 "keybag", True),
    CatalogEntry(r"com\.apple\.purplebuddy\.plist", "Device setup record", "Device Information",
                 "First-boot/activation timestamp — establishes when the device entered service "
                 "and exposes wipe-and-restore events.", "plist", True),
    CatalogEntry(r"com\.apple\.commcenter", "CommCenter / SIM history", "Device Information",
                 "IMSI/ICCID history: every SIM ever inserted, with carrier and timestamps.",
                 "plist", True),
    CatalogEntry(r"sysdiagnose", "sysdiagnose bundle", "Additional Sources",
                 "A user- or MDM-triggered diagnostic archive containing logs, process lists "
                 "and network state; often the only source on a device that cannot be imaged.",
                 "nested_source"),
    CatalogEntry(r"/library/logs/crashreporter/", "Crash reports", "Application Usage",
                 "Names every process that ran and crashed, including deleted applications.",
                 "ips"),
    CatalogEntry(r"/library/mobile documents/", "iCloud Drive cache", "Cloud Storage",
                 "Locally materialised iCloud files plus stubs for evicted content.",
                 "path_inventory"),
    CatalogEntry(r"applicationstate\.db", "Application state", "Installed Applications",
                 "Bundle ID to container UUID mapping — required to attribute a container "
                 "directory to a named app, including apps since uninstalled.", "sqlite", True),
)

PACK = ArtifactScopePack(
    os_family="ios",
    axiom_platform="iOS",
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
