"""macOS artifact scope pack — AXIOM platform 'macOS'.

Closes: FSEvents (extensionless, gzipped), ASL logs, BSM audit trails,
uuidtext/dsc (required to decode .tracev3 unified logs), SFL2 recent items,
Spotlight store, quarantine DB, APFS /System/Volumes/Data path prefixing.
"""

from __future__ import annotations

import re

from .base import ArtifactScopePack, CatalogEntry

KEEP_PREFIXES: tuple[str, ...] = (
    "users/",
    "library/",
    "private/etc/",
    "private/var/db/",
    "private/var/log/",
    "private/var/audit/",
    "private/var/root/",
    "private/var/at/",
    "private/var/vm/",
    "private/var/folders/",
    "private/tmp/",
    "etc/",
    "var/db/",
    "var/log/",
    "var/audit/",
    ".fseventsd/",
    ".spotlight-v100/",
    ".documentrevisions-v100/",
    ".temporaryitems/",
    ".trashes/",
    "volumes/",
    "applications/",
    "system/library/launchdaemons/",
    "system/library/launchagents/",
    "system/library/coreservices/",
    "usr/local/",
    "opt/",
    "cores/",
    # APFS: everything real is under the Data volume on 10.15+
    "system/volumes/data/",
    # --- gap closure -------------------------------------------------------
    "private/var/db/CoreDuet/",          # KnowledgeC + interaction graph
    "private/var/db/biome/",             # Biome/SEGB streams (post-Monterey behaviour)
    "private/var/db/powerlog/",          # app usage / location / network per process
    "private/var/db/analyticsd/",
    "private/var/db/diagnostics/",       # unified log .tracev3
    "private/var/db/uuidtext/",          # REQUIRED to decode the unified log
    "private/var/db/dslocal/",           # local account records + shadow hashes
    "private/var/db/lockdown/",          # iOS devices paired with this Mac
    "private/var/db/mds/",               # Spotlight metadata store
    "private/var/db/receipts/",
    "private/var/db/ConfigurationProfiles/",
    "private/var/db/RemoteManagement/",  # MDM enrolment
    "private/var/db/timed/",             # clock changes = anti-forensics
    "private/var/db/systemstats/",
    "private/var/protected/",
    "private/var/networkd/",
    "private/var/vm/",                   # swapfiles / sleepimage
    "private/var/folders/",              # per-user temp: app caches, drafts
    "system/volumes/preboot/",
    "system/volumes/vm/",
    "library/application support/com.apple.tcc/",
    "library/managed preferences/",
    "library/security/",
    "library/keychains/",
    "library/logs/diagnosticreports/",
    "library/logs/powermanagement/",
    "library/staginglocation/",
)

KEEP_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"/\.fseventsd/", re.I),
    re.compile(r"/library/(preferences|containers|group containers|application support|caches/com\.apple)", re.I),
    re.compile(r"/library/(launchagents|launchdaemons|startupitems|logs|keychains|cookies|mail|messages|safari)/", re.I),
    re.compile(r"/library/application support/com\.apple\.sharedfilelist/", re.I),
    re.compile(r"/library/application support/(knowledge|com\.apple\.tcc|addressbook|mobilesync)/", re.I),
    re.compile(r"/private/var/db/(uuidtext|diagnostics|dslocal|launchd\.db|com\.apple\.xpc\.launchd|analyticsd|CoreDuet|lockdown)/", re.I),
    re.compile(r"/private/var/(audit|log/asl|log/powermanagement|log/DiagnosticMessages)/", re.I),
    re.compile(r"(^|/)\.(bash|zsh|sh)_history$", re.I),
    re.compile(r"(^|/)\.ssh/|(^|/)\.gnupg/|(^|/)\.aws/", re.I),
    re.compile(r"/quarantineeventsv2", re.I),
    re.compile(r"/mobilesync/backup/", re.I),   # iOS backups stored on a Mac
    re.compile(r"/library/developer/coresimulator/", re.I),
)

SPECIAL_BASENAMES: frozenset[str] = frozenset({
    "fseventsd-uuid", "no_log", "current",
    "com.apple.launchservices.quarantineeventsv2",
    "knowledgec.db", "interactionc.db", "cache_encryptedb.db", "cache_encrypteda.db",
    "consolidated.db", "current.db", "history.db", "downloads.plist",
    "asl.db", "com.apple.timemachine.plist", "install.log", "system.log",
    "wifi.log", "appfirewall.log", "commerce.db", "launchservices.plist",
    "com.apple.finder.plist", "com.apple.recentitems.plist", "com.apple.loginitems.plist",
    "com.apple.dock.plist", "com.apple.systempreferences.plist",
    "com.apple.airport.preferences.plist", "networkinterfaces.plist",
    "preferences.plist", "globalpreferences.plist", "authorization.plist",
    "tcc.db", "trustd.db", "ocspcache.sqlite3", "keychain-2.db",
    "store.db", "store", "psid.db", "sudoers", "hosts", "passwd", "master.passwd",
    "group", "sync_data.db", "spotlightknowledge.db", "biome",
    "com.apple.mail.plist", "envelope index", "protectedcloudstorage.plist",
    # --- gap closure -------------------------------------------------------
    "chatstorage.sqlite", "chat.db", "chat.db-wal", "chat.db-shm",   # iMessage
    "nsirecentmodifications.sqlite", "notestore.sqlite", "notes.sqlite",
    "calendar.sqlitedb", "addressbook-v22.abcddb", "contacts.db",
    "photos.sqlite", "photos.db", "library.apdb", "person.db",
    "downloads.28.sqlitedb", "quarantineevents", "quarantineeventsv2",
    "safari/history.db", "historyvisits", "topsites.plist", "lastsession.plist",
    "cloudtabs.db", "browserstate.db", "extensions.plist", "userprofiles.db",
    "powerlog.plsql", "currentpowerlog.plsql", "powerlog_yyyymmdd.plsql",
    "cache_encryptedb.db", "cache_encryptedc.db",
    "com.apple.timemachine.plist", "backup.plist", "snapshot.plist",
    "com.apple.screensharing.plist", "com.apple.remotedesktop.plist",
    "com.apple.remotelogin.plist", "com.apple.smb.server.plist",
    "com.apple.bluetooth.plist", "com.apple.networkextension.plist",
    "com.apple.wifi.known-networks.plist", "com.apple.airport.preferences.plist",
    "com.apple.iokit.pcap", "com.apple.usbmuxd.plist",
    "com.apple.mobiledevice.plist", "com.apple.finder.savedstate",
    "com.apple.driver.appleirinterface.plist", "com.apple.timezonepref.plist",
    "com.apple.systemuiserver.plist", "com.apple.spotlight.plist",
    "com.apple.universalaccess.plist", "com.apple.assistant.backedup.plist",
    "com.apple.security.kek.plist", "com.apple.security.ktrace.plist",
    "loginwindow.plist", "com.apple.loginwindow.plist",
    "usersandgroups.plist", "authdb", "systemversion.plist",
    "preferences.plist", "networkinterfaces.plist", "com.apple.network.identification.plist",
    "sleepimage", "swapfile0", "swapfile1", "kernel_panics",
    "installhistory.plist", "receiptdb", "installer.failurerequests",
    "boms", "bom", "packages.plist",
    "usermanagerd.plist", "com.apple.msc.plist",
    "com.apple.ncprefs.plist", "com.apple.notificationcenterui.plist",
    "db", "db-wal", "db-shm",                  # notification centre store
    "keychain-2.db", "login.keychain", "login.keychain-db", "system.keychain",
    "filevaultmaster.keychain", "encryptedroot.plist.wipekey",
    "com.apple.tcc.db", "tcc.db-wal", "tcc.db-shm",
    "cohortinfo.plist", "com.apple.commerce.plist",
    "asl.db", "logd.0.log", "shutdown.log", "kernel.log",
})

BASENAME_PREFIXES: tuple[str, ...] = (
    "0000000", "fseventsd", "com.apple.", "store-v", "asl.", "biome",
)

BASENAME_SUFFIXES: tuple[str, ...] = (
    ".asl", ".tracev3", ".ips", ".panic", ".diag", ".spin", ".hang", ".crash",
    ".sfl", ".sfl2", ".sfl3", ".plist", ".storedata", ".sqlitedb", ".shm", ".wal",
    ".dmg", ".sparsebundle", ".sparseimage", ".pkg", ".mpkg", ".app",
    ".keychain", ".keychain-db", ".loginkeychain", ".mobileprovision",
    ".aae", ".livephoto", ".webarchive", ".emlx", ".partial.emlx", ".mbox",
    ".dsc", ".shortcut", ".workflow", ".scpt", ".command", ".terminal",
)

EXTENSIONS: frozenset[str] = frozenset({
    ".asl", ".tracev3", ".dsc", ".ips", ".panic", ".diag", ".spin", ".hang", ".crash",
    ".sfl", ".sfl2", ".sfl3", ".plist", ".storedata", ".sqlitedb", ".binarycookies",
    ".keychain", ".keychain-db", ".mobileprovision", ".mobileconfig", ".provisionprofile",
    ".dmg", ".sparsebundle", ".sparseimage", ".pkg", ".mpkg",
    ".emlx", ".mbox", ".webarchive", ".aae", ".livephoto", ".heic", ".heif",
    ".scpt", ".workflow", ".command", ".terminal", ".shortcut",
    ".pages", ".numbers", ".key", ".sketch",
    # --- gap closure -------------------------------------------------------
    ".abcddb", ".apdb", ".plsql", ".segb", ".biome", ".pbdata", ".protobuf",
    ".bom", ".pkgutil", ".dist", ".xip", ".dylib", ".kext", ".bundle",
    ".savedstate", ".sfl4", ".sfl5", ".lockfile",
    ".textbundle", ".rtfd", ".icloud",           # placeholder = evicted iCloud file
    ".photoslibrary", ".migratedphotolibrary", ".aplibrary",
    ".imovielibrary", ".fcpbundle", ".band", ".logicx",
    ".sparsebundle", ".dmg.part", ".cdr", ".toast",
    ".mobilebackup", ".backupdb", ".appdb", ".purgeable",
    ".p12", ".pfx", ".cer", ".der", ".p7b", ".jks",
    ".pcapng", ".pklg",                          # PacketLogger Bluetooth capture
    ".qtz", ".ipsw", ".shsh", ".plist.bak",
    ".sqlite-wal", ".sqlite-shm", ".sqlitedb-wal", ".sqlitedb-shm",
    ".db-wal", ".db-shm", ".storedata-wal", ".storedata-shm",
    ".eml", ".mbox", ".olm", ".mailbox",
    ".vmwarevm", ".utm", ".pvm", ".qcow2", ".e01",
})

EXTENSIONLESS_DIRS: tuple[str, ...] = (
    ".fseventsd/",
    "private/var/audit/",
    "var/audit/",
    "private/var/db/uuidtext/",
    "var/db/uuidtext/",
    "private/var/db/diagnostics/",
    "private/var/log/asl/",
    "private/var/at/",
    "private/etc/",
    "etc/",
    ".spotlight-v100/",
    ".documentrevisions-v100/",
    "/library/keychains/",
    "/library/cookies/",
    "/mobilesync/backup/",
    "/library/mail/",
    "/library/containers/",
    "users/",
    # --- gap closure ---
    "private/var/db/biome/",
    "var/db/biome/",
    "private/var/db/coreduet/",
    "var/db/coreduet/",
    "private/var/db/dslocal/",
    "private/var/db/lockdown/",
    "var/db/lockdown/",
    "private/var/db/mds/",
    "private/var/db/receipts/",
    "private/var/folders/",
    "private/var/protected/",
    "/library/security/",
    "/library/application support/com.apple.tcc/",
    "/library/group containers/",
    "/library/saved application state/",
    "/library/logs/diagnosticreports/",
    "/.trash/",
    "/.trashes/",
)

NOISE_PREFIXES: tuple[str, ...] = (
    "system/library/frameworks/",
    "system/library/privateframeworks/",
    "system/library/extensions/",
    "system/library/templates/",
    "system/library/fonts/",
    "usr/share/",
    "usr/lib/",
    "system/applications/",
    "library/updates/",
)

CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(r"\.fseventsd/", "FSEvents", "Operating System",
                 "File-system change journal — records creation/rename/deletion of files that "
                 "no longer exist, including on ejected external volumes.", "fsevents", True),
    CatalogEntry(r"var/audit/", "BSM audit trail", "Operating System",
                 "Kernel audit records: process execution, logins, privilege use.", "bsm", True),
    CatalogEntry(r"var/log/asl/", "Apple System Log", "Operating System",
                 "Pre-Sierra and fallback system logging.", "asl"),
    CatalogEntry(r"var/db/(uuidtext|diagnostics)", "Unified Log", "Operating System",
                 "tracev3 payloads are meaningless without the uuidtext/dsc string catalogue — "
                 "both must be collected together.", "unifiedlog", True),
    CatalogEntry(r"sharedfilelist/.*\.sfl2?", "Recent Items (SFL/SFL2)", "Operating System",
                 "Recently opened documents, servers, applications and mounted volumes.",
                 "bookmark", True),
    CatalogEntry(r"quarantineeventsv2", "Quarantine Events", "Web Related",
                 "Download provenance: source URL, referring page, timestamp, agent.",
                 "sqlite", True),
    CatalogEntry(r"knowledgec\.db|interactionc\.db|CoreDuet", "KnowledgeC / CoreDuet", "Application Usage",
                 "Per-app focus and usage timeline, device lock/unlock, Now-Playing.", "sqlite", True),
    CatalogEntry(r"\.spotlight-v100/", "Spotlight index", "Operating System",
                 "Metadata for files that were deleted; recovers filenames and Finder comments.",
                 "spotlight", True),
    CatalogEntry(r"/launchagents/|/launchdaemons/|/startupitems/", "Launch persistence", "Operating System",
                 "LaunchAgents/LaunchDaemons are the primary macOS persistence mechanism.",
                 "plist", True),
    CatalogEntry(r"tcc\.db", "TCC privacy database", "Operating System",
                 "Which app was granted camera/mic/screen/full-disk access, and when.", "sqlite"),
    CatalogEntry(r"/library/keychains/", "Keychains", "Encryption & Credentials",
                 "Stored credentials, certificates, WiFi PSKs.", "keychain", True),
    CatalogEntry(r"/mobilesync/backup/", "iOS backups on Mac", "Additional Sources",
                 "Full nested iOS device evidence — must be processed as a separate source.",
                 "ios_backup", True),
    CatalogEntry(r"\.ips$|\.panic$|\.crash$", "Crash / panic reports", "Application Usage",
                 "Proves which binaries ran, with full paths and load addresses.", "text"),
    CatalogEntry(r"private/var/db/dslocal/nodes/default/users/", "Local accounts", "Operating System",
                 "Account names, UIDs, hashes (ShadowHashData), creation time.", "plist", True),
)

CATALOG = CATALOG + (
    # --- gap closure -------------------------------------------------------
    CatalogEntry(r"db/uuidtext/", "Unified Log string catalogue", "Operating System",
                 "uuidtext + dsc entries are the ONLY way to resolve format strings in "
                 ".tracev3. Collecting tracev3 without them yields unreadable logs.",
                 "unifiedlog", True),
    CatalogEntry(r"db/biome/", "Biome / SEGB streams", "Application Usage",
                 "Post-Monterey behavioural streams: app launches, notifications, device "
                 "locking, location. Largely replaced KnowledgeC and is missed by legacy "
                 "collection lists.", "segb", True),
    CatalogEntry(r"powerlog", "PowerLog", "Application Usage",
                 "Per-process app usage, network bytes, location and battery events over "
                 "roughly the last 30 days.", "sqlite", True),
    CatalogEntry(r"db/dslocal/", "DirectoryService local nodes", "Accounts",
                 "Local account records and ShadowHashData — account creation times and "
                 "hidden admin accounts.", "plist", True),
    CatalogEntry(r"db/lockdown/", "iOS pairing records", "Connections",
                 "Proves which iPhones/iPads were trusted-paired to this Mac, and supplies "
                 "the escrow keybag needed for a later logical extraction of that phone.",
                 "plist", True),
    CatalogEntry(r"/com\.apple\.tcc/tcc\.db", "TCC privacy database", "Operating System",
                 "Which application was granted camera/microphone/screen-recording/full-disk "
                 "access, and when — central to stalkerware and insider cases.", "sqlite", True),
    CatalogEntry(r"/library/keychains/", "Keychains", "Encryption & Credentials",
                 "Saved credentials, certificates and FileVault key material.", "keychain", True),
    CatalogEntry(r"\.icloud$", "iCloud placeholder", "Cloud Storage",
                 "A zero-byte stub proving a file EXISTED and was evicted to iCloud. Absence "
                 "of content is not absence of the file.", "plist", True),
    CatalogEntry(r"/chat\.db", "iMessage / SMS", "Chat",
                 "Message content, attachments and handles. The -wal sidecar routinely holds "
                 "the most recent (and most relevant) messages.", "sqlite", True),
    CatalogEntry(r"var/folders/", "Per-user temporary containers", "Additional Sources",
                 "Application caches, unsaved drafts and downloaded attachments the user "
                 "never knowingly saved.", "path_inventory"),
    CatalogEntry(r"var/vm/(sleepimage|swapfile)", "Swap / sleepimage", "Memory",
                 "Paged-out memory: cleartext of encrypted content, keys and message text.",
                 "memory", True),
    CatalogEntry(r"/saved application state/", "Saved application state", "Application Usage",
                 "Window contents at last quit — reconstructs documents that were open.",
                 "plist"),
)

PACK = ArtifactScopePack(
    os_family="macos",
    axiom_platform="macOS",
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
