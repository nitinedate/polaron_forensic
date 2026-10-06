"""Windows artifact scope pack — AXIOM platform 'Windows' / 'Windows Memory'.

Closes the gaps proven by scripts/artifact_coverage_gap_test.py:
NTFS metadata files, hive transaction logs, Scheduled Tasks (extensionless XML),
WMI repository, print spool, BCD, Volume Shadow Copy, DPAPI, WER, OneDrive ODL.
"""

from __future__ import annotations

import re

from .base import ArtifactScopePack, CatalogEntry

KEEP_PREFIXES: tuple[str, ...] = (
    # User & profile data
    "users/",
    "documents and settings/",
    "programdata/microsoft/windows/start menu/",
    "programdata/microsoft/windows/caches/",
    "programdata/microsoft/windows/wer/",
    "programdata/microsoft/search/",
    "programdata/microsoft/diagnosis/",
    "programdata/microsoft/network/",
    "programdata/microsoft/user account pictures/",
    "programdata/microsoft/wlansvc/",
    "programdata/microsoft/crypto/",
    "programdata/usoshared/",
    "programdata/packages/",
    # --- gap closure -------------------------------------------------------
    # StateRepository-Machine.srd: authoritative installed/provisioned app
    # inventory for modern Windows. AXIOM "Installed Programs" reads this.
    "programdata/microsoft/windows/apprepository/",
    # Defender MPLog + Quarantine. Quarantine/ResourceData holds the *actual*
    # malware body, extensionless and RC4-obfuscated — losing it loses the sample.
    "programdata/microsoft/windows defender/",
    "programdata/microsoft/microsoft antimalware/",
    "programdata/microsoft/windows/deliveryoptimization/",
    "programdata/microsoft/windows/hyper-v/",
    "programdata/microsoft/windows nt/",
    "programdata/microsoft/provisioning/",
    "programdata/microsoft/identitycrl/",
    "programdata/microsoft/windows/containers/",
    "programdata/microsoft/windows/clipsvc/",
    "programdata/microsoft/windows/systemdata/",
    # Registry & event logs
    "windows/system32/config/",
    "windows/system32/winevt/",
    "windows/system32/logfiles/",
    "windows/system32/sru/",
    "windows/system32/wdi/",
    "windows/system32/grouppolicy/",
    "windows/system32/tasks/",
    "windows/system32/drivers/etc/",
    "windows/system32/wbem/repository/",
    "windows/system32/wbem/autorecover/",
    "windows/system32/spool/printers/",
    "windows/system32/ras/",
    "windows/system32/lostandfound/",
    "windows/syswow64/tasks/",
    "windows/tasks/",
    "windows/prefetch/",
    "windows/appcompat/",
    "windows/inf/",
    "windows/panther/",
    "windows/debug/",
    "windows/security/logs/",
    "windows/serviceprofiles/",
    "windows/servicestate/",
    "windows/minidump/",
    "windows/logs/",
    "windows/setupapi/",
    "windows/media/",
    "windows/bootstat.dat",
    # --- gap closure -------------------------------------------------------
    "windows/softwaredistribution/datastore/",   # DataStore.edb — patch/update history
    "windows/livekernelreports/",                 # kernel dumps naming loaded drivers
    "windows/system32/dhcp/",                     # server lease history -> IP attribution
    "windows/system32/sysprep/",                  # imaging/cloning provenance
    "windows/system32/catroot2/",                 # catalogue DB, signing tamper
    "windows/servicing/sessions/",                # servicing session XML
    "windows/system32/spp/",                      # licensing / activation timeline
    "windows/system32/smi/store/",                # Windows machine store
    "windows/registration/",
    # Previous OS install after an in-place upgrade. This is a COMPLETE second
    # evidence set (registry, profiles, event logs) covering the period before
    # the upgrade — the most commonly missed tree on an upgraded workstation.
    "windows.old/",
    "$windows.~bt/",
    "$windows.~ws/",
    "$winreagent/",
    "$sysreset/",
    "$getcurrent/",
    # Deleted / recovery / boot
    "$recycle.bin/",
    "recycle.bin/",
    "recycler/",
    "system volume information/",
    "boot/",
    "efi/",
    "recovery/",
    # Servers / web
    "inetpub/",
    "perflogs/",
    "wwwroot/",
    "xampp/",
    "wamp/",
)

KEEP_REGEXES: tuple[re.Pattern[str], ...] = (
    # NTFS metadata files live at volume root and start with '$'.
    re.compile(r"^\$(mft|mftmirr|logfile|volume|attrdef|bitmap|boot|badclus|secure|upcase|quota|objid|reparse|i30)", re.I),
    re.compile(r"^\$extend/", re.I),
    re.compile(r"\$usnjrnl(:\$j|:\$max)?$", re.I),
    re.compile(r"\$txflog", re.I),
    # Alternate data streams — carry hidden payloads and Zone.Identifier provenance.
    re.compile(r":[^/\\:]+$"),
    # Volume Shadow Copy stores (GUID-named, extensionless).
    re.compile(r"system volume information/\{[0-9a-f-]{36}\}", re.I),
    # DPAPI master keys / credentials (extensionless GUID + hex blobs).
    re.compile(r"/microsoft/protect/s-1-5-21-", re.I),
    re.compile(r"/microsoft/(credentials|vault|crypto/rsa|crypto/keys)/", re.I),
    # Scheduled tasks are XML with no extension.
    re.compile(r"/(system32|syswow64)/tasks/", re.I),
    # Per-user activity / timeline / notifications
    re.compile(r"/connecteddevicesplatform/.+/activitiescache\.db", re.I),
    re.compile(r"/notifications/wpndatabase\.db", re.I),
    # Browser & Electron app state under any profile
    re.compile(r"/user data/(default|profile \d+|guest profile)/", re.I),
    re.compile(r"/(local storage|session storage|indexeddb|databases|service worker)/", re.I),
    # Volume-relative WSL distributions carry a whole Linux filesystem
    re.compile(r"/packages/[^/]*windowssubsystemforlinux[^/]*/", re.I),
)

SPECIAL_BASENAMES: frozenset[str] = frozenset({
    # Registry hives + dirty-hive transaction logs
    "sam", "system", "software", "security", "default", "components", "drivers",
    "bbi", "elam", "bcd", "bcd-template", "ntuser.dat", "usrclass.dat",
    "amcache.hve", "syscache.hve", "ntds.dit", "system.sav", "software.sav",
    # Execution / program inventory
    "recentfilecache.bcf", "srudb.dat", "agapplaunch.db", "agglfaultcache.db",
    "agglglobalhistory.db", "agglpersistedfaultcache.db", "agrobust.db", "agusercount.db",
    # Networking / system config
    "hosts", "lmhosts.sam", "networks", "protocol", "services",
    "wmisetup.log", "objects.data", "index.btr", "mapping1.map", "mapping2.map", "mapping3.map",
    # Boot / crash
    "bootstat.dat", "memory.dmp", "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    "setupapi.dev.log", "setupapi.app.log", "setupapi.offline.log",
    # Search / thumbnails / timeline
    "windows.edb", "windows.db", "activitiescache.db", "wpndatabase.db",
    "iconcache.db", "quickaccess.db", "edb.log", "edb.chk",
    # Credential / crypto material
    "policy.pol", "registry.pol", "gpt.ini", "scepol.log",
    # Mail / office
    "outlook.pst", "archive.pst", "outlook.ost", "profile.dat",
    # --- gap closure -------------------------------------------------------
    # Installed-application inventory (modern replacement for Uninstall keys)
    "staterepository-machine.srd", "staterepository-deployment.srd",
    "staterepository-machine.srd-wal", "staterepository-machine.srd-shm",
    # Patch / update history and servicing
    "datastore.edb", "windowsupdate.log", "cbs.log", "cbs.persist.log",
    "reportingevents.log", "netsetup.log", "wpa.dbl", "winsat.log",
    # Malware handling
    "mrt.log", "mpdetection.log", "mpcmdrun.log", "detectionhistory",
    # Certificate / trust tampering
    "catdb", "catdb.log",
    # Cloud identity + licensing
    "tokenbroker.dat", "clipsvc.db", "settings.dat",
    # Mail / archives frequently orphaned outside the profile
    "archive.ost", "outlook.nst", "windowsmail.pst", "store.vol",
    # BitLocker / recovery metadata
    "reagent.xml", "recovery.txt",
    # Cloud sync state
    "syncengine.db", "syncengine-processed.db", "sqlite_bkp.db",
    "safe_storage.db", "usersettings.dat", "clientpolicy.ini",
})

BASENAME_PREFIXES: tuple[str, ...] = (
    "thumbcache_", "iconcache_", "srudb", "amcache", "mplog-", "ntuser.dat",
    "usrclass.dat", "$i", "$r", "readyboot", "etwrt", "eventlog-", "sysmon",
    # --- gap closure ---
    "staterepository", "datastore", "mrt", "cbs", "wuau", "resourcedata",
    "detectionhistory", "edb0", "edbres", "edbtmp", "tmp.edb",
    "windowsupdate", "setupact", "setuperr", "unattend", "pfirewall",
)

BASENAME_SUFFIXES: tuple[str, ...] = (
    ".automaticdestinations-ms", ".customdestinations-ms",
    ".regtrans-ms", ".blf", ".job", ".etl", ".pf", ".wer", ".spl", ".shd",
    ".odl", ".odlgz", ".odlsent", ".aodl", ".sst", ".pol", ".bcf",
    ".search-ms", ".library-ms", ".appref-ms", ".vhdx", ".avhdx",
    # --- gap closure ---
    ".srd", ".srd-wal", ".srd-shm", ".jrs", ".jfm", ".chk", ".rbs",
    ".dat.log1", ".dat.log2", ".hve.log1", ".hve.log2",
)

EXTENSIONS: frozenset[str] = frozenset({
    ".evtx", ".evt", ".etl", ".pf", ".job", ".wer", ".spl", ".shd", ".bcf",
    ".pol", ".sst", ".blf", ".regtrans-ms", ".hve", ".sav", ".dit",
    ".odl", ".odlgz", ".odlsent", ".aodl", ".dmp", ".mdmp", ".hdmp", ".kdmp",
    ".search-ms", ".library-ms", ".appref-ms", ".lnk", ".url", ".website",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".hta", ".reg", ".inf", ".ini", ".manifest", ".rdp", ".ica",
    ".vhd", ".vhdx", ".avhd", ".avhdx", ".vmcx", ".vmrs", ".vsv", ".bin",
    # --- gap closure -------------------------------------------------------
    # ESE database family + its sidecars. Without .jrs/.jfm/.chk an .edb often
    # cannot be replayed to a consistent state and the tool reports zero rows.
    ".srd", ".edb", ".jrs", ".jfm", ".chk", ".pma", ".sqm", ".rbs",
    # Mail stores that turn up outside the user profile (server shares, backups)
    ".pst", ".ost", ".nst", ".olm", ".msg", ".eml", ".mbox", ".dbx", ".wab", ".vcf",
    # Nested acquisition containers found *inside* an image (examiner working
    # copies, prior extractions, ransomware operator toolkits)
    ".e01", ".ex01", ".l01", ".lx01", ".ad1", ".aff", ".aff4", ".s01",
    ".dd", ".001", ".raw", ".img", ".ima", ".vmdk", ".vdi", ".qcow2", ".hdd",
    ".wim", ".swm", ".esd", ".sdi", ".iso",
    # Memory
    ".vmem", ".vmss", ".vmsn", ".mem", ".core", ".lime",
    # Credential / crypto containers
    ".kdbx", ".pfx", ".p12", ".jks", ".keystore", ".wallet", ".dat.log",
    # Script / persistence formats not yet listed
    ".psc1", ".pssc", ".msc", ".scf", ".sct", ".xll", ".wll", ".iqy", ".slk",
    ".lnk_", ".theme", ".cpl", ".mof",
    # Container / WSL / virtualisation
    ".vhdx.tmp", ".ext4", ".tar", ".ova", ".ovf",
})

EXTENSIONLESS_DIRS: tuple[str, ...] = (
    "windows/system32/tasks/",
    "windows/syswow64/tasks/",
    "windows/tasks/",
    "windows/system32/wbem/repository/",
    "windows/system32/spool/printers/",
    "windows/system32/drivers/etc/",
    "windows/system32/catroot/",
    "system volume information/",
    "boot/",
    "efi/microsoft/boot/",
    # --- gap closure: extensionless evidence bodies -------------------------
    "programdata/microsoft/windows defender/quarantine/",   # ResourceData = malware body
    "programdata/microsoft/windows/apprepository/",
    "windows/system32/catroot2/",
    "windows/system32/smi/store/",
    "windows/servicing/sessions/",
    "windows.old/",
    "$windows.~bt/",
    "/appdata/local/microsoft/onedrive/logs/",
    "/appdata/local/comms/unistore/",       # Unified store: mail/contacts/calendar
    "/appdata/local/microsoft/olk/",        # New Outlook local cache
    "/appdata/local/temp/",                 # dropper staging, extensionless payloads
    "/appdata/roaming/microsoft/protect/",
    "/appdata/local/microsoft/vault/",
    "/microsoft/protect/",
    "/microsoft/credentials/",
    "/microsoft/vault/",
    "/microsoft/crypto/",
    "/microsoft/systemcertificates/",
    "/appdata/roaming/microsoft/windows/recent/",
    "/appdata/local/packages/",
    "/user data/",
    "/leveldb/",
    "/indexeddb/",
    "/local storage/",
    "$recycle.bin/",
)

# Trees reduced to "forensic extensions + special names only".
NOISE_PREFIXES: tuple[str, ...] = (
    "windows/winsxs/",
    "windows/servicing/",
    "windows/softwaredistribution/download/",
    "windows/system32/driverstore/filerepository/",
    "windows/assembly/",
    "windows/microsoft.net/",
    "windows/fonts/",
    "windows/systemresources/",
    "windows/schemas/",
    "windows/immersivecontrolpanel/",
    "program files/windowsapps/",
    "programdata/package cache/",
)

CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(r"^\$mft", "NTFS $MFT", "Operating System",
                 "Full file-system timeline, resident data, deleted entries. Feeds every "
                 "'file occurrence' and 'recovered' count domain.", "mft", True),
    CatalogEntry(r"^\$logfile", "NTFS $LogFile", "Operating System",
                 "Transaction rollback records — recovers file names deleted minutes before imaging.",
                 "logfile", True),
    CatalogEntry(r"\$usnjrnl", "USN Journal", "Operating System",
                 "Change journal: creation/deletion/rename of every file, including anti-forensic wiping.",
                 "usnjrnl", True),
    CatalogEntry(r"\$secure", "$Secure:$SDS", "Operating System",
                 "Security descriptors — proves which account owned a file.", "sds"),
    CatalogEntry(r"/(system32|syswow64)/tasks/", "Scheduled Tasks", "Operating System",
                 "Extensionless task XML. Primary persistence mechanism; AXIOM 'Scheduled Tasks'.",
                 "task_xml", True),
    CatalogEntry(r"/wbem/repository/", "WMI Repository", "Operating System",
                 "OBJECTS.DATA / INDEX.BTR hold WMI event-consumer persistence (APT tradecraft).",
                 "wmi_repo", True),
    CatalogEntry(r"/drivers/etc/hosts", "HOSTS file", "Operating System",
                 "DNS hijack / C2 redirection / licence-server blocking evidence.", "text"),
    CatalogEntry(r"/spool/printers/", "Print Spool", "Documents",
                 "SPL/SHD spool files reconstruct documents printed — exfiltration by print.",
                 "spool", True),
    CatalogEntry(r"system volume information/\{", "Volume Shadow Copies", "Additional Sources",
                 "Historical versions of every artifact above; AXIOM processes VSS as a nested source.",
                 "vss", True),
    CatalogEntry(r"/microsoft/protect/", "DPAPI Master Keys", "Encryption & Credentials",
                 "Required to decrypt browser passwords, Credential Manager, WiFi keys.", "dpapi", True),
    CatalogEntry(r"/microsoft/credentials/", "Credential Manager blobs", "Encryption & Credentials",
                 "Stored RDP/network/web credentials.", "dpapi", True),
    CatalogEntry(r"\.odl(gz|sent)?$", "OneDrive ODL logs", "Cloud Storage",
                 "File-level sync/upload history, including files removed from the local disk.",
                 "odl", True),
    CatalogEntry(r"\.wer$", "Windows Error Reports", "Application Usage",
                 "Records the full path and module list of executables that ran and crashed.", "wer"),
    CatalogEntry(r"amcache", "Amcache", "Application Usage",
                 "SHA-1 + full path of every executed/installed binary.", "registry", True),
    CatalogEntry(r"/config/[a-z]+\.log[12]$", "Registry transaction logs",
                 "Operating System",
                 "Dirty-hive replay — recovers keys written after the last flush.", "registry", True),
    CatalogEntry(r"boot/bcd$", "Boot Configuration Data", "Operating System",
                 "Boot entries, safe-mode/test-signing tampering, additional OS installs.", "registry"),
    CatalogEntry(r"/prefetch/.*\.pf$", "Prefetch", "Application Usage",
                 "Execution count, first/last run, loaded file list.", "prefetch", True),
    CatalogEntry(r"/sru/srudb\.dat", "SRUM", "Application Usage",
                 "Per-app bytes sent/received and user attribution — proves exfiltration volume.",
                 "esedb", True),
    CatalogEntry(r"/logfiles/sum/", "User Access Logging (SUM)", "Operating System",
                 "Server RDS/role client access history over 2+ years.", "esedb"),
    CatalogEntry(r":[^/]+$", "Alternate Data Streams", "Operating System",
                 "Zone.Identifier download provenance and hidden payloads.", "ads", True),
    # --- gap closure -------------------------------------------------------
    CatalogEntry(r"^windows\.old/", "Windows.old (previous install)", "Additional Sources",
                 "Complete pre-upgrade evidence set: registry hives, user profiles and event "
                 "logs covering the period before an in-place upgrade. Must be processed as a "
                 "nested source, exactly as AXIOM treats it.", "nested_source", True),
    CatalogEntry(r"apprepository/staterepository", "StateRepository (installed apps)",
                 "Installed Applications",
                 "Authoritative modern installed/provisioned application inventory, including "
                 "Store apps that leave no Uninstall registry key.", "esedb", True),
    CatalogEntry(r"windows defender/quarantine/", "Defender Quarantine", "Malware",
                 "ResourceData holds the obfuscated malware body itself; Entries/Resources "
                 "give original path and detection time. Losing this loses the sample.",
                 "defender_quarantine", True),
    CatalogEntry(r"mplog-", "Defender MPLog", "Malware",
                 "Full path and execution context of every scanned file — a de-facto second "
                 "execution artifact when Prefetch is disabled.", "mplog", True),
    CatalogEntry(r"/softwaredistribution/datastore/datastore\.edb", "Windows Update history",
                 "Operating System",
                 "Patch level over time; establishes whether a known exploit was viable on the "
                 "date in question.", "esedb"),
    CatalogEntry(r"/deliveryoptimization/", "Delivery Optimization", "Network Activity",
                 "Peer-to-peer content transfer records — shows LAN peers of this host.", "sqlite"),
    CatalogEntry(r"/comms/unistore/", "Unified Store (Mail/People/Calendar)", "Email",
                 "Windows Mail, People and Calendar content for accounts that never touched "
                 "Outlook. Extensionless .dat records under a GUID tree.", "unistore", True),
    CatalogEntry(r"/microsoft/olk/", "New Outlook local cache", "Email",
                 "The rebuilt Outlook client stores messages here, not in an OST.", "sqlite"),
    CatalogEntry(r"\.(jrs|jfm|chk)$", "ESE sidecar files", "Operating System",
                 "Log/checkpoint files required to replay an ESE database to a consistent "
                 "state. Without them SRUM/Windows.edb/DataStore report zero rows.", "esedb", True),
    CatalogEntry(r"\.(e01|ex01|l01|ad1|aff4|dd|001|vmdk|vhdx|qcow2)$", "Nested acquisition container",
                 "Additional Sources",
                 "A forensic image or virtual disk found inside the evidence — must be mounted "
                 "and processed recursively, not treated as one opaque file.", "nested_source", True),
    CatalogEntry(r"^\$windows\.~bt/", "Upgrade staging", "Additional Sources",
                 "Setup staging tree retaining panther logs and pre-upgrade file copies.", "text"),
    CatalogEntry(r"/config/regback/", "Registry backup (RegBack)", "Operating System",
                 "Periodic hive copies. On systems where RegBack is still populated this is a "
                 "second, earlier registry state usable to show what changed.", "registry", True),
    CatalogEntry(r"system32/dhcp/", "DHCP server leases", "Network Activity",
                 "Maps IP addresses to MAC/hostname over time — the bridge between a log entry "
                 "and a physical device.", "text"),
)

PACK = ArtifactScopePack(
    os_family="windows",
    axiom_platform="Windows",
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
