"""Linux artifact scope pack — AXIOM platform 'Linux'.

The current filter set has no Linux branch at all: /etc, /var/log, /var/lib and
/opt fall through to "extensions only", which drops shadow, sudoers, wtmp/btmp,
journald, dpkg/rpm state and systemd persistence units. This pack fixes that.
Also covers server-side evidence (webshells, container logs) and WSL rootfs.
"""

from __future__ import annotations

import re

from .base import ArtifactScopePack, CatalogEntry

KEEP_PREFIXES: tuple[str, ...] = (
    # System identity, policy and persistence
    "etc/",
    # Logs and audit
    "var/log/",
    "var/adm/",
    "var/audit/",
    "run/log/",
    "var/run/",
    # State, packages, services, containers
    "var/lib/",
    "var/spool/",
    "var/backups/",
    "var/cache/apt/",
    "var/cache/dnf/",
    "var/cache/yum/",
    "usr/lib/systemd/system/",
    "usr/local/lib/systemd/",
    "lib/systemd/system/",
    # User data
    "home/",
    "root/",
    "srv/",
    "media/",
    "mnt/",
    # Web / application servers
    "var/www/",
    "opt/",
    "usr/local/bin/",
    "usr/local/sbin/",
    "usr/local/etc/",
    "usr/local/share/",
    # Boot / kernel config (rootkit and tampering evidence)
    # --- gap closure -------------------------------------------------------
    "var/lib/containerd/",          # containerd / k8s runtime state
    "var/lib/containers/",          # podman
    "var/lib/kubelet/",
    "etc/kubernetes/",
    "var/lib/libvirt/",             # VM definitions + disk paths
    "var/lib/snapd/",
    "var/lib/AccountsService/",
    "var/lib/bluetooth/",           # paired-device evidence
    "var/lib/NetworkManager/",      # DHCP leases -> IP attribution
    "var/lib/upower/",
    "var/lib/logrotate/",
    "var/lib/samba/",
    "var/lib/postfix/",
    "var/lib/clamav/",
    "var/lib/fail2ban/",
    "var/lib/aide/",
    "var/lib/sss/",                 # SSSD cache: domain identities
    "var/lib/php/sessions/",        # web-shell session evidence
    "var/lib/mysql/",
    "var/lib/postgresql/",
    "var/lib/redis/",
    "var/lib/mongodb/",
    "var/lib/elasticsearch/",
    "var/mail/",
    "var/spool/mail/",
    "var/spool/postfix/",
    "var/spool/cups/",              # print job control + spool bodies
    "var/spool/abrt/",              # crash reports naming executables
    "var/crash/",
    "var/lib/systemd/coredump/",
    "usr/lib/cron/",
    "etc/cron.d/",
    "var/lib/pacman/local/",
    "var/log/audit/",
    "var/log/journal/",
    "var/log/sssd/",
    "var/log/apache2/",
    "var/log/nginx/",
    "var/log/httpd/",
    "var/log/samba/",
    "var/log/cups/",
    "var/log/installer/",
    "var/log/anaconda/",
    "var/log/sysstat/",             # sar: historical CPU/net utilisation
    "var/lib/plocate/",
    "var/lib/mlocate/",             # locate DB = filename listing of DELETED files
    "sys/fs/",
    "boot/grub/",
    "boot/loader/",
    # Temp trees — droppers and staged archives live here
    "tmp/",
    "var/tmp/",
    "dev/shm/",
    # Live-response captures
    "proc/",
)

KEEP_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(^|/)\.(bash|zsh|sh|ksh|fish|mysql|psql|python|node_repl|lesshst|rediscli)_history$", re.I),
    re.compile(r"(^|/)\.ssh/", re.I),
    re.compile(r"(^|/)\.gnupg/", re.I),
    re.compile(r"(^|/)\.aws/|(^|/)\.azure/|(^|/)\.config/gcloud/", re.I),
    re.compile(r"(^|/)\.docker/|(^|/)\.kube/", re.I),
    re.compile(r"(^|/)\.config/autostart/", re.I),
    re.compile(r"(^|/)\.local/share/(recently-used|Trash|keyrings)", re.I),
    re.compile(r"(^|/)\.mozilla/|(^|/)\.config/(google-chrome|chromium|BraveSoftware|microsoft-edge)/", re.I),
    re.compile(r"(^|/)\.thunderbird/|(^|/)\.local/share/evolution/", re.I),
    re.compile(r"/var/lib/docker/(containers|image|volumes)/", re.I),
    re.compile(r"/var/lib/(dpkg|rpm|pacman|snapd|flatpak|AccountsService|NetworkManager|bluetooth|systemd)/", re.I),
    re.compile(r"/var/log/journal/", re.I),
    re.compile(r"/etc/(cron|systemd|init|rc\d?)\.?d?/", re.I),
    # WSL / chroot rootfs nested inside another image
    re.compile(r"/rootfs/(etc|var|home|root)/", re.I),
)

SPECIAL_BASENAMES: frozenset[str] = frozenset({
    # Accounts & authorisation
    "passwd", "passwd-", "shadow", "shadow-", "group", "group-", "gshadow", "gshadow-",
    "sudoers", "login.defs", "securetty", "nsswitch.conf", "pam.conf",
    # Host identity
    "hostname", "hosts", "hosts.allow", "hosts.deny", "machine-id", "os-release",
    "issue", "issue.net", "timezone", "localtime", "fstab", "mtab", "crypttab",
    "resolv.conf", "networks", "protocols", "services",
    # Persistence
    "crontab", "anacrontab", "rc.local", "rc.sysinit", "profile", "bashrc",
    "bash.bashrc", "environment", "ld.so.preload", "ld.so.conf", "modules",
    "sysctl.conf", "sshd_config", "ssh_config", "authorized_keys", "known_hosts",
    # Login / session accounting (binary, extensionless — the classic Linux miss)
    "wtmp", "btmp", "utmp", "lastlog", "faillog", "tallylog", "wtmpx", "utmpx",
    "wtmp.1", "btmp.1", "dmesg", "dmesg.0", "boot.log",
    # Syslog family
    "syslog", "messages", "secure", "auth.log", "kern.log", "daemon.log",
    "user.log", "debug", "cron", "cron.log", "maillog", "mail.log", "yum.log",
    "dpkg.log", "alternatives.log", "wpa_supplicant.conf", "audit.log",
    # Package / software inventory
    "status", "available", "packages", "installed.db", "world", "history.log",
    # Shell / app history
    ".bash_history", ".zsh_history", ".sh_history", ".python_history",
    ".mysql_history", ".psql_history", ".viminfo", ".lesshst", ".wget-hsts",
    ".recently-used", "recently-used.xbel", "user-dirs.dirs",
    # Container / cloud
    "daemon.json", "docker-compose.yml", "config.v2.json", "hostconfig.json",
    "repositories.json", "cloud-init.log", "cloud-init-output.log",
    # --- gap closure ---
    "mlocate.db", "plocate.db", "wtmpdb", "lastlog2", "lastlog2.db", "btmpdb",
    "shells", "motd", "interfaces", "dhclient.leases", "resolved.conf",
    "subuid", "subgid", "access.conf", "limits.conf", "sudo.log",
    "grub.cfg", "grubenv", "cmdline", "modprobe.conf", "blacklist.conf",
    "rsyslog.conf", "journald.conf", "logrotate.conf", "auditd.conf", "audit.rules",
    "swapfile", "swap.img", "core", "vmcore", "vmcore-dmesg.txt",
    "nftables.conf", "rules.v4", "rules.v6", "ufw.conf", "firewalld.conf",
    "id_rsa", "id_ed25519", "authorized_keys2", "known_hosts.old",
    ".netrc", ".pgpass", ".my.cnf", ".git-credentials", ".npmrc", ".pypirc",
    ".gitconfig", ".xsession-errors", ".ICEauthority", ".Xauthority",
    "kubeconfig", "admin.conf", "token", "state.json", "config.json",
    "osquery.conf", "osqueryd.results.log", "ossec.conf", "wazuh.conf",
    "auth.log.1", "syslog.1", "messages.1", "secure.1", "kern.log.1",
})

BASENAME_PREFIXES: tuple[str, ...] = (
    "wtmp", "btmp", "utmp", "lastlog", "syslog", "messages", "secure",
    "auth.log", "audit.log", "dmesg", "history.log", "sudo",
)

BASENAME_SUFFIXES: tuple[str, ...] = (
    ".journal", ".journal~", ".service", ".timer", ".socket", ".mount", ".target",
    ".path", ".slice", ".desktop", ".rules", ".nmconnection", ".network",
    ".xbel", ".preload", ".pcap", ".sh", ".py", ".pl", ".php", ".jsp", ".rb",
    ".ko", ".seed", ".list", ".sources", ".repo",
)

EXTENSIONS: frozenset[str] = frozenset({
    ".journal", ".service", ".timer", ".socket", ".mount", ".target", ".path",
    ".slice", ".desktop", ".rules", ".nmconnection", ".network", ".netdev",
    ".xbel", ".conf", ".cnf", ".cfg", ".ini", ".list", ".sources", ".repo",
    ".sh", ".bash", ".zsh", ".py", ".pl", ".php", ".rb", ".jsp", ".cgi", ".lua",
    ".ko", ".so", ".pcap", ".pcapng", ".gpg", ".asc", ".pem", ".key", ".crt",
    ".kdbx", ".sqlite", ".db", ".yaml", ".yml", ".toml", ".env", ".log", ".gz",
    ".xz", ".zst", ".seed", ".swp", ".swo",
    # --- gap closure ---
    ".rules", ".policy", ".pkla", ".automount", ".swap", ".scope", ".device",
    ".preset", ".link", ".dnssd", ".deb", ".rpm", ".snap", ".appimage", ".run",
    ".mbox", ".eml", ".msf", ".sbd", ".kdb", ".psafe3", ".ovpn", ".wg",
    ".p12", ".pfx", ".jks", ".sqlite3", ".sqlite-wal", ".sqlite-shm",
    ".db-wal", ".db-shm", ".realm", ".bin", ".img", ".iso", ".raw", ".dd", ".e01",
    ".vdi", ".qcow2", ".lime", ".core", ".vmcore", ".crash", ".dump",
    ".cap", ".har", ".jsonl", ".ndjson", ".csv", ".tsv", ".apk", ".dex",
    ".rdp", ".vnc", ".remmina", ".pdf", ".docx", ".xlsx", ".odt", ".jpg", ".png", ".mp4",
})

EXTENSIONLESS_DIRS: tuple[str, ...] = (
    "etc/",
    "var/log/",
    "var/adm/",
    "var/spool/cron/",
    "var/spool/mail/",
    "var/spool/at/",
    "var/lib/dpkg/",
    "var/lib/rpm/",
    "var/lib/accountsservice/",
    "var/lib/systemd/",
    "var/lib/docker/containers/",
    "var/backups/",
    "home/",
    "root/",
    "usr/local/bin/",
    "usr/local/sbin/",
    "tmp/",
    "var/tmp/",
    "dev/shm/",
    "run/",
    # --- gap closure ---
    "var/lib/containerd/",
    "var/lib/containers/",
    "var/lib/kubelet/",
    "var/lib/sss/db/",
    "var/lib/NetworkManager/",
    "var/lib/bluetooth/",
    "var/lib/mlocate/",
    "var/lib/plocate/",
    "var/spool/abrt/",
    "var/spool/cups/",
    "var/crash/",
    "var/lib/systemd/coredump/",
    "etc/ssl/private/",
    "etc/ssh/",
    "/.ssh/",
    "/.gnupg/",
    "/.local/share/keyrings/",
    "/.config/",
    "var/lib/php/sessions/",
    "var/mail/",
    "var/spool/mail/",
)

NOISE_PREFIXES: tuple[str, ...] = (
    "usr/share/doc/",
    "usr/share/man/",
    "usr/share/locale/",
    "usr/share/icons/",
    "usr/share/fonts/",
    "usr/lib/python3/dist-packages/",
    "usr/lib/x86_64-linux-gnu/",
    "usr/lib/modules/",
    "usr/src/",
    "snap/",
    "var/lib/flatpak/repo/",
)

CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(r"etc/shadow", "Password hashes", "Encryption & Credentials",
                 "Account hashes for cracking/attribution; also proves account existence and lock state.",
                 "text", True),
    CatalogEntry(r"etc/(sudoers|sudoers\.d/)", "Sudo policy", "Operating System",
                 "Privilege escalation paths granted to the suspect account.", "text", True),
    CatalogEntry(r"var/log/(wtmp|btmp|lastlog|utmp)", "Login records", "Operating System",
                 "Binary session accounting: who logged in, from which IP, for how long. "
                 "Direct equivalent of Windows 4624/4625.", "utmp", True),
    CatalogEntry(r"var/log/journal/", "systemd journal", "Operating System",
                 "Primary modern Linux log store — service starts, sudo, ssh, USB, shutdown.",
                 "journald", True),
    CatalogEntry(r"var/log/(secure|auth\.log)", "Authentication log", "Operating System",
                 "SSH logins, sudo escalation, PAM failures.", "text", True),
    CatalogEntry(r"var/log/audit/", "auditd", "Operating System",
                 "Syscall-level execve/open records — the Linux equivalent of process auditing.",
                 "auditd", True),
    CatalogEntry(r"etc/(systemd|init\.d|rc\.local)", "Service persistence", "Operating System",
                 "systemd units / init scripts are the primary Linux persistence mechanism.",
                 "text", True),
    CatalogEntry(r"(cron\.d|spool/cron|crontab)", "Cron jobs", "Operating System",
                 "Scheduled execution persistence.", "text", True),
    CatalogEntry(r"var/lib/(dpkg/status|rpm/Packages)", "Installed packages", "Operating System",
                 "Software inventory equivalent to AXIOM 'Installed Programs'.", "pkgdb", True),
    CatalogEntry(r"\.ssh/(authorized_keys|known_hosts|id_)", "SSH key material", "Encryption & Credentials",
                 "authorized_keys = backdoor persistence; known_hosts = lateral movement targets.",
                 "text", True),
    CatalogEntry(r"\.(bash|zsh|mysql|psql|python)_history", "Shell history", "Application Usage",
                 "Verbatim attacker/user commands with ordering.", "text", True),
    CatalogEntry(r"var/lib/docker/containers/", "Container logs & config", "Additional Sources",
                 "Nested evidence source; stdout logs and mount config for each container.",
                 "json", True),
    CatalogEntry(r"var/www/|/html/.*\.(php|jsp|aspx)$", "Web root content", "Web Related",
                 "Webshells and defacement artifacts.", "text", True),
    CatalogEntry(r"\.config/autostart/.*\.desktop", "Desktop autostart", "Operating System",
                 "User-level persistence (GNOME/KDE).", "text"),
    CatalogEntry(r"etc/NetworkManager/system-connections/", "Saved networks", "Connected Devices",
                 "SSIDs and PSKs — device geolocation and network attribution.", "text", True),
    CatalogEntry(r"etc/ld\.so\.preload", "LD_PRELOAD hijack", "Operating System",
                 "Classic userland rootkit indicator.", "text", True),
)

CATALOG = CATALOG + (
    # --- gap closure -------------------------------------------------------
    CatalogEntry(r"/(mlocate|plocate)\.db$", "locate database", "Operating System",
                 "Indexed filename listing. Frequently the only surviving record of files "
                 "the subject deleted before imaging.", "locatedb", True),
    CatalogEntry(r"var/lib/(containerd|containers|docker)/", "Container runtime state",
                 "Additional Sources",
                 "Container layers and config are a nested filesystem: an entire second "
                 "evidence set, including web shells and exfil staging.", "nested_source", True),
    CatalogEntry(r"var/lib/sss/", "SSSD cache", "Accounts",
                 "Cached domain identities and last-login times for accounts that exist only "
                 "in AD/LDAP and appear nowhere in /etc/passwd.", "sssd", True),
    CatalogEntry(r"var/lib/networkmanager/", "NetworkManager leases", "Network Activity",
                 "DHCP lease history — ties this host to an IP address at a point in time.",
                 "text", True),
    CatalogEntry(r"var/lib/bluetooth/", "Bluetooth pairings", "Connections",
                 "Paired device MACs and names: proximity and device-association evidence.",
                 "text"),
    CatalogEntry(r"(wtmpdb|lastlog2)", "systemd session accounting", "Accounts",
                 "systemd 256+ replaced binary wtmp/lastlog with SQLite. Collectors that look "
                 "only for /var/log/wtmp silently report zero logins on modern distributions.",
                 "sqlite", True),
    CatalogEntry(r"var/spool/cups/", "CUPS print spool", "Documents",
                 "Control files plus the spooled document body — print-based exfiltration.",
                 "spool", True),
    CatalogEntry(r"(var/crash|coredump|abrt)/", "Crash dumps", "Application Usage",
                 "Core dumps name the executed binary and can retain in-memory secrets.",
                 "coredump"),
    CatalogEntry(r"var/lib/php/sessions/", "PHP sessions", "Network Activity",
                 "Web-shell and application session state on a compromised web server.", "text"),
    CatalogEntry(r"/\.(netrc|pgpass|my\.cnf|git-credentials|npmrc)$", "Cleartext credential files",
                 "Encryption & Credentials",
                 "Plaintext service credentials used for lateral movement.", "text", True),
    CatalogEntry(r"var/log/sysstat/", "sar accounting", "Operating System",
                 "Historic CPU/network/disk utilisation — corroborates when bulk exfiltration "
                 "or crypto-mining occurred.", "sysstat"),
)

PACK = ArtifactScopePack(
    os_family="linux",
    axiom_platform="Linux",
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
