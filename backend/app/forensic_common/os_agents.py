"""OS-family pipeline agents — one registered agent per supported OS family.

Used by the agent registry UI so disk/mobile jobs are scoped to the OS actually
detected instead of a Windows-shaped default.
"""

from __future__ import annotations

from typing import Any

OS_STAGE_AGENTS: dict[str, dict[str, Any]] = {
    "windows_os_agent": {
        "name": "Windows OS Agent",
        "stage": "os_scope",
        "description": "Scopes extract/parse/inventory for Windows disk images (NTFS, registry, Event Logs).",
        "queue": "disk-build",
        "domain": "disk",
        "os_family": "windows",
        "axiom_platform": "windows",
        "parsers": ("evtx", "registry", "prefetch", "lnk", "sqlite", "browser"),
    },
    "macos_os_agent": {
        "name": "macOS OS Agent",
        "stage": "os_scope",
        "description": "Scopes extract/parse/inventory for macOS disk images (APFS/HFS+, plist, Unified Logs).",
        "queue": "disk-build",
        "domain": "disk",
        "os_family": "macos",
        "axiom_platform": "macos",
        "parsers": ("plist", "sqlite", "browser", "unified_log"),
    },
    "linux_os_agent": {
        "name": "Linux OS Agent",
        "stage": "os_scope",
        "description": "Scopes extract/parse/inventory for Linux disk images (ext/xfs, bash history, systemd).",
        "queue": "disk-build",
        "domain": "disk",
        "os_family": "linux",
        "axiom_platform": "linux",
        "parsers": ("sqlite", "browser", "shell_history", "syslog"),
    },
    "androidagent": {
        "name": "Android Agent",
        "stage": "extract",
        "description": (
            "Owns Android USB/MTP/ADB collection plus extract, parse, and RAG. "
            "Never processes iPhones."
        ),
        "queue": "android-build",
        "domain": "mobile",
        "os_family": "android",
        "axiom_platform": "android",
        "parsers": ("sqlite", "protobuf", "media", "whatsapp"),
    },
    "iosagent": {
        "name": "iOS Agent",
        "stage": "extract",
        "description": (
            "Owns iPhone/iPad USB collection plus extract, parse, and RAG. "
            "Never processes Android phones."
        ),
        "queue": "ios-build",
        "domain": "mobile",
        "os_family": "ios",
        "axiom_platform": "ios",
        "parsers": ("plist", "sqlite", "whatsapp", "media"),
    },
    "android_os_agent": {
        "name": "Android Agent",
        "stage": "os_scope",
        "description": "Alias of androidagent — scopes Android extract/parse/inventory.",
        "queue": "android-build",
        "domain": "mobile",
        "os_family": "android",
        "axiom_platform": "android",
        "alias_of": "androidagent",
        "parsers": ("sqlite", "protobuf", "media", "whatsapp"),
    },
    "ios_os_agent": {
        "name": "iOS Agent",
        "stage": "os_scope",
        "description": "Alias of iosagent — scopes iOS extract/parse/inventory.",
        "queue": "ios-build",
        "domain": "mobile",
        "os_family": "ios",
        "axiom_platform": "ios",
        "alias_of": "iosagent",
        "parsers": ("plist", "sqlite", "whatsapp", "media"),
    },
}
