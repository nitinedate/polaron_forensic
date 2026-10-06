"""Count-domain metadata keyed by normalized artifact name (DOCX §5 platform catalog)."""

from __future__ import annotations

from typing import Any

from app.services.catalog_section_queries import (
    EMAIL_ATTACHMENT_WHERE,
    JUMP_LIST_WHERE,
    LNK_FILE_WHERE,
    LOGFILE_ANALYSIS_WHERE,
    OUTLOOK_EMAIL_WHERE,
    EMLX_FILE_WHERE,
    WINDOWS_MAIL_WHERE,
)

# Normalized artifact name → metadata fields for public.axiom_artifacts.metadata
ARTIFACT_COUNT_METADATA: dict[str, dict[str, Any]] = {
    "usb devices": {
        "count_domain": "artifact_record",
        "record_unit": "registry_value",
        "query_key": "USB_REGISTRY_SETUPAPI",
        "parser_family": "registry",
        "axiom_reconciliation_group": "USB_DEVICES",
    },
    "your phone device": {
        "count_domain": "artifact_record",
        "record_unit": "linked_device_record",
        "query_key": "YOUR_PHONE_REGISTRY",
        "parser_family": "registry",
    },
    "remote desktop protocol": {
        "count_domain": "artifact_record",
        "record_unit": "connection",
        "query_key": "RDP_REGISTRY",
        "parser_family": "registry",
    },
    "remote desktop protocol (rdp)": {
        "count_domain": "artifact_record",
        "record_unit": "connection",
        "query_key": "RDP_REGISTRY",
        "parser_family": "registry",
    },
    "feature usage": {
        "count_domain": "artifact_record",
        "record_unit": "registry_value",
        "query_key": "FEATURE_USAGE_REGISTRY",
        "parser_family": "registry",
    },
    "installed microsoft programs": {
        "count_domain": "artifact_record",
        "record_unit": "installed_program_registry_entry",
        "query_key": "INSTALLED_PROGRAMS_REGISTRY",
        "parser_family": "registry",
    },
    "installed programs (non-microsoft)": {
        "count_domain": "artifact_record",
        "record_unit": "installed_program_registry_entry",
        "query_key": "INSTALLED_PROGRAMS_REGISTRY",
        "parser_family": "registry",
    },
    "windows defender logs": {
        "count_domain": "file_occurrence",
        "record_unit": "defender_log_file",
        "query_key": "WINDOWS_DEFENDER_LOG_FILES",
        "parser_family": "path_inventory",
    },
    "web chat urls": {
        "count_domain": "artifact_record",
        "record_unit": "visit",
        "query_key": "URL_VISIT_WEB_CHAT",
        "parser_family": "sqlite",
    },
    "social media urls": {
        "count_domain": "artifact_record",
        "record_unit": "visit",
        "query_key": "URL_VISIT_SOCIAL",
        "parser_family": "sqlite",
    },
    "malware/phishing urls": {
        "count_domain": "artifact_record",
        "record_unit": "visit",
        "query_key": "URL_VISIT_MALWARE",
        "parser_family": "sqlite",
    },
    "pornography urls": {
        "count_domain": "artifact_record",
        "record_unit": "visit",
        "query_key": "URL_VISIT_PORNOGRAPHY",
        "parser_family": "sqlite",
    },
    "dating site urls": {
        "count_domain": "artifact_record",
        "record_unit": "visit",
        "query_key": "URL_VISIT_DATING",
        "parser_family": "sqlite",
    },
    "audio": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "MEDIA_FULL_DISK",
        "parser_family": "path_inventory",
    },
    "picture": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "MEDIA_FULL_DISK",
        "parser_family": "path_inventory",
    },
    "pictures": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "MEDIA_FULL_DISK",
        "parser_family": "path_inventory",
    },
    "video": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "MEDIA_FULL_DISK",
        "parser_family": "path_inventory",
    },
    "photoshop files": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "MEDIA_FULL_DISK",
        "parser_family": "path_inventory",
    },
    "eml(x) files": {
        "count_domain": "artifact_record",
        "record_unit": "message",
        "query_key": "EMLX_FILE_WHERE",
        "parser_family": "path_inventory",
    },
    "windows mail": {
        "count_domain": "artifact_record",
        "record_unit": "message",
        "query_key": "WINDOWS_MAIL_WHERE",
        "parser_family": "sqlite",
    },
    "email attachments": {
        "count_domain": "artifact_record",
        "record_unit": "attachment",
        "query_key": "EMAIL_ATTACHMENT_WHERE",
        "parser_family": "path_inventory",
    },
    "jump list": {
        "count_domain": "artifact_record",
        "record_unit": "jump_list_destination",
        "query_key": "JUMP_LIST_WHERE",
        "parser_family": "path_inventory",
    },
    "jump lists": {
        "count_domain": "artifact_record",
        "record_unit": "jump_list_destination",
        "query_key": "JUMP_LIST_WHERE",
        "parser_family": "path_inventory",
    },
    "lnk files": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "LNK_FILE_WHERE",
        "parser_family": "path_inventory",
    },
    "logfile analysis": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "LOGFILE_ANALYSIS_WHERE",
        "parser_family": "path_inventory",
    },
    "$logfile analysis": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "LOGFILE_ANALYSIS_WHERE",
        "parser_family": "path_inventory",
    },
    "web related files": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "WEB_RELATED_WHERE",
        "parser_family": "path_inventory",
    },
    "encrypted files": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "ENCRYPTED_CONTENT_SCAN",
        "parser_family": "path_inventory",
    },
    "windows stored credentials": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "WINDOWS_CREDENTIALS_WHERE",
        "parser_family": "path_inventory",
    },
    "outlook emails": {
        "count_domain": "artifact_record",
        "record_unit": "message",
        "query_key": "OUTLOOK_EMAIL_WHERE",
        "parser_family": "sqlite",
    },
    "outlook tasks": {
        "count_domain": "artifact_record",
        "record_unit": "item",
        "query_key": "OUTLOOK_ITEM_PARSED",
        "parser_family": "sqlite",
    },
    "outlook contacts": {
        "count_domain": "artifact_record",
        "record_unit": "item",
        "query_key": "OUTLOOK_ITEM_PARSED",
        "parser_family": "sqlite",
    },
    "outlook appointments": {
        "count_domain": "artifact_record",
        "record_unit": "item",
        "query_key": "OUTLOOK_ITEM_PARSED",
        "parser_family": "sqlite",
    },
}

CATEGORY_DEFAULT_METADATA: dict[str, dict[str, Any]] = {
    "documents": {
        "count_domain": "file_occurrence",
        "record_unit": "file_entry",
        "query_key": "DOCUMENT_EXTENSION",
        "parser_family": "path_inventory",
    },
    "email & calendar": {
        "count_domain": "artifact_record",
        "record_unit": "message",
        "query_key": "OUTLOOK_EMAIL_WHERE",
        "parser_family": "sqlite",
    },
    "email and calendar": {
        "count_domain": "artifact_record",
        "record_unit": "message",
        "query_key": "OUTLOOK_EMAIL_WHERE",
        "parser_family": "sqlite",
    },
    "communication": {
        "count_domain": "artifact_record",
        "record_unit": "visit",
        "query_key": "URL_VISIT_CATEGORY",
        "parser_family": "sqlite",
    },
}

QUERY_SNAPSHOT_FRAGMENTS: dict[str, str] = {
    "EMAIL_ATTACHMENT_WHERE": EMAIL_ATTACHMENT_WHERE.strip(),
    "OUTLOOK_EMAIL_WHERE": OUTLOOK_EMAIL_WHERE.strip(),
    "JUMP_LIST_WHERE": JUMP_LIST_WHERE.strip(),
    "LNK_FILE_WHERE": LNK_FILE_WHERE.strip(),
    "LOGFILE_ANALYSIS_WHERE": LOGFILE_ANALYSIS_WHERE.strip(),
    "EMLX_FILE_WHERE": EMLX_FILE_WHERE.strip(),
    "WINDOWS_MAIL_WHERE": WINDOWS_MAIL_WHERE.strip(),
}


def metadata_for_artifact(*, artifact_name: str, category: str) -> dict[str, Any]:
    import re

    from app.services.catalog_categories import norm_category_key

    name = re.sub(r"\s+", " ", (artifact_name or "").strip().lower())
    cat = norm_category_key(category)
    if name in ARTIFACT_COUNT_METADATA:
        return dict(ARTIFACT_COUNT_METADATA[name])
    for cat_key, meta in CATEGORY_DEFAULT_METADATA.items():
        if cat_key in cat:
            return dict(meta)
    # Long-tail catalog rows without an explicit parser/query contract must not
    # masquerade as parsed artifact records. The fallback is only a source-path hit.
    return {
        "count_domain": "unverified_source_hit",
        "record_unit": "source_file_hit",
        "query_key": "PATH_FALLBACK_UNVERIFIED",
        "parser_family": "path_inventory",
    }


def query_snapshot_for_key(query_key: str, *, artifact_name: str = "", extensions: list[str] | None = None) -> dict[str, Any]:
    snap: dict[str, Any] = {"query_key": query_key, "artifact_name": artifact_name}
    fragment = QUERY_SNAPSHOT_FRAGMENTS.get(query_key)
    if fragment:
        snap["where_fragment"] = fragment[:2000]
    if extensions:
        snap["extensions"] = extensions
    return snap
