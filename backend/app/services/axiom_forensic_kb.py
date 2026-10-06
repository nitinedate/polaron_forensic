"""Authoritative Magnet AXIOM forensic-report knowledge base.

This module integrates the user-supplied ``aetheris_axiom_kb_starter`` package into
Aetheris without introducing a second FastAPI application or a duplicate case/artifact
schema.  The JSON seed from that project is the single source of truth for:

* controlled forensic procedures;
* canonical AXIOM artifact families and aliases;
* primary/supporting/corroborating evidence relationships;
* count and semantic-deduplication rules;
* zero-result wording and limitations; and
* report-writing guardrails.

The existing Aetheris report UI, case intake, evidence collectors, PostgreSQL schema,
PDF/DOCX renderer and report approval workflow remain in place.  Current broad case
objectives are mapped to one or more precise KB report definitions.  An LLM is allowed
only to rewrite a deterministic evidence brief; it never chooses the evidence set or
changes the count.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

_KB_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "axiom_kb" / "axiom_forensic_kb.json"

REPORT_AGENT_SYSTEM_RULES = """
You are the Aetheris forensic report-writing agent. You receive a deterministic evidence brief produced by the forensic rules engine.

MANDATORY RULES:
1. Do not change counts supplied by the rules engine.
2. Do not add artifacts or facts that are absent from the evidence brief.
3. Do not count supporting/corroborating/contextual artifacts as primary events.
4. Do not treat Refined Results, parent artifacts or Timeline timestamp rows as independent events unless the report definition explicitly says so.
5. Do not claim intent, ownership, authorship, execution, remote access, deletion, compromise, file transfer or user action beyond what the evidence directly supports.
6. For carved/partial evidence, explicitly qualify the recovery state.
7. Never output raw Appx BlockMap XML, package manifests, registry dumps, binary blobs, serialized JSON/XML payloads or unrelated strings as observations.
8. Do not use internal labels such as 'Laptop [1]' or catalog IDs as report headings.
9. If a primary count is zero, use only the supplied zero-result interpretation and never claim the activity never happened.
10. Write a short factual observation followed by one simple explanation suitable for a non-technical reader.
11. Preserve limitations and source traceability.
12. If evidence is ambiguous or high-impact, say the conclusion is limited and requires examiner review.
13. Never copy values from example/reference reports. Every name, count, date and conclusion must come from the current case evidence brief.
14. Use the supplied forensic-report exemplar corpus only to learn evidence questions, query/deduplication method, Objective/Procedure structure, Annexure traceability and the distinction between presence/access/connection and stronger actions such as use/transfer/execution/unauthorized control.
15. A negative finding is allowed only when the required evidence family was actually covered; incomplete or unavailable coverage must remain inconclusive.
16. Write every Objective, Procedure and Observation in full. The Report Formation Agent packs Section C onto A4 pages; do not omit a finding to save space and do not invent filler sentences to pad a page.
17. Write every Annexure table row in full. The Report Formation Agent packs only the rows that fit above the footer and must verify no serial is missing; do not drop a URL or invent filler rows.
""".strip()


# Product-level broad objectives -> precise report definitions from the attached KB.
# These mappings select WHICH controlled KB reports answer a business question.  The
# report/procedure/count rules themselves remain in the supplied JSON and are not
# duplicated here.
OBJECTIVE_REPORT_MAP: dict[str, tuple[str, ...]] = {
    # Disk/computer objectives.
    "User Accounts & Login Activity": ("USER_ACCOUNTS", "LOGON_LOGOFF_ACTIVITY", "RDP_ACTIVITY"),
    "File Access and Handling": ("RECENT_DOCUMENTS", "LNK_FILES", "JUMP_LISTS", "RECYCLE_BIN", "DELETED_FILES"),
    "USB and External Device Usage": ("USB_DEVICES", "LNK_FILES", "JUMP_LISTS"),
    "Network Connections": ("RDP_ACTIVITY", "WIFI_ACTIVITY", "SSH_ACTIVITY"),
    "Installed Applications & Tools": ("INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION", "PREFETCH_ANALYSIS", "AMCACHE_ANALYSIS"),
    "Registry Analysis": ("USERASSIST_ANALYSIS", "AMCACHE_ANALYSIS", "SHELLBAGS", "AUTORUNS_STARTUP"),
    "Scheduled Tasks & Startup Items": ("SCHEDULED_TASKS", "AUTORUNS_STARTUP"),
    "Antivirus & Patch Status": ("SECURITY_DETECTIONS", "WINDOWS_EVENT_LOGS"),
    "Event Logs & Timeline Reconstruction": ("WINDOWS_EVENT_LOGS", "TIMELINE_EVENTS", "LOGON_LOGOFF_ACTIVITY"),
    "Email Artifacts (Local Clients)": ("EMAIL_COMMUNICATIONS",),
    # The supplied KB has no dedicated clipboard/print report. Leave unmapped rather
    # than pretending another artifact family answers the question.
    "Clipboard & Print Activity": (),
    "Virtual Machines or Sandbox Use": ("INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION"),
    "Chat / Communication Apps": ("INSTANT_MESSAGING", "CALL_HISTORY", "BROWSER_HISTORY"),
    "Hidden Partitions / Alternate Data Streams (ADS)": ("VOLUME_INFORMATION",),
    "Anti-Forensic Tools or Cleanup Attempts": ("INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION", "WINDOWS_EVENT_LOGS", "SECURITY_DETECTIONS"),
    "Data Sync Clients": ("INSTALLED_APPLICATIONS", "BROWSER_HISTORY", "BROWSER_DOWNLOADS", "CLOUD_FILES", "CLOUD_ACTIVITY"),
    "Shadow Copies & Backup Artifacts": ("VOLUME_INFORMATION",),
    "Detection of Torrent Activity": ("INSTALLED_APPLICATIONS", "BROWSER_HISTORY", "BROWSER_DOWNLOADS"),
    "Malware, Phishing and Pornography URLs": ("SECURITY_DETECTIONS", "BROWSER_HISTORY", "BROWSER_DOWNLOADS", "HASH_MATCHES"),
    "Access to Cloud Storage Services": ("BROWSER_HISTORY", "BROWSER_DOWNLOADS", "CLOUD_FILES", "CLOUD_ACTIVITY"),
    "Connection of External Hard Disks": ("USB_DEVICES", "LNK_FILES", "JUMP_LISTS"),
    "Use of WhatsApp Web and Download of RRP Files": ("BROWSER_HISTORY", "BROWSER_DOWNLOADS", "INSTANT_MESSAGING"),
    "Deleted Files Found in Recycle Bin": ("RECYCLE_BIN", "DELETED_FILES"),
    "Presence of Encrypted Files": ("ENCRYPTED_FILES",),
    "Email Accounts Used on the Laptop": ("EMAIL_COMMUNICATIONS", "USER_ACCOUNTS", "BROWSER_HISTORY"),
    "Storage of Email Login Details in Notepad": ("DOCUMENTS", "KEYWORD_SEARCH"),
    "Storage of RRP-Related Documents on Personal Laptop": ("DOCUMENTS", "KEYWORD_SEARCH", "EMAIL_COMMUNICATIONS", "BROWSER_DOWNLOADS", "CLOUD_FILES"),
    # Reference-corpus objectives. These aliases keep the current Aetheris
    # KB authoritative while allowing report titles used by the supplied examiner
    # reports to resolve to the same controlled artifact families.
    "Verify Use of Unauthorized Remote Access Tools": ("INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION", "RDP_ACTIVITY", "WINDOWS_EVENT_LOGS"),
    "Cloud Storage Service Usage": ("BROWSER_HISTORY", "BROWSER_DOWNLOADS", "CLOUD_FILES", "CLOUD_ACTIVITY"),
    "Analysis of Chat / Communication Apps": ("BROWSER_HISTORY", "INSTANT_MESSAGING", "CALL_HISTORY"),
    "Analysis of Social Media Activity": ("BROWSER_HISTORY",),
    "Internet and Network Connection Review": ("BROWSER_HISTORY", "BROWSER_DOWNLOADS", "RDP_ACTIVITY", "WIFI_ACTIVITY", "SSH_ACTIVITY"),
    "Anti-Forensics Tools": ("INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION", "PREFETCH_ANALYSIS", "AMCACHE_ANALYSIS", "WINDOWS_EVENT_LOGS"),
    "Torrent URLs": ("BROWSER_HISTORY", "BROWSER_DOWNLOADS", "INSTALLED_APPLICATIONS", "PROGRAM_EXECUTION"),
    "Malware / Phishing URL Verification": ("BROWSER_HISTORY", "BROWSER_DOWNLOADS", "SECURITY_DETECTIONS", "HASH_MATCHES"),
    # Mobile objectives.
    "Device Identity & SIM Attribution": ("MOBILE_DEVICE_INFORMATION",),
    "Mobile Chat & Messaging Applications": ("INSTANT_MESSAGING", "CALL_HISTORY"),
    "Mobile File Access & Media Handling": ("DOCUMENTS", "PICTURES", "VIDEOS", "AUDIO", "DELETED_FILES"),
    "Mobile User Accounts & App Logins": ("USER_ACCOUNTS", "MOBILE_APP_USAGE"),
    "Installed Mobile Applications": ("MOBILE_INSTALLED_APPS",),
    "Mobile Email & Attachments": ("EMAIL_COMMUNICATIONS",),
    "Social Media & LinkedIn Activity": ("INSTANT_MESSAGING", "BROWSER_HISTORY", "MOBILE_APP_USAGE"),
    "Mobile Cloud Storage & Sync": ("CLOUD_FILES", "CLOUD_ACTIVITY", "MOBILE_APP_USAGE"),
    "Contacts & Address Book": ("CONTACTS",),
    "Mobile External Storage & USB/OTG": ("USB_DEVICES", "VOLUME_INFORMATION"),
}

# Known aspects that the supplied starter does not directly model.  These are shown as
# limitations so the report agent cannot silently fill a gap using unrelated evidence.
# Of the KB reports selected above, only these directly answer the broad Case-intake
# question without needing an additional target/content filter. Other mapped reports are
# supporting/corroborating context. This prevents a generic Browser History, Documents,
# LNK, Excel or RDP total from becoming the answer to a different objective.
OBJECTIVE_DIRECT_REPORT_MAP: dict[str, tuple[str, ...]] = {
    "User Accounts & Login Activity": ("USER_ACCOUNTS", "LOGON_LOGOFF_ACTIVITY"),
    "File Access and Handling": (),
    "USB and External Device Usage": ("USB_DEVICES",),
    "Network Connections": ("RDP_ACTIVITY", "WIFI_ACTIVITY", "SSH_ACTIVITY"),
    "Installed Applications & Tools": ("INSTALLED_APPLICATIONS",),
    "Registry Analysis": ("USERASSIST_ANALYSIS", "AMCACHE_ANALYSIS", "SHELLBAGS", "AUTORUNS_STARTUP"),
    "Scheduled Tasks & Startup Items": ("SCHEDULED_TASKS", "AUTORUNS_STARTUP"),
    "Antivirus & Patch Status": ("SECURITY_DETECTIONS",),
    "Event Logs & Timeline Reconstruction": ("WINDOWS_EVENT_LOGS", "TIMELINE_EVENTS"),
    "Email Artifacts (Local Clients)": ("EMAIL_COMMUNICATIONS",),
    "Clipboard & Print Activity": (),
    "Virtual Machines or Sandbox Use": (),
    "Chat / Communication Apps": ("INSTANT_MESSAGING", "CALL_HISTORY"),
    "Hidden Partitions / Alternate Data Streams (ADS)": (),
    "Anti-Forensic Tools or Cleanup Attempts": (),
    "Data Sync Clients": ("CLOUD_ACTIVITY", "CLOUD_FILES"),
    "Shadow Copies & Backup Artifacts": (),
    "Detection of Torrent Activity": (),
    "Malware, Phishing and Pornography URLs": ("SECURITY_DETECTIONS",),
    "Access to Cloud Storage Services": (),
    "Connection of External Hard Disks": (),
    "Use of WhatsApp Web and Download of RRP Files": (),
    "Deleted Files Found in Recycle Bin": ("RECYCLE_BIN", "DELETED_FILES"),
    "Presence of Encrypted Files": ("ENCRYPTED_FILES",),
    "Email Accounts Used on the Laptop": (),
    "Storage of Email Login Details in Notepad": (),
    "Storage of RRP-Related Documents on Personal Laptop": (),
    "Verify Use of Unauthorized Remote Access Tools": (),
    "Cloud Storage Service Usage": (),
    "Analysis of Chat / Communication Apps": (),
    "Analysis of Social Media Activity": (),
    "Internet and Network Connection Review": (),
    "Anti-Forensics Tools": (),
    "Torrent URLs": (),
    "Malware / Phishing URL Verification": (),
    "Device Identity & SIM Attribution": ("MOBILE_DEVICE_INFORMATION",),
    "Mobile Chat & Messaging Applications": ("INSTANT_MESSAGING", "CALL_HISTORY"),
    "Mobile File Access & Media Handling": ("DOCUMENTS", "PICTURES", "VIDEOS", "AUDIO", "DELETED_FILES"),
    "Mobile User Accounts & App Logins": ("USER_ACCOUNTS", "MOBILE_APP_USAGE"),
    "Installed Mobile Applications": ("MOBILE_INSTALLED_APPS",),
    "Mobile Email & Attachments": ("EMAIL_COMMUNICATIONS",),
    "Social Media & LinkedIn Activity": (),
    "Mobile Cloud Storage & Sync": ("CLOUD_FILES", "CLOUD_ACTIVITY"),
    "Contacts & Address Book": ("CONTACTS",),
    "Mobile External Storage & USB/OTG": ("USB_DEVICES", "VOLUME_INFORMATION"),
}


OBJECTIVE_KB_LIMITATIONS: dict[str, tuple[str, ...]] = {
    "Clipboard & Print Activity": (
        "The supplied AXIOM report knowledge base does not define a dedicated clipboard or print-activity report.",
    ),
    "Antivirus & Patch Status": (
        "The supplied knowledge base covers security detections and operating-system logs, but does not define a dedicated patch-inventory report.",
    ),
    "Hidden Partitions / Alternate Data Streams (ADS)": (
        "The supplied knowledge base defines volume/partition reporting but does not define a dedicated Alternate Data Streams report.",
    ),
    "Shadow Copies & Backup Artifacts": (
        "The supplied knowledge base does not define a dedicated Volume Shadow Copy/backup report.",
    ),
}


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _tokens(value: Any) -> set[str]:
    return {t for t in _norm(value).split() if len(t) > 2 and t not in {"the", "and", "for", "with", "from", "this", "that"}}


@lru_cache(maxsize=1)
def load_knowledge_base() -> dict[str, Any]:
    data = json.loads(_KB_PATH.read_text(encoding="utf-8"))
    # Defensive copy happens at public edges; cached data is never mutated.
    return data


@lru_cache(maxsize=1)
def _active_exclusion_regexes() -> tuple[re.Pattern[str], ...]:
    """Compile the global narrative exclusions supplied by the AXIOM KB."""
    compiled: list[re.Pattern[str]] = []
    for rule in load_knowledge_base().get("exclusions", []):
        if not rule.get("active", True):
            continue
        if str(rule.get("pattern_type") or "REGEX").upper() != "REGEX":
            continue
        pattern = str(rule.get("pattern") or "").strip()
        if not pattern:
            continue
        try:
            compiled.append(re.compile(pattern, re.I))
        except re.error:
            continue
    return tuple(compiled)


@lru_cache(maxsize=1)
def _report_by_id() -> dict[str, dict[str, Any]]:
    return {str(r["id"]): r for r in load_knowledge_base().get("reports", [])}


@lru_cache(maxsize=1)
def _procedure_by_id() -> dict[str, dict[str, Any]]:
    return {str(p["id"]): p for p in load_knowledge_base().get("procedures", [])}


@lru_cache(maxsize=1)
def _artifact_alias_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for row in load_knowledge_base().get("artifact_catalog", []):
        canonical = str(row.get("canonical_name") or "").strip()
        if not canonical:
            continue
        for name in [canonical, *(row.get("aliases") or [])]:
            n = _norm(name)
            if n:
                idx[n] = canonical
    # Product/catalog spellings seen in the existing Aetheris project.
    idx.update({
        "remote desktop protocol rdp": "RDP Activity",
        "remote desktop protocol": "RDP Activity",
        "outlook emails": "Email Messages",
        "windows mail": "Email Messages",
        "eml x files": "Email Messages",
        "email attachments": "Communication Attachments",
        "web chat urls": "Browser History",
        "social media urls": "Browser History",
        "malware phishing urls": "Browser History",
        "pornography urls": "Browser History",
        "dating site urls": "Browser History",
        "web related files": "Browser History",
        "microsoft word documents": "Documents",
        "microsoft excel documents": "Documents",
        "microsoft powerpoint documents": "Documents",
        "pdf documents": "Documents",
        "rtf documents": "Documents",
        "text documents": "Documents",
        "picture": "Pictures",
        "photoshop files": "Pictures",
        "video": "Videos",
        "jump list": "Jump Lists",
        "logfile analysis": "Windows Event Log",
        "feature usage": "Mobile App Usage",
        "installed microsoft programs": "Installed Applications",
        "installed programs non microsoft": "Installed Applications",
        "windows defender logs": "Security Detections",
        "encrypted files": "Encrypted Files",
        "usb devices": "USB Devices",
    })
    return idx


def canonical_artifact_family(name: Any) -> str | None:
    """Map AXIOM/current-catalog display names to the supplied canonical family."""
    n = _norm(name)
    if not n:
        return None
    idx = _artifact_alias_index()
    if n in idx:
        return idx[n]
    # Conservative partial alias matching; require a meaningful long alias.
    matches: list[tuple[int, str]] = []
    for alias, canonical in idx.items():
        if len(alias) >= 8 and (alias in n or n in alias):
            matches.append((len(alias), canonical))
    if matches:
        matches.sort(reverse=True)
        return matches[0][1]
    return None


def report_definition(report_id: str) -> dict[str, Any] | None:
    row = _report_by_id().get(str(report_id or ""))
    return deepcopy(row) if row else None


def procedure_definition(procedure_id: str) -> dict[str, Any] | None:
    row = _procedure_by_id().get(str(procedure_id or ""))
    return deepcopy(row) if row else None


def all_report_definitions() -> list[dict[str, Any]]:
    return deepcopy(load_knowledge_base().get("reports", []))


def all_procedures() -> list[dict[str, Any]]:
    return deepcopy(load_knowledge_base().get("procedures", []))


def all_artifact_catalog() -> list[dict[str, Any]]:
    return deepcopy(load_knowledge_base().get("artifact_catalog", []))


def _lexical_report_ids(title: str, statement: str = "", *, limit: int = 4) -> list[str]:
    """Fallback for new/custom objectives not present in OBJECTIVE_REPORT_MAP."""
    query_tokens = _tokens(f"{title} {statement}")
    if not query_tokens:
        return []
    scored: list[tuple[float, str]] = []
    for report in load_knowledge_base().get("reports", []):
        proc = _procedure_by_id().get(str(report.get("procedure_id") or ""), {})
        mappings = " ".join(str(m.get("artifact_family") or "") for m in report.get("artifact_mappings", []))
        hay = f"{report.get('title','')} {report.get('objective','')} {proc.get('name','')} {proc.get('purpose','')} {mappings}"
        rt = _tokens(hay)
        overlap = query_tokens & rt
        if not overlap:
            continue
        # Favor title/objective overlap while still allowing procedure/artifact vocabulary.
        title_overlap = query_tokens & _tokens(f"{report.get('title','')} {report.get('objective','')}")
        score = len(overlap) + 1.5 * len(title_overlap)
        scored.append((score, str(report["id"])))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [rid for _, rid in scored[:limit]]


def resolve_objective_report_ids(title: str, statement: str = "") -> list[str]:
    exact = OBJECTIVE_REPORT_MAP.get(str(title or "").strip())
    if exact is not None:
        return list(exact)
    # The supplied report corpus adds a curated semantic alias layer.  It contributes
    # only report/procedure selection guidance; it never contributes case facts.
    try:
        from app.services.report_reference_kb import reference_report_ids_for_objective

        reference_ids = reference_report_ids_for_objective(title, statement)
        if reference_ids:
            return reference_ids
    except Exception:
        pass
    return _lexical_report_ids(title, statement)


def objective_knowledge_plan(title: str, statement: str = "") -> dict[str, Any]:
    """Return the deterministic knowledge plan for one current Aetheris objective."""
    report_ids = resolve_objective_report_ids(title, statement)
    reports = [r for rid in report_ids if (r := report_definition(rid))]
    procedure_ids: list[str] = []
    procedures: list[dict[str, Any]] = []
    for report in reports:
        pid = str(report.get("procedure_id") or "")
        if pid and pid not in procedure_ids:
            procedure_ids.append(pid)
            proc = procedure_definition(pid)
            if proc:
                procedures.append(proc)

    primary: list[str] = []
    supporting: list[str] = []
    corroborating: list[str] = []
    contextual: list[str] = []
    for report in reports:
        for m in report.get("artifact_mappings", []):
            family = str(m.get("artifact_family") or "").strip()
            relationship = str(m.get("relationship") or "").upper()
            target = {
                "PRIMARY": primary,
                "SUPPORTING": supporting,
                "CORROBORATING": corroborating,
                "CONTEXTUAL": contextual,
            }.get(relationship, supporting)
            if family and family not in target:
                target.append(family)

    limitations: list[str] = list(OBJECTIVE_KB_LIMITATIONS.get(str(title or "").strip(), ()))
    for report in reports:
        for item in report.get("limitations") or []:
            text = str(item).strip()
            if text and text not in limitations:
                limitations.append(text)

    direct_ids = list(OBJECTIVE_DIRECT_REPORT_MAP.get(str(title or "").strip(), ()))
    if str(title or "").strip() not in OBJECTIVE_DIRECT_REPORT_MAP:
        # For a custom objective that lexically matches the supplied KB, only the
        # strongest matching report is treated as the direct answer. Remaining matches
        # are evidence context until an examiner maps them explicitly.
        direct_ids = report_ids[:1]

    direct_primary: list[str] = []
    for report in reports:
        if report.get("id") not in set(direct_ids):
            continue
        for mapping in report.get("artifact_mappings") or []:
            family = str(mapping.get("artifact_family") or "").strip()
            if str(mapping.get("relationship") or "").upper() == "PRIMARY" and family and family not in direct_primary:
                direct_primary.append(family)

    try:
        from app.services.report_reference_kb import reference_agent_guidance, reference_corpus_fingerprint

        reference_guidance = reference_agent_guidance(title, statement)
        reference_fingerprint = reference_corpus_fingerprint() if reference_guidance else None
    except Exception:
        reference_guidance = {}
        reference_fingerprint = None

    try:
        from app.services.document_report_model import document_model_for_agent

        document_model = document_model_for_agent(title, statement)
    except Exception:
        document_model = {}

    return {
        "title": str(title or "").strip(),
        "statement": str(statement or "").strip(),
        "report_ids": report_ids,
        "direct_report_ids": direct_ids,
        "supporting_report_ids": [rid for rid in report_ids if rid not in set(direct_ids)],
        "reports": reports,
        "procedure_ids": procedure_ids,
        "procedures": procedures,
        "primary_artifact_families": primary,
        "direct_primary_artifact_families": direct_primary,
        "supporting_artifact_families": supporting,
        "corroborating_artifact_families": corroborating,
        "contextual_artifact_families": contextual,
        "limitations": limitations,
        "knowledge_base_version": "starter-1.0+forensic-report-exemplars-v2.0",
        "knowledge_base_fingerprint": knowledge_base_fingerprint(),
        "reference_exemplar_guidance": reference_guidance,
        "reference_exemplar_fingerprint": reference_fingerprint,
        "document_report_model": document_model,
        "knowledge_base_counts": {
            "procedures": len(load_knowledge_base().get("procedures", [])),
            "reports": len(load_knowledge_base().get("reports", [])),
            "artifact_families": len(load_knowledge_base().get("artifact_catalog", [])),
            "exclusions": len(load_knowledge_base().get("exclusions", [])),
        },
    }


def controlled_objective_text(title: str, statement: str = "") -> str:
    """Client objective wording derived from the supplied KB report definitions.

    When one or more KB reports directly answer the Case-intake question, their
    controlled objectives are used.  When the Case-intake question is broader than
    any single KB report, the printed objective names the business question and the
    precise controlled report scopes that will be correlated.  Legacy database wording
    is never allowed to override this at report-generation time.
    """
    plan = objective_knowledge_plan(title, statement)
    direct = set(plan.get("direct_report_ids") or [])
    reports = [r for r in (plan.get("reports") or []) if r.get("id") in direct]
    sentences: list[str] = []
    for report in reports[:2]:
        obj = re.sub(r"\s+", " ", str(report.get("objective") or "").strip())
        if not obj:
            continue
        if obj.endswith("."):
            obj = obj[:-1]
        sentence = obj if re.match(r"(?i)^to\s+", obj) else "To " + obj[:1].lower() + obj[1:]
        if sentence not in sentences:
            sentences.append(sentence)
    if sentences:
        return ". ".join(sentences) + "."

    mapped_titles = [
        re.sub(r"\s+", " ", str(r.get("title") or "").strip())
        for r in (plan.get("reports") or [])
        if str(r.get("title") or "").strip()
    ]
    display = re.sub(r"\s+", " ", str(title or "").strip())
    if mapped_titles and display:
        shown = mapped_titles[:4]
        scope = ", ".join(shown[:-1]) + (" and " + shown[-1] if len(shown) > 1 else shown[0])
        return (
            f"To examine {display.lower()} by correlating the controlled {scope} evidence and "
            "report only findings supported by the mapped primary evidence rules."
        )

    fallback = re.sub(r"\s+", " ", str(statement or "").strip())
    if fallback:
        return fallback if fallback.endswith(".") else fallback + "."
    return f"To examine evidence related to {display.lower()}." if display else ""


def controlled_procedure_text(title: str, statement: str = "", *, max_steps: int = 6) -> str:
    """Simple client-facing procedure built only from controlled KB procedures."""
    plan = objective_knowledge_plan(title, statement)
    if not plan["procedures"]:
        return (
            "The available forensic evidence was reviewed for this question. "
            "The supplied AXIOM knowledge base does not define a dedicated controlled procedure for this topic, "
            "so no unrelated artifact family was substituted."
        )
    steps: list[str] = []
    if max_steps > 0:
        for proc in plan["procedures"]:
            for step in proc.get("steps") or []:
                text = re.sub(r"\s+", " ", str(step).strip())
                if text and text not in steps:
                    steps.append(text)
                if len(steps) >= max_steps:
                    break
            if len(steps) >= max_steps:
                break
    purpose = "; ".join(str(p.get("purpose") or "").strip() for p in plan["procedures"] if p.get("purpose"))
    intro = "The examination used the controlled AXIOM procedure(s) linked to this objective."
    if purpose:
        intro += " " + purpose
    if not steps:
        return intro
    return intro + " " + " ".join(f"{i + 1}. {s}" for i, s in enumerate(steps))


def evidence_questions_for_objective(title: str, statement: str = "") -> list[str]:
    """Generate evidence questions from KB objectives, fields and controlled steps."""
    plan = objective_knowledge_plan(title, statement)
    questions: list[str] = []
    for report in plan["reports"]:
        obj = str(report.get("objective") or "").strip()
        if obj:
            questions.append(f"Does the current case evidence support this controlled report objective: {obj}")
        fields = [*(report.get("required_fields") or []), *(report.get("optional_fields") or [])]
        if fields:
            questions.append("Which supported values are available for: " + ", ".join(str(x) for x in fields[:8]) + "?")
        unit = str((report.get("count_rule") or {}).get("unit") or "").strip()
        keys = (report.get("count_rule") or {}).get("key_fields") or []
        if unit:
            questions.append(
                f"How many distinct {unit.lower().replace('_', ' ')} values remain after exclusions and semantic deduplication"
                + (f" using {', '.join(keys)}" if keys else "") + "?"
            )
    try:
        from app.services.report_reference_kb import reference_evidence_questions

        questions.extend(reference_evidence_questions(title, statement))
    except Exception:
        pass
    # Stable de-duplication.
    seen: set[str] = set()
    return [q for q in questions if q and not (q in seen or seen.add(q))][:16]


def rag_terms_for_objective(title: str, statement: str = "") -> list[str]:
    plan = objective_knowledge_plan(title, statement)
    terms: list[str] = [title]
    try:
        from app.services.document_report_model import extraction_queries_for_objective

        terms.extend(extraction_queries_for_objective(title, statement))
    except Exception:
        pass
    for report in plan["reports"]:
        terms.append(str(report.get("title") or ""))
        terms.append(str(report.get("objective") or ""))
        terms.extend(str(m.get("artifact_family") or "") for m in report.get("artifact_mappings", []))
        terms.extend(str(f) for f in report.get("optional_fields") or [])
    out: list[str] = []
    seen: set[str] = set()
    for term in terms:
        text = re.sub(r"\s+", " ", str(term).strip())
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out[:24]


def text_contains_prohibited_payload(value: Any) -> bool:
    text = str(value or "")
    if not text:
        return False
    if any(pattern.search(text) for pattern in _active_exclusion_regexes()):
        return True
    # Serialized wrappers are an Aetheris transport shape, not a forensic rule.
    if re.search(r"\[\s*\{\s*[\"']text[\"']\s*:\s*[\"']\s*<\?xml", text, re.I):
        return True
    return False


def sanitize_narrative_text(value: Any, *, max_len: int = 600) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text or text_contains_prohibited_payload(text):
        return ""
    # Remove internal source paths and serialized data fragments from narrative inputs.
    if text.startswith(("[{", "{\"", "{'")):
        return ""
    text = re.sub(r"[A-Za-z]:\\[^\s,;]+", "[internal path omitted]", text)
    text = re.sub(r"/(?:Users|home|var|Windows|usr)/[^\s,;]+", "[internal path omitted]", text, flags=re.I)
    # Some extractors/renderers emit Windows paths without a leading drive/slash
    # (for example ``Users/LENOVO/AppData/...`` or
    # ``Windows/SoftwareDistribution/Download``). Treat these as internal paths too.
    text = re.sub(
        r"\b(?:Users|Windows|ProgramData|Program Files(?: \(x86\))?|AppData)(?:[\\/][^\s,;]+)+",
        "[internal path omitted]",
        text,
        flags=re.I,
    )
    return text[:max_len].rstrip()


def knowledge_base_fingerprint() -> str:
    """SHA-256 of the exact user-supplied seed used by the report engine."""
    return hashlib.sha256(_KB_PATH.read_bytes()).hexdigest()


def validate_knowledge_base_integrity() -> list[str]:
    """Return configuration errors without silently repairing the supplied KB."""
    data = load_knowledge_base()
    errors: list[str] = []
    procedures = data.get("procedures") or []
    reports = data.get("reports") or []
    catalog = data.get("artifact_catalog") or []
    pids = [str(x.get("id") or "") for x in procedures]
    rids = [str(x.get("id") or "") for x in reports]
    families = {str(x.get("canonical_name") or "") for x in catalog}
    if len(set(pids)) != len(pids):
        errors.append("duplicate procedure id")
    if len(set(rids)) != len(rids):
        errors.append("duplicate report id")
    if "" in families:
        errors.append("artifact catalog contains blank canonical name")
    for report in reports:
        rid = str(report.get("id") or "<blank>")
        pid = str(report.get("procedure_id") or "")
        if pid not in set(pids):
            errors.append(f"{rid}: unknown procedure_id {pid!r}")
        relationships = {"PRIMARY", "SUPPORTING", "CORROBORATING", "CONTEXTUAL"}
        for mapping in report.get("artifact_mappings") or []:
            family = str(mapping.get("artifact_family") or "")
            rel = str(mapping.get("relationship") or "").upper()
            if family not in families:
                errors.append(f"{rid}: unknown artifact family {family!r}")
            if rel not in relationships:
                errors.append(f"{rid}: invalid relationship {rel!r}")
        if not (report.get("count_rule") or {}).get("unit"):
            errors.append(f"{rid}: count_rule.unit is missing")
    # Compiling through the same runtime path verifies active exclusion regexes.
    _active_exclusion_regexes()
    return errors


def kb_summary() -> dict[str, int]:
    data = load_knowledge_base()
    return {
        "procedures": len(data.get("procedures", [])),
        "reports": len(data.get("reports", [])),
        "artifact_families": len(data.get("artifact_catalog", [])),
        "exclusions": len(data.get("exclusions", [])),
    }


def iter_objective_titles() -> Iterable[str]:
    return OBJECTIVE_REPORT_MAP.keys()
