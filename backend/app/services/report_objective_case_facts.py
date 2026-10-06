"""Objective-specific forensic fact detection for Section C.

This module is the record-level adapter between Aetheris collectors and the
user-supplied AXIOM report knowledge base.  The KB defines *what* must be
examined; this adapter resolves those questions against the same structured
records already used by Sections A/B/D (User Profile, Artifacts and Annexure).

It intentionally does not copy any names/counts from a reference report.
Every returned fact is derived from the current job.
"""
from __future__ import annotations

from collections import defaultdict
import logging
from pathlib import PurePosixPath
import json
import re
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("report_objective_case_facts")

from app.db.sql_helpers import fetchall, fetchone
from app.services.axiom_forensic_kb import sanitize_narrative_text

_DOC_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv",
}
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
_CREDENTIAL_WORD_RE = re.compile(r"\b(pass(?:word|wd|code)?|pwd|login|log[- ]?in|username|user\s*id|mail\s*id|email\s*id|credential|secret)\b", re.I)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)

_CLOUD_HOSTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|\.)drive\.google\.com$", re.I), "Google Drive"),
    (re.compile(r"(^|\.)docs\.google\.com$", re.I), "Google Drive"),
    (re.compile(r"(^|\.)dropbox\.com$", re.I), "Dropbox"),
    (re.compile(r"(^|\.)mega\.(?:nz|io|com)$", re.I), "Mega"),
    (re.compile(r"(^|\.)onedrive\.(?:com|live\.com|cloud\.microsoft|live-int\.com)$", re.I), "OneDrive"),
    (re.compile(r"(^|\.)api\.onedrive\.com$", re.I), "OneDrive"),
    (re.compile(r"(^|\.)1drv\.(?:ms|com)$", re.I), "OneDrive"),
    (re.compile(r"(^|\.)skydrive\.live\.com$", re.I), "SkyDrive / OneDrive"),
    (re.compile(r"(^|\.)sharepoint\.com$", re.I), "SharePoint / OneDrive"),
    (re.compile(r"(^|\.)icloud\.com$", re.I), "iCloud"),
    (re.compile(r"(^|\.)box\.com$", re.I), "Box"),
    (re.compile(r"(^|\.)egnyte\.com$", re.I), "Egnyte"),
    (re.compile(r"(^|\.)sync\.com$", re.I), "Sync.com"),
    (re.compile(r"(^|\.)tresorit\.com$", re.I), "Tresorit"),
    (re.compile(r"(^|\.)idgard\.de$", re.I), "iDGard"),
    (re.compile(r"(^|\.)pcloud\.com$", re.I), "pCloud"),
    (re.compile(r"(^|\.)wetransfer\.com$", re.I), "WeTransfer"),
    (re.compile(r"(^|\.)mediafire\.com$", re.I), "MediaFire"),
)

_CHAT_HOSTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|\.)web\.whatsapp\.com$", re.I), "WhatsApp Web"),
    (re.compile(r"(^|\.)web\.telegram\.org$", re.I), "Telegram Web"),
    (re.compile(r"(^|\.)(?:discord\.com|discordapp\.com|cdn\.discordapp\.com)$", re.I), "Discord"),
    (re.compile(r"(^|\.)slack\.com$", re.I), "Slack"),
    (re.compile(r"(^|\.)(?:zoom\.us|zoom\.com|zoomgov\.com)$", re.I), "Zoom"),
    (re.compile(r"(^|\.)(?:hangouts\.google\.com|chat\.google\.com)$", re.I), "Google Hangouts / Chat"),
    (re.compile(r"(^|\.)gotomeeting\.com$", re.I), "GoToMeeting"),
)

_SOCIAL_HOSTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|\.)instagram\.com$", re.I), "Instagram"),
    (re.compile(r"(^|\.)youtube\.com$|(^|\.)youtu\.be$", re.I), "YouTube"),
    (re.compile(r"(^|\.)linkedin\.com$", re.I), "LinkedIn"),
    (re.compile(r"(^|\.)facebook\.com$", re.I), "Facebook"),
    (re.compile(r"(^|\.)reddit\.com$", re.I), "Reddit"),
    (re.compile(r"(^|\.)pantip\.com$", re.I), "Pantip"),
    (re.compile(r"(^|\.)pinterest\.com$", re.I), "Pinterest"),
    (re.compile(r"(^|\.)tiktok\.com$", re.I), "TikTok"),
    (re.compile(r"(^|\.)(?:twitter\.com|x\.com)$", re.I), "Twitter / X"),
    (re.compile(r"(^|\.)vk\.com$", re.I), "VK"),
    (re.compile(r"(^|\.)weibo\.com$", re.I), "Weibo"),
    (re.compile(r"(^|\.)zhihu\.com$", re.I), "Zhihu"),
    (re.compile(r"(^|\.)quora\.com$", re.I), "Quora"),
    (re.compile(r"(^|\.)snapchat\.com$", re.I), "Snapchat"),
    (re.compile(r"(^|\.)douban\.com$", re.I), "Douban"),
    (re.compile(r"(^|\.)xing\.com$", re.I), "Xing"),
)


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _safe_name(path: Any) -> str:
    raw = str(path or "").replace("\\", "/").rstrip("/")
    name = PurePosixPath(raw).name if raw else ""
    return sanitize_narrative_text(name, max_len=140)


def _host(url: str) -> str:
    try:
        return (urlsplit(str(url or "")).hostname or "").lower().strip(".")
    except Exception:
        return ""


def _primary_browser_records(db, job_id: str) -> list[dict[str, Any]]:
    """Return browser visit evidence, including recovered History/WAL rows.

    V9 used only live ``browser_history`` rows whenever any were present. That could
    discard recovered History/WAL rows containing a cloud/WhatsApp visit and create a
    false negative in Section C while the same evidence was visible elsewhere.
    """
    from app.services.browser_url_inventory import collect_job_browser_url_records

    rows = collect_job_browser_url_records(db, job_id)
    accepted = {"browser_history", "browser_history_recovered"}
    history = [r for r in rows if str(r.get("record_origin") or "browser_history") in accepted]
    return history or rows


def _stored_browser_snapshot_urls(db, job_id: str) -> list[dict[str, Any]]:
    """Recover URL evidence already persisted by artifact inventory.

    This is a resilience path, not a second count source.  It is used when raw History
    materialization is unavailable during report generation but the case inventory has
    already persisted browser/cloud query snapshots.
    """
    try:
        rows = fetchall(
            db,
            """SELECT aa.artifact_name, jar.query_snapshot
                 FROM job_axiom_artifact_results jar
                 JOIN public.axiom_artifacts aa ON aa.artifact_id=jar.artifact_id
                WHERE jar.job_id=:jid
                  AND (
                    aa.artifact_name ILIKE '%Browser History%'
                    OR aa.artifact_name ILIKE '%Browser Downloads%'
                    OR aa.artifact_name ILIKE '%Cloud%'
                    OR aa.artifact_name ILIKE '%Web Related%'
                  )
                  AND jar.query_snapshot IS NOT NULL""",
            {"jid": job_id},
        )
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        raw = row.get("query_snapshot")
        if isinstance(raw, (dict, list)):
            text = json.dumps(raw, ensure_ascii=False, default=str)
        else:
            text = str(raw or "")
        text = text.replace('\\/', '/')
        for match in _URL_RE.findall(text):
            url = match.rstrip('.,;:!?)>]}")\'')
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "url": url,
                "visit_count": 1,
                "source": str(row.get("artifact_name") or "stored artifact snapshot"),
                "record_origin": "stored_browser_snapshot",
            })
    return out


def _browser_records_with_persisted_fallback(db, job_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    live = _primary_browser_records(db, job_id)
    records = list(live)
    notes = [f"live/recovered browser-history records reviewed: {len(live):,}"]
    # Always merge snapshot URLs because the inventory may contain a provider visit that
    # the raw database reader could not materialize on a later report run.
    snap = _stored_browser_snapshot_urls(db, job_id)
    if snap:
        notes.append(f"persisted browser/cloud snapshot URLs reviewed: {len(snap):,}")
        seen = {(str(r.get("url") or "").lower(), str(r.get("record_origin") or "")) for r in records}
        for row in snap:
            key = (str(row.get("url") or "").lower(), str(row.get("record_origin") or ""))
            if key not in seen:
                seen.add(key)
                records.append(row)
    return records, notes


def _cloud_provider(url: str) -> str | None:
    host = _host(url)
    if not host:
        return None
    for pattern, label in _CLOUD_HOSTS:
        if pattern.search(host):
            return label
    return None


def _company_terms(intake: dict[str, Any] | None) -> list[str]:
    intake = intake or {}
    vol18 = intake.get("vol18_form_json") or {}
    if isinstance(vol18, str):
        try:
            vol18 = json.loads(vol18)
        except Exception:
            vol18 = {}
    values = [
        intake.get("organization"),
        intake.get("requesting_agency"),
        intake.get("client_name"),
        intake.get("company"),
        intake.get("customer"),
        vol18.get("client_name") if isinstance(vol18, dict) else None,
        vol18.get("organization") if isinstance(vol18, dict) else None,
        vol18.get("requesting_agency") if isinstance(vol18, dict) else None,
    ]
    terms: list[str] = []
    stop = {"ltd", "limited", "pvt", "private", "technologies", "technology", "company", "inc", "llp"}
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        # Keep the full organization phrase and meaningful tokens/acronyms.
        full = re.sub(r"\s+", " ", text).strip()
        if len(full) >= 3 and full.lower() not in terms:
            terms.append(full.lower())
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]{2,}", text):
            low = token.lower().strip("._-")
            if len(low) >= 3 and low not in stop and low not in terms:
                terms.append(low)
    return terms[:8]


def _matches_company(text: str, terms: list[str]) -> bool:
    low = str(text or "").lower()
    for term in terms:
        if not term:
            continue
        # Acronyms such as RRP should be bounded; longer phrases can be substring matched.
        if len(term) <= 4 and " " not in term:
            if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", low, re.I):
                return True
        elif term in low:
            return True
    return False


def _fact(
    *,
    title: str,
    status: str,
    observation: str,
    explanation: str,
    counts: list[dict[str, Any]] | None = None,
    entities: dict[str, list[Any]] | None = None,
    evidence: list[str] | None = None,
    limitations: list[str] | None = None,
    confidence: str = "B",
) -> dict[str, Any]:
    obs = " ".join(str(observation or "").split()).strip()
    exp = " ".join(str(explanation or "").split()).strip()
    if exp and not exp.lower().startswith("this means"):
        exp = "This means " + exp[0].lower() + exp[1:] if len(exp) > 1 else "This means " + exp.lower()
    return {
        "detector": "aetheris_live_axiom_facts_v12",
        "title": title,
        "status": status,
        "observation": obs,
        "simple_explanation": exp,
        "allowed_counts": counts or [],
        "key_entities": entities or {},
        "safe_evidence": [sanitize_narrative_text(x, max_len=300) for x in (evidence or []) if sanitize_narrative_text(x, max_len=300)][:12],
        "limitations": [str(x) for x in (limitations or []) if str(x).strip()][:8],
        "confidence": confidence,
    }


def _malware_web_fact(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.url_category_counts import classify_url_category

    records = _primary_browser_records(db, job_id)
    matched: list[dict[str, Any]] = []
    cats: dict[str, int] = defaultdict(int)
    for row in records:
        url = str(row.get("url") or "")
        cat = str(classify_url_category(url) or "other").lower()
        if cat in {"malware/phishing urls", "pornography urls"}:
            matched.append(row)
            cats[cat] += max(int(row.get("visit_count") or 0), 1)
    unique_urls = []
    for row in matched:
        u = str(row.get("url") or "").strip()
        if u and u not in unique_urls:
            unique_urls.append(u)
    if not unique_urls:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No browser-history URLs classified as malware, phishing, or pornography were recovered from the examined browser records.",
            explanation="the available browser evidence does not show a visit to a URL in those categories; this does not prove that such activity could never have occurred outside the recovered evidence.",
            counts=[{"report_id": "LIVE_WEB_RISK", "report_title": title, "count": 0, "unit": "URL"}],
            evidence=["Browser-history category counts for malware/phishing and pornography were zero."],
            confidence="A",
        )
    domains = []
    for u in unique_urls:
        h = _host(u)
        if h and h not in domains:
            domains.append(h)
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=f"The examination identified {len(unique_urls):,} distinct browser URL(s) classified as malware/phishing or pornography in the recovered browser history.",
        explanation="these are browser-history findings; a visit alone does not prove that malware was downloaded or executed.",
        counts=[{"report_id": "LIVE_WEB_RISK", "report_title": title, "count": len(unique_urls), "unit": "URL"}],
        entities={"domains": domains[:8]},
        evidence=[f"Classified domains: {', '.join(domains[:8])}" if domains else "Classified browser URLs were recovered."],
        confidence="B",
    )


def _cloud_access_fact(db, job_id: str, title: str) -> dict[str, Any]:
    records, source_notes = _browser_records_with_persisted_fallback(db, job_id)
    providers: list[str] = []
    matches: list[dict[str, Any]] = []
    for row in records:
        provider = _cloud_provider(str(row.get("url") or ""))
        if not provider:
            continue
        matches.append(row)
        if provider not in providers:
            providers.append(provider)
    if not matches:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No recovered browser-history records showed access to the supported cloud-storage services examined for this objective.",
            explanation="no cloud-service visit was identified in the recovered browser evidence; this does not prove that cloud services were never used.",
            counts=[{"report_id": "LIVE_CLOUD_ACCESS", "report_title": title, "count": 0, "unit": "SERVICE"}],
            evidence=source_notes,
            limitations=["A zero result is accepted only after live/recovered browser history and persisted browser/cloud snapshots have both been checked."],
            confidence="A" if records else "C",
        )
    times = [str(r.get("last_visit") or r.get("event_time") or "").strip() for r in matches]
    times = [t for t in times if t]
    named = ", ".join(providers)
    obs = f"Recovered browser history showed access to {named}."
    if times:
        obs += f" The records include dated browsing activity for these services."
    obs += " No direct upload, download, or sync event was established from browser-history records alone."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="the computer reached these cloud services, but visiting a cloud website by itself does not prove that a file was uploaded or downloaded.",
        counts=[{"report_id": "LIVE_CLOUD_ACCESS", "report_title": title, "count": len(providers), "unit": "SERVICE"}],
        entities={"providers": providers[:8]},
        evidence=[f"Cloud providers recovered from browser evidence: {named}.", *source_notes],
        limitations=["Browser-history access is not the same as a cloud upload/download/sync event."],
        confidence="A",
    )



def _named_service(url: str, mapping: tuple[tuple[re.Pattern[str], str], ...]) -> str | None:
    host = _host(url)
    if not host:
        return None
    for pattern, label in mapping:
        if pattern.search(host):
            return label
    return None


def _distinct_services(records: list[dict[str, Any]], mapping: tuple[tuple[re.Pattern[str], str], ...]) -> tuple[list[str], list[dict[str, Any]]]:
    services: list[str] = []
    matches: list[dict[str, Any]] = []
    for row in records:
        service = _named_service(str(row.get("url") or ""), mapping)
        if not service:
            continue
        matches.append(row)
        if service not in services:
            services.append(service)
    return services, matches


def _chat_fact(db, job_id: str, title: str) -> dict[str, Any]:
    records, notes = _browser_records_with_persisted_fallback(db, job_id)
    services, matches = _distinct_services(records, _CHAT_HOSTS)
    if not services:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No supported browser records identified access to the web-based chat or communication services examined for this objective.",
            explanation="the recovered browser evidence does not show access to a supported chat service; this does not prove that no communication occurred outside the recovered evidence.",
            counts=[{"report_id": "LIVE_CHAT_SERVICES", "report_title": title, "count": 0, "unit": "SERVICE"}],
            evidence=notes,
            confidence="A" if records else "C",
        )
    named = ", ".join(services)
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=f"The examination identified browser evidence of access to {named}. No message content or file transfer is inferred from service-access records alone.",
        explanation="these records support access to the named communication services, while messaging, calls, attachments or transfers require separate content-level evidence.",
        counts=[{"report_id": "LIVE_CHAT_SERVICES", "report_title": title, "count": len(services), "unit": "SERVICE"}],
        entities={"services": services[:10]},
        evidence=[f"Communication services recovered from browser evidence: {named}.", *notes],
        limitations=["Static/resources records are context; a stronger content-level conclusion requires message/call/attachment evidence."],
        confidence="A",
    )


def _social_fact(db, job_id: str, title: str) -> dict[str, Any]:
    records, notes = _browser_records_with_persisted_fallback(db, job_id)
    services, matches = _distinct_services(records, _SOCIAL_HOSTS)
    if not services:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No supported browser-history records identified access to the social-media, entertainment or professional-networking services examined for this objective.",
            explanation="the recovered browser evidence does not show access to a supported platform; it does not prove that the services were never used outside the recovered evidence.",
            counts=[{"report_id": "LIVE_SOCIAL_SERVICES", "report_title": title, "count": 0, "unit": "SERVICE"}],
            evidence=notes,
            confidence="A" if records else "C",
        )
    named = ", ".join(services)
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=f"Recovered browser records identified access to {named}. The records establish platform access but do not by themselves establish posting, messaging, account ownership, or other user actions.",
        explanation="the named platforms appeared in browser evidence, while a specific action on those platforms requires separate evidence.",
        counts=[{"report_id": "LIVE_SOCIAL_SERVICES", "report_title": title, "count": len(services), "unit": "SERVICE"}],
        entities={"services": services[:12]},
        evidence=[f"Social/entertainment services recovered from browser evidence: {named}.", *notes],
        confidence="A",
    )


def _remote_access_fact(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_installed_programs, collect_rdp_connections

    programs = collect_installed_programs(db, job_id)
    names: list[str] = []
    for item in [*(programs.get("non_microsoft") or []), *(programs.get("microsoft") or [])]:
        if isinstance(item, dict):
            value = str(item.get("display_name") or "").strip()
        else:
            value = str(item or "").strip()
        if value and value not in names:
            names.append(value)
    for value in [*(programs.get("samples_non_ms") or []), *(programs.get("samples_ms") or [])]:
        value = str(value or "").strip()
        if value and value not in names:
            names.append(value)
    remote_re = re.compile(r"anydesk|ultra\s*viewer|ultraviewer|teamviewer|rustdesk|splashtop|screenconnect|connectwise\s*control|logmein|remote\s*utilities|aeroadmin|supremo|dwservice|parsec", re.I)
    tools = [n for n in names if remote_re.search(n)]
    rdp = collect_rdp_connections(db, job_id)
    rdp_count = int(rdp.get("count") or 0)
    if not tools and rdp_count == 0:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="The examination did not identify a supported third-party remote-access application or recovered RDP connection record in the examined evidence.",
            explanation="no remote-access tool or session trace was identified in the available evidence; this is not proof that remote access could never have occurred outside the recovered scope.",
            counts=[{"report_id": "LIVE_REMOTE_TOOLS", "report_title": title, "count": 0, "unit": "TOOL"}, {"report_id": "LIVE_RDP", "report_title": title, "count": 0, "unit": "SESSION"}],
            confidence="B",
        )
    parts: list[str] = []
    counts: list[dict[str, Any]] = []
    entities: dict[str, list[Any]] = {}
    if tools:
        parts.append("Remote-access application" + ("s" if len(tools) != 1 else "") + " identified: " + ", ".join(tools[:6]) + ".")
        counts.append({"report_id": "LIVE_REMOTE_TOOLS", "report_title": title, "count": len(tools), "unit": "TOOL"})
        entities["remote_tools"] = tools[:8]
    if rdp_count:
        parts.append(f"The recovered system records also contain {rdp_count:,} RDP connection record{'s' if rdp_count != 1 else ''}.")
        counts.append({"report_id": "LIVE_RDP", "report_title": title, "count": rdp_count, "unit": "SESSION"})
        hosts = [str(x) for x in (rdp.get("samples") or []) if str(x).strip()]
        if hosts:
            entities["rdp_hosts"] = hosts[:8]
    parts.append("The available evidence does not by itself establish that the access was unauthorized or that external control occurred.")
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=" ".join(parts),
        explanation="software presence and session traces are reported separately; an unauthorized-access conclusion requires additional case evidence.",
        counts=counts,
        entities=entities,
        evidence=[f"Installed remote-access tools identified: {len(tools):,}.", f"RDP connection records identified: {rdp_count:,}."],
        limitations=["Tool installation does not prove execution; an RDP record does not by itself prove unauthorized use."],
        confidence="B",
    )


def _anti_forensics_fact(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_installed_programs

    programs = collect_installed_programs(db, job_id)
    names = [str(x or "").strip() for x in (programs.get("samples_non_ms") or []) if str(x or "").strip()]
    for item in programs.get("non_microsoft") or []:
        if isinstance(item, dict):
            value = str(item.get("display_name") or "").strip()
            if value and value not in names:
                names.append(value)
    anti_re = re.compile(r"ccleaner|bleachbit|eraser|sdelete|secure\s*erase|privacy\s*eraser|wise\s*(?:disk|care)|glary|disk\s*wipe|dban|shredder", re.I)
    tools = [n for n in names if anti_re.search(n)]
    if not tools:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No supported cleanup, wiping or trace-removal utility was identified in the installed-application evidence examined for this objective.",
            explanation="the available application evidence does not show one of the controlled anti-forensic/cleanup tools; it does not prove that no cleanup action could have occurred by another method.",
            counts=[{"report_id": "LIVE_ANTI_FORENSIC_TOOLS", "report_title": title, "count": 0, "unit": "TOOL"}],
            confidence="B",
        )
    named = ", ".join(tools[:8])
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=f"The examination identified cleanup or data-removal software on the system: {named}. The presence of this software does not by itself establish that it was used to erase or conceal case-relevant evidence.",
        explanation="the software was available on the computer, while actual wiping or concealment requires separate execution and activity evidence.",
        counts=[{"report_id": "LIVE_ANTI_FORENSIC_TOOLS", "report_title": title, "count": len(tools), "unit": "TOOL"}],
        entities={"tools": tools[:8]},
        evidence=[f"Cleanup/anti-forensic applications identified: {named}."],
        limitations=["Installation/presence is not proof of execution or evidence destruction."],
        confidence="B",
    )


_TORRENT_HOST_RE = re.compile(r"(^|\.)(?:thepiratebay\.|1337x\.|torrentgalaxy\.|limetorrents\.|yts\.|nyaa\.|torrentdownloads\.|bittorrent\.)", re.I)


def _is_torrent_url(url: str) -> bool:
    raw = str(url or "").strip()
    if raw.lower().startswith("magnet:?"):
        return True
    host = _host(raw)
    if host and _TORRENT_HOST_RE.search(host):
        return True
    low = raw.lower()
    return ".torrent" in low or "/torrent/" in low or "magnet:?" in low


def _torrent_fact(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_installed_programs

    records, notes = _browser_records_with_persisted_fallback(db, job_id)
    urls: list[str] = []
    for row in records:
        url = str(row.get("url") or "").strip()
        if url and _is_torrent_url(url) and url not in urls:
            urls.append(url)
    programs = collect_installed_programs(db, job_id)
    names = [str(x or "").strip() for x in (programs.get("samples_non_ms") or []) if str(x or "").strip()]
    client_re = re.compile(r"qbittorrent|u\s*torrent|utorrent|bittorrent|deluge|transmission|vuze|azureus|tixati", re.I)
    clients = [n for n in names if client_re.search(n)]
    if not urls and not clients:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No supported torrent/magnet URL or installed torrent-client evidence was identified in the records examined for this objective.",
            explanation="the available evidence does not show torrent-related access or a torrent client; this does not prove activity could never have occurred outside the recovered evidence.",
            counts=[{"report_id": "LIVE_TORRENT_URLS", "report_title": title, "count": 0, "unit": "URL"}],
            evidence=notes,
            confidence="B",
        )
    parts: list[str] = []
    counts: list[dict[str, Any]] = []
    entities: dict[str, list[Any]] = {}
    if urls:
        parts.append(f"The examination identified {len(urls):,} distinct torrent/magnet-related URL record{'s' if len(urls) != 1 else ''}.")
        counts.append({"report_id": "LIVE_TORRENT_URLS", "report_title": title, "count": len(urls), "unit": "URL"})
        entities["torrent_hosts"] = list(dict.fromkeys(_host(u) for u in urls if _host(u)))[:8]
    if clients:
        parts.append("Installed torrent-client software identified: " + ", ".join(clients[:6]) + ".")
        counts.append({"report_id": "LIVE_TORRENT_CLIENTS", "report_title": title, "count": len(clients), "unit": "APPLICATION"})
        entities["torrent_clients"] = clients[:8]
    parts.append("These findings do not by themselves establish that a file was downloaded, uploaded or shared through a torrent session.")
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=" ".join(parts),
        explanation="torrent-related access/client presence is reported separately from actual file-transfer evidence.",
        counts=counts,
        entities=entities,
        evidence=notes,
        limitations=["Archive.org or other ordinary web pages are not classified as torrent activity merely because a reference report listed them under a torrent heading."],
        confidence="B",
    )


def _internet_network_fact(db, job_id: str, title: str) -> dict[str, Any]:
    records, notes = _browser_records_with_persisted_fallback(db, job_id)
    cloud, _ = _distinct_services(records, _CLOUD_HOSTS)
    chat, _ = _distinct_services(records, _CHAT_HOSTS)
    social, _ = _distinct_services(records, _SOCIAL_HOSTS)
    services = list(dict.fromkeys([*cloud, *chat, *social]))
    from app.services.forensic_inventory import collect_rdp_connections
    rdp = collect_rdp_connections(db, job_id)
    rdp_count = int(rdp.get("count") or 0)
    if not services and not rdp_count:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No supported internet-service or remote-session finding was identified from the recovered browsing and network-related records examined for this objective.",
            explanation="the recovered evidence did not establish one of the monitored external-service or remote-session activities; this does not prove that no network activity occurred outside the recovered evidence.",
            confidence="C" if not records else "B",
        )
    parts: list[str] = []
    counts: list[dict[str, Any]] = []
    entities: dict[str, list[Any]] = {}
    if services:
        named = ", ".join(services[:12])
        parts.append(f"Recovered browsing records identified access to {named}.")
        counts.append({"report_id": "LIVE_INTERNET_SERVICES", "report_title": title, "count": len(services), "unit": "SERVICE"})
        entities["services"] = services[:12]
    if rdp_count:
        parts.append(f"The evidence also contains {rdp_count:,} RDP connection record{'s' if rdp_count != 1 else ''}.")
        counts.append({"report_id": "LIVE_NETWORK_SESSIONS", "report_title": title, "count": rdp_count, "unit": "SESSION"})
    parts.append("No file sharing, messaging, or data transfer is inferred unless separate transfer/content evidence supports it.")
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=" ".join(parts),
        explanation="internet or network access is a supported fact, while a data-transfer conclusion needs additional evidence showing the transfer itself.",
        counts=counts,
        entities=entities,
        evidence=notes,
        limitations=["Platform access and data transfer are separate findings."],
        confidence="B",
    )

def _is_storage_noise(dev: dict[str, Any]) -> bool:
    text = " ".join(str(dev.get(k) or "") for k in ("device_name", "class_id", "bus", "source"))
    return bool(re.search(r"root\s*hub|input\s*device|camera|bluetooth|composite|keyboard|mouse|receiver", text, re.I))


def classify_external_storage_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce raw Enum\\USB rows to distinct physical removable storage devices.

    Interface rows (UAS / generic mass-storage), hubs and cameras are supporting
    evidence only.  USBSTOR and strongly identified external SCSI disk models are
    treated as physical-device records and semantically deduplicated by serial/model.
    """
    physical: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dev in devices or []:
        if _is_storage_noise(dev):
            continue
        bus = str(dev.get("bus") or "").upper()
        name = str(dev.get("device_name") or "").strip()
        class_id = str(dev.get("class_id") or "").strip()
        serial = str(dev.get("serial") or "").strip()
        text = f"{name} {class_id} {bus}"
        if re.search(r"NVMe|SKHynix|internal", text, re.I):
            continue
        source = str(dev.get("source") or "")
        source_text = f"{source} {class_id}"
        # Some legacy/promoted records lost their original bus label even though the
        # source is clearly SYSTEM\...\USBSTOR or a SCSI disk identity. Treat the
        # provenance as authoritative enough to classify the physical storage row.
        strong = bus in {"USBSTOR", "SCSI_STORAGE"} or bool(re.search(r"\bUSBSTOR\b", source_text, re.I))
        if not strong:
            # Generic UAS / Mass Storage rows are interfaces unless a real vendor/model
            # identity is also present.
            if re.fullmatch(r"USB(?: Attached SCSI \(UAS\))? Mass Storage Device", name, re.I):
                continue
            strong = bool(re.search(r"portable\s*(?:hdd|ssd)|external\s*(?:hdd|ssd|disk)|expansion|passport|elements|apacer\s+portable|seagate\s+expansion", f"{text} {source_text}", re.I))
        if not strong:
            continue
        serial_key = re.sub(r"&0$", "", serial.lower())
        model_key = _norm(name or class_id)
        key = serial_key if serial_key and len(serial_key) >= 4 else model_key
        if not key or key in seen:
            continue
        seen.add(key)
        physical.append({
            "device_name": sanitize_narrative_text(name or class_id, max_len=120),
            "serial": sanitize_narrative_text(serial, max_len=80),
            "last_connected": dev.get("last_write") or dev.get("last_connected") or dev.get("event_time"),
            "bus": bus,
        })
    return physical


def _usb_fact(db, job_id: str, title: str, *, external_only: bool) -> dict[str, Any]:
    from app.services.catalog_aligned_counts import count_usb_device_records

    raw_count, devices = count_usb_device_records(db, job_id)
    physical = classify_external_storage_devices(devices)
    if external_only:
        if not physical:
            # A raw USB/device population with no classified physical disk is not a
            # defensible negative finding. It means the classification/correlation is
            # incomplete and must remain inconclusive.
            status = "INCONCLUSIVE" if raw_count > 0 else "NOT_FOUND"
            observation = (
                "USB/device records were recovered, but no distinct physical external hard disk could be established after classifying hubs, cameras, Bluetooth/input devices, storage interfaces, volumes and internal disks."
                if raw_count > 0
                else "No distinct physical external hard disk could be established from the recovered USB and storage-device records."
            )
            return _fact(
                title=title,
                status=status,
                observation=observation,
                explanation="raw USB/device rows are not treated as separate hard disks; a negative external-disk conclusion is accepted only when the relevant storage evidence was successfully classified.",
                counts=[{"report_id": "LIVE_EXTERNAL_STORAGE", "report_title": title, "count": 0, "unit": "DEVICE"}],
                evidence=[f"{raw_count:,} raw USB/device record(s) were reviewed and classified."],
                limitations=["When USB/device evidence exists but cannot be resolved to a physical disk identity, examiner review is required instead of a zero finding."],
                confidence="C" if raw_count > 0 else "B",
            )
        names = [d.get("device_name") for d in physical if d.get("device_name")]
        n = len(physical)
        obs = f"The examination identified {n:,} distinct physical external storage device{'s' if n != 1 else ''} connected to the computer."
        if names:
            obs += " Identified device" + ("s include " if len(names) > 1 else ": ") + ", ".join(names[:4]) + "."
        obs += " The connection records alone do not prove that files were copied to or from the device."
        return _fact(
            title=title,
            status="CONFIRMED",
            observation=obs,
            explanation="the evidence proves connection of the external storage device, while file transfer requires separate file-access or write evidence.",
            counts=[{"report_id": "LIVE_EXTERNAL_STORAGE", "report_title": title, "count": n, "unit": "DEVICE"}],
            entities={"devices": names[:6]},
            evidence=[f"{raw_count:,} raw USB/device record(s) were reduced to {n:,} distinct physical storage device(s)."],
            confidence="A",
        )

    # The five supplied reports treat mobile/Your Phone evidence separately from
    # physical storage. Resolve both instead of using the raw USB row count as the
    # objective finding.
    try:
        from app.services.forensic_inventory import collect_phone_usage

        phone = collect_phone_usage(db, job_id)
    except Exception:
        phone = {"unique_device_count": 0, "devices": []}
    phone_count = int(phone.get("unique_device_count") or 0)
    phone_names = [sanitize_narrative_text((d or {}).get("device_name"), max_len=100) for d in (phone.get("devices") or [])]
    phone_names = [x for x in phone_names if x]

    if raw_count <= 0 and phone_count <= 0:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No supported USB storage or mobile-device connection record was identified in the examined system evidence.",
            explanation="no relevant external-device connection was recovered within the available evidence; this does not prove a device was never connected outside the recovered scope.",
            counts=[{"report_id": "LIVE_EXTERNAL_STORAGE", "report_title": title, "count": 0, "unit": "DEVICE"}, {"report_id": "LIVE_MOBILE_DEVICE", "report_title": title, "count": 0, "unit": "DEVICE"}],
            confidence="A",
        )
    n = len(physical)
    names = [d.get("device_name") for d in physical if d.get("device_name")]
    parts: list[str] = []
    counts: list[dict[str, Any]] = []
    entities: dict[str, list[Any]] = {}
    if n:
        parts.append(f"After classifying the USB/device records, {n:,} distinct physical external storage device{'s were' if n != 1 else ' was'} identified.")
        if names:
            parts.append("Identified storage device" + ("s include " if len(names) > 1 else ": ") + ", ".join(names[:5]) + ".")
        counts.append({"report_id": "LIVE_EXTERNAL_STORAGE", "report_title": title, "count": n, "unit": "DEVICE"})
        entities["external_storage_devices"] = names[:6]
    if phone_count:
        parts.append(f"The examination also identified {phone_count:,} distinct mobile/portable device connection{'s' if phone_count != 1 else ''}.")
        if phone_names:
            parts.append("Mobile/portable device evidence includes " + ", ".join(phone_names[:4]) + ".")
        counts.append({"report_id": "LIVE_MOBILE_DEVICE", "report_title": title, "count": phone_count, "unit": "DEVICE"})
        entities["mobile_devices"] = phone_names[:6]
    if not n and not phone_count:
        parts.append("USB-related records were recovered, but they consisted of interfaces/peripherals and did not establish a distinct external storage or mobile device after classification.")
    parts.append("The connection records alone do not prove that files were copied to or from any connected device.")
    return _fact(
        title=title,
        status="CONFIRMED" if (n or phone_count) else "INCONCLUSIVE",
        observation=" ".join(parts),
        explanation="the report separates physical storage and mobile-device connections from raw USB interfaces; a connection does not by itself prove file transfer.",
        counts=counts,
        entities=entities,
        evidence=[f"Raw USB records reviewed: {raw_count:,}; physical storage devices: {n:,}; mobile/portable devices: {phone_count:,}."],
        limitations=["Hubs, input devices, cameras, Bluetooth, internal disks and interface/volume duplicates are not counted as separate external storage devices."],
        confidence="A" if (n or phone_count) else "B",
    )


def _user_accounts_fact(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.report_evidence import collect_windows_users_structured

    users = collect_windows_users_structured(db, job_id)
    if not users:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No parsed Windows user-account records were recovered from the available SAM or profile evidence.",
            explanation="the report cannot identify a user account when the account records themselves are unavailable.",
            counts=[{"report_id": "LIVE_USERS", "report_title": title, "count": 0, "unit": "ACCOUNT"}],
            confidence="B",
        )
    names = [str(u.get("username") or "").strip() for u in users if str(u.get("username") or "").strip()]
    active = [u for u in users if str(u.get("last_logon") or "—") not in {"", "—", "None"}]
    obs = f"The examination identified {len(names):,} distinct Windows user account{'s' if len(names) != 1 else ''}: {', '.join(names[:8])}."
    if active:
        details = [f"{u.get('username')} ({u.get('last_logon')})" for u in active[:4]]
        obs += " Recorded last-logon information was available for " + ", ".join(details) + "."
    obs += " Account presence alone does not establish unauthorized access."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="the account records show which accounts existed and any recorded logon time; unusual access must be supported by separate authentication evidence.",
        counts=[{"report_id": "LIVE_USERS", "report_title": title, "count": len(names), "unit": "ACCOUNT"}],
        entities={"usernames": names[:10]},
        evidence=[f"Structured SAM/ProfileList records identified {len(names):,} account(s)."],
        confidence="A",
    )


def _recycle_item_token(name: str) -> str:
    low = str(name or "").lower()
    if low.startswith("$i") or low.startswith("$r"):
        return low[2:]
    return low


def _manifest_recycle_descriptor_paths(db, job_id: str) -> set[str]:
    """Return $I descriptor paths visible in the disk manifest/index.

    The manifest is the best coverage check for older jobs: if it lists ten $I files
    but only one was materialized, Section C must not report one deletion as the full
    Recycle Bin result.
    """
    try:
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:jid", {"jid": job_id}) or {}
        manifest = row.get("disk_source")
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        if not manifest:
            return set()
        from app.services.artifact_materialize import _entries_from_manifest

        entries = _entries_from_manifest(manifest)
    except Exception:
        return set()
    out: set[str] = set()
    for entry in entries or []:
        path = str(entry.get("path") or "").replace("\\", "/").strip()
        low = path.lower().lstrip("/")
        name = PurePosixPath(low).name
        if name.startswith("$i") and ("$recycle.bin/" in low or "recycle.bin/" in low):
            out.add(path.lower())
    return out


def _live_recycle_bin_records(db, job_id: str) -> list[dict[str, Any]]:
    """Read and parse Windows $Recycle.Bin descriptors directly at report time.

    This closes a V9 gap: $I files are extensionless and were not part of the
    high-priority forensic parse SQL, so a report could say "no deleted files" even
    when the acquired image contained Recycle Bin metadata.
    """
    rows = fetchall(
        db,
        """SELECT id, file_path, file_name, size_bytes, minio_uri, metadata
             FROM job_artifacts
            WHERE job_id=:jid
              AND lower(translate(file_path, chr(92), '/')) LIKE '%$recycle.bin%'
            ORDER BY file_path
            LIMIT 20000""",
        {"jid": job_id},
    )
    if not rows:
        return []

    by_token: dict[str, dict[str, Any]] = {}
    descriptor_rows: list[dict[str, Any]] = []
    for row in rows:
        path = str(row.get("file_path") or "").replace("\\", "/")
        name = str(row.get("file_name") or PurePosixPath(path).name or "")
        token = _recycle_item_token(name)
        if not token:
            continue
        meta = row.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        rec = by_token.setdefault(token, {
            "token": token,
            "descriptor_path": None,
            "payload_path": None,
            "original_name": meta.get("original_name"),
            "original_path": meta.get("original_path"),
            "deleted_at": meta.get("deleted_at"),
        })
        if name.lower().startswith("$i"):
            rec["descriptor_path"] = path
            descriptor_rows.append(row)
        elif name.lower().startswith("$r"):
            rec["payload_path"] = path

    # Parse $I descriptors directly when parse/metadata promotion has not happened.
    if descriptor_rows:
        try:
            from app.services.artifact_live_counts import _read_job_files
            from app.parsers.recycle_bin import parse_recycle_bin_i

            contents = _read_job_files(db, job_id, descriptor_rows, max_bytes=4_000_000)
            for row in descriptor_rows:
                path = str(row.get("file_path") or "").replace("\\", "/")
                name = str(row.get("file_name") or PurePosixPath(path).name or "")
                token = _recycle_item_token(name)
                data = contents.get(path)
                if not data:
                    continue
                parsed = parse_recycle_bin_i(data, path)
                if not parsed:
                    continue
                item = parsed[0]
                rec = by_token.setdefault(token, {"token": token})
                for src, dst in (
                    ("original_name", "original_name"),
                    ("original_path", "original_path"),
                    ("deleted_at", "deleted_at"),
                    ("original_size_bytes", "original_size_bytes"),
                ):
                    if item.get(src) not in (None, ""):
                        rec[dst] = item.get(src)
        except Exception as exc:
            log.warning("live Recycle Bin descriptor parse failed job=%s: %s", job_id, exc)

    # A Recycle Bin item is keyed by the shared $I/$R token. Prefer descriptors; an
    # orphaned $R is retained as a lower-confidence deleted item rather than double-counting.
    return [dict(v) for _, v in sorted(by_token.items()) if v.get("descriptor_path") or v.get("payload_path")]


def _deleted_fact(db, job_id: str, title: str) -> dict[str, Any]:
    live_items = _live_recycle_bin_records(db, job_id)
    manifest_descriptors = _manifest_recycle_descriptor_paths(db, job_id)

    # Parsed/indexed counters remain a cross-check, but the distinct $I token set is
    # authoritative. $I/$R are one logical deleted item and must never be double-counted.
    try:
        from app.services.deleted_evidence import count_deleted_job_artifacts
        indexed = count_deleted_job_artifacts(db, job_id)
    except Exception:
        indexed = {}

    names: list[str] = []
    times: list[str] = []
    descriptor_items: list[dict[str, Any]] = []
    valid_descriptor_items: list[dict[str, Any]] = []
    for item in live_items:
        if item.get("descriptor_path"):
            descriptor_items.append(item)
            if item.get("original_path") or item.get("deleted_at") or item.get("original_name"):
                valid_descriptor_items.append(item)
        name = sanitize_narrative_text(item.get("original_name") or "", max_len=140)
        if name and name not in names:
            names.append(name)
        deleted_at = str(item.get("deleted_at") or "").strip()
        if deleted_at and deleted_at not in times:
            times.append(deleted_at)

    descriptor_count = len(descriptor_items)
    parsed_descriptor_count = len(valid_descriptor_items)
    manifest_count = len(manifest_descriptors)
    parsed_count = int(indexed.get("recycle_bin") or 0)

    # Coverage gate: a manifest/index with more $I descriptors than the materialized
    # evidence means report generation is incomplete. Never report the partial count as
    # the full Recycle Bin count (the V10 screenshot showed exactly this failure: 1 item).
    if manifest_count and descriptor_count < manifest_count:
        return _fact(
            title=title,
            status="INCONCLUSIVE",
            observation=(
                f"The disk index contains {manifest_count:,} Windows Recycle Bin descriptor file(s), but only {descriptor_count:,} were available to the report detector. "
                "The partial set was not reported as the final deleted-file count."
            ),
            explanation="all Recycle Bin descriptors must be materialized and parsed before the report can state the distinct deleted-file count.",
            evidence=[
                f"Manifest $I descriptors: {manifest_count:,}; materialized descriptors: {descriptor_count:,}; successfully parsed descriptors: {parsed_descriptor_count:,}."
            ],
            limitations=["Re-materialize the complete $Recycle.Bin tree from the disk index and regenerate the report."],
            confidence="C",
        )

    if descriptor_count and parsed_descriptor_count < descriptor_count:
        return _fact(
            title=title,
            status="INCONCLUSIVE",
            observation=(
                f"{descriptor_count:,} Recycle Bin descriptor file(s) were available, but only {parsed_descriptor_count:,} contained usable original-path or deletion-time metadata. "
                "The incomplete parse was not converted into a final deleted-file count."
            ),
            explanation="a Recycle Bin entry is counted only after its descriptor metadata is successfully interpreted.",
            evidence=[f"Materialized descriptors: {descriptor_count:,}; successfully parsed descriptors: {parsed_descriptor_count:,}."],
            limitations=["Review or re-parse the unreadable $I descriptors before making a deleted-file count."],
            confidence="C",
        )

    # When descriptors are present and parsed, their shared $I/$R token count is the
    # distinct deleted-item count. A parsed legacy fallback is used only if original
    # descriptors are no longer materializable.
    count = parsed_descriptor_count
    if count <= 0 and parsed_count > 0 and not manifest_count:
        count = parsed_count
        for sample in indexed.get("samples") or []:
            if str(sample.get("recovery_state") or "") != "recycle_bin" and "$recycle.bin" not in str(sample.get("file_path") or "").lower():
                continue
            n = sanitize_narrative_text(sample.get("title") or sample.get("file_name") or "", max_len=140)
            if n and n not in names:
                names.append(n)
            t = str(sample.get("deleted_at") or "").strip()
            if t and t not in times:
                times.append(t)

    if count <= 0:
        # Absence from materialized artifacts is not proof that the source image had an
        # empty Recycle Bin. Old extraction profiles could omit extensionless $I files.
        return _fact(
            title=title,
            status="INCONCLUSIVE",
            observation="No successfully parsed Windows Recycle Bin descriptor was available in the currently indexed/extracted evidence for this report run.",
            explanation="a zero indexed result is not treated as proof that no files were deleted; the $Recycle.Bin source must be covered by extraction before a negative finding is accepted.",
            evidence=[
                f"Manifest $I descriptors: {manifest_count:,}; live item tokens: {len(live_items):,}; parsed/indexed Recycle Bin count: {parsed_count:,}."
            ],
            limitations=["If this job was extracted before $Recycle.Bin became a priority forensic path, re-run evidence materialization/parsing before concluding that the Recycle Bin is empty."],
            confidence="C",
        )

    obs = f"A total of {count:,} distinct Recycle Bin item{'s were' if count != 1 else ' was'} identified from parsed Windows $I deletion metadata."
    if times:
        obs += " Recovered deletion time" + ("s include " if len(times) > 1 else ": ") + ", ".join(t[:32] for t in times[:4]) + "."
    if names:
        obs += " Examples include " + ", ".join(names[:4]) + "."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="the parsed Recycle Bin metadata supports that these distinct items were deleted; any statement about whether deletion occurred before handover requires a reliable handover time from case intake or other evidence.",
        counts=[{"report_id": "LIVE_RECYCLE", "report_title": title, "count": count, "unit": "RECYCLE_BIN_ITEM"}],
        entities={"deleted_files": names[:8], "deletion_times": times[:8]},
        evidence=[
            f"Manifest $I descriptors: {manifest_count:,}; materialized descriptors: {descriptor_count:,}; parsed descriptors: {parsed_descriptor_count:,}; indexed cross-check: {parsed_count:,}."
        ],
        confidence="A" if times else "B",
    )

def _encrypted_fact(db, job_id: str, title: str) -> dict[str, Any]:
    # Report generation is the authoritative/reporting path, so request the content/header
    # scan when possible. The inventory cache prevents re-reading the same job repeatedly.
    try:
        from app.services.encryption_inventory import compute_report_encryption_counts, collect_encryption_artifact
        compute_report_encryption_counts(db, job_id, scan_encrypted=True)
        data = collect_encryption_artifact(db, job_id, "Encrypted Files")
    except Exception:
        from app.services.encryption_inventory import collect_encryption_artifact
        data = collect_encryption_artifact(db, job_id, "Encrypted Files")
    count = int(data.get("count") or 0)
    names = [_safe_name(x) for x in (data.get("samples") or [])]
    names = [x for x in names if x]
    if count <= 0:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No files with supported encryption or password-protection indicators were identified by the available encryption checks.",
            explanation="no supported encrypted-file indicator was recovered in the examined evidence; this does not prove that protected data could not exist outside the acquired data.",
            counts=[{"report_id": "LIVE_ENCRYPTED", "report_title": title, "count": 0, "unit": "FILE"}],
            confidence="B",
        )
    obs = f"A total of {count:,} encrypted or password-protected file{'s were' if count != 1 else ' was'} identified on the computer."
    if names:
        obs += " Examples include " + ", ".join(names[:4]) + "."
    obs += " Encryption by itself does not establish wrongdoing."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="the files are protected or encrypted, but the protection method alone does not show why the files were protected.",
        counts=[{"report_id": "LIVE_ENCRYPTED", "report_title": title, "count": count, "unit": "FILE"}],
        entities={"files": names[:6]},
        evidence=[f"Encrypted/protected file count from the authoritative encryption scan: {count:,}."],
        confidence="A",
    )


def _live_browser_login_accounts(db, job_id: str) -> list[dict[str, Any]]:
    rows = fetchall(
        db,
        """SELECT file_path, file_name, size_bytes, minio_uri
             FROM job_artifacts
            WHERE job_id=:jid AND size_bytes > 512
              AND lower(coalesce(file_name,''))='login data'
            ORDER BY size_bytes DESC
            LIMIT 200""",
        {"jid": job_id},
    )
    if not rows:
        return []
    try:
        from app.services.artifact_live_counts import _read_job_files
        from app.parsers.sqlite_parser import parse_sqlite
        contents = _read_job_files(db, job_id, rows, max_bytes=256_000_000)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        path = str(row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path)
        if not data:
            continue
        try:
            parsed = parse_sqlite(data, path)
        except Exception:
            continue
        for rec in parsed:
            if rec.get("record_type") != "browser_login_account":
                continue
            account = str(rec.get("account") or "").strip()
            url = str(rec.get("url") or "").strip()
            key = (account.lower(), url.lower())
            if not account or key in seen:
                continue
            seen.add(key)
            out.append(rec)
    return out


def _email_addresses_fact(db, job_id: str, title: str) -> dict[str, Any]:
    """Find actual account/address strings, not Outlook message totals."""
    live_login_accounts = _live_browser_login_accounts(db, job_id)
    rows = fetchall(
        db,
        """SELECT apr.normalized::text AS content, ja.file_path
             FROM artifact_parse_results apr
             JOIN job_artifacts ja ON ja.id=apr.job_artifact_id
            WHERE ja.job_id=:jid
              AND apr.normalized::text LIKE '%@%'
              AND (
                 apr.normalized::text ILIKE '%email%'
                 OR apr.normalized::text ILIKE '%sender%'
                 OR apr.normalized::text ILIKE '%recipient%'
                 OR lower(coalesce(ja.extension,'')) IN ('.eml','.emlx','.msg','.pst','.ost')
              )
            LIMIT 500""",
        {"jid": job_id},
    )
    # RAG often contains decoded message headers/webmail account details even when the
    # original container is PST/OST.
    try:
        rows += fetchall(
            db,
            """SELECT content, file_path FROM rag_chunks
                WHERE job_id=:jid AND content LIKE '%@%'
                  AND (content ILIKE '%email%' OR content ILIKE '%from:%' OR content ILIKE '%to:%' OR file_path ILIKE '%mail%')
                LIMIT 500""",
            {"jid": job_id},
        )
    except Exception:
        pass
    addresses: list[str] = []
    for row in rows:
        for address in _EMAIL_RE.findall(str(row.get("content") or "")):
            low = address.lower().strip(".,;:<>()[]{}")
            if low and low not in addresses and len(low) <= 160:
                addresses.append(low)
    for rec in live_login_accounts:
        for address in _EMAIL_RE.findall(str(rec.get("account") or "")):
            low = address.lower().strip(".,;:<>()[]{}")
            if low and low not in addresses and len(low) <= 160:
                addresses.append(low)
    # Remove obvious machine/package-looking values that happen to match the regex.
    addresses = [a for a in addresses if not a.endswith((".png", ".jpg", ".dll", ".exe"))]
    if not addresses:
        return _fact(
            title=title,
            status="INCONCLUSIVE",
            observation="Email-message or webmail records were present, but no distinct email account address could be established from the decoded account/session evidence used for this objective.",
            explanation="message totals are not treated as the number of email accounts; an account is reported only when an address or account identity is recovered.",
            confidence="C",
        )
    obs = f"The examination identified {len(addresses):,} distinct email address{'es' if len(addresses) != 1 else ''} in decoded email/account-related evidence: {', '.join(addresses[:8])}."
    obs += " The presence of an address does not by itself prove that the account was actively signed in at the time of examination."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="these addresses were recovered from email/account-related evidence; current sign-in status requires separate session or login evidence.",
        counts=[{"report_id": "LIVE_EMAIL_ACCOUNTS", "report_title": title, "count": len(addresses), "unit": "ACCOUNT"}],
        entities={"email_addresses": addresses[:12]},
        evidence=[f"Distinct email addresses recovered from decoded email/account evidence: {len(addresses):,}.", f"Browser Login Data account records reviewed: {len(live_login_accounts):,}."],
        limitations=["An address in a message is not automatically proof that the account was signed in on the computer."],
        confidence="B",
    )


def _decode_user_text(data: bytes) -> str:
    """Decode user-created notes defensibly across common Windows encodings."""
    if not data:
        return ""
    # Modern Notepad uses UTF-8 by default, but older Windows notes are commonly
    # UTF-16LE/UTF-16.  Falling back to cp1252 avoids silently missing legacy text.
    for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "cp1252"):
        try:
            text = data.decode(enc)
        except Exception:
            continue
        if not text:
            continue
        printable = sum(1 for ch in text[:5000] if ch.isprintable() or ch in "\r\n\t")
        ratio = printable / max(min(len(text), 5000), 1)
        if ratio >= 0.70:
            return text
    return data.decode("utf-8", errors="ignore")


def _credential_note_fact(db, job_id: str, title: str) -> dict[str, Any]:
    """Locate actual user-created credential notes, never generic text-file totals.

    V10 relied heavily on RAG and slash-specific Desktop/Documents paths.  That missed
    Windows paths stored with backslashes, UTF-16 Notepad files, OneDrive/user-root
    notes, and parsed text that had not been promoted into RAG yet.
    """
    matches: list[str] = []
    evidence_rows_reviewed = 0

    def _consider(path: Any, content: Any) -> None:
        nonlocal evidence_rows_reviewed
        evidence_rows_reviewed += 1
        text = str(content or "")
        if not _EMAIL_RE.search(text) or not _CREDENTIAL_WORD_RE.search(text):
            return
        name = sanitize_narrative_text(_safe_name(path), max_len=140)
        if name and name not in matches:
            matches.append(name)

    # 1) Parsed text results are closest to the source artifact and do not depend on RAG.
    try:
        parsed_rows = fetchall(
            db,
            """SELECT ja.file_path, apr.normalized::text AS content
                 FROM artifact_parse_results apr
                 JOIN job_artifacts ja ON ja.id=apr.job_artifact_id
                WHERE ja.job_id=:jid
                  AND apr.normalized::text LIKE '%@%'
                  AND (
                    apr.normalized::text ILIKE '%password%'
                    OR apr.normalized::text ILIKE '%passwd%'
                    OR apr.normalized::text ILIKE '%pwd%'
                    OR apr.normalized::text ILIKE '%login%'
                    OR apr.normalized::text ILIKE '%username%'
                    OR apr.normalized::text ILIKE '%credential%'
                  )
                  AND (
                    lower(translate(ja.file_path, chr(92), '/')) LIKE 'users/%'
                    OR lower(translate(ja.file_path, chr(92), '/')) LIKE '%/users/%'
                  )
                LIMIT 1000""",
            {"jid": job_id},
        )
        for row in parsed_rows:
            _consider(row.get("file_path"), row.get("content"))
    except Exception:
        pass

    # 2) Indexed text/OCR. Do not require a particular chunk_type: older jobs used
    # different labels for document/note text.
    try:
        rag_rows = fetchall(
            db,
            """SELECT file_path, content
                 FROM rag_chunks
                WHERE job_id=:jid
                  AND content LIKE '%@%'
                  AND (
                    content ILIKE '%password%'
                    OR content ILIKE '%passwd%'
                    OR content ILIKE '%pwd%'
                    OR content ILIKE '%login%'
                    OR content ILIKE '%username%'
                    OR content ILIKE '%credential%'
                  )
                  AND (
                    lower(translate(file_path, chr(92), '/')) LIKE 'users/%'
                    OR lower(translate(file_path, chr(92), '/')) LIKE '%/users/%'
                    OR lower(translate(file_path, chr(92), '/')) LIKE '%/desktop/%'
                    OR lower(translate(file_path, chr(92), '/')) LIKE '%/documents/%'
                    OR lower(translate(file_path, chr(92), '/')) LIKE '%/downloads/%'
                    OR lower(translate(file_path, chr(92), '/')) LIKE '%/onedrive/%'
                  )
                LIMIT 1000""",
            {"jid": job_id},
        )
        for row in rag_rows:
            _consider(row.get("file_path"), row.get("content"))
    except Exception:
        pass

    # 3) Live source-file fallback. This is essential when the note was extracted but
    # never indexed, or when it is UTF-16 (common with older Windows Notepad).
    live_candidate_count = 0
    if not matches:
        try:
            note_rows = fetchall(
                db,
                """SELECT file_path, file_name, size_bytes, minio_uri, extension
                     FROM job_artifacts
                    WHERE job_id=:jid
                      AND size_bytes BETWEEN 1 AND 4194304
                      AND (
                        lower(translate(file_path, chr(92), '/')) LIKE 'users/%'
                        OR lower(translate(file_path, chr(92), '/')) LIKE '%/users/%'
                      )
                      AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/appdata/%'
                      AND (
                        lower(coalesce(extension,'')) IN ('.txt','txt','.log','log','.md','md','.csv','csv','.rtf','rtf','')
                        OR lower(coalesce(file_name,'')) ~ '\\.(txt|log|md|csv|rtf)$'
                      )
                    ORDER BY size_bytes ASC
                    LIMIT 5000""",
                {"jid": job_id},
            )
            live_candidate_count = len(note_rows)
            from app.services.artifact_live_counts import _read_job_files
            for start in range(0, len(note_rows), 100):
                batch = note_rows[start:start + 100]
                contents = _read_job_files(db, job_id, batch, max_bytes=4_194_304)
                for row in batch:
                    path = str(row.get("file_path") or "").replace("\\", "/")
                    data = contents.get(path)
                    if not data:
                        continue
                    _consider(path, _decode_user_text(data))
                    if len(matches) >= 20:
                        break
                if len(matches) >= 20:
                    break
        except Exception as exc:
            log.warning("credential note live scan failed job=%s: %s", job_id, exc)

    if not matches:
        # If there were no actual user-note candidates at all, a negative conclusion is
        # unsafe because extraction coverage may be incomplete.  If candidates were
        # reviewed and none matched, NOT_FOUND is defensible for the recovered evidence.
        status = "NOT_FOUND" if evidence_rows_reviewed > 0 or live_candidate_count > 0 else "INCONCLUSIVE"
        observation = (
            "No user-created text note was identified that contained both an email address and password/login wording in the recovered user-note evidence."
            if status == "NOT_FOUND"
            else "The currently materialized evidence did not contain enough user-created note content to complete the email-login-details check."
        )
        return _fact(
            title=title,
            status=status,
            observation=observation,
            explanation=(
                "general text-file counts are not proof that login details were saved in Notepad or another note."
                if status == "NOT_FOUND"
                else "the note evidence must be materialized and readable before the report can make a negative finding."
            ),
            counts=[{"report_id": "LIVE_CREDENTIAL_NOTES", "report_title": title, "count": 0, "unit": "NOTE"}] if status == "NOT_FOUND" else [],
            evidence=[f"User-note evidence records reviewed: {evidence_rows_reviewed:,}; live note candidates: {live_candidate_count:,}."],
            limitations=[] if status == "NOT_FOUND" else ["User-created note coverage was insufficient for a reliable negative conclusion."],
            confidence="B" if status == "NOT_FOUND" else "C",
        )

    obs = f"The examination identified {len(matches):,} user-created text note{'s' if len(matches) != 1 else ''} containing an email address together with login/password wording."
    obs += " Secret values are intentionally not reproduced in the report."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="the note content supports that login details were stored in plain text, while the actual password or secret remains redacted.",
        counts=[{"report_id": "LIVE_CREDENTIAL_NOTES", "report_title": title, "count": len(matches), "unit": "NOTE"}],
        entities={"note_files": matches[:6]},
        evidence=[f"Credential-bearing note file(s): {', '.join(matches[:6])}.", f"User-note evidence records reviewed: {evidence_rows_reviewed:,}."],
        confidence="A",
    )

def _company_document_fact(db, job_id: str, title: str, intake: dict[str, Any] | None) -> dict[str, Any]:
    """Identify company-related documents from filename, metadata, index text and live file content.

    A total Word/Excel/PDF count is never used as proof. V11 adds a source-file fallback
    because older jobs can contain the document in ``job_artifacts`` without having its
    body indexed into RAG.
    """
    terms = _company_terms(intake)
    if not terms:
        return _fact(
            title=title,
            status="INCONCLUSIVE",
            observation="Company-related document detection could not be completed because no reliable organization name or company search term was available in the case intake.",
            explanation="a document can be called company-related only when the case supplies a reliable company identifier and the file content or metadata supports that link.",
            confidence="C",
        )

    matches: dict[str, str] = {}
    evidence_sources: list[str] = []
    term_params = {f"term{i}": f"%{term}%" for i, term in enumerate(terms[:8])}
    term_sql = " OR ".join(
        f"(file_name ILIKE :term{i} OR file_path ILIKE :term{i})"
        for i in range(len(term_params))
    ) or "FALSE"

    # Filename/path metadata is strong and cheap.
    rows = fetchall(
        db,
        f"""SELECT id, file_name, file_path, extension
             FROM job_artifacts
            WHERE job_id=:jid
              AND lower(coalesce(extension,'')) = ANY(:exts)
              AND ({term_sql})
            LIMIT 5000""",
        {"jid": job_id, "exts": sorted(_DOC_EXTS), **term_params},
    )
    for row in rows:
        text = f"{row.get('file_name') or ''} {row.get('file_path') or ''}"
        if _matches_company(text, terms):
            name = sanitize_narrative_text(row.get("file_name") or _safe_name(row.get("file_path")), max_len=140)
            if name:
                matches[str(row.get("id") or name)] = name
    if rows:
        evidence_sources.append(f"document filename/path records reviewed: {len(rows):,}")

    # Parsed/indexed text. Do not require one historical chunk_type label.
    try:
        pattern_rows: list[dict[str, Any]] = []
        for term in terms[:6]:
            pattern_rows.extend(fetchall(
                db,
                """SELECT artifact_id, file_path, content
                     FROM rag_chunks
                    WHERE job_id=:jid AND content ILIKE :q
                    LIMIT 400""",
                {"jid": job_id, "q": f"%{term}%"},
            ))
        for row in pattern_rows:
            if not _matches_company(str(row.get("content") or ""), terms):
                continue
            name = _safe_name(row.get("file_path"))
            if name and PurePosixPath(name).suffix.lower() in _DOC_EXTS:
                matches[str(row.get("artifact_id") or row.get("file_path"))] = name
        if pattern_rows:
            evidence_sources.append(f"indexed document-text matches reviewed: {len(pattern_rows):,}")
    except Exception:
        pass

    # Direct source-content fallback. This specifically addresses jobs where documents
    # were extracted but their text was never promoted to RAG. Keep the scan bounded and
    # examiner-facing: we only retain filenames, never raw document text.
    live_scanned = 0
    live_candidates_total = 0
    scan_limit = 1200
    try:
        count_row = fetchall(
            db,
            """SELECT count(*) AS c
                 FROM job_artifacts
                WHERE job_id=:jid
                  AND lower(coalesce(extension,'')) = ANY(:exts)
                  AND coalesce(size_bytes,0) BETWEEN 1 AND 26214400
                  AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/windows/%'
                  AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/program files/%'
                  AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/program files (x86)/%'""",
            {"jid": job_id, "exts": sorted(_DOC_EXTS)},
        )
        if count_row:
            live_candidates_total = int(count_row[0].get("c") or 0)
    except Exception:
        live_candidates_total = 0

    # If metadata/RAG already produced many examples there is no need to read the whole
    # corpus. Otherwise inspect user documents directly.
    if len(matches) < 8:
        try:
            doc_rows = fetchall(
                db,
                """SELECT id, file_path, file_name, extension, size_bytes, minio_uri
                     FROM job_artifacts
                    WHERE job_id=:jid
                      AND lower(coalesce(extension,'')) = ANY(:exts)
                      AND coalesce(size_bytes,0) BETWEEN 1 AND 26214400
                      AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/windows/%'
                      AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/program files/%'
                      AND lower(translate(file_path, chr(92), '/')) NOT LIKE '%/program files (x86)/%'
                    ORDER BY
                      CASE WHEN lower(translate(file_path, chr(92), '/')) LIKE '%/users/%' OR lower(translate(file_path, chr(92), '/')) LIKE 'users/%' THEN 0 ELSE 1 END,
                      size_bytes ASC
                    LIMIT :lim""",
                {"jid": job_id, "exts": sorted(_DOC_EXTS), "lim": scan_limit},
            )
            from app.services.artifact_live_counts import _read_job_files
            from app.services.artifact_preview import _extract_document_preview_text

            for start_idx in range(0, len(doc_rows), 12):
                batch = doc_rows[start_idx:start_idx + 12]
                contents = _read_job_files(db, job_id, batch, max_bytes=26_214_400)
                for row in batch:
                    path = str(row.get("file_path") or "").replace("\\", "/")
                    data = contents.get(path)
                    if not data:
                        continue
                    live_scanned += 1
                    ext = str(row.get("extension") or PurePosixPath(path).suffix or "").lower()
                    if ext and not ext.startswith("."):
                        ext = "." + ext

                    # Fast direct string check catches TXT/RTF/legacy Office and many PDFs.
                    found = False
                    low_bytes = data.lower()
                    for term in terms:
                        ascii_term = term.encode("utf-8", errors="ignore").lower()
                        utf16_term = term.encode("utf-16-le", errors="ignore").lower()
                        if (ascii_term and ascii_term in low_bytes) or (utf16_term and utf16_term in low_bytes):
                            found = True
                            break

                    if not found:
                        extracted = _extract_document_preview_text(data, ext=ext, path=path) or ""
                        found = _matches_company(extracted, terms)
                    if not found and ext in {".txt", ".csv", ".rtf"}:
                        found = _matches_company(_decode_user_text(data), terms)
                    if not found:
                        continue
                    name = sanitize_narrative_text(row.get("file_name") or _safe_name(path), max_len=140)
                    if name:
                        matches[str(row.get("id") or path)] = name
                    if len(matches) >= 25:
                        break
                if len(matches) >= 25:
                    break
            if doc_rows:
                evidence_sources.append(f"live document bodies reviewed: {live_scanned:,}")
        except Exception as exc:
            log.warning("company document live scan failed job=%s: %s", job_id, exc)

    names = list(dict.fromkeys(matches.values()))
    if not names:
        # If we did not cover all available candidate documents, do not turn a bounded
        # report-time scan into a definitive zero.
        incomplete = bool(live_candidates_total and live_scanned < min(live_candidates_total, scan_limit))
        status = "INCONCLUSIVE" if incomplete else "NOT_FOUND"
        return _fact(
            title=title,
            status=status,
            observation=(
                "The report-time document review did not identify a distinct company-related document, but the available document corpus was not fully covered by the bounded live scan."
                if status == "INCONCLUSIVE"
                else "No distinct company-related document was identified from document names, metadata, indexed text, or the recovered document content examined for this objective."
            ),
            explanation=(
                "the remaining document evidence must be reviewed before a reliable negative finding can be made."
                if status == "INCONCLUSIVE"
                else "the total number of Word, Excel, PDF, or other documents is not used as the company-document count."
            ),
            counts=[{"report_id": "LIVE_COMPANY_DOCS", "report_title": title, "count": 0, "unit": "DOCUMENT"}] if status == "NOT_FOUND" else [],
            evidence=["Company terms searched: " + ", ".join(terms[:8]), *evidence_sources],
            limitations=[f"Live document scan covered {live_scanned:,} of {live_candidates_total:,} candidate document(s)."] if status == "INCONCLUSIVE" else [],
            confidence="C" if status == "INCONCLUSIVE" else "B",
        )

    obs = "The examination identified company-related documents on the computer from filename, metadata, indexed text, or the document content itself."
    obs += " Examples include " + ", ".join(names[:5]) + "."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="these files are called company-related because their own content or metadata matches the organization, not because they belong to a general document category.",
        counts=[{"report_id": "LIVE_COMPANY_DOCS", "report_title": title, "count": len(names), "unit": "DOCUMENT"}],
        entities={"documents": names[:10]},
        evidence=["Company terms searched: " + ", ".join(terms[:8]), *evidence_sources],
        limitations=[f"Examples are capped for reporting; {live_scanned:,} live document body/bodies were reviewed during fallback detection."] if live_scanned else [],
        confidence="A",
    )

def _whatsapp_company_fact(db, job_id: str, title: str, intake: dict[str, Any] | None) -> dict[str, Any]:
    records, browser_notes = _browser_records_with_persisted_fallback(db, job_id)
    wa = [r for r in records if _host(str(r.get("url") or "")) in {"web.whatsapp.com", "api.whatsapp.com", "www.whatsapp.com"}]
    web = [r for r in wa if _host(str(r.get("url") or "")) == "web.whatsapp.com"]
    company = _company_document_fact(db, job_id, "company document correlation", intake)
    if not wa:
        return _fact(
            title=title,
            status="NOT_FOUND",
            observation="No recovered browser-history record showed WhatsApp Web or WhatsApp web endpoints being used on the examined computer.",
            explanation="the available browser evidence does not establish WhatsApp Web use; this does not prove it was never used outside the recovered evidence.",
            counts=[{"report_id": "LIVE_WHATSAPP_WEB", "report_title": title, "count": 0, "unit": "WEB_ENDPOINT"}],
            confidence="A",
        )
    obs = "Recovered browser history shows that WhatsApp Web was accessed on the computer." if web else "Recovered browser history contains WhatsApp web-service records."
    company_count = next((int(c.get("count") or 0) for c in company.get("allowed_counts") or [] if c.get("report_id") == "LIVE_COMPANY_DOCS"), 0)
    if company_count > 0:
        obs += f" The examination also identified {company_count:,} company-related document{'s' if company_count != 1 else ''} on the computer."
        obs += " The currently available evidence does not by itself prove that those files were transferred through WhatsApp unless a download/attachment/referrer record links the file to the WhatsApp activity."
    else:
        obs += " No company-related file transfer through WhatsApp was established from the available file and browser evidence."
    counts = [{"report_id": "LIVE_WHATSAPP_WEB", "report_title": title, "count": len({str(r.get('url') or '') for r in wa}), "unit": "WEB_ENDPOINT"}]
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="WhatsApp Web use and the presence of a company file are separate facts unless a forensic record directly links the file to a WhatsApp transfer.",
        counts=counts,
        entities={"whatsapp_hosts": sorted({_host(str(r.get("url") or "")) for r in wa})},
        evidence=[f"WhatsApp browser records recovered: {len(wa):,}.", *browser_notes],
        limitations=["Timing overlap alone is not proof that a particular file was sent or received through WhatsApp."],
        confidence="A" if web else "B",
    )


def _file_access_fact(db, job_id: str, title: str) -> dict[str, Any]:
    """Use specific recent-file targets, not global document counts."""
    rows = fetchall(
        db,
        """SELECT apr.normalized
             FROM artifact_parse_results apr
             JOIN job_artifacts ja ON ja.id=apr.job_artifact_id
            WHERE ja.job_id=:jid
              AND (
                apr.normalized::text ILIKE '%jump_list_entry%'
                OR apr.normalized::text ILIKE '%lnk%'
                OR apr.normalized::text ILIKE '%recent_document%'
              )
            LIMIT 500""",
        {"jid": job_id},
    )
    targets: list[dict[str, str]] = []
    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                continue
        recs = norm if isinstance(norm, list) else [norm] if isinstance(norm, dict) else []
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            path = rec.get("target_path") or rec.get("path") or rec.get("file_path") or rec.get("target")
            name = _safe_name(path)
            if not name or PurePosixPath(name).suffix.lower() not in _DOC_EXTS:
                continue
            event_time = rec.get("event_time") or rec.get("timestamp") or rec.get("last_accessed") or rec.get("modified")
            key = (name.lower(), str(event_time or ""))
            if any((x.get("file_name", "").lower(), x.get("event_time", "")) == key for x in targets):
                continue
            targets.append({"file_name": name, "event_time": str(event_time or "")[:32]})
            if len(targets) >= 20:
                break
        if len(targets) >= 20:
            break
    if not targets:
        return _fact(
            title=title,
            status="INCONCLUSIVE",
            observation="The available recent-document, shortcut, and filesystem evidence did not identify a specific relevant file together with a supported open, change, copy, rename, or delete action for this objective.",
            explanation="general document totals are not proof that a particular file was opened, copied, renamed, changed, or deleted.",
            confidence="C",
        )
    names = [x["file_name"] for x in targets]
    obs = f"Recent-file evidence identified {len(targets):,} distinct file reference{'s' if len(targets) != 1 else ''} to specific user documents."
    obs += " Examples include " + ", ".join(names[:5]) + "."
    obs += " These records support recent/open-reference activity, but they do not by themselves prove copying or renaming."
    return _fact(
        title=title,
        status="CONFIRMED",
        observation=obs,
        explanation="the report names only files that have a specific recent-file/shortcut reference and keeps stronger actions such as copy, rename, or delete separate unless those actions are independently supported.",
        counts=[{"report_id": "LIVE_FILE_REFERENCES", "report_title": title, "count": len(targets), "unit": "FILE_REFERENCE"}],
        entities={"files": names[:10]},
        evidence=[f"Specific recent-file/shortcut targets recovered: {len(targets):,}."],
        confidence="B",
    )


def build_objective_case_fact(
    db,
    job_id: str,
    objective: dict[str, Any],
    *,
    intake: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a live structured fact for high-value objectives, otherwise ``None``.

    The supplied KB remains authoritative for procedure/artifact selection. These
    detectors are the Aetheris adapter that asks the KB question against full live
    records rather than only inventory totals/previews.
    """
    title = str(objective.get("title") or "").strip()
    key = _norm(title)
    if key == _norm("File Access and Handling"):
        return _file_access_fact(db, job_id, title)
    if key in {_norm("Malware, Phishing and Pornography URLs"), _norm("Malware / Phishing URL Verification")} or ("malware" in key and "phishing" in key):
        return _malware_web_fact(db, job_id, title)
    if key == _norm("Verify Use of Unauthorized Remote Access Tools") or ("remote access" in key and "tool" in key):
        return _remote_access_fact(db, job_id, title)
    if key == _norm("USB and External Device Usage"):
        return _usb_fact(db, job_id, title, external_only=False)
    if key == _norm("User Accounts & Login Activity"):
        return _user_accounts_fact(db, job_id, title)
    if key in {_norm("Access to Cloud Storage Services"), _norm("Cloud Storage Service Usage")} or ("cloud" in key and "storage" in key):
        return _cloud_access_fact(db, job_id, title)
    if key == _norm("Analysis of Chat / Communication Apps") or ("chat" in key and "communication" in key):
        return _chat_fact(db, job_id, title)
    if key == _norm("Analysis of Social Media Activity") or ("social media" in key and "activity" in key):
        return _social_fact(db, job_id, title)
    if key in {_norm("Internet and Network Connection Review"), _norm("Network Connections")} or ("internet" in key and "network" in key):
        return _internet_network_fact(db, job_id, title)
    if key == _norm("Anti-Forensics Tools") or "anti forensic" in key or "anti forensics" in key:
        return _anti_forensics_fact(db, job_id, title)
    if key == _norm("Torrent URLs") or "torrent" in key:
        return _torrent_fact(db, job_id, title)
    if key == _norm("Connection of External Hard Disks") or ("external" in key and ("hard disk" in key or "drive" in key)):
        return _usb_fact(db, job_id, title, external_only=True)
    if key == _norm("Deleted Files Found in Recycle Bin") or ("recycle" in key and "deleted" in key):
        return _deleted_fact(db, job_id, title)
    if key == _norm("Email Accounts Used on the Laptop"):
        return _email_addresses_fact(db, job_id, title)
    if key == _norm("Presence of Encrypted Files"):
        return _encrypted_fact(db, job_id, title)
    if key == _norm("Storage of Email Login Details in Notepad"):
        return _credential_note_fact(db, job_id, title)
    if key == _norm("Storage of RRP-Related Documents on Personal Laptop") or (
        "related documents" in key and "personal" in key
    ):
        return _company_document_fact(db, job_id, title, intake)
    if key == _norm("Use of WhatsApp Web and Download of RRP Files") or "whatsapp web" in key:
        return _whatsapp_company_fact(db, job_id, title, intake)
    return None
