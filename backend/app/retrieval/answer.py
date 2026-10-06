"""Grounded natural-language answers from retrieved forensic evidence only."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.config import get_settings
from app.services.model_router import generate_text

log = logging.getLogger("rag_answer")

_USER_INTENT = re.compile(
    r"\b(users?|accounts?|profiles?|who\s+used|logged\s+in|login|logon|username|"
    r"password\s+chang|last\s+logon|last\s+login)\b",
    re.I,
)
_LOGIN_DETAIL_INTENT = re.compile(
    r"\b(last\s+log(in|on)|logon\s+date|login\s+date|password\s+(last\s+)?(chang|set|reset)|when\s+.+\s+log)",
    re.I,
)
_OS_INTENT = re.compile(
    # OS identity / version only — NOT "operating system artifacts" inventory.
    # Include common typos (opearting) and short forms (os info / provide os).
    r"\b(os\s+details?|os\s+(?:info|information)|windows\s+version|which\s+os|what\s+os|"
    r"what\s+(is\s+)?(the\s+)?(?:operating|opearting|oprating)\s+system|"
    r"which\s+(?:operating|opearting|oprating)\s+system|"
    r"(?:operating|opearting|oprating)\s+system\s+(version|name|edition|build|info|information|details?|installed)|"
    r"provide\s+(?:(?:operating|opearting|oprating)\s+system|os)\b|"
    r"(?:operating|opearting|oprating)\s+system\s+details?\s+in\s+table|"
    r"product\s+key|computer\s+name|build\s+number|install\s+date|system\s+root)\b",
    re.I,
)
_HARDWARE_INTENT = re.compile(
    r"\b(hardware\s+(information|info|details?)|"
    r"what\s+hardware|provide\s+hardware|computer\s+hardware|"
    r"device\s+specifications?|system\s+specifications?|"
    r"(?:processor|cpu|ram|memory|bios|motherboard|baseboard))\b",
    re.I,
)
_OS_ARTIFACTS_INTENT = re.compile(
    # Report §8 inventory: Logfile / Jump List / LNK — not OS identity.
    r"\b(operating\s+system|os)\b.*\b(artifacts?|counts?|inventory|catalog)\b|"
    r"\bartifacts?\b.*\b(operating\s+system|\bos\b)\b|"
    r"\b(operating\s+system|os)\s+(artifact\s+)?(counts?|inventory|catalog)\b|"
    r"\b(logfile\s+analysis|jump\s*lists?|lnk\s+files?)\b",
    re.I,
)
_COUNT_INTENT = re.compile(
    # Only total artifact inventory — not OS/section/document typed counts.
    r"\b(how\s+many|count|number\s+of|total)\b.*\bartifacts?\b(?!.*\b(operating\s+system|\bos\b|pdf|csv|document))",
    re.I,
)
_SECTION_INTENT = re.compile(
    r"\b(artifact\s+sections?|axiom\s+artifacts?|connected\s+devices|"
    r"application\s+usages?|communication\s+(section|artifacts?|urls?)|"
    r"document\s+section|documents?\s+section|b\.\s*artifacts|"
    r"operating\s+system\s+artifacts?|os\s+artifacts?|"
    r"media\s+artifacts?|artifacts?\s+for\s+media|\bmedia\b.*\bartifacts?\b|"
    r"artifacts?\s+for\s+(connected\s+devices|application\s+usages?|operating\s+system|"
    r"communication|documents?|media|browser|execution)|"
    r"installed\s+(microsoft\s+)?programs?|"
    r"windows\s+defender|web\s+chat|social\s+media|malware|phishing|"
    r"remote\s+desktop|\brdp\b|feature\s+usage|jump\s*lists?|lnk\s+files?|"
    r"logfile\s+analysis)\b",
    re.I,
)
_USB_INTENT = re.compile(
    r"\b(usb|connected\s+devices?|removable\s+(media|drives?|devices?)|flash\s+drives?|"
    r"thumb\s+drives?|external\s+(drives?|devices?)|usbstor)\b",
    re.I,
)
# Frequency / how-many-times questions (not unique device inventory).
_USB_USAGE_INTENT = re.compile(
    r"\b(how\s+many\s+times|how\s+often|usage\s+count|times?\s+(used|connected|plugged)|"
    r"(used|connected|plugged|inserted)\s+(how\s+many\s+times|usb)|"
    r"usb\s+(usage|activity|connections?|insertions?|events?)|"
    r"when\s+(was|were)\s+usb|"
    r"usb\s+.*\b(times?|used|connected|plugged)\b)\b",
    re.I,
)
_BROWSER_INTENT = re.compile(
    r"\b(urls?|web\s+chat|browser\s+history|visited\s+sites?|browsing\s+history|"
    r"chrome|edge|firefox|web\s+history|websites?\s+visited)\b",
    re.I,
)
_EMAIL_INTENT = re.compile(
    r"\b(emails?|outlook|\.pst|\.eml|mailboxes?|mail\s+files?)\b",
    re.I,
)
_WHATSAPP_INTENT = re.compile(
    r"\b(whatsapp|wa\s+messages?|chat\s+messages?)\b",
    re.I,
)
_PHONE_INTENT = re.compile(
    r"\b(phones?|mobile\s+phones?|cell\s+phones?|android|iphone|smartphone|"
    r"phone\s+devices?|mobile\s+devices?|portable\s+devices?)\b",
    re.I,
)
_PHONE_USAGE_INTENT = re.compile(
    r"\b(how\s+many\s+times|how\s+often|times?\s+used|used\b|connected|plugged|"
    r"usage|activity|connections?)\b.*\b(phones?|mobile|android|iphone)\b|"
    r"\b(phones?|mobile|android|iphone|phone\s+devices?)\b.*\b(used|times?|connected|plugged|usage)\b|"
    r"\bhow\s+many\b.*\bphone\s+devices?\b.*\bused\b",
    re.I,
)
_USER_FROM_PATH = re.compile(r"^Users/([^/]+)/", re.I)
_SKIP_PROFILES = frozenset({"default", "defaultuser0", "public", "all users", "default user"})


def _score(chunk: dict) -> float:
    for key in ("rerank_score", "rrf_score", "score"):
        val = chunk.get(key)
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
    return 0.0


def _meta(chunk: dict) -> dict:
    raw = chunk.get("metadata")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return {}


def _users_from_chunks(chunks: list[dict]) -> list[str]:
    users: set[str] = set()
    profile_users: list[str] = []
    for c in chunks:
        meta = _meta(c)
        if meta.get("kind") == "windows_users" and isinstance(meta.get("users"), list):
            for u in meta["users"]:
                if isinstance(u, str) and u.strip() and u.strip().lower() not in _SKIP_PROFILES:
                    profile_users.append(u.strip())
        path = (c.get("file_path") or "").replace("\\", "/")
        pm = _USER_FROM_PATH.match(path)
        if pm:
            name = pm.group(1).strip()
            if name and name.lower() not in _SKIP_PROFILES:
                users.add(name)
    # Prefer synthetic profile fact list (Users\ folders only)
    if profile_users:
        return sorted(set(profile_users), key=str.lower)
    return sorted(users, key=str.lower)


def _accounts_from_chunks(chunks: list[dict]) -> dict[str, dict]:
    accounts: dict[str, dict] = {}

    def put(user: str, **fields: object) -> None:
        if not user or user.lower() in _SKIP_PROFILES:
            return
        bucket = accounts.setdefault(user, {"username": user})
        for k, v in fields.items():
            if v is None:
                continue
            if k in ("last_logon", "password_last_set") and isinstance(v, str):
                # Keep only an ISO-like timestamp token — ignore trailing junk
                m = re.match(
                    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?(?:\s*\(approximate\))?)",
                    v.strip(),
                )
                if not m:
                    continue
                v = {"at": m.group(1).replace(" ", "T").replace("+00:00", "Z")}
            if k in ("last_logon", "password_last_set") and isinstance(v, dict) and v.get("at"):
                prev = bucket.get(k)
                prev_at = prev.get("at") if isinstance(prev, dict) else None
                if not prev_at or str(v["at"]) > str(prev_at):
                    bucket[k] = v
            elif k not in bucket:
                bucket[k] = v

    for c in chunks:
        meta = _meta(c)
        if meta.get("kind") == "windows_users":
            for acct in meta.get("accounts") or []:
                if not isinstance(acct, dict) or not acct.get("username"):
                    continue
                put(
                    str(acct["username"]),
                    last_logon=acct.get("last_logon"),
                    password_last_set=acct.get("password_last_set"),
                    rid=acct.get("rid"),
                    sid=acct.get("sid"),
                )
        content = c.get("content") or ""
        for m in re.finditer(
            r"Account timeline for ([^:\n]+):\s*([^\n]+)",
            content,
            re.I,
        ):
            user = m.group(1).strip()
            rest = m.group(2).strip()
            if "not found" in rest.lower():
                put(user)
                continue
            lm = re.search(r"last logon:\s*([^;\[]+)", rest, re.I)
            pm = re.search(r"password last changed:\s*([^;\[]+)", rest, re.I)
            put(
                user,
                last_logon=lm.group(1).strip() if lm else None,
                password_last_set=pm.group(1).strip() if pm else None,
            )
        for m in re.finditer(
            r"Windows local account:\s*([A-Za-z0-9._\-]+)\s*\(RID\s*(\d+)\)"
            r"(?:;\s*last logon:\s*([0-9T:\-.Z+]+))?"
            r"(?:;\s*password last changed:\s*([0-9T:\-.Z+]+))?",
            content,
            re.I,
        ):
            put(
                m.group(1).strip(),
                rid=int(m.group(2)),
                last_logon=m.group(3),
                password_last_set=m.group(4),
            )
        for m in re.finditer(
            r"successful logon;\s*user:\s*([A-Za-z0-9._\-]+)\s*;"
            r"(?:[^;]*;)?\s*at:\s*([0-9T:\-.Z+]+)",
            content,
            re.I,
        ):
            put(m.group(1).strip(), last_logon=m.group(2).strip())
    return accounts


def _ts_display(val) -> str | None:
    if isinstance(val, dict):
        at = val.get("at")
        if not at:
            return None
        approx = " (approximate)" if val.get("approx") else ""
        # Strip source paths from display value if embedded
        at = re.split(r"\s*\[", str(at), maxsplit=1)[0].strip()
        return f"{at}{approx}"
    if isinstance(val, str) and val.strip():
        m = re.match(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
            val.strip(),
        )
        return (m.group(1).replace(" ", "T") if m else None)
    return None


def _filter_relevant_chunks(query: str, chunks: list[dict], *, top_k: int = 8) -> list[dict]:
    """Keep chunks that can support a correct answer — prefer forensic sources, keep breadth."""
    if not chunks:
        return []

    if _USER_INTENT.search(query or ""):
        preferred: list[dict] = []
        path_hits: list[dict] = []
        account_hits: list[dict] = []
        for c in chunks:
            path = (c.get("file_path") or "").replace("\\", "/")
            meta = _meta(c)
            content = (c.get("content") or "").lower()
            if path == "__forensic__/windows_user_profiles" or meta.get("kind") == "windows_users":
                preferred.append(c)
                continue
            pl = path.lower()
            if any(
                x in pl
                for x in (
                    "/sam",
                    "/software",
                    "ntuser.dat",
                    "security.evtx",
                    "system.evtx",
                    "profilelist",
                )
            ) or any(
                x in content
                for x in ("last logon", "password last", "sam_user", "successful logon", "profilelist")
            ):
                account_hits.append(c)
                continue
            if re.match(r"^Users/[^/]+/(NTUSER\.DAT|Desktop|Documents|Downloads)(/|$)", path, re.I):
                path_hits.append(c)
            elif path.lower().startswith("users/") and path.count("/") <= 2:
                path_hits.append(c)
        selected = preferred + account_hits + path_hits
        if not selected:
            selected = [
                c for c in chunks if "Users/" in ((c.get("file_path") or "").replace("\\", "/"))
            ] or list(chunks)
        # de-dupe by id/path
        seen: set[str] = set()
        out: list[dict] = []
        for c in selected:
            key = str(c.get("id") or c.get("file_path") or id(c))
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out[: max(top_k, 12)]

    if _OS_INTENT.search(query or "") and not _OS_ARTIFACTS_INTENT.search(query or ""):
        os_hits = []
        preferred = []
        for c in chunks:
            path = (c.get("file_path") or "").replace("\\", "/")
            pl = path.lower()
            meta = _meta(c)
            content = (c.get("content") or "").lower()
            # Browser/SQLite noise (Favicons, History) must not outrank hive facts.
            if any(
                x in pl
                for x in (
                    "/google/chrome/",
                    "/microsoft/edge/",
                    "/mozilla/firefox/",
                    "/brave-browser/",
                    "favicons",
                    "/user data/",
                )
            ):
                continue
            if path == "__forensic__/windows_os" or meta.get("kind") == "windows_os":
                preferred.append(c)
                continue
            if any(
                x in pl or x in content
                for x in (
                    "/config/software",
                    "/config/system",
                    "windows nt",
                    "productname",
                    "currentversion",
                    "operating system",
                    "windows 10",
                    "windows 11",
                    "computername",
                    "__forensic__/windows_os",
                )
            ):
                os_hits.append(c)
        return (preferred + os_hits or [])[:top_k]

    # Generic: drop encyclopedia-only noise when evidence exists; keep more chunks for broad search
    evidence = [c for c in chunks if (c.get("chunk_type") or "evidence") == "evidence"]
    pool = evidence or list(chunks)
    pool = sorted(pool, key=_score, reverse=True)
    return pool[: max(top_k, 12)]


def _answer_users(
    query: str,
    chunks: list[dict],
    *,
    account_timeline: dict[str, dict] | None = None,
) -> dict[str, Any] | None:
    users = _users_from_chunks(chunks)
    accounts = _accounts_from_chunks(chunks)
    # Live SAM/EVTX timeline wins over stale chunk metadata
    if account_timeline:
        for name, facts in account_timeline.items():
            if not isinstance(facts, dict):
                continue
            key = next((u for u in users if u.lower() == str(name).lower()), None)
            if not key:
                # Keep only profile users in the primary list; still attach if exact match later
                continue
            merged = {**accounts.get(key, {"username": key}), **facts, "username": key}
            accounts[key] = merged
    want_detail = bool(_LOGIN_DETAIL_INTENT.search(query or ""))
    # Explicit "users only" / names-only questions should not dump timestamps
    if re.search(r"\bonly\b|\bjust\s+(the\s+)?(users?|accounts?|names?)\b", query or "", re.I):
        want_detail = False

    if not users:
        return {
            "answer": (
                "I could not confirm which user accounts used this laptop from the indexed evidence. "
                "No Windows user profiles were found under Users\\ on this disk image."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"users": [], "accounts": {}},
        }

    if len(users) == 1:
        prose = (
            f"Based on the Windows user profile folders recovered from this disk image, "
            f"the account that used this laptop is **{users[0]}** "
            f"(profile path: Users\\{users[0]}\\)."
        )
    else:
        listed = ", ".join(users[:-1]) + f", and {users[-1]}"
        prose = (
            f"Based on the Windows user profile folders recovered from this disk image, "
            f"**{len(users)} accounts** used this laptop: **{listed}**.\n\n"
            f"These names come from profile directories under `Users\\` on the evidence disk "
            f"(system profiles such as Default/Public are excluded)."
        )

    detail_lines: list[str] = []
    missing_logon: list[str] = []
    missing_pwd: list[str] = []
    if want_detail:
        for u in users:
            acct = accounts.get(u) or {}
            ll = _ts_display(acct.get("last_logon"))
            pw = _ts_display(acct.get("password_last_set"))
            bits = []
            if ll:
                bits.append(f"last logon **{ll}**")
            else:
                missing_logon.append(u)
            if pw:
                bits.append(f"password last changed **{pw}**")
            else:
                missing_pwd.append(u)
            if bits:
                detail_lines.append(f"- **{u}**: " + "; ".join(bits))

        if detail_lines:
            prose += "\n\nAccount timeline from SAM / Security event logs / NTUSER where available:\n"
            prose += "\n".join(detail_lines)
        else:
            prose += (
                "\n\nLast logon and password-change timestamps were **not found** in the currently "
                "indexed SAM, Security.evtx, ProfileList, or NTUSER.DAT evidence for these accounts."
            )
        if missing_logon and detail_lines:
            prose += f"\n\nNo last-logon timestamp was found for: {', '.join(missing_logon)}."
        if missing_pwd and detail_lines:
            prose += f"\n\nNo password-change timestamp was found for: {', '.join(missing_pwd)}."

    conf = "high"
    return {
        "answer": prose,
        "confidence": conf,
        "grounded": True,
        "facts": {
            "users": users,
            "accounts": accounts if want_detail else {u: {"username": u} for u in users},
        },
    }


def _answer_os(
    chunks: list[dict],
    *,
    os_facts: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    facts: dict[str, Any] = dict(os_facts or {})
    for c in chunks:
        meta = _meta(c)
        if meta.get("kind") == "windows_os":
            for k, v in meta.items():
                if k != "kind" and v and not facts.get(k):
                    facts[k] = v
        content = c.get("content") or ""
        for key, pat in (
            ("product_name", r"(?:ProductName|Operating System):\s*(.+)"),
            ("display_version", r"Display Version:\s*(.+)"),
            ("version_number", r"Version Number:\s*(.+)"),
            ("current_version", r"Operating System Version:\s*(.+)"),
            ("current_build", r"Build Number:\s*(.+)"),
            ("product_id", r"Product ID:\s*(.+)"),
            ("product_key", r"Product Key:\s*(.+)"),
            ("computer_name", r"Computer Name:\s*(.+)"),
            ("install_date", r"Installed/Updated Date/Time:\s*(.+)"),
            ("last_shutdown", r"Last Shutdown Date/Time:\s*(.+)"),
            ("system_root", r"System Root:\s*(.+)"),
            ("path", r"^Path:\s*(.+)"),
        ):
            if facts.get(key):
                continue
            m = re.search(pat, content, re.I | re.M)
            if m:
                facts[key] = m.group(1).strip()

    product = facts.get("product_name")
    if not product and not facts.get("computer_name"):
        return {
            "answer": (
                "I could not determine a specific operating system version from the indexed evidence "
                "with high confidence. Re-run enrichment if registry hives (SOFTWARE/SYSTEM) were not parsed."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"os": facts},
        }

    build = facts.get("current_build")
    if build and facts.get("ubr") and "." not in str(build):
        build = f"{build}.{facts['ubr']}"

    rows = [
        ("Operating System", product),
        ("Version Number", facts.get("version_number") or facts.get("display_version")),
        ("Installed/Updated Date/Time", facts.get("install_time") or facts.get("install_date")),
        ("Product Key", facts.get("product_key") or facts.get("product_key_alt")),
        ("Computer Name", facts.get("computer_name")),
        ("Operating System Version", facts.get("current_version")),
        ("Build Number", build),
        ("Product ID", facts.get("product_id")),
        ("Last Shutdown Date/Time", facts.get("last_shutdown")),
        ("System Root", facts.get("system_root") or facts.get("path_name")),
        ("Path", facts.get("path")),
    ]
    extras = [
        ("Display Version", facts.get("display_version")),
        ("Edition", facts.get("edition_id")),
        ("Installation Type", facts.get("installation_type")),
        ("Build Lab", facts.get("build_lab")),
        ("Registered Owner", facts.get("registered_owner")),
        ("Processor", facts.get("processor_identifier")),
        ("Architecture", facts.get("processor_architecture")),
        ("CPU Count", facts.get("number_of_processors")),
    ]

    lines = ["Operating system details from this disk image registry evidence:", ""]
    for label, value in rows:
        lines.append(f"- **{label}**: {value if value else 'not found in indexed evidence'}")
    extra_bits = [(l, v) for l, v in extras if v]
    if extra_bits:
        lines.append("")
        lines.append("Additional related details:")
        for label, value in extra_bits:
            lines.append(f"- **{label}**: {value}")
    lines.append("")
    lines.append(
        "Sources: `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`, "
        "`SYSTEM\\…\\ComputerName`, `ShutdownTime`, and `Environment\\Path`."
    )
    found_core = sum(1 for _, v in rows if v)
    return {
        "answer": "\n".join(lines),
        "confidence": "high" if found_core >= 5 else ("medium" if product else "low"),
        "grounded": True,
        "facts": {"os": facts},
    }


def _answer_hardware(*, os_facts: dict[str, Any] | None = None) -> dict[str, Any] | None:
    facts = dict(os_facts or {})
    processor = facts.get("processor_identifier")
    architecture = facts.get("processor_architecture")
    cpu_count = facts.get("number_of_processors")
    if not processor and not architecture and not cpu_count:
        return {
            "answer": (
                "No hardware details were found in indexed registry evidence. "
                "Re-run enrichment if SYSTEM hive environment paths were not parsed."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"hardware": facts},
        }
    header = "| Processor | Architecture | CPU Count | Computer Name |"
    sep = "| --- | --- | --- | --- |"
    row = (
        f"| {processor or '—'} | {architecture or '—'} | {cpu_count or '—'} | "
        f"{facts.get('computer_name') or '—'} |"
    )
    return {
        "answer": "\n".join([header, sep, row]),
        "confidence": "high" if processor else "medium",
        "grounded": True,
        "facts": {"hardware": facts},
    }


def _llm_answer(query: str, chunks: list[dict]) -> str | None:
    settings = get_settings()
    evidence_blocks = []
    for i, c in enumerate(chunks[:6], start=1):
        evidence_blocks.append(
            f"[{i}] path={c.get('file_path') or 'n/a'}\n{(c.get('content') or '')[:900]}"
        )
    evidence = "\n\n".join(evidence_blocks)
    system = (
        "You are a digital forensics assistant. Answer ONLY using the evidence blocks. "
        "Write clear human-readable language. "
        "If the question asks about multiple artifact sections (e.g. Connected Devices AND "
        "Application Usages), cover EACH named section with counts — do not omit any. "
        "If the question asks for 'operating system artifacts' / 'OS artifacts', return the "
        "forensic artifact inventory with counts (System/encyclopedia types) — NOT OS version, "
        "product key, or computer name identity. "
        "For USB/phone/Connected Devices, prefer 'devices used' / connect-usage event counts "
        "over unique device inventory unless the user asks specifically for unique devices. "
        "If evidence is insufficient, say you cannot confirm. "
        "Do not invent users, dates, IPs, or OS versions. "
        "Do not dump raw JSON as the whole answer — summarize facts."
    )
    prompt = f"Question: {query}\n\nEvidence:\n{evidence}\n\nAnswer:"
    try:
        raw = generate_text(
            prompt,
            model=settings.llm_fast_model,
            system=system,
            temperature=0,
        )
        if not raw or raw.startswith("[Model ") or "unavailable" in raw.lower():
            return None
        # Reject answers that ignore grounding (common stub/hallucination markers)
        if len(raw.strip()) < 20:
            return None
        return raw.strip()
    except Exception as exc:
        log.warning("LLM answer failed: %s", exc)
        return None


def _answer_artifact_count(inventory: dict[str, Any] | None) -> dict[str, Any]:
    inv = inventory or {}
    total = int(inv.get("artifacts_total") or 0)
    by = inv.get("by_parse_status") or {}
    chunks = int(inv.get("chunks_total") or 0)
    priority = int(inv.get("priority_forensic_files") or 0)
    if total <= 0:
        return {
            "answer": (
                "I could not find registered artifacts for this job yet. "
                "If extraction just finished, click Enrich / Parse drain so files are materialized into Artifacts."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"inventory": inv},
        }
    lines = [
        f"This job currently has **{total:,} artifacts** registered from the disk image.",
        "",
        "Parse status breakdown:",
    ]
    for st, c in sorted(by.items(), key=lambda x: -x[1]):
        lines.append(f"- **{st}**: {int(c):,}")
    lines.append(f"- **RAG evidence chunks indexed**: {chunks:,}")
    lines.append(f"- **High-value forensic files tracked** (browser/email/USB/setupapi/hives): {priority:,}")
    if int(by.get("pending") or 0) > 0:
        lines.append(
            "\nNote: many artifacts are still **pending parse**, so browser history, email, "
            "and device details appear as parsing catches up. Ask again after enrichment, "
            "or re-run priority forensic parse."
        )
    cats = inv.get("top_categories") or []
    if cats:
        # Prefer forensic-interesting categories first in the answer.
        priority_prefixes = (
            "BRW-", "EML-", "CHAT-", "WRG-HIVE-", "WRG-EVT-", "WRG-USB-",
            "WRX-", "WFS-SHL-", "WFS-RB-", "DOC-", "USR-",
        )
        def _rank(cat: dict) -> tuple:
            cid = str(cat.get("id") or "")
            for i, p in enumerate(priority_prefixes):
                if cid.startswith(p):
                    return (0, i, -int(cat.get("count") or 0))
            return (1, 99, -int(cat.get("count") or 0))

        ordered = sorted(cats, key=_rank)
        lines.append("\nTop encyclopedia categories:")
        for cat in ordered[:12]:
            label = cat.get("name") or cat.get("id") or "unknown"
            cid = cat.get("id")
            count = int(cat.get("count") or 0)
            if cid and cid != label:
                lines.append(f"- **{label}** (`{cid}`): {count:,}")
            else:
                lines.append(f"- **{label}**: {count:,}")
    return {
        "answer": "\n".join(lines),
        "confidence": "high",
        "grounded": True,
        "facts": {"inventory": inv},
    }


def _answer_usb_usage(usage: dict | None, devices: list[dict] | None) -> dict[str, Any]:
    info = usage or {}
    events = list(info.get("events") or [])
    device_count = int(info.get("unique_device_count") or len(devices or []) or 0)
    event_count = int(info.get("usage_event_count") or len(events) or 0)

    if event_count <= 0 and device_count <= 0:
        return {
            "answer": (
                "No USB usage/connect events were found yet in SetupAPI or USBSTOR evidence. "
                "Ask again after setupapi.dev.log / SYSTEM hive are re-parsed."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"usb_usage": info},
        }

    lines = [
        "This answers **how many times USB was used/connected** (usage events), "
        "not how many unique USB devices exist.",
        "",
        f"- **USB usage/connect events found:** **{event_count}**",
        f"- **Unique USB devices known on this system:** **{device_count}**",
        "",
    ]
    if events:
        lines.append("Event timeline (from SetupAPI / USBSTOR key last-write):")
        for ev in events[:40]:
            when = ev.get("event_time") or "unknown time"
            device = ev.get("device_id") or "USB device"
            kind = ev.get("event_kind") or "event"
            lines.append(f"- **{when}** — {device} ({kind})")
        if event_count > 40:
            lines.append(f"\n…and {event_count - 40} more events.")
    elif device_count > 0:
        lines.append(
            "Unique devices were enumerated from USBSTOR, but discrete connect-event "
            "timestamps were not available in indexed SetupAPI yet."
        )
        for d in (devices or info.get("devices") or [])[:20]:
            lines.append(
                f"- {d.get('device_name')}"
                + (f" (last write={d.get('last_write')})" if d.get("last_write") else "")
            )

    lines.append(
        "\nNote: SetupAPI “Device Install (Hardware initiated)” entries count plug/"
        "install activity; USBSTOR key last-write is additional usage evidence, "
        "not a full plug-count guarantee."
    )
    return {
        "answer": "\n".join(lines),
        "confidence": "high" if event_count > 0 else "medium",
        "grounded": True,
        "facts": {
            "usb_usage": info,
            "usage_event_count": event_count,
            "unique_device_count": device_count,
        },
    }


def _answer_phone(phone_info: dict | None, *, usage_focus: bool) -> dict[str, Any]:
    info = phone_info or {}
    events = list(info.get("events") or [])
    devices = list(info.get("devices") or [])
    event_count = int(info.get("usage_event_count") or len(events) or 0)
    device_count = int(info.get("unique_device_count") or len(devices) or 0)

    if event_count <= 0 and device_count <= 0:
        return {
            "answer": (
                "No phone / portable-device USB connection evidence was found in SetupAPI "
                "(WPDBUSENUM / phone VID-PID / MTP). "
                "Bluetooth-only phones without USB pairing may not appear here."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"phone": info},
        }

    if usage_focus:
        lines = [
            "This answers **how many times phone device(s) were used/connected** "
            "(USB/MTP/portable-device install events), not only unique phone count.",
            "",
            f"- **Phone usage/connect events:** **{event_count}**",
            f"- **Unique phone / portable devices:** **{device_count}**",
            "",
        ]
        if events:
            lines.append("Event timeline:")
            for ev in events[:40]:
                lines.append(
                    f"- **{ev.get('event_time') or 'unknown'}** — {ev.get('device_id')}"
                )
            if event_count > 40:
                lines.append(f"\n…and {event_count - 40} more.")
    else:
        lines = [
            f"**{device_count} phone / portable device(s)** were identified from USB connection evidence "
            f"({event_count} connect/install event(s) recorded).",
            "",
        ]
        for d in devices[:40]:
            extra = []
            if d.get("event_count"):
                extra.append(f"events={d['event_count']}")
            if d.get("first_seen"):
                extra.append(f"first={d['first_seen']}")
            if d.get("last_seen"):
                extra.append(f"last={d['last_seen']}")
            lines.append(
                f"- **{d.get('device_name')}**"
                + (f" ({', '.join(extra)})" if extra else "")
            )

    if info.get("note"):
        lines.append(f"\nNote: {info['note']}")
    return {
        "answer": "\n".join(lines),
        "confidence": "high" if event_count > 0 else "medium",
        "grounded": True,
        "facts": {
            "phone": info,
            "usage_event_count": event_count,
            "unique_device_count": device_count,
        },
    }


def _answer_usb(devices: list[dict] | None, chunks: list[dict]) -> dict[str, Any]:
    devices = list(devices or [])
    if not devices:
        # try metadata from chunks
        for c in chunks:
            meta = _meta(c)
            if meta.get("kind") == "usb_devices" and isinstance(meta.get("devices"), list):
                devices = meta["devices"]
                break
            content = c.get("content") or ""
            for m in re.finditer(r"Connected USB device:\s*([^\n;(]+)", content, re.I):
                devices.append({"device_name": m.group(1).strip()})
    # unique names
    seen: set[str] = set()
    uniq: list[dict] = []
    for d in devices:
        name = (d.get("device_name") or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        uniq.append(d)
    if not uniq:
        return {
            "answer": (
                "No connected USB / removable devices were found in the currently parsed evidence "
                "(SYSTEM\\Enum\\USBSTOR / MountedDevices). "
                "If SYSTEM hive parse is still pending, re-ask after priority forensic parse."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"devices": []},
        }
    lines = [f"**{len(uniq)} connected USB / removable device(s)** were found:", ""]
    for d in uniq[:40]:
        extra = []
        if d.get("vendor"):
            extra.append(f"vendor={d['vendor']}")
        if d.get("product"):
            extra.append(f"product={d['product']}")
        if d.get("serial"):
            extra.append(f"serial={d['serial']}")
        lines.append(f"- **{d.get('device_name')}**" + (f" ({', '.join(extra)})" if extra else ""))
    return {
        "answer": "\n".join(lines),
        "confidence": "high",
        "grounded": True,
        "facts": {"devices": uniq, "device_count": len(uniq)},
    }


def _answer_browser(urls: list[dict] | None, chunks: list[dict]) -> dict[str, Any]:
    urls = list(urls or [])
    if not urls:
        for c in chunks:
            content = c.get("content") or ""
            for m in re.finditer(r"Visited URL:\s*(\S+)", content):
                urls.append({"url": m.group(1), "source": c.get("file_path")})
    seen: set[str] = set()
    uniq = []
    for u in urls:
        url = (u.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        uniq.append(u)
    if not uniq:
        return {
            "answer": (
                "No browser history URLs are available in indexed evidence yet. "
                "Chrome/Edge `History` databases may still be pending parse — "
                "re-ask after priority forensic parse completes."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"urls": []},
        }
    lines = [f"Found **{len(uniq)} web URL(s)** in browser history evidence (sample):", ""]
    for u in uniq[:25]:
        title = u.get("title")
        lines.append(f"- {u['url']}" + (f" — {title}" if title else ""))
    if len(uniq) > 25:
        lines.append(f"\n…and {len(uniq) - 25} more.")
    return {
        "answer": "\n".join(lines),
        "confidence": "high",
        "grounded": True,
        "facts": {"urls": uniq[:50], "url_count": len(uniq)},
    }


def _answer_email(email_info: dict | None) -> dict[str, Any]:
    info = email_info or {}
    count = int(info.get("count") or 0)
    if count <= 0:
        return {
            "answer": "No email artifacts (.eml / .pst / Outlook files) were registered on this job yet.",
            "confidence": "low",
            "grounded": True,
            "facts": {"email": info},
        }
    lines = [
        f"Found **{count} email mailbox / message file(s)** on this disk image "
        f"({int(info.get('pst_count') or 0)} PST, "
        f"{int(info.get('ost_count') or 0)} OST, "
        f"{int(info.get('eml_count') or 0)} EML).",
        "",
        "Files:",
    ]
    for item in (info.get("items") or [])[:20]:
        lines.append(f"- `{item.get('file_path')}` (status={item.get('parse_status')})")
    if info.get("pst_count") or info.get("ost_count"):
        lines.append(
            "\nNote: PST/OST containers are registered; full message extraction is limited "
            "until a dedicated mail parser is enabled. Paths above confirm mailbox presence."
        )
    return {
        "answer": "\n".join(lines),
        "confidence": "high",
        "grounded": True,
        "facts": {"email": info},
    }


def _answer_whatsapp(wa: dict | None) -> dict[str, Any]:
    info = wa or {}
    files = info.get("files") or []
    if not files and not info.get("message_count"):
        return {
            "answer": (
                "No WhatsApp databases/files were found under this job’s artifacts yet "
                "(searched for WhatsApp / msgstore paths)."
            ),
            "confidence": "low",
            "grounded": True,
            "facts": {"whatsapp": info},
        }
    lines = [f"WhatsApp-related evidence: **{len(files)} file(s)** found."]
    if info.get("message_count"):
        lines.append(f"Parsed message rows: **{info['message_count']}**.")
    if files:
        lines.append("\nFiles:")
        for f in files[:20]:
            lines.append(f"- `{f}`")
    for s in (info.get("samples") or [])[:5]:
        lines.append(f"- Sample message: {s}")
    return {
        "answer": "\n".join(lines),
        "confidence": "high" if files else "medium",
        "grounded": True,
        "facts": {"whatsapp": info},
    }


def _format_bytes(n: int | None) -> str:
    if n is None:
        return "unknown size"
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "unknown size"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} bytes"


def _answer_documents(doc_info: dict | None) -> dict[str, Any]:
    info = doc_info or {}
    label = info.get("label") or "documents"
    count = int(info.get("count") or 0)
    exts = ", ".join(info.get("extensions") or []) or "n/a"
    items = list(info.get("items") or [])

    if count <= 0:
        return {
            "answer": (
                f"No **{label}** were found in the registered artifacts for this job "
                f"(looked for extension(s): {exts})."
            ),
            "confidence": "high",
            "grounded": True,
            "facts": {"documents": info},
        }

    lines = [
        f"Found **{count:,} {label}** on this disk image.",
        "",
        f"File type filter: `{exts}`",
        "",
        "Examples:",
    ]
    for item in items[:25]:
        path = item.get("file_path") or "unknown"
        size = _format_bytes(item.get("size_bytes"))
        lines.append(f"- `{path}` ({size})")
    if count > len(items):
        lines.append(f"\n…and **{count - len(items):,}** more not listed here.")
    lines.append(
        "\nThese counts come from the artifact inventory (file paths on the image), "
        "not from keyword search snippets."
    )
    return {
        "answer": "\n".join(lines),
        "confidence": "high",
        "grounded": True,
        "facts": {"documents": info, "document_count": count},
    }


def _generic_grounded_summary(query: str, chunks: list[dict]) -> str:
    # Drop useless graph stubs
    usable = [
        c for c in chunks
        if (c.get("file_path") or "") and not str(c.get("content") or "").startswith("Graph related artifact")
    ] or chunks
    lines = [
        "I could not produce a structured inventory answer for this question, "
        "so here is the closest indexed evidence (may be incomplete):",
        "",
    ]
    for i, c in enumerate(usable[:5], start=1):
        path = c.get("file_path") or "unknown path"
        content = re.sub(r"\s+", " ", (c.get("content") or "")).strip()
        content = re.sub(r"^Evidence file [^\n]+\n?", "", content).strip()
        if content.startswith("Graph related artifact"):
            continue
        # Prefer a short human sentence over a raw dump
        snippet = content[:180] + ("…" if len(content) > 180 else "")
        lines.append(f"{i}. **File:** `{path}`")
        if snippet:
            lines.append(f"   Summary: {snippet}")
    lines.append("")
    lines.append(
        "Tip: ask with a clear type (for example: “How many CSV documents are available?” "
        "or “How many PDF files are available?”) for a precise count."
    )
    return "\n".join(lines)


def _answer_encyclopedia_category(info: dict[str, Any] | None) -> dict[str, Any] | None:
    if not info:
        return None
    title = info.get("category") or "Category"
    total = int(info.get("count") or 0)
    items = info.get("items") or []
    if total <= 0 and not items:
        return {
            "answer": (
                f"No encyclopedia artifacts were found for **{title}** on this job yet. "
                "Re-run classification / enrichment if extraction just finished."
            ),
            "confidence": "medium",
            "grounded": True,
            "facts": {"encyclopedia_category": info},
        }

    lines = [
        f"**{title} artifacts** — encyclopedia / artifact inventory with counts",
        "",
        f"Total files in this category: **{total:,}**",
        "",
    ]
    for i, it in enumerate(items, start=1):
        lines.append(
            f"{i}. **{it.get('label') or it.get('artifact_id')}** — Count: **{int(it.get('count') or 0):,}**"
        )
        if it.get("artifact_id"):
            lines.append(f"   Encyclopedia ID: `{it['artifact_id']}`")

    for rel in info.get("related") or []:
        lines.append("")
        lines.append(
            f"### Related: {rel.get('category')} — **{int(rel.get('count') or 0):,}** files"
        )
        for j, it in enumerate(rel.get("items") or [], start=1):
            lines.append(
                f"{j}. **{it.get('label') or it.get('artifact_id')}** — Count: **{int(it.get('count') or 0):,}**"
            )

    lines.append("")
    lines.append(
        "Note: this is the **artifact inventory** for this category — not OS version / product-key identity. "
        "Ask “What operating system is installed?” for OS details."
    )
    return {
        "answer": "\n".join(lines),
        "confidence": "high",
        "grounded": True,
        "facts": {"encyclopedia_category": info},
    }


def _answer_sections(
    query: str,
    section_inventory: dict[str, Any] | None,
    *,
    usage_focus: bool = False,
    defer_device_items: bool = True,
) -> dict[str, Any] | None:
    if not section_inventory:
        return None
    from app.services.artifact_sections import (
        detect_usage_focus,
        format_multi_section_answer,
        format_sections_markdown,
        match_all_section_queries,
    )

    q = query or ""
    from app.services.artifact_sections import detect_usage_focus, format_sections_table

    matches = match_all_section_queries(q, section_inventory)
    want_table = bool(re.search(r"\btable\s+format\b", q, re.I))

    # Named multi-section asks (data leakage, Connected Devices + Documents + …)
    if len(matches) >= 2:
        usage = usage_focus or detect_usage_focus(q) or bool(
            re.search(r"\b(devices-used|usage\s+event|connect\s+event)\b", q, re.I)
        )
        if want_table:
            answer = format_sections_table(section_inventory, matches=matches)
        else:
            answer = format_multi_section_answer(
                matches,
                usage_focus=usage,
                report_style=True,
            )
        return {
            "answer": answer,
            "confidence": "high",
            "grounded": True,
            "facts": {
                "section_matches": matches,
                "section_match": matches[0],
                "sections": section_inventory,
                "usage_focus": usage,
            },
        }

    # Full Axiom catalog overview (images 2–3 style) — only when no named section subset
    if re.search(
        r"\b(all\s+artifact\s+sections?|axiom\s+summary|artifact\s+catalog|"
        r"b\.\s*artifacts|show\s+(all\s+)?(artifact\s+)?sections?|"
        r"list\s+(all\s+)?(artifact\s+)?sections?)\b",
        q,
        re.I,
    ):
        answer = format_sections_table(section_inventory) if want_table else format_sections_markdown(section_inventory)
        return {
            "answer": answer,
            "confidence": "high",
            "grounded": True,
            "facts": {"sections": section_inventory},
        }

    if not matches:
        return None

    # Drop sole USB/phone item matches so dedicated handlers can answer richer timelines.
    if defer_device_items and len(matches) == 1:
        item = matches[0].get("item") or {}
        if matches[0].get("level") == "item" and item.get("key") in ("usb_devices", "phone_devices"):
            return None

    # Prefer connect/usage events for device questions (not unique-device inventory).
    usage = usage_focus or detect_usage_focus(q)
    if not usage and any(
        (m.get("section") or {}).get("key") == "connected_devices" for m in matches
    ):
        if re.search(r"\b(how\s+many|count|details|provide)\b", q, re.I):
            usage = True

    return {
        "answer": format_multi_section_answer(
            matches,
            usage_focus=usage,
            report_style=True,
        ),
        "confidence": "high",
        "grounded": True,
        "facts": {
            "section_matches": matches,
            "section_match": matches[0],
            "sections": section_inventory,
            "usage_focus": usage,
        },
    }


def compose_answer(
    query: str,
    chunks: list[dict],
    *,
    account_timeline: dict[str, dict] | None = None,
    os_facts: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    usb_devices: list[dict] | None = None,
    usb_usage: dict[str, Any] | None = None,
    phone_info: dict[str, Any] | None = None,
    document_info: dict[str, Any] | None = None,
    section_inventory: dict[str, Any] | None = None,
    encyclopedia_category: dict[str, Any] | None = None,
    browser_urls: list[dict] | None = None,
    email_info: dict[str, Any] | None = None,
    whatsapp_info: dict[str, Any] | None = None,
    db: Any | None = None,
    job_id: str | None = None,
    schema_name: str | None = None,
    primary_model: str | None = None,
) -> dict[str, Any]:
    """Build a human-language, evidence-grounded answer."""
    relevant = _filter_relevant_chunks(query, chunks, top_k=8)
    special: dict[str, Any] | None = None
    q = query or ""

    # 1) Explicit document/file-type inventory (CSV/PDF/…)
    if document_info is not None:
        special = _answer_documents(document_info)

    # 1b) Axiom report sections (Media, OS, Documents, …) — "artifacts for X along with counts"
    if special is None and section_inventory is not None and (
        _OS_ARTIFACTS_INTENT.search(q)
        or _SECTION_INTENT.search(q)
        or re.search(
            r"\bartifacts?\b.*\b(operating\s+system|os|media|documents?|communication|"
            r"connected\s+devices|application\s+usages?)\b",
            q,
            re.I,
        )
        or re.search(
            r"\b(operating\s+system|os|media|documents?|communication|"
            r"connected\s+devices|application\s+usages?)\b.*\b(artifacts?|counts?)\b",
            q,
            re.I,
        )
    ):
        special = _answer_sections(q, section_inventory, defer_device_items=False)
        if special is None and _OS_ARTIFACTS_INTENT.search(q):
            os_sec = next(
                (s for s in (section_inventory.get("sections") or []) if s.get("key") == "operating_system"),
                None,
            )
            if os_sec:
                from app.services.artifact_sections import format_multi_section_answer

                special = {
                    "answer": format_multi_section_answer(
                        [{"level": "section", "section": os_sec, "item": None}],
                        usage_focus=False,
                        report_style=True,
                    ),
                    "confidence": "high",
                    "grounded": True,
                    "facts": {
                        "section_matches": [{"level": "section", "section": os_sec, "item": None}],
                        "section_match": {"level": "section", "section": os_sec, "item": None},
                        "sections": section_inventory,
                    },
                }
        if special is None and encyclopedia_category is not None:
            special = _answer_encyclopedia_category(encyclopedia_category)

    # 1c) Other encyclopedia category inventories (Registry, Browser, …)
    if special is None and encyclopedia_category is not None:
        special = _answer_encyclopedia_category(encyclopedia_category)

    # 2) Axiom section overview / named sections (Connected Devices, Documents, …)
    #    before USB intent — "connected devices" must mean the full section, not USB-only.
    if special is None and section_inventory is not None and (
        _SECTION_INTENT.search(q)
        or re.search(r"\b(axiom|artifact\s+sections?|b\.\s*artifacts)\b", q, re.I)
    ):
        special = _answer_sections(q, section_inventory, defer_device_items=False)

    # 3) Classic specialized intents
    if special is None and _COUNT_INTENT.search(q) and not _OS_ARTIFACTS_INTENT.search(q):
        special = _answer_artifact_count(inventory)
    elif special is None and (
        _PHONE_USAGE_INTENT.search(q)
        or (_PHONE_INTENT.search(q) and re.search(r"\b(used|times?|connected|plugged|usage)\b", q, re.I))
    ):
        special = _answer_phone(phone_info, usage_focus=True)
    elif special is None and _PHONE_INTENT.search(q):
        special = _answer_phone(phone_info, usage_focus=False)
    elif special is None and _USB_USAGE_INTENT.search(q):
        special = _answer_usb_usage(usb_usage, usb_devices)
    elif special is None and _USB_INTENT.search(q):
        special = _answer_usb(usb_devices, relevant or chunks)
    elif special is None and _WHATSAPP_INTENT.search(q):
        special = _answer_whatsapp(whatsapp_info)
    elif special is None and _EMAIL_INTENT.search(q):
        special = _answer_email(email_info)
    elif special is None and _BROWSER_INTENT.search(q):
        special = _answer_browser(browser_urls, relevant or chunks)
    elif special is None and _USER_INTENT.search(q):
        if db is not None and job_id:
            from app.services.identity_evidence_prompts import answer_users_with_prompt

            special = answer_users_with_prompt(
                db,
                job_id,
                q,
                schema_name=schema_name,
                primary_model=primary_model,
                output_format="qa",
            )
        else:
            special = _answer_users(query, relevant or chunks, account_timeline=account_timeline)
    elif special is None and _HARDWARE_INTENT.search(q) and not _OS_INTENT.search(q):
        if db is not None and job_id:
            from app.services.identity_evidence_prompts import answer_hardware_with_prompt

            special = answer_hardware_with_prompt(
                db,
                job_id,
                q,
                schema_name=schema_name,
                primary_model=primary_model,
                output_format="qa",
            )
        else:
            special = _answer_hardware(os_facts=os_facts)
    elif special is None and _OS_INTENT.search(q) and not _OS_ARTIFACTS_INTENT.search(q):
        if db is not None and job_id:
            from app.services.identity_evidence_prompts import answer_os_with_prompt

            special = answer_os_with_prompt(
                db,
                job_id,
                q,
                schema_name=schema_name,
                primary_model=primary_model,
                output_format="qa",
            )
        else:
            special = _answer_os(relevant or chunks, os_facts=os_facts)

    # 4) Fallback: any other Axiom catalog item (Defender, RDP, social URLs, programs, …)
    if special is None and section_inventory is not None:
        special = _answer_sections(q, section_inventory, defer_device_items=True)

    if not relevant and not special:
        return {
            "answer": (
                "No relevant evidence chunks matched this question with enough confidence. "
                "Try a more specific forensic question (for example: users on this laptop, "
                "USB devices, browser history, email PST files), or re-run RAG enrichment."
            ),
            "confidence": "none",
            "grounded": True,
            "items": [],
            "citations": [],
            "facts": {},
        }

    identity_intent = bool(
        (_OS_INTENT.search(q) and not _OS_ARTIFACTS_INTENT.search(q))
        or _USER_INTENT.search(q)
        or (_HARDWARE_INTENT.search(q) and not _OS_INTENT.search(q))
    )
    # Never let generic RAG (Favicons, etc.) overwrite structured OS/user/hardware answers.
    llm_text = None
    if (not special or special.get("confidence") == "low") and not (
        special and special.get("grounded") and identity_intent and (special.get("answer") or "").strip()
    ):
        if relevant:
            llm_text = _llm_answer(query, relevant)

    if special and special.get("confidence") in ("high", "medium"):
        answer = special["answer"]
        confidence = special["confidence"]
        facts = special.get("facts") or {}
    elif special and identity_intent and (special.get("answer") or "").strip():
        answer = special["answer"]
        confidence = special.get("confidence") or "low"
        facts = special.get("facts") or {}
    elif llm_text:
        answer = llm_text
        confidence = special.get("confidence") if special else "medium"
        facts = (special or {}).get("facts") or {}
    elif special:
        answer = special["answer"]
        confidence = special.get("confidence") or "low"
        facts = special.get("facts") or {}
    else:
        answer = _generic_grounded_summary(query, relevant)
        confidence = "medium"
        facts = {}

    citations = []
    items_out = relevant or []

    # For structured inventory answers, show matching files as evidence — not unrelated RAG hits.
    if special and special.get("confidence") in ("high", "medium") and document_info is not None:
        items_out = []
        citations = []
        for i, item in enumerate((document_info.get("items") or [])[:12], start=1):
            path = item.get("file_path") or ""
            size = item.get("size_bytes")
            excerpt = f"{document_info.get('label')}: {path}"
            if size is not None:
                excerpt += f" ({_format_bytes(size)})"
            row = {
                "id": f"doc-{i}",
                "file_path": path,
                "content": excerpt,
                "artifact_id": None,
                "chunk_type": "inventory",
                "score": 1.0,
            }
            items_out.append(row)
            citations.append(
                {
                    "id": row["id"],
                    "file_path": path,
                    "artifact_id": None,
                    "chunk_type": "inventory",
                    "score": 1.0,
                    "excerpt": excerpt,
                }
            )
    elif special and special.get("confidence") in ("high", "medium") and (special.get("facts") or {}).get(
        "encyclopedia_category"
    ):
        items_out = []
        citations = []
        info = (special.get("facts") or {}).get("encyclopedia_category") or {}
        for i, it in enumerate((info.get("items") or [])[:12], start=1):
            path = f"encyclopedia/{it.get('artifact_id')}"
            excerpt = f"{it.get('label')}: {int(it.get('count') or 0):,} files"
            row = {
                "id": f"enc-{i}",
                "file_path": path,
                "content": excerpt,
                "artifact_id": it.get("artifact_id"),
                "chunk_type": "encyclopedia",
                "score": 1.0,
            }
            items_out.append(row)
            citations.append(
                {
                    "id": row["id"],
                    "file_path": path,
                    "artifact_id": it.get("artifact_id"),
                    "chunk_type": "encyclopedia",
                    "score": 1.0,
                    "excerpt": excerpt,
                }
            )
    elif special and special.get("confidence") in ("high", "medium") and (
        (special.get("facts") or {}).get("section_matches")
        or (special.get("facts") or {}).get("section_match")
    ):
        items_out = []
        citations = []
        matches = (special.get("facts") or {}).get("section_matches") or []
        if not matches and (special.get("facts") or {}).get("section_match"):
            matches = [(special.get("facts") or {}).get("section_match")]
        samples: list[tuple[str, str]] = []
        for sm in matches:
            if not sm:
                continue
            if sm.get("item"):
                label = sm["item"].get("title") or "section"
                for s in sm["item"].get("samples") or []:
                    samples.append((label, s))
            else:
                for it in (sm.get("section") or {}).get("items") or []:
                    label = it.get("title") or (sm.get("section") or {}).get("title") or "section"
                    for s in (it.get("samples") or [])[:4]:
                        samples.append((label, s))
        for i, (label, path) in enumerate(samples[:12], start=1):
            excerpt = f"{label}: {path}"
            row = {
                "id": f"sec-{i}",
                "file_path": path,
                "content": excerpt,
                "artifact_id": None,
                "chunk_type": "section",
                "score": 1.0,
            }
            items_out.append(row)
            citations.append(
                {
                    "id": row["id"],
                    "file_path": path,
                    "artifact_id": None,
                    "chunk_type": "section",
                    "score": 1.0,
                    "excerpt": excerpt,
                }
            )
    else:
        for c in (relevant or chunks)[:6]:
            if str(c.get("content") or "").startswith("Graph related artifact"):
                continue
            citations.append(
                {
                    "id": str(c.get("id") or ""),
                    "file_path": c.get("file_path"),
                    "artifact_id": c.get("artifact_id"),
                    "chunk_type": c.get("chunk_type"),
                    "score": _score(c),
                    "excerpt": ((c.get("content") or "")[:280]),
                }
            )

    return {
        "answer": answer,
        "confidence": confidence,
        "grounded": True,
        "facts": facts,
        "items": items_out,
        "citations": citations,
        "total": len(items_out),
    }
