"""Prompt-only OS and Windows user answers from SAM / SYSTEM / Security.evtx evidence."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Literal

from app.config import get_settings
from app.db.sql_helpers import fetchall, fetchone
from app.retrieval.hybrid import hybrid_retrieve
from app.services.forensic_profile_index import (
    collect_account_timeline,
    collect_os_facts,
    ensure_critical_account_artifacts,
    ensure_os_fact_chunks,
    ensure_os_hive_parsed,
    ensure_profile_fact_chunks,
)
from app.services.model_router import generate_text

log = logging.getLogger("identity_evidence_prompts")

OS_CANONICAL_PROMPT = (
    "Provide operating system details in table format: Operating System, Version Number, "
    "Build Number, Computer Name, Install Date, Product Key, Product ID, Last Shutdown, System Root."
)

USER_CANONICAL_PROMPT = (
    "Which users use this laptop? List all Windows user accounts in table format with columns: "
    "Sr No, Username, Type of User, Profile Path, Last Local Login Date/Time, "
    "Last Password Change Date/Time. Use SAM, Security.evtx, ProfileList, and NTUSER evidence."
)

from app.services.critical_forensic_paths import CRITICAL_PATH_SQL as _CRITICAL_PATH_SQL


def _display_ts(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, dict):
        value = value.get("at") or value.get("timestamp")
    if not value:
        return "—"
    raw = str(value).strip()
    m = re.search(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", raw)
    if m:
        try:
            dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}")
            return dt.strftime("%d/%m/%Y %I:%M:%S %p")
        except ValueError:
            pass
    return raw[:40]


def _resolve_system_root(root: str | None) -> str:
    if not root or str(root).startswith("%"):
        return "C:\\Windows"
    return str(root)


def _infer_build_from_winsxs(db, job_id: str) -> str | None:
    rows = fetchall(
        db,
        """SELECT file_path FROM job_artifacts
           WHERE job_id=:jid AND file_path ILIKE '%10.0.%'
           LIMIT 200""",
        {"jid": job_id},
    )
    builds: set[int] = set()
    for row in rows:
        path = row.get("file_path") or ""
        for m in re.finditer(r"10\.0\.(\d{4,5})(?:\.|\b)", path):
            try:
                builds.add(int(m.group(1)))
            except ValueError:
                continue
    if not builds:
        return None
    return str(max(builds))


def merge_os_facts(db, job_id: str) -> dict[str, Any]:
    """Structured OS facts for prompt hints (never returned directly as the answer)."""
    try:
        ensure_os_hive_parsed(db, job_id)
        ensure_os_fact_chunks(db, job_id, refresh_hives=False)
        db.flush()
    except Exception as exc:
        log.warning("OS fact refresh failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass

    facts: dict[str, Any] = dict(collect_os_facts(db, job_id))

    chunk = fetchone(
        db,
        """SELECT content, metadata FROM rag_chunks
           WHERE job_id=:jid AND file_path='__forensic__/windows_os' LIMIT 1""",
        {"jid": job_id},
    )
    if chunk:
        meta = chunk.get("metadata")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = {}
        if isinstance(meta, dict):
            for k, v in meta.items():
                if k != "kind" and v and not facts.get(k):
                    facts[k] = v

    if not facts.get("current_build") and not facts.get("build_number"):
        winsxs = _infer_build_from_winsxs(db, job_id)
        if winsxs:
            facts["build_number"] = winsxs
            facts.setdefault("current_build", winsxs)

    if not facts.get("product_name") and facts.get("os_env") == "Windows_NT":
        build = facts.get("build_number") or facts.get("current_build") or ""
        edition = facts.get("edition_id") or facts.get("display_version") or ""
        try:
            major = int(str(build)[:5]) if build else 0
        except ValueError:
            major = 0
        if major >= 22000:
            facts["product_name"] = f"Windows 11{(' ' + edition) if edition else ''}".strip()
        elif build or edition:
            facts["product_name"] = f"Windows{(' ' + edition) if edition else ''}".strip()

    build = facts.get("current_build") or facts.get("build_number")
    if build and facts.get("ubr") and "." not in str(build):
        facts["build_number"] = f"{build}.{facts['ubr']}"
    elif build and not facts.get("build_number"):
        facts["build_number"] = str(build)

    if facts.get("system_root"):
        facts["system_root"] = _resolve_system_root(str(facts["system_root"]))

    for key in ("last_shutdown", "install_time", "install_date"):
        if facts.get(key):
            facts[key] = _display_ts(facts[key])

    pk = facts.get("product_key") or facts.get("product_key_alt")
    if pk:
        facts["product_key"] = pk

    return facts


def _dump_parse_evidence(db, job_id: str, *, record_types: set[str] | None = None, limit: int = 80) -> str:
    rows = fetchall(
        db,
        f"""SELECT ja.file_path, apr.normalized
            FROM job_artifacts ja
            JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
            WHERE ja.job_id=:jid AND ({_CRITICAL_PATH_SQL})
            ORDER BY ja.file_path, apr.created_at DESC""",
        {"jid": job_id},
    )
    lines: list[str] = []
    seen = 0
    for row in rows:
        path = row.get("file_path") or ""
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict):
                continue
            rtype = rec.get("record_type") or ""
            if record_types and rtype not in record_types:
                continue
            lines.append(f"[{path}] {json.dumps(rec, default=str)[:900]}")
            seen += 1
            if seen >= limit:
                return "\n".join(lines)
    return "\n".join(lines)


def gather_identity_evidence_context(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    mode: Literal["os", "user", "both"] = "both",
) -> str:
    """Collect parsed hive/EVTX + forensic chunks + hybrid retrieval for LLM prompts."""
    blocks: list[str] = []

    if mode in ("user", "both"):
        try:
            ensure_critical_account_artifacts(db, job_id)
            ensure_profile_fact_chunks(db, job_id, refresh_critical=False)
            db.flush()
        except Exception as exc:
            log.warning("User evidence refresh failed: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass

    if mode in ("os", "both"):
        try:
            ensure_os_hive_parsed(db, job_id)
            ensure_os_fact_chunks(db, job_id, refresh_hives=False)
            db.flush()
        except Exception as exc:
            log.warning("OS evidence refresh failed: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass

    for path in ("__forensic__/windows_os", "__forensic__/windows_user_profiles"):
        if mode == "os" and path.endswith("user_profiles"):
            continue
        if mode == "user" and path.endswith("windows_os"):
            continue
        chunk = fetchone(
            db,
            """SELECT file_path, content FROM rag_chunks
               WHERE job_id=:jid AND file_path=:path LIMIT 1""",
            {"jid": job_id, "path": path},
        )
        if chunk and chunk.get("content"):
            blocks.append(f"=== Forensic summary [{path}] ===\n{(chunk['content'] or '')[:4000]}")

    if mode in ("user", "both"):
        sam_dump = _dump_parse_evidence(
            db, job_id,
            record_types={"sam_user", "profile_list", "security_event", "ntuser_hive"},
            limit=60,
        )
        if sam_dump:
            blocks.append(f"=== Parsed SAM / ProfileList / Security.evtx / NTUSER ===\n{sam_dump}")

        timeline = collect_account_timeline(db, job_id)
        if timeline:
            blocks.append(
                "=== Merged account timeline ===\n"
                + json.dumps(timeline, indent=2, default=str)[:5000]
            )

    if mode in ("os", "both"):
        os_dump = _dump_parse_evidence(
            db, job_id,
            record_types={
                "windows_os", "computer_name", "system_root", "last_shutdown",
                "system_path", "system_directory", "system_environment",
            },
            limit=40,
        )
        if os_dump:
            blocks.append(f"=== Parsed SOFTWARE / SYSTEM OS records ===\n{os_dump}")

        facts = merge_os_facts(db, job_id)
        if facts:
            blocks.append(
                "=== Extracted OS fact hints ===\n"
                + "\n".join(f"- {k}: {v}" for k, v in facts.items() if v)
            )

    query = OS_CANONICAL_PROMPT if mode == "os" else USER_CANONICAL_PROMPT
    if mode == "both":
        query = f"{OS_CANONICAL_PROMPT} {USER_CANONICAL_PROMPT}"

    try:
        chunks = hybrid_retrieve(
            db, job_id, query, top_k=14, schema_name=schema_name, skip_vector=True,
        )
        rag_bits = [
            f"[{c.get('file_path')}] {(c.get('content') or '')[:1400]}"
            for c in chunks[:12]
        ]
        if rag_bits:
            blocks.append("=== Related indexed evidence ===\n" + "\n\n".join(rag_bits))
    except Exception as exc:
        log.warning("Hybrid retrieve for identity evidence failed: %s", exc)

    return "\n\n".join(blocks)[:24000]


def _os_qa_system() -> str:
    return (
        "You are a digital forensics assistant. Answer ONLY using the supplied evidence. "
        "Output a single markdown table — no preamble, no notes after the table unless a field is "
        "genuinely absent from all evidence (use — for that cell). "
        "Do NOT invent product keys, build numbers, or version strings. "
        "Prefer SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion and SYSTEM hive values over file paths. "
        "Resolve %SystemRoot% to C:\\Windows when no literal path exists."
    )


def _user_qa_system() -> str:
    return (
        "You are a digital forensics assistant. Answer ONLY using the supplied evidence. "
        "List EVERY account in SAM (Administrator, Guest, DefaultAccount, WDAGUtilityAccount, "
        "local users, and domain/Microsoft accounts from Security.evtx). "
        "Include built-in service profiles when ProfileList evidence shows them. "
        "Output a single markdown table — no preamble. "
        "Format timestamps as DD/MM/YYYY H:MM:SS AM/PM when available; otherwise —. "
        "Do NOT invent accounts or dates."
    )


def _os_report_system() -> str:
    return (
        "You are a forensic examiner drafting an Aetheris report section. "
        "Use ONLY supplied evidence. Output markdown starting with the table header row only "
        "(Sr No | Artifacts Details | Value) followed by exactly 10 data rows. "
        "No conversational text. Use — for unknown fields."
    )


def _user_report_system() -> str:
    return (
        "You are a forensic examiner drafting an Aetheris USER PROFILE section. "
        "Use ONLY supplied evidence. Output markdown table rows with columns: "
        "Sr No | Username | Type of User | Profile Path | Last Local Login Date/Time | "
        "Last Password Change Date/Time. Include all SAM accounts and built-in profiles from evidence. "
        "Type of User: Local User, Built-in, Domain / Microsoft Account, or Administrator. "
        "No conversational preamble."
    )


def _clean_llm_table(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    fence = re.search(r"```(?:markdown)?\s*\n([\s\S]*?)```", text, re.I)
    if fence:
        text = fence.group(1).strip()
    lines = [ln for ln in text.splitlines() if ln.strip().startswith("|")]
    if not lines:
        return text
    return "\n".join(lines)


def _table_data_rows(answer: str) -> list[str]:
    rows: list[str] = []
    for ln in answer.splitlines():
        if not ln.strip().startswith("|"):
            continue
        if re.search(r"^\|\s*[-: ]+\|", ln):
            continue
        if re.search(r"\b(Sr No|Username|Operating System|Artifacts Details)\b", ln, re.I):
            continue
        rows.append(ln)
    return rows


def _count_filled_cells(row: str) -> int:
    cells = [c.strip() for c in row.strip("|").split("|")]
    return sum(
        1 for c in cells
        if c and c not in {"—", "-", "N/A", "n/a", "not found", "unknown"}
    )


def _score_os_confidence(answer: str) -> str:
    rows = _table_data_rows(answer)
    if not rows:
        return "low"
    filled = max((_count_filled_cells(r) for r in rows), default=0)
    if filled >= 5:
        return "high"
    if filled >= 3:
        return "medium"
    return "low"


def _score_user_confidence(answer: str) -> str:
    rows = _table_data_rows(answer)
    if len(rows) >= 5:
        return "high"
    if len(rows) >= 2:
        return "medium"
    return "low"


def collect_sam_accounts_raw(db, job_id: str) -> list[dict[str, Any]]:
    """All SAM accounts including Guest / DefaultAccount (no profile-folder filter)."""
    rows = fetchall(
        db,
        """SELECT apr.normalized FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid AND ja.file_path ILIKE '%/config/SAM'""",
        {"jid": job_id},
    )
    accounts: dict[str, dict[str, Any]] = {}
    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if not isinstance(rec, dict) or rec.get("record_type") != "sam_user":
                continue
            name = (rec.get("username") or "").strip()
            if not name or name == "-":
                continue
            key = name.lower()
            bucket = accounts.setdefault(key, {"username": name})
            for field in ("rid", "sid", "last_logon", "password_last_set", "last_logoff"):
                if rec.get(field) and not bucket.get(field):
                    bucket[field] = rec[field]
    timeline = collect_account_timeline(db, job_id)
    for key, acct in accounts.items():
        tl = timeline.get(acct["username"]) or timeline.get(key)
        if tl:
            for field in ("last_logon", "password_last_set", "profile_path", "sid"):
                if tl.get(field) and not acct.get(field):
                    acct[field] = tl[field]
    for name, tl in timeline.items():
        key = name.lower()
        if key not in accounts:
            accounts[key] = dict(tl)
    return sorted(accounts.values(), key=lambda a: (a.get("username") or "").lower())


def _os_core_fact_count(facts: dict[str, Any]) -> int:
    keys = (
        "product_name", "computer_name", "build_number", "current_build",
        "last_shutdown", "system_root", "version_number", "display_version",
    )
    return sum(1 for k in keys if facts.get(k))


def _os_answer_matches_facts(answer: str, facts: dict[str, Any]) -> bool:
    if not facts.get("computer_name"):
        return True
    expected = str(facts["computer_name"]).lower()
    return expected in answer.lower()


def answer_os_with_prompt(
    db,
    job_id: str,
    query: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    output_format: Literal["qa", "report"] = "qa",
) -> dict[str, Any]:
    settings = get_settings()
    model = primary_model or settings.llm_fast_model
    facts = merge_os_facts(db, job_id)
    known = "\n".join(f"- {k}: {v}" for k, v in facts.items() if v)

    if _os_core_fact_count(facts) >= 2 or (
        facts.get("product_name") or facts.get("computer_name")
    ):
        answer = _fallback_os_table(facts, output_format)
        conf = "high" if _os_core_fact_count(facts) >= 4 else "medium"
        return {
            "answer": answer,
            "confidence": conf,
            "grounded": True,
            "facts": {"os": facts, "prompt": OS_CANONICAL_PROMPT},
        }

    context = gather_identity_evidence_context(db, job_id, schema_name=schema_name, mode="os")

    if output_format == "report":
        user_prompt = f"""Complete the OPERATING SYSTEM INFORMATION table for an Aetheris forensic report.

Required rows (Sr No | Artifacts Details | Value):
1 Operating System
2 Version Number
3 Installed/Updated Date/Time
4 Product Key
5 Computer Name
6 Operating System Version
7 Build Number
8 Product ID
9 Last Shutdown Date/Time
10 System Root

Extracted fact hints:
{known or 'None'}

EVIDENCE:
{context}

Output ONLY markdown table rows (| Sr No | Artifacts Details | Value |)."""
        system = _os_report_system()
    else:
        user_prompt = f"""{OS_CANONICAL_PROMPT}

Extracted fact hints (prefer these when consistent with evidence):
{known or 'None'}

EVIDENCE:
{context}

Output ONLY one markdown table with columns:
| Operating System | Version Number | Build Number | Computer Name | Install Date | Product Key | Product ID | Last Shutdown | System Root |"""
        system = _os_qa_system()

    raw = generate_text(user_prompt, model=model, system=system, temperature=0.05)
    answer = _clean_llm_table(raw or "")
    rows = _table_data_rows(answer)
    if (
        not answer
        or answer.startswith("[Model ")
        or not rows
        or _count_filled_cells(rows[0]) < 3
        or not _os_answer_matches_facts(answer, facts)
    ):
        answer = _fallback_os_table(facts, output_format)
        conf = "medium" if _table_data_rows(answer) else "low"
    else:
        conf = _score_os_confidence(answer)

    return {
        "answer": answer,
        "confidence": conf,
        "grounded": True,
        "facts": {"os": facts, "prompt": OS_CANONICAL_PROMPT},
    }


def answer_users_with_prompt(
    db,
    job_id: str,
    query: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    output_format: Literal["qa", "report"] = "qa",
) -> dict[str, Any]:
    settings = get_settings()
    model = primary_model or settings.llm_fast_model

    # Prefer already-parsed SAM rows — avoid expensive critical-path reparse checks on every ask.
    sam_accounts = collect_sam_accounts_raw(db, job_id)
    if len(sam_accounts) < 1:
        try:
            ensure_critical_account_artifacts(db, job_id)
            db.flush()
        except Exception as exc:
            log.warning("User evidence refresh failed: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass
        sam_accounts = collect_sam_accounts_raw(db, job_id)

    if len(sam_accounts) >= 1:
        answer = _fallback_user_table(sam_accounts, output_format, db=db, job_id=job_id)
        return {
            "answer": answer,
            "confidence": _score_user_confidence(answer) if len(sam_accounts) >= 2 else "medium",
            "grounded": True,
            "facts": {"accounts": sam_accounts, "prompt": USER_CANONICAL_PROMPT},
        }

    context = gather_identity_evidence_context(db, job_id, schema_name=schema_name, mode="user")
    timeline = collect_account_timeline(db, job_id)

    if output_format == "report":
        user_prompt = f"""{USER_CANONICAL_PROMPT}

Also include Type of User and Profile Path columns (Aetheris report format).

SAM accounts ({len(sam_accounts)}):
{json.dumps(sam_accounts, indent=2, default=str)[:5000]}

EVIDENCE:
{context}

Output ONLY markdown table rows:
| Sr No | Username | Type of User | Profile Path | Last Local Login Date/Time | Last Password Change Date/Time |"""
        system = _user_report_system()
    else:
        user_prompt = f"""{USER_CANONICAL_PROMPT}

SAM accounts ({len(sam_accounts)}):
{json.dumps(sam_accounts, indent=2, default=str)[:5000]}

EVIDENCE:
{context}

Output ONLY one markdown table:
| Username | Last Logon Date | Last Password Change Date |"""
        system = _user_qa_system()

    raw = generate_text(user_prompt, model=model, system=system, temperature=0.05)
    answer = _clean_llm_table(raw or "")
    rows = _table_data_rows(answer)
    min_rows = 2 if output_format == "qa" else 3
    if not answer or answer.startswith("[Model ") or len(rows) < min_rows:
        answer = _fallback_user_table(sam_accounts or list(timeline.values()), output_format, db=db, job_id=job_id)
        conf = _score_user_confidence(answer)
    else:
        conf = _score_user_confidence(answer)

    return {
        "answer": answer,
        "confidence": conf,
        "grounded": True,
        "facts": {"accounts": sam_accounts or timeline, "prompt": USER_CANONICAL_PROMPT},
    }


def _fallback_os_table(facts: dict[str, Any], output_format: Literal["qa", "report"]) -> str:
    if output_format == "report":
        lines = ["| Sr No | Artifacts Details | Value |", "| ---: | --- | --- |"]
        report_rows = [
            ("Operating System", facts.get("product_name")),
            ("Version Number", facts.get("version_number") or facts.get("display_version")),
            ("Installed/Updated Date/Time", facts.get("install_time") or facts.get("install_date")),
            ("Product Key", facts.get("product_key")),
            ("Computer Name", facts.get("computer_name")),
            (
                "Operating System Version",
                facts.get("current_version") or facts.get("display_version") or facts.get("edition_id"),
            ),
            ("Build Number", facts.get("build_number") or facts.get("current_build")),
            ("Product ID", facts.get("product_id")),
            ("Last Shutdown Date/Time", facts.get("last_shutdown")),
            ("System Root", facts.get("system_root")),
        ]
        for i, (label, val) in enumerate(report_rows, 1):
            lines.append(f"| {i} | {label} | {val if val else '—'} |")
        return "\n".join(lines)

    header = (
        "| Operating System | Version Number | Build Number | Computer Name | Install Date | "
        "Product Key | Product ID | Last Shutdown | System Root |"
    )
    sep = "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    vals = [
        facts.get("product_name") or "—",
        facts.get("version_number") or facts.get("display_version") or "—",
        facts.get("build_number") or facts.get("current_build") or "—",
        facts.get("computer_name") or "—",
        facts.get("install_time") or facts.get("install_date") or "—",
        facts.get("product_key") or "—",
        facts.get("product_id") or "—",
        facts.get("last_shutdown") or "—",
        facts.get("system_root") or "—",
    ]
    return "\n".join([header, sep, "| " + " | ".join(str(v) for v in vals) + " |"])


HARDWARE_CANONICAL_PROMPT = (
    "Provide hardware information in table format: Processor, Architecture, CPU Count, Computer Name."
)


def merge_hardware_facts(db, job_id: str) -> dict[str, Any]:
    """Hardware facts from SYSTEM hive environment and related registry evidence."""
    facts = merge_os_facts(db, job_id)
    return {
        "processor": facts.get("processor_identifier"),
        "architecture": facts.get("processor_architecture"),
        "cpu_count": facts.get("number_of_processors"),
        "computer_name": facts.get("computer_name"),
        "system_root": facts.get("system_root"),
    }


def _fallback_hardware_table(facts: dict[str, Any], output_format: Literal["qa", "report"]) -> str:
    if output_format == "report":
        lines = ["| Sr No | Artifacts Details | Value |", "| ---: | --- | --- |"]
        rows = [
            ("Processor", facts.get("processor")),
            ("Architecture", facts.get("architecture")),
            ("CPU Count", facts.get("cpu_count")),
            ("Computer Name", facts.get("computer_name")),
        ]
        for i, (label, val) in enumerate(rows, 1):
            lines.append(f"| {i} | {label} | {val if val else '—'} |")
        return "\n".join(lines)

    header = "| Processor | Architecture | CPU Count | Computer Name |"
    sep = "| --- | --- | --- | --- |"
    vals = [
        facts.get("processor") or "—",
        facts.get("architecture") or "—",
        facts.get("cpu_count") or "—",
        facts.get("computer_name") or "—",
    ]
    return "\n".join([header, sep, "| " + " | ".join(str(v) for v in vals) + " |"])


def answer_hardware_with_prompt(
    db,
    job_id: str,
    query: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    output_format: Literal["qa", "report"] = "qa",
) -> dict[str, Any]:
    settings = get_settings()
    model = primary_model or settings.llm_fast_model
    try:
        ensure_os_hive_parsed(db, job_id)
        ensure_os_fact_chunks(db, job_id, refresh_hives=False)
        db.flush()
    except Exception as exc:
        log.warning("Hardware evidence refresh failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass

    facts = {k: v for k, v in merge_hardware_facts(db, job_id).items() if v}
    known = "\n".join(f"- {k}: {v}" for k, v in facts.items())

    if facts.get("processor") or facts.get("architecture"):
        answer = _fallback_hardware_table(facts, output_format)
        return {
            "answer": answer,
            "confidence": "high" if facts.get("processor") else "medium",
            "grounded": True,
            "facts": {"hardware": facts, "prompt": HARDWARE_CANONICAL_PROMPT},
        }

    context = gather_identity_evidence_context(db, job_id, schema_name=schema_name, mode="os")
    user_prompt = f"""{HARDWARE_CANONICAL_PROMPT}

Extracted fact hints:
{known or 'None'}

EVIDENCE:
{context}

Output ONLY one markdown table with columns:
| Processor | Architecture | CPU Count | Computer Name |"""
    raw = generate_text(
        user_prompt,
        model=model,
        system=(
            "You are a forensic examiner assistant. Answer ONLY from evidence. "
            "Output a single markdown table for hardware identity fields."
        ),
        temperature=0.05,
    )
    answer = _clean_llm_table(raw or "")
    rows = _table_data_rows(answer)
    if not answer or answer.startswith("[Model ") or not rows:
        answer = _fallback_hardware_table(facts, output_format)
        conf = "medium" if _table_data_rows(answer) else "low"
    else:
        conf = "medium" if facts else "low"

    return {
        "answer": answer,
        "confidence": conf,
        "grounded": True,
        "facts": {"hardware": facts, "prompt": HARDWARE_CANONICAL_PROMPT},
    }


def _user_type(username: str) -> str:
    low = (username or "").lower()
    if low in ("administrator", "admin"):
        return "Built-in / Administrator"
    if low in ("guest", "defaultaccount", "wdagutilityaccount"):
        return "Local User"
    if "@" in username:
        return "Domain / Microsoft Account"
    if low in ("system", "local service", "network service"):
        return "Built-in"
    return "Local User"


def _profile_path_for(db, job_id: str, username: str, acct: dict[str, Any]) -> str:
    if acct.get("profile_path"):
        return str(acct["profile_path"])
    row = fetchone(
        db,
        """SELECT 1 FROM job_artifacts
           WHERE job_id=:jid AND file_path ILIKE :path LIMIT 1""",
        {"jid": job_id, "path": f"Users/{username}/%"},
    )
    if row:
        return f"C:\\Users\\{username}"
    low = (username or "").lower()
    if low in ("system",):
        return "%systemroot%\\system32\\config\\systemprofile"
    if low in ("network service",):
        return "%systemroot%\\ServiceProfiles\\NetworkService"
    if low in ("local service",):
        return "%systemroot%\\ServiceProfiles\\LocalService"
    return "—"


def _fallback_user_table(
    accounts: list[dict[str, Any]] | dict[str, dict],
    output_format: Literal["qa", "report"],
    *,
    db=None,
    job_id: str | None = None,
) -> str:
    if isinstance(accounts, dict):
        account_list = sorted(accounts.values(), key=lambda a: (a.get("username") or "").lower())
    else:
        account_list = list(accounts)

    account_list = [
        a for a in account_list
        if (a.get("username") or "").strip() and (a.get("username") or "").strip() != "-"
    ]

    if not account_list:
        return (
            "**Insufficient evidence** — no Windows user accounts were recovered from SAM, "
            "Security.evtx, ProfileList, or NTUSER evidence."
        )

    if output_format == "report":
        lines = [
            "| Sr No | Username | Type of User | Profile Path | Last Local Login Date/Time | Last Password Change Date/Time |",
            "| ---: | --- | --- | --- | --- | --- |",
        ]
        for i, acct in enumerate(account_list, 1):
            name = acct.get("username") or "—"
            profile = acct.get("profile_path") or "—"
            if db and job_id and profile == "—":
                profile = _profile_path_for(db, job_id, name, acct)
            lines.append(
                f"| {i} | {name} | {_user_type(name)} | {profile} | "
                f"{_display_ts(acct.get('last_logon'))} | {_display_ts(acct.get('password_last_set'))} |"
            )
        return "\n".join(lines)

    lines = [
        "| Username | Last Logon Date | Last Password Change Date |",
        "| --- | --- | --- |",
    ]
    for acct in account_list:
        name = acct.get("username") or "—"
        lines.append(
            f"| {name} | {_display_ts(acct.get('last_logon'))} | "
            f"{_display_ts(acct.get('password_last_set'))} |"
        )
    return "\n".join(lines)


def build_os_report_section(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
) -> str:
    intro = """## A. OPERATING SYSTEM

### 1. OPERATING SYSTEM INFORMATION

This refers to details about the installed OS (Windows, macOS, Linux, etc.), including version, system settings, user accounts, boot logs, and configurations.

| Sr No | Artifacts Details | Value |
| ---: | --- | --- |"""
    result = answer_os_with_prompt(
        db, job_id, OS_CANONICAL_PROMPT,
        schema_name=schema_name, primary_model=primary_model, output_format="report",
    )
    body = result["answer"]
    if body.startswith("##"):
        return body
    table_rows = [ln for ln in body.splitlines() if ln.strip().startswith("|")]
    data_rows = [
        ln for ln in table_rows
        if "---" not in ln and not ("Sr No" in ln and "Artifacts Details" in ln)
    ]
    if not data_rows:
        return intro + "\n" + body
    return intro + "\n" + "\n".join(data_rows)


def build_user_report_section(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
) -> str:
    intro = """## A. OPERATING SYSTEM

### 2. USER PROFILE

The User Profile contains key information about individuals who have used the computer. It includes the name of the user, the type of account they used, where their personal data is stored, when they last accessed the device, and when their password was last changed.

**Status:** All user profile information was examined to determine the users present on the system, the nature of their accounts, and their most recent activity.

| Sr No | Username | Type of User | Profile Path | Last Local Login Date/Time | Last Password Change Date/Time |
| ---: | --- | --- | --- | --- | --- |"""
    result = answer_users_with_prompt(
        db, job_id, USER_CANONICAL_PROMPT,
        schema_name=schema_name, primary_model=primary_model, output_format="report",
    )
    body = result["answer"]
    if "### 2. USER PROFILE" in body:
        return body.strip()
    table_rows = [ln for ln in body.splitlines() if ln.strip().startswith("|")]
    data_rows = [r for r in table_rows if "Username" not in r and "---" not in r]
    if not data_rows:
        return body if "Insufficient evidence" in body else intro + "\n" + body
    if table_rows and "Sr No" in table_rows[0]:
        data_rows = [r for r in table_rows if "Sr No" not in r and "---" not in r]
    return intro + "\n" + "\n".join(data_rows)
