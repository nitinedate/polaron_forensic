"""Forensic report generation — evidence-backed sections with intake objectives and artifact scope."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.config import get_settings
from app.db.session import apply_firm_search_path
from app.db.sql_helpers import execute, fetchall, fetchone
from app.retrieval.hybrid import hybrid_retrieve
from app.retrieval.query_understand import understand_query
from app.services.model_router import generate_text, select_section_models
from app.services.report_evidence import gather_structured_section
from app.services.report_renderer import section_order_for_report_type, section_title

log = logging.getLogger("report_generator")

GRADE_MAP = {"A": 0.95, "B": 0.8, "C": 0.65, "D": 0.45, "E": 0.25}
GRADE_ORDER = {"A": 5, "B": 4, "C": 3, "D": 2, "E": 1}

_section_progress: dict[str, dict] = {}
_progress_column_ready = False


def ensure_report_run_progress_schema(db) -> None:
    """Add report_runs.progress jsonb for live section progress across API/worker processes."""
    global _progress_column_ready
    if _progress_column_ready:
        return
    try:
        execute(
            db,
            "ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS progress jsonb",
        )
        for column in ('progress_at timestamptz','operation_deadline timestamptz'):
            execute(db,f'ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS {column}')
        db.flush()
        _progress_column_ready = True
    except Exception as exc:
        log.warning("ensure report_runs.progress failed: %s", exc)


def _set_run_progress(
    db,
    report_run_id: str | None,
    *,
    section_key: str,
    section_index: int,
    total_sections: int,
    stage: str,
    primary_model: str | None = None,
    review_model: str | None = None,
    confidence_grade: str | None = None,
    detail: str | None = None,
    sub_index: int | None = None,
    sub_total: int | None = None,
) -> dict[str, Any]:
    """Persist current section so the API SSE stream can show live progress."""
    payload: dict[str, Any] = {
        "section_key": section_key,
        "section_index": section_index,
        "total_sections": total_sections,
        "stage": stage,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if primary_model:
        payload["primary_model"] = primary_model
    if review_model:
        payload["review_model"] = review_model
    if confidence_grade:
        payload["confidence_grade"] = confidence_grade
    if detail:
        payload["detail"] = str(detail)[:240]
    if sub_index is not None:
        payload["sub_index"] = int(sub_index)
    if sub_total is not None:
        payload["sub_total"] = int(sub_total)
    if report_run_id:
        _section_progress[report_run_id] = payload
        try:
            ensure_report_run_progress_schema(db)
            execute(
                db,
                """UPDATE report_runs SET progress_at=CASE
                    WHEN (progress-'updated_at') IS DISTINCT FROM (CAST(:pp AS jsonb)-'updated_at') THEN NOW() ELSE progress_at END,
                    operation_deadline=CASE WHEN (progress-'updated_at') IS DISTINCT FROM (CAST(:pp AS jsonb)-'updated_at')
                    THEN NOW()+INTERVAL '330 seconds' ELSE operation_deadline END,
                    progress=CAST(:pp AS jsonb) WHERE id=:id""",
                {"id": report_run_id, "pp": json.dumps(payload)},
            )
            db.commit()
        except Exception as exc:
            log.warning("persist report progress failed run=%s: %s", report_run_id, exc)
            try:
                db.rollback()
            except Exception:
                pass
    return payload


# Sections rendered from Aetheris template + structured evidence (no generic RAG draft).
_TEMPLATE_SECTIONS = frozenset({
    "cover_page",
    "table_of_contents",
    "introduction",
    "scope_of_work",
    "tools_used",
    "forensic_imaging",
    "artifact_summary",
    "suspicious_activity",
    "annexure",
    "final_analysis_summary",
    "appendix",
})

# Sections filled via forensic profile index + section prompts (OS / users).
_PROMPT_PROFILE_SECTIONS = frozenset({"os_information", "user_profile_information"})

# Mobile report sections — prompt + RAG from indexed extraction (host evidence IO).
_MOBILE_PROMPT_SECTIONS = frozenset({"device_information", "extraction_summary"})

# Only section where LLM augments template content (Observation paragraphs).
_LLM_OBSERVATION_SECTION = "objectives_procedure_observation"

_SECTION_RETRIEVAL_HINTS: dict[str, str] = {
    "user_profile_information": (
        "Windows user accounts SAM Security.evtx ProfileList NTUSER last logon password change"
    ),
    "os_information": (
        "operating system version build computer name install date product key SYSTEM SOFTWARE registry"
    ),
    "artifact_summary": "forensic artifact inventory counts selected examination scope",
    "objectives_procedure_observation": "examination objective procedure observation findings mobile chat media",
    "device_information": "mobile device manufacturer model android build.prop serial IMEI",
    "extraction_summary": "mobile extraction hash SHA256 file counts images audio whatsapp",
    "annexure": "social media URLs web chat URLs malware phishing browser history samples",
    "introduction": "case background scope subject organization seizure",
    "scope_of_work": "scope of work objectives procedures examination request",
    "evidence_details": "evidence imaging hash chain of custody disk source",
    "forensic_imaging": "forensic imaging acquisition write blocker hash verification",
}


def get_section_progress(report_run_id: str) -> dict | None:
    return _section_progress.get(report_run_id)


def _intake_ready(db, job_id: str) -> tuple[bool, list[str]]:
    from app.services.mobile_report_service import is_mobile_intake

    row = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    missing: list[str] = []
    if not row:
        return False, ["subjects", "case_type", "report_type", "objectives"]
    subjects = row.get("subjects") or []
    if isinstance(subjects, str):
        subjects = json.loads(subjects)
    if not subjects:
        missing.append("subjects")
    if not row.get("case_type"):
        missing.append("case_type")
    if not row.get("report_type"):
        missing.append("report_type")
    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    # Mobile forensic reports (Sujit / Vivo sample) do not require selected objectives.
    if is_mobile_intake(dict(row), job):
        return len(missing) == 0, missing
    objs = row.get("objective_ids") or []
    if isinstance(objs, str):
        objs = json.loads(objs)
    custom = row.get("custom_objectives") or []
    if isinstance(custom, str):
        custom = json.loads(custom)
    if not objs and not custom:
        missing.append("objectives")
    return len(missing) == 0, missing


def _build_retrieval_query(section_key: str, intake: dict) -> str:
    from app.services.mobile_report_service import is_mobile_intake

    hint = _SECTION_RETRIEVAL_HINTS.get(section_key) or section_title(section_key)
    if section_key == "objectives_procedure_observation" and is_mobile_intake(intake):
        hint = (
            "mobile forensic objective procedure observation whatsapp sms chat messages "
            "calls photos videos accounts applications Android iOS extraction findings"
        )
    base = f"{hint} forensic report section for {intake.get('report_type', 'investigation')}"
    understood = understand_query(base)
    filters = understood.get("filters") or {}
    if filters.get("category"):
        base += f" {filters['category']}"
    if filters.get("os"):
        base += f" {filters['os']}"
    return base


def _extract_citations(content: str, chunks: list[dict]) -> list[dict]:
    cites: list[dict] = []
    for c in chunks[:10]:
        aid = c.get("artifact_id")
        cid = str(c.get("id")) if c.get("id") else None
        if aid and str(aid) in content:
            cites.append({"artifact_id": aid, "file_path": c.get("file_path"), "chunk_id": cid})
        elif cid and cid in content:
            cites.append({"artifact_id": aid, "file_path": c.get("file_path"), "chunk_id": cid})
    if not cites and chunks:
        c0 = chunks[0]
        cites.append({
            "artifact_id": c0.get("artifact_id"),
            "file_path": c0.get("file_path"),
            "chunk_id": str(c0.get("id")) if c0.get("id") else None,
        })
    return cites


def validate_citations(content: str, chunks: list[dict], citations: list[dict]) -> tuple[bool, list[str]]:
    issues: list[str] = []
    valid_aids = {str(c.get("artifact_id")) for c in chunks if c.get("artifact_id")}
    cited_aids = {str(c.get("artifact_id")) for c in citations if c.get("artifact_id")}
    if chunks and not cited_aids and valid_aids:
        issues.append("No artifact IDs cited despite available evidence")
    return len(issues) == 0, issues


def _confidence_grade(chunks: list[dict], citations: list[dict], citation_valid: bool) -> str:
    if not chunks and not citations:
        return "C"
    if not citation_valid:
        return "D"
    if len(citations) >= 2:
        return "A"
    if len(citations) == 1:
        return "B"
    return "C"


def _structured_evidence(
    section_key: str, db, job_id: str, intake: dict, *, schema_name: str | None = None,
) -> tuple[str, dict[str, Any] | None]:
    return gather_structured_section(section_key, db, job_id, intake, schema_name=schema_name)


def _fill_objective_observations(
    template_md: str,
    db,
    job_id: str,
    intake: dict,
    *,
    schema_name: str,
    primary_model: str,
    progress_cb=None,
) -> str:
    from app.services.mobile_report_service import is_mobile_intake
    from app.services.report_objectives_observation_service import fill_objective_observations
    from app.services.report_template import _device_label
    from app.services.report_template_service import resolve_report_objectives

    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    # Mobile: always a single Objective/Procedure + LLM findings (never catalog objectives).
    if is_mobile_intake(intake, job):
        if primary_model:
            return _polish_mobile_findings(
                template_md,
                db,
                job_id,
                intake,
                schema_name=schema_name,
                primary_model=primary_model,
            )
        return template_md

    objectives = resolve_report_objectives(db, job_id, intake)
    if not objectives:
        return template_md

    device = _device_label(intake, job)
    return fill_objective_observations(
        db,
        job_id,
        intake,
        objectives,
        schema_name=schema_name,
        primary_model=primary_model,
        device_label=device,
        polish_with_llm=bool(primary_model),
        progress_cb=progress_cb,
    )


_NOISE_PATH_RE = re.compile(
    r"(?i)(indexeddb|leveldb|\.ldb\b|\.log\b|youtubei|/log_event|protobuf|msgstore\.db|wa\.db|"
    r"chrome.*History|Cache/|code_cache|webview)"
)
_NOISE_TEXT_RE = re.compile(
    r"(?i)(indexeddb|leveldb|protobuf|youtubei/v1/log_event|encoded data|http request header|"
    r"key observations:|snippets are parts of log files)"
)


def _is_noisy_mobile_evidence(path: str, text: str = "") -> bool:
    """Drop dump/log noise that steers the LLM into IndexedDB/API analysis."""
    if _NOISE_PATH_RE.search(path or ""):
        return True
    if _NOISE_TEXT_RE.search(text or ""):
        return True
    # High symbol density = binary/log residue, not examiner findings.
    if text and len(text) > 80:
        symbols = sum(1 for ch in text if ch in r"{}[]<>\\|`~^")
        if symbols / len(text) > 0.08:
            return True
    return False


def _readable_text_snippet(text: str, *, max_len: int = 700) -> str:
    """Keep only mostly-printable text so binary dump chunks do not derail the LLM."""
    raw = (text or "").replace("\x00", " ")
    if not raw.strip():
        return ""
    printable = sum(1 for ch in raw if ch.isprintable() or ch in "\n\r\t")
    if printable / max(len(raw), 1) < 0.72:
        # Keep short readable tokens (paths, urls, labels) from noisy blobs.
        tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{3,}", raw)
        raw = " ".join(tokens[:80])
    cleaned = re.sub(r"[^\S\n]+", " ", raw)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned[:max_len]


def _looks_like_dump_analysis(text: str) -> bool:
    """Detect Image-2 style technical dump commentary (reject)."""
    t = (text or "").lower()
    markers = (
        "indexeddb",
        "leveldb",
        "youtube api",
        "youtubei",
        "log_event",
        "encoded data",
        "http request header",
        "key observations:",
        "snippets are parts of log",
        "decoding indexeddb",
        "protobuf",
        "not human-readable",
    )
    return any(m in t for m in markers)


def _mobile_inventory_nonzero(db, job_id: str) -> dict[str, int]:
    try:
        from app.services.mobile_forensic.inventory import build_mobile_inventory_snapshot

        snap = build_mobile_inventory_snapshot(db, job_id)
        counts = snap.get("counts") or {}
        return {str(k): int(v) for k, v in counts.items() if int(v or 0) > 0}
    except Exception:
        return {}


def _gather_mobile_payment_evidence(db, job_id: str, *, limit: int = 30) -> list[dict[str, str]]:
    """Collect grounded payment/media snippets from indexed chunks (paths + readable text)."""
    rows = fetchall(
        db,
        """
        SELECT file_path, LEFT(COALESCE(content, ''), 600) AS content
        FROM rag_chunks
        WHERE job_id = CAST(:jid AS uuid)
          AND (
            file_path ILIKE '%upi%' OR file_path ILIKE '%gpay%' OR file_path ILIKE '%google%pay%'
            OR file_path ILIKE '%phonepe%' OR file_path ILIKE '%paytm%' OR file_path ILIKE '%receipt%'
            OR file_path ILIKE '%cheque%' OR file_path ILIKE '%payment%' OR file_path ILIKE '%transaction%'
            OR content ILIKE '%UPI%' OR content ILIKE '%Google Pay%' OR content ILIKE '%PhonePe%'
            OR content ILIKE '%Paytm%' OR content ILIKE '%receipt%' OR content ILIKE '%cheque%'
            OR content ILIKE '%transaction%' OR content ILIKE '%paid to%' OR content ILIKE '%payment successful%'
          )
        ORDER BY created_at DESC NULLS LAST
        LIMIT :lim
        """,
        {"jid": job_id, "lim": limit},
    )
    out: list[dict[str, str]] = []
    for r in rows or []:
        path = str(r.get("file_path") or "")
        snippet = _readable_text_snippet(str(r.get("content") or ""), max_len=420)
        if not path and not snippet:
            continue
        out.append({"file_path": path, "content": snippet})
    return out


def _observation_bullets_grounded(text: str, evidence_blob: str) -> bool:
    """Reject observation text that invents payee/org names absent from evidence."""
    blob = (evidence_blob or "").lower()
    # Multi-word Title Case names (e.g. Tokarshi Bhawanji) must appear in evidence.
    for name in re.findall(r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3})\b", text or ""):
        if name.lower() not in blob and all(tok.lower() not in blob for tok in name.split()):
            return False
    return True


def _fallback_mobile_observations(
    nonzero: dict[str, int],
    *,
    payment_hits: list[dict[str, str]] | None = None,
    objective_txt: str = "",
    procedure_txt: str = "",
) -> str:
    """Simple client-language Observations when LLM returns unusable text."""
    from app.services.mobile_report_llm import plain_fallback_observations

    _ = payment_hits  # kept for call-site compatibility
    return plain_fallback_observations(
        nonzero,
        objective_txt=objective_txt,
        procedure_txt=procedure_txt,
    )


def _splice_mobile_observations(template_md: str, observations_md: str) -> str:
    """Replace only section 3. Observations in the fixed Objective/Procedure template."""
    obs = (observations_md or "").strip()
    if not obs:
        return template_md
    # If model returned a full section, keep only the observations body.
    m = re.search(
        r"(?is)(?:###\s*3\.\s*Observations|^\s*Observations\s*:)\s*(.+)$",
        obs,
    )
    if m:
        obs = m.group(1).strip()
    # Drop accidental re-stated Objective/Procedure blocks.
    obs = re.split(r"(?im)^\s*###\s*[12]\.\s*", obs)[0].strip()
    if not obs.startswith(("-", "*", "1.", "•")) and "\n-" not in obs:
        # Normalize plain paragraphs into bullets.
        lines = [ln.strip() for ln in obs.splitlines() if ln.strip()]
        if lines:
            obs = "\n".join(ln if ln.startswith(("-", "*", "•")) else f"- {ln}" for ln in lines)
    pattern = re.compile(
        r"(?is)(###\s*3\.\s*Observations\s*\n)(.*?)(?=\n##\s|\Z)",
    )
    if pattern.search(template_md):
        return pattern.sub(lambda m: f"{m.group(1)}\n{obs}\n", template_md, count=1)
    return template_md.rstrip() + "\n\n### 3. Observations\n\n" + obs + "\n"


def _polish_mobile_findings(
    template_md: str,
    db,
    job_id: str,
    intake: dict,
    *,
    schema_name: str,
    primary_model: str,
) -> str:
    """Fill section 3. Observations in simple client language (no paths / jargon)."""
    from app.retrieval.hybrid import hybrid_retrieve
    from app.services.mobile_report_llm import (
        evidence_summary_for_llm,
        looks_like_llm_stub,
        looks_too_technical,
        plain_fallback_observations,
        resolve_mobile_report_model,
        rewrite_mobile_observations_plain,
        strip_technical_noise,
    )
    from app.services.model_router import generate_text

    # Prefer media/payment/comms queries; skip_vector avoids HF hang on report workers.
    queries = [
        "UPI google pay phonepe transaction receipt cheque payment money transfer jpg jpeg",
        "handwritten receipt cheque audio note money conversation whatsapp media",
        "rooted configuration profile malware browser history photos documents",
        "deleted recovered trash recycle photos videos messages",
    ]
    chunks: list[dict] = []
    seen_paths: set[str] = set()
    for q in queries:
        for c in hybrid_retrieve(
            db,
            job_id,
            q,
            top_k=12,
            schema_name=schema_name,
            skip_vector=True,
        ):
            key = str(c.get("file_path") or c.get("id") or "")
            if key in seen_paths:
                continue
            path = str(c.get("file_path") or "")
            snippet = _readable_text_snippet(str(c.get("content") or ""))
            if len(snippet) < 40 or _is_noisy_mobile_evidence(path, snippet):
                continue
            seen_paths.add(key)
            chunks.append({**c, "content": snippet, "file_path": path})
            if len(chunks) >= 10:
                break
        if len(chunks) >= 10:
            break

    nonzero = _mobile_inventory_nonzero(db, job_id)
    payment_hits = [
        h
        for h in _gather_mobile_payment_evidence(db, job_id, limit=30)
        if not _is_noisy_mobile_evidence(h.get("file_path") or "", h.get("content") or "")
    ]

    # Path-free brief for all LLM stages (never send raw paths to the writer).
    evidence_brief = evidence_summary_for_llm(
        inventory=nonzero,
        payment_hits=payment_hits,
        rag_snippets=[str(c.get("content") or "") for c in chunks[:8]],
    )

    objective_m = re.search(r"(?is)###\s*1\.\s*Objective\s*(.*?)(?=###\s*2\.|\Z)", template_md)
    procedure_m = re.search(r"(?is)###\s*2\.\s*Procedure\s*(.*?)(?=###\s*3\.|\Z)", template_md)
    objective_txt = strip_technical_noise((objective_m.group(1).strip() if objective_m else "")[:900])
    procedure_txt = strip_technical_noise((procedure_m.group(1).strip() if procedure_m else "")[:900])

    if not evidence_brief.strip() and not nonzero:
        return _splice_mobile_observations(
            template_md,
            plain_fallback_observations(
                nonzero,
                objective_txt=objective_txt,
                procedure_txt=procedure_txt,
            ),
        )

    narrative_model = resolve_mobile_report_model() or primary_model
    observations = ""
    try:
        polished = generate_text(
            (
                "Write section 3. Observations for a mobile phone examination report.\n"
                "Audience: a non-technical client. Use simple, everyday English only.\n\n"
                "Observations MUST be based on the Objective and the Procedure below.\n"
                "- Start from what the Objective asked you to look for.\n"
                "- Reflect what the Procedure actually checked.\n"
                "- Then state what was found (or not found) in plain words.\n\n"
                "REQUIRED OUTPUT:\n"
                "### 3. Observations\n"
                "- bullet 1\n"
                "- bullet 2\n\n"
                "STRUCTURE:\n"
                "1) First 4–6 bullets about phone safety / integrity in everyday words "
                "(unusual system changes, phishing/malware signs in browsing, unusual background activity).\n"
                "2) Then detailed bullets about chats, photos, payment screens, voice notes, "
                "deleted/recovered items, and what they mean for the Objective.\n"
                "3) End with 1–2 bullets that explain, in plain terms, why this matters for the case.\n\n"
                "HARD RULES:\n"
                "- NEVER mention file paths, folders, database names, package names, hashes, or tool names.\n"
                "- Do NOT invent payee names, amounts, dates, or people.\n"
                "- Do NOT write IndexedDB, LevelDB, API, protobuf, freelist, WAL, or log decoding.\n"
                "- Prefer words like photos, chat messages, payment app screens, voice notes, deleted items.\n"
                "- Return ONLY ### 3. Observations and hyphen bullets.\n\n"
                f"Objective (must guide the Observations):\n{objective_txt}\n\n"
                f"Procedure / what was done (must guide the Observations):\n{procedure_txt}\n\n"
                f"Evidence brief:\n{evidence_brief[:8000]}"
            ),
            model=narrative_model,
            system=(
                "You write mobile examination findings for everyday readers. "
                "Simple detailed English only. Never include paths or technical jargon. "
                "Never invent facts. Always connect findings to the stated Objective and Procedure."
            ),
            temperature=0.15,
        ).strip()
        bad = (
            not polished
            or looks_like_llm_stub(polished)
            or looks_too_technical(polished)
            or _looks_like_dump_analysis(polished)
            or re.search(r"(?i)^\s*###\s*\d+\.\s+.+\s*&\s+", polished, flags=re.M)
            or ("### 1." in polished and "### 3." not in polished)
            or "key observations" in polished.lower()
            or "required style" in polished.lower()
        )
        if not bad and len(polished) > 80:
            observations = polished
    except Exception as exc:
        log.warning("mobile findings polish failed: %s", exc)

    if not observations or looks_like_llm_stub(observations):
        observations = plain_fallback_observations(
            nonzero,
            objective_txt=objective_txt,
            procedure_txt=procedure_txt,
        )

    # Second pass: force plain language + strip any residual technical noise.
    try:
        rewritten = rewrite_mobile_observations_plain(
            observations,
            evidence_brief=evidence_brief
            or plain_fallback_observations(
                nonzero,
                objective_txt=objective_txt,
                procedure_txt=procedure_txt,
            ),
            objective_txt=objective_txt,
            procedure_txt=procedure_txt,
            model=narrative_model,
        )
        if rewritten and not looks_like_llm_stub(rewritten) and not looks_too_technical(rewritten):
            observations = rewritten
        else:
            observations = strip_technical_noise(observations)
            if looks_like_llm_stub(observations):
                observations = plain_fallback_observations(
                    nonzero,
                    objective_txt=objective_txt,
                    procedure_txt=procedure_txt,
                )
    except Exception as exc:
        log.warning("mobile plain-language rewrite failed: %s", exc)
        observations = strip_technical_noise(observations)
        if looks_like_llm_stub(observations):
            observations = plain_fallback_observations(
                nonzero,
                objective_txt=objective_txt,
                procedure_txt=procedure_txt,
            )

    return _splice_mobile_observations(template_md, observations)


def _section_draft_prompt(
    section_key: str,
    intake: dict,
    *,
    outline: str,
    context: str,
    evidence_md: str,
) -> str:
    title = section_title(section_key)
    if section_key == "user_profile_information":
        task = (
            "List all Windows user accounts on this laptop in table format with columns: "
            "Username, Last Logon Date, Last Password Change Date. "
            "Use SAM, Security.evtx, ProfileList, and NTUSER evidence."
        )
    elif section_key == "os_information":
        task = (
            "Provide operating system details in table format: Operating System, Version Number, "
            "Build Number, Computer Name, Install Date, Product Key, Product ID, Last Shutdown, "
            "System Root (in short)."
        )
    elif section_key == "artifact_summary":
        task = (
            "Summarize only the artifact groups and individual artifacts selected on the Artifacts page. "
            "For each selected item use the same Magnet AXIOM prompt_question as the Artifacts UI "
            "(count + grounded description from inventory answers)."
        )
    elif section_key == "objectives_procedure_observation":
        task = (
            "For each examination objective from intake, write Objective, Procedure, and Observation subsections. "
            "Use corresponding scoped artifacts to describe possible evidence found. "
            "Ground observations in retrieved context only."
        )
    elif section_key == "annexure":
        task = (
            "Present annexure URL tables. Show at most 15 sample records per URL category in the report; "
            "note total counts when higher."
        )
    elif section_key == "final_analysis_summary":
        task = "Write E. Analysis Summary — concise findings per intake objective."
    elif section_key == "appendix":
        task = "Write F. Appendix with supporting references and pointers to full artifact exports."
    else:
        task = f"Write the '{title}' section following standard forensic report structure."

    return f"""Write the '{title}' section for a court-defensible forensic report (Aetheris template).

TASK:
{task}

OUTLINE:
{outline}

STRUCTURED EVIDENCE (prefer this when present):
{evidence_md or 'None'}

INTAKE:
report_type={intake.get('report_type')}
background={str(intake.get('background') or '')[:800]}
case_type={intake.get('case_type')}
organization={intake.get('organization')}

RETRIEVED CONTEXT (cite artifact IDs inline):
{context}"""


def _generate_outline(section_key: str, intake: dict, chunks: list[dict], *, fast_model: str) -> str:
    context = "\n".join((c.get("content") or "")[:300] for c in chunks[:5])
    prompt = f"""Create a bullet outline for the '{section_title(section_key)}' section.
Report type: {intake.get('report_type')}
Use only facts from context. List 4-8 bullet points.

CONTEXT:
{context or 'Use standard Aetheris forensic report section structure.'}"""
    return generate_text(prompt, model=fast_model, system="Forensic report planner. Markdown bullets only.", temperature=0.1)


def _review_section(draft: str, chunks: list[dict], *, review_model: str) -> tuple[bool, str, str]:
    context = "\n".join((c.get("content") or "")[:400] for c in chunks[:5])
    prompt = f"""Review this forensic report section for factual grounding.

CONTEXT:
{context}

DRAFT:
{draft}

Reply JSON: {{"passed": true/false, "grade": "A-E", "notes": "...", "refusal": false}}"""
    raw = generate_text(prompt, model=review_model, temperature=0.1)
    try:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            data = json.loads(m.group())
            if data.get("refusal"):
                return False, "E", str(data.get("notes", "Review refused"))
            return bool(data.get("passed", True)), str(data.get("grade", "B")), str(data.get("notes", ""))
    except Exception:
        pass
    return True, "B", raw[:500]


def _persist_report_section(
    db,
    *,
    report_run_id: str | None,
    job_id: str,
    section_key: str,
    content: str,
    structured_json: dict[str, Any] | None,
    grade: str,
    primary: str | None,
    review: str | None,
    review_passed: bool,
    review_notes: dict[str, Any],
    idx: int,
) -> None:
    execute(
        db,
        """INSERT INTO report_sections (report_run_id, job_id, section_key, title, content_md, structured_json,
           status, confidence_grade, primary_model, review_model, review_passed, review_notes, sort_order)
           VALUES (:rid, :jid, :key, :title, :content, CAST(:sj AS jsonb), 'draft', :grade, :pm, :rm, :rp,
                   CAST(:rn AS jsonb), :ord)
           ON CONFLICT (report_run_id, section_key) DO UPDATE SET
             content_md=EXCLUDED.content_md,
             structured_json=EXCLUDED.structured_json,
             confidence_grade=EXCLUDED.confidence_grade,
             primary_model=EXCLUDED.primary_model,
             review_model=EXCLUDED.review_model,
             review_passed=EXCLUDED.review_passed,
             review_notes=EXCLUDED.review_notes,
             updated_at=NOW()""",
        {
            "rid": report_run_id,
            "jid": job_id,
            "key": section_key,
            "title": section_title(section_key),
            "content": content,
            "sj": json.dumps(structured_json) if structured_json else None,
            "grade": grade,
            "pm": primary,
            "rm": review,
            "rp": review_passed,
            "rn": json.dumps(review_notes),
            "ord": idx,
        },
    )


def _fallback_section_markdown(
    section_key: str, db, job_id: str, intake: dict, schema_name: str,
) -> str:
    """Keep the report start-to-end even when one section fails."""
    try:
        evidence_md, _ = _structured_evidence(section_key, db, job_id, intake, schema_name=schema_name)
        if evidence_md and "Insufficient evidence" not in evidence_md:
            if section_key == _LLM_OBSERVATION_SECTION:
                return _fill_objective_observations(
                    evidence_md,
                    db,
                    job_id,
                    intake,
                    schema_name=schema_name,
                    primary_model="",
                    progress_cb=None,
                )
            return evidence_md
    except Exception:
        log.exception("fallback evidence failed section=%s", section_key)
    return (
        f"## {section_title(section_key)}\n\n"
        "This section is included so the report is complete from start to end. "
        "Re-run Recreate after extraction finishes if more detail is needed."
    )


def _write_one_report_section(
    db,
    job_id: str,
    intake: dict,
    *,
    schema_name: str,
    report_run_id: str | None,
    section_key: str,
    idx: int,
    section_order: list[str],
    settings,
) -> None:
    apply_firm_search_path(db, schema_name)
    primary, review = select_section_models(section_key)
    _set_run_progress(
        db,
        report_run_id,
        section_key=section_key,
        section_index=idx + 1,
        total_sections=len(section_order),
        stage="retrieval",
        primary_model=primary,
        review_model=review,
    )
    apply_firm_search_path(db, schema_name)
    evidence_md, structured_json = _structured_evidence(
        section_key, db, job_id, intake, schema_name=schema_name,
    )

    from app.services.mobile_report_service import is_mobile_intake
    if section_key == "os_information":
        from app.services.report_profile_sections import build_os_report_markdown

        evidence_md = build_os_report_markdown(
            db, job_id, schema_name=schema_name, primary_model=primary,
        )
    elif section_key == "user_profile_information" and not is_mobile_intake(intake):
        from app.services.report_profile_sections import build_user_report_markdown

        evidence_md = build_user_report_markdown(
            db, job_id, schema_name=schema_name, primary_model=primary,
        )
    elif section_key == "device_information":
        from app.services.report_mobile_sections import build_mobile_device_report_markdown

        evidence_md = build_mobile_device_report_markdown(
            db, job_id, intake, schema_name=schema_name, primary_model=primary,
        )
    elif section_key == "extraction_summary":
        from app.services.report_mobile_sections import build_mobile_extraction_report_markdown

        evidence_md = build_mobile_extraction_report_markdown(
            db, job_id, intake, schema_name=schema_name, primary_model=primary,
        )

    use_template = section_key in _TEMPLATE_SECTIONS
    use_objective_llm = section_key == _LLM_OBSERVATION_SECTION
    use_profile_section = section_key in _PROMPT_PROFILE_SECTIONS
    use_mobile_prompt = section_key in _MOBILE_PROMPT_SECTIONS

    chunks: list[dict] = []
    context = ""
    if not use_template and not use_objective_llm and not use_profile_section and not use_mobile_prompt:
        query = _build_retrieval_query(section_key, intake)
        chunks = hybrid_retrieve(
            db,
            job_id,
            query,
            top_k=10,
            schema_name=schema_name,
            skip_vector=True,
        )
        context = "\n\n---\n\n".join(
            f"[{c.get('artifact_id') or 'evidence'}]\n{(c.get('content') or '')[:1500]}"
            for c in chunks
        )

    _set_run_progress(
        db,
        report_run_id,
        section_key=section_key,
        section_index=idx + 1,
        total_sections=len(section_order),
        stage="draft",
        primary_model=primary,
        review_model=review,
    )
    apply_firm_search_path(db, schema_name)

    if use_profile_section and evidence_md and "Insufficient evidence" not in evidence_md:
        content = evidence_md
        grade = "B" if evidence_md.count("—") > 4 else "A"
        review_passed = True
        review_notes: dict[str, Any] = {"source": "profile_facts_and_prompts"}
        citations: list[dict] = []
    elif use_mobile_prompt and evidence_md and "Insufficient evidence" not in evidence_md:
        content = evidence_md
        grade = "B" if evidence_md.count("—") > 6 else "A"
        review_passed = True
        review_notes = {"source": "mobile_facts_and_prompts"}
        citations = []
    elif use_template and evidence_md and "Insufficient evidence" not in evidence_md:
        content = evidence_md
        grade = "A"
        review_passed = True
        review_notes = {"source": "aetheris_template"}
        citations = _extract_citations(content, chunks)
    elif use_objective_llm and evidence_md:
        def _obj_progress(phase: str, sub_i: int, sub_n: int, title: str = "") -> None:
            detail = f"{phase} {sub_i}/{sub_n}"
            if title:
                detail = f"{detail}: {title[:80]}"
            _set_run_progress(
                db,
                report_run_id,
                section_key=section_key,
                section_index=idx + 1,
                total_sections=len(section_order),
                stage="draft",
                primary_model=primary,
                review_model=review,
                detail=detail,
                sub_index=sub_i,
                sub_total=sub_n,
            )
            apply_firm_search_path(db, schema_name)

        try:
            from app.services.report_objectives_observation_service import (
                assemble_section_c_from_saved_observations,
            )

            assembled = assemble_section_c_from_saved_observations(db, job_id, intake, require_all=True)
            if assembled and assembled.count("**Observation**") >= 1:
                content = assembled
            else:
                content = _fill_objective_observations(
                    evidence_md,
                    db,
                    job_id,
                    intake,
                    schema_name=schema_name,
                    primary_model=primary,
                    progress_cb=_obj_progress,
                )
        except Exception:
            log.exception("observation LLM failed job=%s — writing from artifacts only", job_id)
            content = _fill_objective_observations(
                evidence_md,
                db,
                job_id,
                intake,
                schema_name=schema_name,
                primary_model="",
                progress_cb=_obj_progress,
            )
        grade = "B" if chunks else "C"
        review_passed = True
        review_notes = {"source": "linked_artifacts_observation"}
        citations = _extract_citations(content, chunks)
    elif not chunks and not evidence_md:
        content = "**Insufficient evidence** — no retrieved chunks support this section."
        grade = "E"
        review_passed = True
        review_notes = {"reason": "no_chunks"}
        citations = []
    else:
        outline = _generate_outline(section_key, intake, chunks, fast_model=settings.llm_fast_model)
        prompt = _section_draft_prompt(
            section_key,
            intake,
            outline=outline,
            context=context,
            evidence_md=evidence_md,
        )
        content = generate_text(
            prompt,
            model=primary,
            system=(
                "Digital forensic examiner writing a formal Aetheris Technologies report. "
                "Third-person, court-defensible prose. Never use conversational phrases like "
                "'It appears that you provided'. Markdown output only."
            ),
            temperature=0.2,
            timeout=60,
        )
        if evidence_md and section_key in _TEMPLATE_SECTIONS:
            content = f"{evidence_md}\n\n---\n\n{content}"
        citations = _extract_citations(content, chunks)
        citation_valid, citation_issues = validate_citations(content, chunks, citations)
        grade = _confidence_grade(chunks, citations, citation_valid)
        review_passed = True
        review_notes = {"outline": outline[:500], "citation_issues": citation_issues}

        if not citation_valid and citation_issues:
            content += f"\n\n> **Citation review note:** {'; '.join(citation_issues)}"

        if review:
            review_passed, rgrade, notes = _review_section(content, chunks, review_model=review)
            if GRADE_ORDER.get(rgrade, 0) < GRADE_ORDER.get(grade, 3):
                grade = rgrade
            review_notes["review"] = notes
            if not review_passed:
                content = f"**Review flagged this section (grade {rgrade})**\n\n{notes}\n\n---\n\n{content}"

    if not (content or "").strip():
        content = _fallback_section_markdown(section_key, db, job_id, intake, schema_name)

    _persist_report_section(
        db,
        report_run_id=report_run_id,
        job_id=job_id,
        section_key=section_key,
        content=content,
        structured_json=structured_json,
        grade=grade,
        primary=primary,
        review=review,
        review_passed=review_passed,
        review_notes=review_notes,
        idx=idx,
    )
    db.commit()
    apply_firm_search_path(db, schema_name)

    sec = fetchone(
        db,
        "SELECT id FROM report_sections WHERE report_run_id=:rid AND section_key=:key",
        {"rid": report_run_id, "key": section_key},
    )
    if sec and citations:
        for cit in citations:
            execute(
                db,
                """INSERT INTO report_citations (report_section_id, artifact_id, chunk_id, file_path, citation_label)
                   VALUES (:sid, :aid, :cid, :path, :label)""",
                {
                    "sid": sec["id"],
                    "aid": cit.get("artifact_id"),
                    "cid": cit.get("chunk_id"),
                    "path": cit.get("file_path"),
                    "label": cit.get("artifact_id"),
                },
            )
        db.commit()
        apply_firm_search_path(db, schema_name)

    _set_run_progress(
        db,
        report_run_id,
        section_key=section_key,
        section_index=idx + 1,
        total_sections=len(section_order),
        stage="done",
        primary_model=primary,
        review_model=review,
        confidence_grade=grade,
    )
    apply_firm_search_path(db, schema_name)


def generate_report(db, job_id: str, *, schema_name: str, report_run_id: str | None = None) -> dict:
    settings = get_settings()
    apply_firm_search_path(db, schema_name)
    ready, missing = _intake_ready(db, job_id)
    if not ready:
        # Persist a failed run so the SSE stream stops "waiting" and the UI can show the reason.
        err = f"Intake incomplete — missing: {', '.join(missing)}"
        apply_firm_search_path(db, schema_name)
        try:
            if report_run_id:
                execute(
                    db,
                    """UPDATE report_runs SET status='failed', error=:err, completed_at=NOW()
                       WHERE id=:id""",
                    {"err": err[:500], "id": report_run_id},
                )
            else:
                job_exists = fetchone(db, "SELECT id FROM jobs WHERE id=:id", {"id": job_id})
                if job_exists:
                    execute(
                        db,
                        """INSERT INTO report_runs (job_id, status, error, started_at, completed_at)
                           VALUES (:jid, 'failed', :err, NOW(), NOW())""",
                        {"jid": job_id, "err": err[:500]},
                    )
            db.commit()
        except Exception as persist_exc:
            log.warning(
                "could not persist intake-incomplete report_run job=%s schema=%s: %s",
                job_id,
                schema_name,
                persist_exc,
            )
            try:
                db.rollback()
            except Exception:
                pass
            apply_firm_search_path(db, schema_name)
        return {"status": "blocked", "missing_fields": missing, "error": err}

    intake = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id}) or {}

    # A report recreation is an explicit request for the current case state. Drop the
    # 30-minute browser/encryption caches before Section B/C/D are built so an earlier
    # inventory pass cannot make Section C disagree with the Annexure.
    try:
        from app.services.browser_url_inventory import clear_browser_url_cache
        from app.services.encryption_inventory import clear_encryption_count_cache

        clear_browser_url_cache(job_id)
        clear_encryption_count_cache(job_id)
    except Exception as exc:
        log.debug("report evidence cache reset skipped job=%s: %s", job_id, exc)

    # Backfill critical paths that older extraction profiles could omit from
    # job_artifacts. In particular, extensionless Windows $Recycle.Bin/$I descriptors
    # are needed for defensible deleted-file findings. This reads the existing disk
    # manifest only; it does not alter the source acquisition.
    try:
        from app.services.artifact_materialize import materialize_critical_forensic_paths

        backfill = materialize_critical_forensic_paths(db, job_id)
        if int(backfill.get("added") or 0) > 0:
            db.commit()
            apply_firm_search_path(db, schema_name)
            log.info("report critical-path backfill job=%s added=%s", job_id, backfill.get("added"))
    except Exception as exc:
        log.warning("report critical-path backfill skipped job=%s: %s", job_id, exc)
        try:
            db.rollback()
        except Exception:
            pass
        apply_firm_search_path(db, schema_name)

    # Mobile: refresh forensic board + ensure AXIOM inventory exists before drafting sections.
    try:
        from app.services.mobile_report_service import is_mobile_intake
        from app.services.mobile_forensic.detection import is_mobile_job

        job_row_pre = fetchone(db, "SELECT disk_source, type FROM jobs WHERE id=:id", {"id": job_id}) or {}
        if is_mobile_intake(intake, job_row_pre) or is_mobile_job(db, job_id):
            from app.services.mobile_forensic.inventory import persist_mobile_inventory_snapshot
            from app.services.axiom_artifact_runner import (
                axiom_inventory_progress,
                queue_axiom_artifact_inventory,
            )

            persist_mobile_inventory_snapshot(db, job_id)
            db.commit()
            apply_firm_search_path(db, schema_name)
            inv = axiom_inventory_progress(db, job_id)
            if int(inv.get("completed") or 0) <= 0 and schema_name:
                # Rebuild catalog counts so B. ARTIFACTS / objectives have AXIOM rows.
                queue_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
                db.commit()
                apply_firm_search_path(db, schema_name)
    except Exception as exc:
        log.warning("mobile inventory pre-report refresh failed job=%s: %s", job_id, exc)

    ensure_report_run_progress_schema(db)
    if report_run_id is None:
        execute(
            db,
            """INSERT INTO report_runs (job_id, status, started_at, primary_model, review_model, fast_model, embedding_model)
               VALUES (:jid, 'running', NOW(), :pm, :rm, :fm, :em)""",
            {
                "jid": job_id,
                "pm": settings.llm_primary_model,
                "rm": settings.llm_review_model,
                "fm": settings.llm_fast_model,
                "em": settings.rag_embedding_model,
            },
        )
        row = fetchone(db, "SELECT id FROM report_runs WHERE job_id=:jid ORDER BY created_at DESC LIMIT 1", {"jid": job_id})
        report_run_id = str(row["id"]) if row else None
    else:
        execute(db, "UPDATE report_runs SET status='running', started_at=NOW() WHERE id=:id", {"id": report_run_id})

    db.commit()
    apply_firm_search_path(db, schema_name)
    started = datetime.now(timezone.utc)
    execute(db, "UPDATE jobs SET status='report_generating', updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()
    apply_firm_search_path(db, schema_name)

    generated_this_run = 0
    report_type = intake.get("report_type")
    job_row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    section_order = section_order_for_report_type(report_type, intake, job_row)
    already_written = {
        str(r["section_key"])
        for r in fetchall(
            db,
            "SELECT section_key FROM report_sections WHERE report_run_id=:rid",
            {"rid": report_run_id},
        )
        or []
    }
    for idx, section_key in enumerate(section_order):
        if section_key in already_written:
            generated_this_run += 1
            continue
        try:
            _write_one_report_section(
                db,
                job_id,
                intake,
                schema_name=schema_name,
                report_run_id=report_run_id,
                section_key=section_key,
                idx=idx,
                section_order=section_order,
                settings=settings,
            )
            generated_this_run += 1
        except Exception as exc:
            log.exception("report section failed job=%s key=%s: %s", job_id, section_key, exc)
            try:
                db.rollback()
            except Exception:
                pass
            apply_firm_search_path(db, schema_name)
            fallback = _fallback_section_markdown(section_key, db, job_id, intake, schema_name)
            _persist_report_section(
                db,
                report_run_id=report_run_id,
                job_id=job_id,
                section_key=section_key,
                content=fallback,
                structured_json=None,
                grade="C",
                primary=settings.llm_primary_model,
                review=None,
                review_passed=True,
                review_notes={"source": "fallback_after_error", "error": str(exc)[:240]},
                idx=idx,
            )
            db.commit()
            apply_firm_search_path(db, schema_name)
            generated_this_run += 1
            _set_run_progress(
                db,
                report_run_id,
                section_key=section_key,
                section_index=idx + 1,
                total_sections=len(section_order),
                stage="done",
                detail="fallback",
            )
            apply_firm_search_path(db, schema_name)

    apply_firm_search_path(db, schema_name)
    written_keys = {
        str(r["section_key"])
        for r in fetchall(
            db,
            "SELECT section_key FROM report_sections WHERE report_run_id=:rid",
            {"rid": report_run_id},
        )
        or []
    }
    for idx, section_key in enumerate(section_order):
        if section_key in written_keys:
            continue
        fallback = _fallback_section_markdown(section_key, db, job_id, intake, schema_name)
        _persist_report_section(
            db,
            report_run_id=report_run_id,
            job_id=job_id,
            section_key=section_key,
            content=fallback,
            structured_json=None,
            grade="C",
            primary=settings.llm_primary_model,
            review=None,
            review_passed=True,
            review_notes={"source": "missing_section_backfill"},
            idx=idx,
        )
        generated_this_run += 1
        written_keys.add(section_key)
    db.commit()

    # V9 consistency pass: Section E must be a verbatim summary of the final
    # persisted Section-C observations. This prevents stale/generic summary prose
    # from contradicting the evidence-specific finding (for example "no cloud
    # traces" while Section C and Annexure show Google Drive).
    if "final_analysis_summary" in section_order:
        try:
            from app.services.report_evidence import gather_analysis_summary_markdown

            summary_md = gather_analysis_summary_markdown(db, job_id, intake)
            execute(
                db,
                """UPDATE report_sections
                      SET content_md=:content, confidence_grade='A', review_passed=TRUE,
                          review_notes=CAST(:notes AS jsonb), updated_at=NOW()
                    WHERE report_run_id=:rid AND section_key='final_analysis_summary'""",
                {
                    "content": summary_md,
                    "notes": json.dumps({"source": "section_c_consistency_refresh"}),
                    "rid": report_run_id,
                },
            )
            db.commit()
            apply_firm_search_path(db, schema_name)
        except Exception as exc:
            log.warning("analysis summary consistency refresh failed job=%s: %s", job_id, exc)
            try:
                db.rollback()
            except Exception:
                pass
            apply_firm_search_path(db, schema_name)

    finished = datetime.now(timezone.utc)
    duration_ms = int((finished - started).total_seconds() * 1000)
    execute(
        db,
        "UPDATE report_runs SET status='completed', completed_at=NOW(), duration_ms=:ms WHERE id=:id",
        {"ms": duration_ms, "id": report_run_id},
    )
    execute(db, "UPDATE jobs SET status='report_ready', updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()
    try:
        execute(
            db,
            """DELETE FROM report_citations
               WHERE report_section_id IN (
                 SELECT rs.id FROM report_sections rs
                 JOIN report_runs rr ON rr.id = rs.report_run_id
                 WHERE rr.job_id=:jid AND rr.id <> :rid AND rr.status='superseded'
               )""",
            {"jid": job_id, "rid": report_run_id},
        )
        execute(
            db,
            """DELETE FROM report_sections
               WHERE report_run_id IN (
                 SELECT id FROM report_runs
                 WHERE job_id=:jid AND id <> :rid AND status='superseded'
               )""",
            {"jid": job_id, "rid": report_run_id},
        )
        db.commit()
    except Exception as exc:
        log.warning("superseded report cleanup skipped job=%s: %s", job_id, exc)
        try:
            db.rollback()
        except Exception:
            pass
    return {"status": "completed", "report_run_id": report_run_id, "duration_ms": duration_ms}
