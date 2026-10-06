"""Mobile report objectives — AXIOM-aligned objectives/procedures and RAG over mobile extracts."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall
from app.retrieval.hybrid import hybrid_retrieve
from app.services.mobile_report_catalog import MOBILE_FORENSIC_OBJECTIVE_TITLES

# Report section title → mobile extract search terms (Android/iOS indexed paths).
MOBILE_OBJECTIVE_RAG_HINTS: dict[str, str] = {
    "Chat / Communication Apps": (
        "whatsapp sms mms signal telegram chat messages calls com.whatsapp msgstore "
        "communication instant messaging"
    ),
    "Mobile Chat & Messaging Applications": (
        "whatsapp sms mms signal telegram facebook messenger chat messages calls "
        "msgstore chatstorage mmssms communication"
    ),
    "File Access and Handling": (
        "files documents pictures photos videos audio downloads media storage DCIM "
        "file access modified created deleted"
    ),
    "Mobile File Access & Media Handling": (
        "pictures photos videos audio pdf documents downloads DCIM heic mp4 media "
        "whatsapp media file access"
    ),
    "User Accounts & Login Activity": (
        "accounts google account sim contacts owner user profile login device accounts "
        "apple id icloud"
    ),
    "Mobile User Accounts & App Logins": (
        "accounts information google accounts apple id login profile whatsapp account "
        "telegram account"
    ),
    "USB and External Device Usage": (
        "usb external storage sd card mtp mount removable media OTG"
    ),
    "Mobile External Storage & USB/OTG": (
        "sdcard otg usb external storage removable mount mtp"
    ),
    "Installed Applications & Tools": (
        "installed applications packages apk app list program usage permissions"
    ),
    "Installed Mobile Applications": (
        "installed applications google play packages.xml apk uninstall app list"
    ),
    "Device Identity & SIM Attribution": (
        "android device information build.prop iccid imsi sim imei serial model os "
        "acquisition_manifest device_info"
    ),
    "Mobile Email & Attachments": (
        "gmail android emails outlook mail attachments eml msg email"
    ),
    "Social Media & LinkedIn Activity": (
        "instagram linkedin facebook messenger social networking profile messages"
    ),
    "Mobile Cloud Storage & Sync": (
        "google drive dropbox onedrive icloud cloud sync upload download"
    ),
    "Contacts & Address Book": (
        "contacts address book whatsapp contacts telegram contacts phonebook"
    ),
    "Email Artifacts (Local Clients)": "email mail gmail outlook messages attachments",
    "Network Connections": "wifi network bluetooth connection vpn dns ip address",
    "Malware, Phishing and Pornography URLs": "browser history urls web phishing malware",
}


def _is_detailed_procedure_text(text: str | None) -> bool:
    value = (text or "").strip()
    if len(value) < 120:
        return False
    markers = (
        "Examination approach:",
        "How to check",
        "AXIOM examination procedure",
        "1.",
    )
    return sum(1 for m in markers if m in value) >= 2


def mobile_platform_for_job(db: Session, job_id: str) -> str:
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    return resolve_job_axiom_platform(db, job_id)


def enrich_mobile_objectives(
    db: Session,
    job_id: str,
    intake: dict[str, Any],
    objectives: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enrich mobile objectives with platform-scoped prompts; keep detailed DB procedures."""
    from app.services.report_objective_evidence import (
        build_objective_evidence_prompt,
        list_catalog_artifacts_for_objective,
    )
    from app.services.report_objective_procedures import enrich_axiom_procedure_for_title
    from app.services.report_template_service import (
        _fetch_axiom_objective_detail,
        artifact_lookup_objective_id,
    )

    platform = mobile_platform_for_job(db, job_id)
    enriched: list[dict[str, Any]] = []

    for obj in objectives:
        row = dict(obj)
        title = str(row.get("title") or "").strip()
        axiom_id = artifact_lookup_objective_id(row, db)
        detail = _fetch_axiom_objective_detail(db, axiom_id) if axiom_id else None
        stored_proc = str(row.get("procedure_text") or row.get("procedure") or "").strip()

        if detail:
            row["objective"] = detail["statement"]
            row["statement"] = detail["statement"]
            row["axiom_objective_id"] = axiom_id
            row["required_observation_fields"] = detail.get("required_observation_fields")
            row["expected_output_fields"] = detail.get("expected_output_fields")
            row["minimum_corroboration"] = detail.get("minimum_corroboration")
            row["limitations"] = detail.get("limitations")

            if _is_detailed_procedure_text(stored_proc):
                procedure_text = stored_proc
            else:
                procedure_text = enrich_axiom_procedure_for_title(
                    title,
                    str(detail.get("procedure_text") or ""),
                )
            row["procedure_text"] = procedure_text
            row["procedure"] = procedure_text

            linked = list_catalog_artifacts_for_objective(
                db,
                axiom_objective_id=axiom_id,
                header_title=title,
                platform=platform,
            )
            row["evidence_prompt"] = build_objective_evidence_prompt(
                header_title=title,
                objective_statement=detail["statement"],
                procedure_text=procedure_text,
                report_type=f"mobile_forensic/{platform}",
                axiom_objective_id=axiom_id,
                required_observation_fields=detail.get("required_observation_fields"),
                expected_output_fields=detail.get("expected_output_fields"),
                minimum_corroboration=detail.get("minimum_corroboration"),
                limitations=detail.get("limitations"),
                intake=intake,
                linked_artifacts=linked,
            )
        elif stored_proc and not row.get("evidence_prompt"):
            row["evidence_prompt"] = build_objective_evidence_prompt(
                header_title=title,
                objective_statement=str(row.get("objective") or row.get("statement") or ""),
                procedure_text=stored_proc,
                report_type=f"mobile_forensic/{platform}",
                intake=intake,
            )

        row["mobile_platform"] = platform
        # Baseline evidence contract (exact artifacts/paths); LLM refine happens at observation time.
        if not isinstance(row.get("evidence_contract"), dict):
            from app.services.evidence_contract import baseline_mobile_evidence_contract
            from app.services.evidence_contract import contract_to_evidence_prompt_section

            contract = baseline_mobile_evidence_contract(title)
            row["evidence_contract"] = contract
            row["linked_artifact_names"] = list(contract.get("artifact_names") or [])
            block = contract_to_evidence_prompt_section(contract)
            ep = str(row.get("evidence_prompt") or "")
            if "EVIDENCE CONTRACT" not in ep:
                row["evidence_prompt"] = (ep + "\n\n" + block).strip() if ep else block
        enriched.append(row)

    return enriched


def build_mobile_objective_rag_query(objective: dict[str, Any], platform: str) -> str:
    """Hybrid-retrieval query scoped to mobile extraction content."""
    title = str(objective.get("title") or "").strip()
    stmt = str(objective.get("objective") or objective.get("statement") or "")[:500]
    oid = str(objective.get("axiom_objective_id") or objective.get("id") or objective.get("objective_id") or "")
    hints = MOBILE_OBJECTIVE_RAG_HINTS.get(title, "")
    proc = str(objective.get("procedure_text") or objective.get("procedure") or "")[:300]
    contract = objective.get("evidence_contract") if isinstance(objective.get("evidence_contract"), dict) else {}
    contract_queries = " ".join(str(q) for q in (contract.get("rag_queries") or [])[:8])
    contract_paths = " ".join(str(p) for p in (contract.get("path_patterns") or [])[:6])
    return " ".join(
        part
        for part in (
            platform,
            "mobile forensic extraction",
            title,
            stmt,
            proc,
            hints,
            contract_queries,
            contract_paths,
            oid,
            "evidence counts timestamps users messages files paths",
        )
        if part
    ).strip()


def mobile_indexed_evidence_context(
    db: Session,
    job_id: str,
    objective: dict[str, Any],
    *,
    platform: str,
    schema_name: str | None,
    top_k: int = 12,
) -> str:
    """Retrieve indexed mobile extract chunks for observation generation."""
    query = build_mobile_objective_rag_query(objective, platform)
    try:
        chunks = hybrid_retrieve(
            db,
            job_id,
            query,
            top_k=top_k,
            schema_name=schema_name,
            skip_vector=False,
        )
    except Exception:
        chunks = hybrid_retrieve(
            db,
            job_id,
            query,
            top_k=top_k,
            schema_name=schema_name,
            skip_vector=True,
        )

    lines: list[str] = []
    for chunk in chunks[:10]:
        path = str(chunk.get("file_path") or chunk.get("artifact_id") or "evidence")
        content = (chunk.get("content") or "").strip().replace("\n", " ")
        if not content:
            continue
        lines.append(f"[{path}] {content[:1000]}")
    return "\n".join(lines)


def mobile_artifact_inventory_context(
    db: Session,
    job_id: str,
    objective: dict[str, Any],
    *,
    platform: str,
    enabled_keys: set[str],
) -> str:
    """Platform-scoped AXIOM artifact hits for a mobile objective."""
    from app.services.report_template_service import artifact_lookup_objective_id
    from app.services.structured_observation_service import _artifacts_for_objective

    axiom_id = artifact_lookup_objective_id(objective, db)
    artifacts = _artifacts_for_objective(
        db,
        job_id,
        axiom_id,
        enabled_keys,
        objective_title=str(objective.get("title") or ""),
        platform=platform,
    )
    lines: list[str] = []
    if artifacts:
        lines.append(f"MOBILE AXIOM ARTIFACTS ({platform}):")
        for art in artifacts[:14]:
            count = int(art.get("occurrence_count") or 0)
            label = art.get("label") or art.get("artifact_id")
            answer = (art.get("answer") or art.get("observation_focus") or "")[:400]
            line = f"- {label}: count {count:,}"
            if answer:
                line += f" — {answer}"
            lines.append(line)

    # Always append mobile forensic board counts relevant to this objective title.
    try:
        from app.services.mobile_forensic.inventory import (
            build_mobile_inventory_snapshot,
            _map_axiom_name_to_key,
        )

        snap = build_mobile_inventory_snapshot(db, job_id)
        counts = snap.get("counts") or {}
        title = str(objective.get("title") or "")
        mapped = _map_axiom_name_to_key(title)
        board_lines: list[str] = []
        if mapped and int(counts.get(mapped) or 0) > 0:
            board_lines.append(f"- {mapped.replace('_', ' ').title()}: {int(counts[mapped]):,}")
        # Related communication families for chat/media objectives
        title_l = title.lower()
        related = []
        if "whatsapp" in title_l or "chat" in title_l or "message" in title_l:
            related = [
                "whatsapp_messages",
                "whatsapp_chats",
                "whatsapp_calls",
                "whatsapp_groups",
                "whatsapp_media",
            ]
        elif "sms" in title_l or "imessage" in title_l:
            related = ["sms", "sms_chats"]
        elif "email" in title_l or "mail" in title_l:
            related = ["emails", "email_attachments"]
        elif "contact" in title_l:
            related = ["contacts", "whatsapp_contacts"]
        elif "photo" in title_l or "picture" in title_l or "media" in title_l:
            related = ["pictures", "videos", "audio", "whatsapp_media"]
        for key in related:
            n = int(counts.get(key) or 0)
            if n > 0 and f"- {key.replace('_', ' ').title()}:" not in "\n".join(board_lines):
                board_lines.append(f"- {key.replace('_', ' ').title()}: {n:,}")
        if board_lines:
            lines.append("MOBILE FORENSIC BOARD COUNTS:")
            lines.extend(board_lines[:10])
            for lim in snap.get("limitations") or []:
                lines.append(f"  note: {lim}")
                break
    except Exception:
        pass

    return "\n".join(lines)


def mobile_extract_file_counts(db: Session, job_id: str, objective: dict[str, Any]) -> str:
    """Fallback counts from indexed job_artifacts when AXIOM inventory is empty."""
    title = str(objective.get("title") or "").lower()
    hints = MOBILE_OBJECTIVE_RAG_HINTS.get(objective.get("title") or "", "")
    tokens = {t for t in hints.split() if len(t) > 3}
    if not tokens:
        return ""

    rows = fetchall(
        db,
        """SELECT lower(file_path) AS path, lower(file_name) AS name
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    if not rows:
        return ""

    matched = 0
    samples: list[str] = []
    for row in rows:
        blob = f"{row.get('path') or ''} {row.get('name') or ''}"
        if any(token in blob for token in tokens):
            matched += 1
            if len(samples) < 6:
                samples.append(str(row.get("path") or row.get("name") or ""))

    if matched == 0:
        return ""

    lines = [
        f"MOBILE EXTRACT FILE INDEX ({title or 'objective'}):",
        f"- Matching indexed paths: {matched:,}",
    ]
    for sample in samples:
        lines.append(f"  • {sample[:200]}")
    return "\n".join(lines)


def default_mobile_objective_titles() -> list[str]:
    return list(MOBILE_FORENSIC_OBJECTIVE_TITLES)
