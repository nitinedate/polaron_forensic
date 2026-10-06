"""Bridge the supplied AXIOM forensic KB to the existing Aetheris evidence store.

The attached starter ships its own demo SQLAlchemy case/artifact schema.  Aetheris
already has a production case/job/artifact schema and mature collectors, so duplicating
those tables would create two sources of truth.  This bridge keeps the starter's
forensic semantics while adapting current ``job_axiom_artifact_results`` and query
provenance into a deterministic evidence brief for Section C.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall
from app.services.axiom_forensic_kb import (
    REPORT_AGENT_SYSTEM_RULES,
    canonical_artifact_family,
    objective_knowledge_plan,
    rag_terms_for_objective,
    sanitize_narrative_text,
    text_contains_prohibited_payload,
)

log = logging.getLogger("axiom_forensic_report_engine")

_REL_ORDER = {"PRIMARY": 0, "SUPPORTING": 1, "CORROBORATING": 2, "CONTEXTUAL": 3}
_SENSITIVE_KEYS = {"password", "passwd", "token", "secret", "credential", "cookie_value", "auth_token"}
_CLIENT_ENTITY_KEYS = {
    "url", "domain", "browser", "profile", "username", "account", "email", "remote_ip", "hostname",
    "message_id", "conversation_id", "event_id", "record_id", "file_name", "file_path", "sha256",
    "device_serial", "serial", "vid", "pid", "manufacturer", "model", "ssid", "bssid", "event_time",
    "original_path", "deletion_time", "action", "provider", "object_id", "application", "target_path",
    "volume_serial", "detection_name", "result", "os_name", "os_version", "build", "timezone",
}

_CANONICAL_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "url": ("url", "web url", "uri"),
    "username": ("user", "username", "account", "user name"),
    "remote_ip": ("remote ip", "destination ip", "ip address"),
    "hostname": ("host", "hostname", "computer name", "remote host"),
    "message_id": ("message id", "messageid", "native message id"),
    "session_id": ("session id", "sessionid"),
    "event_id": ("event id", "record id", "eventrecordid"),
    "file_path": ("file path", "path", "target path"),
    "sha256": ("sha256", "sha 256"),
    "domain": ("domain", "host"),
    "ssid": ("ssid", "network name"),
    "device_serial": ("serial number", "device serial", "device serial number"),
}


def _canonical_url(value: str) -> str:
    try:
        parts = urlsplit(value.strip())
        host = (parts.hostname or "").lower()
        port = parts.port
        netloc = host
        if port and not ((parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)):
            netloc = f"{host}:{port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    except Exception:
        return value.strip()


def _canonicalize_record_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Version-adapter semantics from the supplied starter, applied to current snapshots."""
    out = dict(row)
    normalized_keys = {_norm(k): k for k in row}
    for canonical, aliases in _CANONICAL_FIELD_ALIASES.items():
        if out.get(canonical) not in (None, "", []):
            continue
        for alias in aliases:
            original = normalized_keys.get(_norm(alias))
            if original is not None and row.get(original) not in (None, "", []):
                out[canonical] = row.get(original)
                break
    if isinstance(out.get("url"), str):
        out["url"] = _canonical_url(out["url"])
    if isinstance(out.get("domain"), str):
        out["domain"] = out["domain"].lower().strip(".")
    if isinstance(out.get("email"), str):
        out["email"] = out["email"].lower().strip()
    if isinstance(out.get("username"), str):
        out["username"] = out["username"].strip()
    return out


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _safe_scalar(key: str, value: Any) -> Any:
    if str(key).lower() in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        cleaned = sanitize_narrative_text(value, max_len=280)
        return cleaned or None
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return None


def _walk_dicts(value: Any, *, depth: int = 0):
    if depth > 5:
        return
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value[:200]:
            yield from _walk_dicts(child, depth=depth + 1)


def _extract_snapshot_records(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract record-like dicts from existing collector snapshots without raw payloads."""
    if not isinstance(snapshot, dict):
        return []
    preferred: list[dict[str, Any]] = []
    for key in ("records", "devices", "samples", "items", "connections", "events", "messages"):
        value = snapshot.get(key)
        if isinstance(value, list):
            preferred.extend(x for x in value if isinstance(x, dict))
    if preferred:
        source = preferred[:200]
    else:
        source = list(_walk_dicts(snapshot))[:200]

    out: list[dict[str, Any]] = []
    for row in source:
        # Starter exclusion semantics are record-level: package XML/BlockMap content
        # cannot survive as a partially sanitized narrative record.
        if any(text_contains_prohibited_payload(v) for v in row.values() if isinstance(v, str)):
            continue
        safe: dict[str, Any] = {}
        for key, value in row.items():
            k = str(key)
            kn = _norm(k).replace(" ", "_")
            if k.lower() in _SENSITIVE_KEYS:
                safe[k] = "[REDACTED]"
                continue
            # Keep useful scalar fields; raw/encoded payloads are never evidence narrative.
            if isinstance(value, (str, int, float, bool)) and not text_contains_prohibited_payload(value):
                val = _safe_scalar(k, value)
                if val not in (None, ""):
                    safe[k] = val
                    # Add stable aliases for common current-parser keys.
                    if kn in {"serial_number", "device_serial_number"}:
                        safe.setdefault("device_serial", val)
                    elif kn in {"device_name", "friendly_name"}:
                        safe.setdefault("model", val)
                    elif kn in {"path", "target", "target_file"}:
                        safe.setdefault("file_path", val)
                    elif kn in {"timestamp", "time", "datetime", "last_connected", "last_seen"}:
                        safe.setdefault("event_time", val)
                    elif kn in {"user", "user_name"}:
                        safe.setdefault("username", val)
                    elif kn in {"host", "computer_name"}:
                        safe.setdefault("hostname", val)
        if safe:
            out.append(_canonicalize_record_fields(safe))
    return out


def _field_value(record: dict[str, Any], field: str, *, evidence_source_id: str = "current") -> Any:
    if field == "evidence_source_id":
        return evidence_source_id
    if field == "external_artifact_id":
        return record.get("external_artifact_id") or record.get("record_id") or record.get("event_id")
    if field == "content_hash":
        return record.get("content_hash") or record.get("sha256")
    value = record.get(field)
    if value not in (None, "", []):
        return value
    # Common equivalent fields in current parsers.
    aliases = {
        "device_serial": ("serial", "serial_number"),
        "file_path": ("path", "target_path", "original_path"),
        "event_time": ("timestamp", "time", "datetime", "last_connected", "last_seen", "deletion_time"),
        "browser": ("browser_name",),
        "profile": ("browser_profile", "user_profile"),
        "username": ("user", "account"),
        "event_id": ("record_id",),
    }
    for alias in aliases.get(field, ()):
        if record.get(alias) not in (None, "", []):
            return record.get(alias)
    return None


def _semantic_dedup_count(records: list[dict[str, Any]], report: dict[str, Any]) -> tuple[int | None, list[dict[str, Any]]]:
    """Apply supplied semantic-dedup rules when current collector samples are complete enough."""
    if not records:
        return None, []
    priorities = (report.get("dedup_rule") or {}).get("deduplicate_by_priority") or []
    count_fields = (report.get("count_rule") or {}).get("key_fields") or []
    seen: set[tuple[Any, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for index, row in enumerate(records):
        if row.get("parent_external_artifact_id") and row.get("refined_view_only"):
            # Parent/refined-result protection from the supplied starter.
            continue
        key = None
        for fields in priorities:
            vals = tuple(_field_value(row, str(f)) for f in fields)
            if fields and all(v not in (None, "", []) for v in vals):
                key = ("DEDUP", *vals)
                break
        if key is None:
            key = ("ROW", index, json.dumps(row, sort_keys=True, default=str)[:500])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    if count_fields:
        count_keys: set[tuple[Any, ...]] = set()
        for row in deduped:
            vals = tuple(_field_value(row, str(f)) for f in count_fields)
            if all(v not in (None, "", []) for v in vals):
                count_keys.add(vals)
        if count_keys:
            return len(count_keys), deduped
    return len(deduped), deduped


def _entity_values(records: list[dict[str, Any]], fields: list[str], *, limit: int = 8) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for field in fields:
        values: list[Any] = []
        for row in records:
            value = _field_value(row, field)
            if value in (None, "", []) or text_contains_prohibited_payload(value):
                continue
            safe = _safe_scalar(field, value)
            if safe in (None, ""):
                continue
            if field in {"file_path", "target_path", "original_path"}:
                # The report writer gets only the display name, not internal paths.
                safe = re.split(r"[\\/]", str(safe))[-1]
            if safe not in values:
                values.append(safe)
            if len(values) >= limit:
                break
        if values:
            out[field] = values
    return out


def _artifact_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    from app.services.catalog_artifact_runner import load_stored_axiom_inventory
    from app.services.report_template_service import resolve_report_artifact_keys

    inventory = load_stored_axiom_inventory(db, job_id)
    if not inventory:
        return []
    selected = resolve_report_artifact_keys(db, job_id)
    ids = list(inventory.keys())
    rows = fetchall(
        db,
        """SELECT artifact_id, artifact_name, category, platform
             FROM public.axiom_artifacts WHERE artifact_id = ANY(:ids)""",
        {"ids": ids},
    )
    meta = {str(r.get("artifact_id")): dict(r) for r in rows}

    # Query-manifest provenance is the current project's traceability layer.  It is
    # supporting metadata only; the supplied KB decides whether the artifact is primary.
    try:
        from app.services.catalog_query_manifest import provenance_for_artifacts
        provenance = provenance_for_artifacts(db, job_id, ids)
    except Exception:
        provenance = {}

    out: list[dict[str, Any]] = []
    for aid, inv in inventory.items():
        if selected and aid not in selected:
            continue
        m = meta.get(aid) or {}
        label = str(m.get("artifact_name") or aid)
        family = canonical_artifact_family(label)
        if not family:
            # Unknown current catalog rows remain outside the supplied report KB.
            continue
        answer = sanitize_narrative_text(inv.get("answer") or "", max_len=420)
        snapshot = inv.get("query_snapshot") if isinstance(inv.get("query_snapshot"), dict) else {}
        records = _extract_snapshot_records(snapshot)
        out.append({
            "artifact_id": aid,
            "label": label,
            "category": m.get("category"),
            "platform": m.get("platform"),
            "family": family,
            "occurrence_count": int(inv.get("occurrence_count") or inv.get("count") or 0),
            "unique_count": inv.get("unique_count"),
            "count_domain": inv.get("count_domain"),
            "answer": answer,
            "snapshot_records": records,
            "provenance": provenance.get(aid) or {},
            "confidence": inv.get("confidence"),
            "status": inv.get("status"),
        })
    return out


def _relationship_map(report: dict[str, Any]) -> dict[str, str]:
    return {
        str(m.get("artifact_family") or ""): str(m.get("relationship") or "SUPPORTING").upper()
        for m in report.get("artifact_mappings") or []
        if m.get("artifact_family")
    }


def _run_kb_report(report: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    rel_by_family = _relationship_map(report)
    relevant = [deepcopy(a) for a in artifacts if a.get("family") in rel_by_family]
    for row in relevant:
        row["relationship"] = rel_by_family.get(str(row.get("family")), "SUPPORTING")

    primary = [a for a in relevant if a.get("relationship") == "PRIMARY"]
    supporting = [a for a in relevant if a.get("relationship") in {"SUPPORTING", "CORROBORATING"}]
    raw_hit_count = sum(int(a.get("occurrence_count") or 0) for a in relevant)

    # The current collector result is already case-scoped. Apply supplied semantic
    # dedup again only when its query snapshot includes enough record-level data.
    sample_records: list[dict[str, Any]] = []
    for art in primary:
        sample_records.extend(art.get("snapshot_records") or [])
    sample_count, deduped_samples = _semantic_dedup_count(sample_records, report)

    primary_family_counts: dict[str, int] = defaultdict(int)
    for art in primary:
        # Prefer a collector-provided unique count when available; it is more faithful
        # than an occurrence count for a DISTINCT KB unit.
        unique = art.get("unique_count")
        n = int(unique) if unique not in (None, "") else int(art.get("occurrence_count") or 0)
        primary_family_counts[str(art.get("family"))] += n

    # A single-primary-family report can safely use the current collector count.  For a
    # multi-primary-family report, do not add heterogeneous families together unless
    # record-level semantic keys are available; that would recreate the double-counting
    # problem the supplied starter explicitly prevents.
    primary_families = {str(a.get("family")) for a in primary}
    if sample_count is not None and sample_records and len(deduped_samples) >= min(len(sample_records), 1):
        # Samples are a valid exact count only when they represent the whole current
        # result set.  Compare against primary occurrence total to avoid mistaking a
        # preview list for the full population.
        primary_occ_total = sum(int(a.get("occurrence_count") or 0) for a in primary)
        if len(sample_records) == primary_occ_total:
            reported_count: int | None = sample_count
            count_basis = "kb_semantic_deduplication"
        elif len(primary_families) == 1:
            reported_count = next(iter(primary_family_counts.values()), 0)
            count_basis = "current_collector_count; sample_is_preview"
        else:
            reported_count = None
            count_basis = "multiple_primary_families_require_record_level_deduplication"
    elif len(primary_families) == 1:
        reported_count = next(iter(primary_family_counts.values()), 0)
        count_basis = "current_collector_count"
    elif not primary:
        reported_count = 0
        count_basis = "no_primary_artifact"
    else:
        reported_count = None
        count_basis = "multiple_primary_families_require_record_level_deduplication"

    unit = str((report.get("count_rule") or {}).get("unit") or "RECORD")
    entity_fields = [str(x) for x in (report.get("observation_rule") or {}).get("entity_fields") or []]
    key_entities = _entity_values(deduped_samples or sample_records, entity_fields)

    # If no record-level samples expose entities, accept safe collector answers as
    # narrative facts, but never raw XML/paths/serialized payloads.
    safe_facts: list[str] = []
    for art in relevant:
        ans = sanitize_narrative_text(art.get("answer") or "", max_len=320)
        if ans and ans not in safe_facts:
            safe_facts.append(ans)

    review = bool((report.get("observation_rule") or {}).get("always_require_examiner_review"))
    if any(
        str(row.get("recovery_status") or "").upper() in {"CARVED", "CARVED_PARTIAL", "PARTIAL", "CORRUPT"}
        for row in (deduped_samples or sample_records)
    ):
        review = True
    return {
        "report_id": report.get("id"),
        "report_title": report.get("title"),
        "report_objective": report.get("objective"),
        "procedure_id": report.get("procedure_id"),
        "count_unit": unit,
        "reported_count": reported_count,
        "count_basis": count_basis,
        "raw_hit_count": raw_hit_count,
        "primary_family_counts": dict(primary_family_counts),
        "primary_artifact_present": bool(primary),
        "primary_evidence": primary,
        "supporting_evidence": supporting,
        "key_entities": key_entities,
        "safe_facts": safe_facts[:8],
        "zero_result_rule": deepcopy(report.get("zero_result_rule") or {}),
        "limitations": list(report.get("limitations") or []),
        "examiner_review_required": review,
    }


def build_objective_evidence_brief(
    db: Session,
    job_id: str,
    objective: dict[str, Any],
    *,
    intake: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministic, LLM-safe evidence brief for one Section C objective."""
    title = str(objective.get("title") or "").strip()
    statement = str(objective.get("objective") or objective.get("statement") or "").strip()
    plan = objective_knowledge_plan(title, statement)
    artifacts = _artifact_rows(db, job_id)
    results = [_run_kb_report(report, artifacts) for report in plan.get("reports") or []]
    direct_ids = set(plan.get("direct_report_ids") or [])
    for result in results:
        result["objective_role"] = "DIRECT" if result.get("report_id") in direct_ids else "SUPPORTING"

    direct_results = [r for r in results if r.get("objective_role") == "DIRECT"]
    direct_positive = [
        r for r in direct_results
        if isinstance(r.get("reported_count"), int) and int(r["reported_count"]) > 0
    ]
    direct_indeterminate = [
        r for r in direct_results
        if r.get("reported_count") is None and r.get("primary_artifact_present")
    ]
    related_evidence_present = any(
        bool(r.get("primary_artifact_present"))
        and (r.get("reported_count") is None or int(r.get("reported_count") or 0) > 0)
        for r in results
    )
    if direct_positive:
        status = "CONFIRMED"
    elif direct_indeterminate:
        status = "INCONCLUSIVE"
    elif direct_results and related_evidence_present:
        # The exact direct report did not establish the finding, but related KB reports
        # contain evidence that may need a target-specific filter/correlation. Do not
        # turn those supporting totals into the answer.
        status = "INCONCLUSIVE"
    elif direct_results:
        status = "NOT_FOUND"
    elif results:
        # This Case-intake question is more specific than any single supplied report
        # definition. The mapped KB reports are context only until filtered/correlated.
        status = "INCONCLUSIVE" if related_evidence_present else "NOT_EXAMINED"
    else:
        status = "NOT_EXAMINED"

    limitations: list[str] = list(plan.get("limitations") or [])
    for result in results:
        if result.get("reported_count") is None:
            limitations.append(
                f"{result.get('report_title')}: multiple primary artifact families were available but the current collector did not expose a complete record-level set for the supplied semantic deduplication rule; no combined count was invented."
            )
        for item in result.get("limitations") or []:
            text = str(item).strip()
            if text and text not in limitations:
                limitations.append(text)

    allowed_counts: list[dict[str, Any]] = []
    for result in direct_results:
        count = result.get("reported_count")
        if isinstance(count, int):
            allowed_counts.append({
                "report_id": result.get("report_id"),
                "report_title": result.get("report_title"),
                "count": count,
                "unit": result.get("count_unit"),
            })

    # V9: ask the supplied KB question against the same full, record-level evidence
    # used by Sections A/B/D. V8 stopped at catalog/inventory totals, which made
    # Section C say "not specific enough" even when the Annexure already contained
    # Google Drive URLs, WhatsApp rows, user accounts or physical USB storage.
    case_fact = None
    case_fact_error = None
    try:
        from app.services.report_objective_case_facts import build_objective_case_fact

        case_fact = build_objective_case_fact(db, job_id, objective, intake=intake)
    except Exception as exc:
        # Never silently convert a detector failure into a negative forensic finding.
        # V9 swallowed this exception and allowed the generic KB zero-result path to
        # write "no cloud/external/deleted evidence" even when another report section
        # already exposed the underlying records.
        case_fact_error = f"{type(exc).__name__}: {str(exc)[:220]}"
        log.exception("objective-specific evidence detector failed job=%s objective=%s", job_id, title)
        status = "INCONCLUSIVE"
        allowed_counts = []
        limitations.append(
            "The objective-specific record detector did not complete successfully. No negative conclusion was accepted from the generic inventory fallback."
        )
    if case_fact:
        status = str(case_fact.get("status") or status)
        fact_counts = [c for c in (case_fact.get("allowed_counts") or []) if isinstance(c.get("count"), int)]
        # For an objective-specific detector these are the only counts that answer the
        # question. Generic KB/report totals remain contextual and cannot leak into the
        # narrative as substitutes.
        allowed_counts = fact_counts
        for item in case_fact.get("limitations") or []:
            text = str(item).strip()
            if text and text not in limitations:
                limitations.append(text)

    return {
        "objective": {
            "title": title,
            "statement": statement,
            "objective_id": objective.get("id") or objective.get("objective_id"),
        },
        "status": status,
        "knowledge_plan": plan,
        "report_results": results,
        "allowed_counts": allowed_counts,
        "limitations": limitations[:12],
        "examiner_review_required": any(bool(r.get("examiner_review_required")) for r in results),
        "rag_terms": rag_terms_for_objective(title, statement),
        "intake_context": {
            k: v for k, v in (intake or {}).items()
            if k in {"case_type", "organization", "case_number", "incident_summary", "background"} and v
        },
        "case_fact": case_fact,
        "case_fact_error": case_fact_error,
        "agent_rules": REPORT_AGENT_SYSTEM_RULES,
    }


def deterministic_observation_from_brief(brief: dict[str, Any]) -> str:
    """Safe fallback when LLM writing is unavailable or fails validation."""
    case_fact = brief.get("case_fact") or {}
    if case_fact:
        observation = sanitize_narrative_text(case_fact.get("observation") or "", max_len=1050)
        explanation = sanitize_narrative_text(case_fact.get("simple_explanation") or "", max_len=420)
        parts = [x for x in (observation, explanation) if x]
        if parts:
            return " ".join(parts)
    title = str((brief.get("objective") or {}).get("title") or "this objective")
    status = str(brief.get("status") or "INCONCLUSIVE")
    results = brief.get("report_results") or []
    direct_results = [r for r in results if r.get("objective_role") == "DIRECT"]
    sentences: list[str] = []

    if status == "NOT_EXAMINED":
        sentences.append(
            f"The supplied AXIOM forensic knowledge base does not define a controlled report that directly answers {title}."
        )
        sentences.append("No unrelated artifact category was used as a substitute for this question.")
        sentences.append("This means no conclusion was made where the controlled knowledge base does not support one.")
        return " ".join(sentences)

    positive = [
        r for r in direct_results
        if isinstance(r.get("reported_count"), int) and int(r["reported_count"]) > 0
    ]
    if not positive:
        if status == "INCONCLUSIVE":
            if direct_results:
                sentences.append(
                    f"For {title}, the controlled reports found related evidence, but it was not specific enough to make the requested finding without further filtering or correlation."
                )
            else:
                sentences.append(
                    f"For {title}, the supplied knowledge base contains related evidence sources, but none of the mapped reports can by itself answer this more specific question."
                )
            sentences.append("Supporting artifact totals were not used as a substitute for the requested finding.")
        elif status == "NOT_EXAMINED":
            sentences.append(
                "The supplied AXIOM knowledge base does not contain a direct report definition that can answer this specific question without an additional examiner-defined filter."
            )
            sentences.append("No unrelated artifact total was used as a substitute.")
        else:
            names = [str(r.get("report_title") or "") for r in direct_results[:3] if r.get("report_title")]
            suffix = f" for {', '.join(names)}" if names else ""
            sentences.append(f"For {title}, no primary evidence matching the direct controlled report criteria was identified{suffix}.")
            sentences.append("Supporting or contextual records were not treated as proof of the activity by themselves.")
        sentences.append("This means the report states only what the controlled evidence can support for this question.")
        return " ".join(sentences)

    for result in positive[:3]:
        count = int(result["reported_count"])
        unit = str(result.get("count_unit") or "record").lower().replace("_", " ")
        report_title = str(result.get("report_title") or title)
        sentences.append(f"The examination identified {count:,} distinct {unit}{'' if count != 1 else ''} relevant to {report_title}.")
        entities = result.get("key_entities") or {}
        entity_bits: list[str] = []
        for field, values in entities.items():
            vals = [str(v) for v in (values or [])[:3] if str(v).strip()]
            if vals:
                entity_bits.append(f"{field.replace('_', ' ')}: {', '.join(vals)}")
        if entity_bits:
            sentences.append("Supported details include " + "; ".join(entity_bits[:2]) + ".")
        if len(sentences) >= 4:
            break
    if brief.get("limitations"):
        sentences.append("The finding does not extend beyond the specific evidence and limitations recorded for this objective.")
    sentences.append("This means only evidence that met the controlled AXIOM rules was used to answer this question.")
    return " ".join(sentences[:6])


def _allowed_numeric_counts(brief: dict[str, Any]) -> set[int]:
    return {int(c.get("count") or 0) for c in brief.get("allowed_counts") or []}


def validate_observation_against_brief(text: str, brief: dict[str, Any]) -> tuple[bool, list[str]]:
    """Reject common hallucination/leak patterns before a narrative reaches the report."""
    body = str(text or "").strip()
    errors: list[str] = []
    if not body:
        return False, ["empty observation"]
    if text_contains_prohibited_payload(body):
        errors.append("raw XML/package payload detected")
    if re.search(r"\b(?:Laptop|Desktop|Device)\s*\[\d+\]", body, re.I):
        errors.append("internal evidence-source label detected")
    if re.search(r"\b(?:query[_ ]key|count[_ ]domain|artifact[_ ]record|GET /api/|AXIOM reference)\b", body, re.I):
        errors.append("internal implementation language detected")
    if re.search(r"[A-Za-z]:\\[^\s]{3,}|/(?:Users|home|var|Windows|usr)/[^\s]{3,}", body, re.I):
        errors.append("internal path detected")

    # Counts attached to forensic count nouns must come from the deterministic brief.
    allowed = _allowed_numeric_counts(brief)
    for raw in re.findall(
        r"\b(\d[\d,]*)\s+(?:distinct\s+)?(?:files?|records?|items?|devices?|events?|messages?|accounts?|urls?|sessions?|documents?|applications?|contacts?|calls?|downloads?)\b",
        body,
        flags=re.I,
    ):
        value = int(raw.replace(",", ""))
        if value not in allowed:
            errors.append(f"count {value} is not supplied by the deterministic evidence brief")

    case_fact = brief.get("case_fact") or {}
    fact_status = str(case_fact.get("status") or "").upper()
    if fact_status == "CONFIRMED" and re.search(
        r"\b(?:no traces|no evidence|nothing (?:was )?found|were not found|was not found|did not identify|no [^.]{0,120}\b(?:was|were)\s+found)\b",
        body,
        re.I,
    ):
        errors.append("observation contradicts confirmed objective-specific evidence")
    if fact_status == "NOT_FOUND" and re.search(
        r"\b(?:relevant traces were found|evidence (?:shows|showed)|were identified|was identified|was used|showed access)\b",
        body,
        re.I,
    ):
        errors.append("observation contradicts zero-result objective-specific evidence")

    # A confirmed objective-specific fact should remain specific.  This prevents the
    # writer from turning "Google Drive" or "Apacer Portable HDD" back into vague
    # boilerplate such as "relevant traces were found".
    if fact_status == "CONFIRMED":
        entity_values: list[str] = []
        for values in (case_fact.get("key_entities") or {}).values():
            for value in values or []:
                text = sanitize_narrative_text(value, max_len=120)
                if text and len(text) >= 3:
                    entity_values.append(text)
        if entity_values and not any(v.lower() in body.lower() for v in entity_values[:12]):
            errors.append("confirmed observation omitted the objective-specific evidence identity")

    if not re.search(r"\bthis means\b", body, re.I):
        errors.append("simple explanation sentence missing")
    if len(body) > 1400:
        errors.append("observation is too long")
    return not errors, errors
