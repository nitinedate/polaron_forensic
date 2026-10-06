"""Report B. ARTIFACTS — selected Magnet groups/items using Artifacts-page prompts."""

from __future__ import annotations

import json
import re
from typing import Any

from app.db.sql_helpers import execute, fetchall
from app.services.artifact_export import artifact_scope_payload


def _artifact_template_description_map() -> dict[tuple[str, str], str]:
    try:
        from app.services.report_catalog_sync import REPORT_ARTIFACTS
    except Exception:
        return {}
    out: dict[tuple[str, str], str] = {}
    for item in REPORT_ARTIFACTS:
        category = str(item.get("category") or "").strip()
        name = str(item.get("name") or "").strip()
        description = str(item.get("description") or "").strip()
        if category and name and description:
            out[(category.casefold(), name.casefold())] = description
    return out


_ARTIFACT_TEMPLATE_DESCRIPTIONS = _artifact_template_description_map()
_ARTIFACT_CATEGORY_TITLE_OVERRIDES = {"Application Usage": "Application Usages"}


def _display_category_title(title: str) -> str:
    clean = (title or "").strip()
    return _ARTIFACT_CATEGORY_TITLE_OVERRIDES.get(clean, clean)


def _artifact_fallback_description(category: str, label: str, count: int) -> str:
    mapped = _ARTIFACT_TEMPLATE_DESCRIPTIONS.get((category.casefold(), label.casefold()))
    if mapped:
        return mapped
    return f"{_format_count(count)} artifact record occurrences ({label})."


def _format_count(n: int) -> str:
    return f"{n:,}"


def _with_catalog_shape(structured: dict[str, Any] | None) -> dict[str, Any]:
    """UI ArtifactReportPages reads catalog.sections; generation historically stored categories."""
    payload = dict(structured or {})
    categories = payload.get("categories")
    if not isinstance(categories, list):
        categories = []
        payload["categories"] = categories
    if not isinstance(payload.get("catalog"), dict) or not (payload["catalog"] or {}).get("sections"):
        payload["catalog"] = {
            "sections": [
                {
                    "title": cat.get("title"),
                    "subcategories": [
                        {
                            "name": item.get("label") or item.get("key"),
                            "count": item.get("count"),
                            "usage_count": item.get("count"),
                            "description": item.get("description"),
                        }
                        for item in (cat.get("items") or [])
                        if isinstance(item, dict)
                    ],
                }
                for cat in categories
                if isinstance(cat, dict)
            ]
        }
    return payload


def structured_has_artifact_groups(structured: Any) -> bool:
    if isinstance(structured, str):
        try:
            structured = json.loads(structured)
        except Exception:
            return False
    if not isinstance(structured, dict):
        return False
    catalog = structured.get("catalog")
    if isinstance(catalog, dict):
        sections = catalog.get("sections")
        if isinstance(sections, list) and sections:
            return True
    categories = structured.get("categories")
    return isinstance(categories, list) and any(isinstance(c, dict) and (c.get("items") or c.get("title")) for c in categories)


def hydrate_artifact_summary_section(db, job_id: str, row: dict[str, Any]) -> dict[str, Any]:
    """Rebuild a stub B. ARTIFACTS section from live inventory so the UI is not blank."""
    if str(row.get("section_key") or "") != "artifact_summary":
        return row
    if structured_has_artifact_groups(row.get("structured_json")):
        sj = row.get("structured_json")
        if isinstance(sj, str):
            try:
                sj = json.loads(sj)
            except Exception:
                return row
        if isinstance(sj, dict) and not (
            isinstance(sj.get("catalog"), dict) and (sj.get("catalog") or {}).get("sections")
        ):
            row["structured_json"] = _with_catalog_shape(sj)
        return row
    md, structured = gather_artifact_summary(db, job_id)
    structured = _with_catalog_shape(structured or {})
    if not structured_has_artifact_groups(structured):
        return row
    if md:
        row["content_md"] = md
    row["structured_json"] = structured
    try:
        execute(
            db,
            """UPDATE report_sections
               SET content_md=:md, structured_json=CAST(:sj AS jsonb), updated_at=NOW()
               WHERE id=:id""",
            {"md": md or row.get("content_md"), "sj": json.dumps(structured), "id": row["id"]},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return row


def _report_count(n: int) -> str:
    if 0 <= n < 10:
        return f"{n:02d}"
    return _format_count(n)


def _selected_sections(scope: dict[str, Any], *, report_keys: set[str] | None = None) -> list[dict[str, Any]]:
    """Return only ticked artifact groups and ticked sub-artifacts from scope."""
    if report_keys:
        enabled = set(report_keys)
    else:
        enabled = set(scope.get("enabled_keys") or [])
    if not enabled:
        return []

    group_enabled: dict[str, bool] = {}
    for group in scope.get("groups") or []:
        name = group.get("group_name") or ""
        group_enabled[name] = bool(group.get("enabled"))

    selected: list[dict[str, Any]] = []
    for section in scope.get("sections") or []:
        title = section.get("title") or "Other"
        if group_enabled and title in group_enabled and not group_enabled[title]:
            continue
        subs = [
            sub for sub in (section.get("subcategories") or [])
            if sub.get("key") in enabled
        ]
        if not subs:
            continue
        selected.append({
            **section,
            "subcategories": subs,
            "count": sum(int(s.get("count") or 0) for s in subs),
        })
    return selected


def _load_inventory_map(db, job_id: str) -> dict[str, dict[str, Any]]:
    rows = fetchall(
        db,
        """SELECT r.artifact_id, r.artifact_count, r.answer, r.status,
                  aa.artifact_name, aa.prompt_question, aa.observation_focus
           FROM job_axiom_artifact_results r
           JOIN public.axiom_artifacts aa ON aa.artifact_id = r.artifact_id
           WHERE r.job_id=:jid""",
        {"jid": job_id},
    )
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        aid = row.get("artifact_id")
        if not aid:
            continue
        out[aid] = {
            "count": int(row.get("artifact_count") or 0),
            "answer": (row.get("answer") or "").strip(),
            "status": row.get("status"),
            "artifact_name": row.get("artifact_name"),
            "prompt_question": (row.get("prompt_question") or "").strip(),
            "observation_focus": (row.get("observation_focus") or "").strip(),
        }
    return out


def _compact_answer(text: str, *, limit: int = 600) -> str:
    cleaned = re.sub(r"\s+", " ", (text or "").strip())
    if not cleaned:
        return ""
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def _description_from_prompt_result(
    *,
    prompt: str,
    answer: str,
    observation_focus: str,
    count: int,
    label: str,
    category: str = "",
) -> str:
    if category:
        mapped = _ARTIFACT_TEMPLATE_DESCRIPTIONS.get((category.casefold(), label.casefold()))
        if mapped:
            return mapped
    if answer:
        compact = _compact_answer(answer)
        if compact:
            return compact
    if observation_focus:
        return observation_focus
    if prompt:
        return _compact_answer(prompt, limit=400)
    return _artifact_fallback_description(category, label, count)


def _inventory_count_for_artifact(
    sub: dict[str, Any],
    *,
    inventory_map: dict[str, dict[str, Any]] | None = None,
    title_counts: dict[str, int] | None = None,
) -> int:
    """Prefer persisted AXIOM inventory; never inflate a stored zero with a catalog hint."""
    key = str(sub.get("key") or "")
    inventory_map = inventory_map or {}
    if key and key in inventory_map:
        return int(inventory_map[key].get("count") or 0)
    if title_counts and key and key in title_counts:
        return int(title_counts.get(key) or 0)
    return int(sub.get("count") or 0)


def _resolve_selected_artifact(
    db,
    job_id: str,
    sub: dict[str, Any],
    *,
    section_inventory: dict[str, Any],
    title_counts: dict[str, int],
    inventory_map: dict[str, dict[str, Any]],
    schema_name: str | None = None,
    quick: bool = True,
) -> tuple[int, str, str]:
    """Return (count, description, prompt_used) for one selected catalog artifact."""
    key = sub.get("key") or ""
    label = sub.get("label") or key
    prompt = (sub.get("prompt_question") or "").strip()
    observation = (sub.get("description") or "").strip()

    cached = inventory_map.get(key)
    if cached and cached.get("answer"):
        count = int(cached.get("count") if cached.get("count") is not None else sub.get("count") or 0)
        used_prompt = cached.get("prompt_question") or prompt
        desc = _description_from_prompt_result(
            prompt=used_prompt,
            answer=cached["answer"],
            observation_focus=observation or cached.get("observation_focus") or "",
            count=count,
            label=label,
            category=str(sub.get("section") or ""),
        )
        return count, desc, used_prompt

    from app.services.axiom_artifact_runner import (
        _find_exact_section_item,
        _format_item_answer,
        _resolve_axiom_artifact_count,
    )

    count = _inventory_count_for_artifact(
        sub,
        inventory_map=inventory_map,
        title_counts=title_counts,
    )
    section, item = _find_exact_section_item(section_inventory, label)
    if count <= 0 and title_counts:
        count = int(title_counts.get(key, 0) or 0)
    if item:
        answer = _format_item_answer(section, item)
    else:
        _, answer = _resolve_axiom_artifact_count(
            db,
            job_id,
            artifact_name=label,
            artifact_id=key,
            collector_counts=title_counts or {},
            section_inventory=section_inventory,
        )
    desc = _description_from_prompt_result(
        prompt=prompt,
        answer=answer,
        observation_focus=observation,
        count=count,
        label=label,
        category=str(sub.get("section") or ""),
    )
    return count, desc, prompt


def gather_artifact_summary_structured(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    report_fast: bool = True,
) -> dict[str, Any]:
    from app.services.report_template_service import resolve_report_artifact_keys

    scope = artifact_scope_payload(db, job_id, read_only=True)
    report_keys = resolve_report_artifact_keys(db, job_id)
    platform = str(scope.get("platform") or "")
    try:
        from app.services.artifact_selection_catalog import resolve_job_axiom_platform

        platform = resolve_job_axiom_platform(db, job_id) or platform
    except Exception:
        pass

    # Mobile jobs: always refresh AXIOM-style board so WhatsApp/SMS/email counts appear
    # even when job_axiom_artifact_results was purged or is still empty.
    mobile_counts: dict[str, int] = {}
    is_mobile = str(platform).lower() in {"ios", "android"}
    if is_mobile:
        try:
            from app.services.mobile_forensic.inventory import (
                build_mobile_inventory_snapshot,
                clear_mobile_inventory_cache,
            )

            clear_mobile_inventory_cache(job_id)
            snap = build_mobile_inventory_snapshot(db, job_id, force=True)
            mobile_counts = {k: int(v or 0) for k, v in (snap.get("counts") or {}).items()}
        except Exception:
            mobile_counts = {}

    if not report_keys:
        if mobile_counts:
            return _mobile_board_as_artifact_summary(mobile_counts, platform=platform)
        return _with_catalog_shape({"categories": [], "enabled_count": 0})
    sections = _selected_sections(scope, report_keys=report_keys)
    if not sections:
        if mobile_counts:
            return _mobile_board_as_artifact_summary(mobile_counts, platform=platform)
        return _with_catalog_shape({"categories": [], "enabled_count": 0})

    inventory_map = _load_inventory_map(db, job_id)
    title_counts: dict[str, int] = {}
    section_inventory: dict[str, Any] = {"sections": []}

    if report_fast:
        # Report generation uses persisted job_axiom_artifact_results only.
        # Full section collectors + aligned counts scan the entire disk catalog and can
        # run for hours or OOM on large jobs.
        pass
    else:
        from app.services.artifact_sections import build_job_artifact_sections
        from app.services.axiom_aligned_counts import compute_all_aligned_counts

        section_inventory = build_job_artifact_sections(db, job_id, schema_name=schema_name)
        title_counts = compute_all_aligned_counts(db, job_id, platform)

    categories: list[dict[str, Any]] = []
    for cat_idx, section in enumerate(sections, 1):
        items: list[dict[str, Any]] = []
        for sub_idx, sub in enumerate(section.get("subcategories") or [], 1):
            if report_fast:
                key = sub.get("key") or ""
                label = sub.get("label") or key
                count = _inventory_count_for_artifact(
                    sub,
                    inventory_map=inventory_map,
                    title_counts=title_counts,
                )
                # Overlay mobile forensic SQLite counts when AXIOM row is missing/zero.
                if is_mobile and count <= 0 and mobile_counts:
                    try:
                        from app.services.mobile_forensic.inventory import _map_axiom_name_to_key

                        mkey = _map_axiom_name_to_key(str(label))
                        if mkey and int(mobile_counts.get(mkey) or 0) > 0:
                            count = int(mobile_counts[mkey])
                    except Exception:
                        pass
                prompt_used = (sub.get("prompt_question") or "").strip()
                cached = inventory_map.get(key) or {}
                if cached.get("prompt_question"):
                    prompt_used = cached["prompt_question"]
                answer = cached.get("answer") or ""
                try:
                    description = _description_from_prompt_result(
                        prompt=prompt_used,
                        answer=answer,
                        observation_focus=(sub.get("description") or cached.get("observation_focus") or ""),
                        count=count,
                        label=label,
                        category=str(section.get("title") or ""),
                    )
                except Exception:
                    description = _artifact_fallback_description(
                        str(section.get("title") or ""),
                        str(label),
                        int(count or 0),
                    )
            else:
                count, description, prompt_used = _resolve_selected_artifact(
                    db,
                    job_id,
                    sub,
                    section_inventory=section_inventory,
                    title_counts=title_counts,
                    inventory_map=inventory_map,
                    schema_name=schema_name,
                )
            items.append({
                "index": sub_idx,
                "key": sub.get("key"),
                "label": sub.get("label") or sub.get("key"),
                "count": count,
                "description": description,
                "prompt_question": prompt_used,
                "recovery_method": sub.get("recovery_method"),
            })
        categories.append({
            "index": cat_idx,
            "title": section.get("title") or "Other",
            "count": sum(int(i.get("count") or 0) for i in items),
            "items": items,
        })

    # If catalog selection exists but every count is still zero on mobile, surface the board.
    if is_mobile and mobile_counts and not any(int(c.get("count") or 0) > 0 for c in categories):
        return _mobile_board_as_artifact_summary(mobile_counts, platform=platform)

    return _with_catalog_shape({
        "categories": categories,
        "enabled_count": len(report_keys),
        "platform": scope.get("platform") or platform,
    })


_MOBILE_BOARD_LABELS = {
    "whatsapp_messages": ("Communication", "WhatsApp Messages"),
    "whatsapp_chats": ("Communication", "WhatsApp Chats"),
    "whatsapp_calls": ("Communication", "WhatsApp Calls"),
    "whatsapp_contacts": ("Communication", "WhatsApp Contacts"),
    "whatsapp_groups": ("Communication", "WhatsApp Groups"),
    "whatsapp_media": ("Communication", "WhatsApp Media"),
    "sms": ("Communication", "SMS / iMessage"),
    "sms_chats": ("Communication", "SMS / iMessage Chats"),
    "call_logs": ("Communication", "Call Logs"),
    "emails": ("Email", "Emails"),
    "email_attachments": ("Email", "Email Attachments"),
    "contacts": ("Contacts", "Device Contacts"),
    "pictures": ("Media", "Pictures"),
    "videos": ("Media", "Videos"),
    "audio": ("Media", "Audio"),
    "documents": ("Documents", "Documents"),
    "facebook": ("Social", "Facebook"),
    "linkedin": ("Social", "LinkedIn"),
    "instagram": ("Social", "Instagram"),
    "telegram": ("Communication", "Telegram"),
    "signal": ("Communication", "Signal"),
}


def _mobile_board_as_artifact_summary(counts: dict[str, int], *, platform: str) -> dict[str, Any]:
    """Build B. ARTIFACTS from mobile forensic board when AXIOM catalog rows are unavailable."""
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for key, n in counts.items():
        n = int(n or 0)
        if n <= 0:
            continue
        cat, label = _MOBILE_BOARD_LABELS.get(key, ("Mobile Artifacts", key.replace("_", " ").title()))
        by_cat.setdefault(cat, []).append({
            "key": key,
            "label": label,
            "count": n,
            "description": f"Mobile forensic inventory (AXIOM-style) — {label} count {n:,}.",
            "prompt_question": "",
            "recovery_method": "sqlite_path_inventory",
        })
    categories: list[dict[str, Any]] = []
    for idx, (title, items) in enumerate(by_cat.items(), 1):
        for i, item in enumerate(items, 1):
            item["index"] = i
        categories.append({
            "index": idx,
            "title": title,
            "count": sum(int(i["count"]) for i in items),
            "items": items,
        })
    return _with_catalog_shape({
        "categories": categories,
        "enabled_count": sum(len(c["items"]) for c in categories),
        "platform": platform,
        "source": "mobile_forensic_inventory",
    })


def artifact_summary_markdown(structured: dict[str, Any]) -> str:
    lines: list[str] = []
    for gi, sec in enumerate(structured.get("categories") or [], 1):
        title = _display_category_title(str(sec.get("title") or "Artifacts"))
        lines.append(f"## {gi}. {title}:")
        for si, item in enumerate(sec.get("items") or [], 1):
            count = int(item.get("count") or 0)
            label = str(item.get("label") or item.get("key") or "Artifact").strip()
            desc = (item.get("description") or _artifact_fallback_description(str(sec.get("title") or ""), label, count)).strip()
            lines.append(f"{si}. **{label}**")
            lines.append(f"   **Count:** {_report_count(count)}")
            lines.append(f"   **Description:** {desc}")
            lines.append("")
        lines.append("")
    return "\n".join(lines).strip()


def gather_artifact_summary(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
) -> tuple[str, dict[str, Any]]:
    structured = gather_artifact_summary_structured(db, job_id, schema_name=schema_name)
    return artifact_summary_markdown(structured), structured


def gather_artifact_summary_markdown(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
) -> str:
    md, _ = gather_artifact_summary(db, job_id, schema_name=schema_name)
    return md
