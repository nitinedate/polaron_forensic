"""Export AXIOM catalog + Aetheris report template rows as SQL INSERT scripts.

Reads data/axiom/grouped_workbook.xlsx (Magnet AXIOM 10.2.0) and report_catalog_sync
constants. Writes idempotent INSERT ... ON CONFLICT scripts under updatedDatabase/04-seed-axiom/.

Usage:
  python scripts/export_axiom_seed_sql.py
  python scripts/export_axiom_seed_sql.py --out updatedDatabase/04-seed-axiom
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))

from app.services.axiom_catalog_ingest import (  # noqa: E402
    _build_artifact_prompt,
    _build_objective_prompt,
    _build_procedure_prompt,
    _load_grouped_artifacts,
    _load_objectives,
    _load_procedures,
    _workbook_path,
    axiom_data_dir,
)
from app.services.report_catalog_sync import (  # noqa: E402
    REPORT_ARTIFACTS,
    REPORT_OBJECTIVES,
    _artifact_prompt,
    _norm,
    _norm_name,
    _objective_prompt,
    _procedure_prompt,
)

REPORT_PLATFORM = "Windows"
CHUNK_SIZE = 40


def _sql_str(value: Any) -> str:
    if value is None:
        return "NULL"
    text = str(value)
    if text == "":
        return "NULL"
    return "'" + text.replace("'", "''") + "'"


def _sql_bool(value: bool) -> str:
    return "TRUE" if value else "FALSE"


def _sql_int(value: Any) -> str:
    if value is None or value == "":
        return "NULL"
    return str(int(value))


def _sql_jsonb(value: dict[str, Any]) -> str:
    return _sql_str(json.dumps(value, ensure_ascii=False)) + "::jsonb"


def _write_sql_inserts(
    path: Path,
    comment: str,
    insert_head: str,
    row_sqls: list[str],
    on_conflict: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not row_sqls:
        path.write_text(f"-- {comment}\n-- (no rows)\n", encoding="utf-8")
        return
    lines = [f"-- {comment}", ""]
    for i in range(0, len(row_sqls), CHUNK_SIZE):
        chunk = row_sqls[i : i + CHUNK_SIZE]
        lines.append(insert_head)
        lines.append("VALUES")
        lines.append(",\n".join(chunk))
        lines.append(on_conflict)
        lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _load_magnet_catalog() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    data_dir = axiom_data_dir()
    xlsx_path = _workbook_path(data_dir)
    if not xlsx_path.is_file():
        raise FileNotFoundError(f"Missing AXIOM workbook: {xlsx_path}")

    objectives_map = _load_objectives(xlsx_path)
    procedures_map = _load_procedures(xlsx_path)

    objectives: list[dict[str, Any]] = []
    for obj in objectives_map.values():
        proc = procedures_map.get(obj.get("procedure_id") or "", {})
        objectives.append({**obj, "prompt_question": _build_objective_prompt(obj, proc or None)})

    procedures: list[dict[str, Any]] = []
    for proc in procedures_map.values():
        obj = objectives_map.get(proc.get("objective_id") or "", {})
        procedures.append({**proc, "prompt_question": _build_procedure_prompt(proc, obj or None)})

    artifacts: list[dict[str, Any]] = []
    sort_order = 0
    for rec in _load_grouped_artifacts(xlsx_path):
        sort_order += 1
        primary_oid = rec.get("primary_objective_id")
        procedure_id = rec.get("procedure_id")
        objective = objectives_map.get(primary_oid or "", {})
        procedure = procedures_map.get(procedure_id or "", {})
        critical = (objective.get("priority") or "").lower() == "core"
        prompt = _build_artifact_prompt(
            platform=rec["platform"],
            category=rec["category"],
            artifact_name=rec["artifact_name"],
            observation_focus=rec.get("observation_focus"),
            objective=objective or None,
            procedure=procedure or None,
            recovery_method=rec.get("recovery_method"),
        )
        artifacts.append(
            {
                **rec,
                "prompt_question": prompt,
                "critical": critical,
                "sort_order": sort_order,
                "metadata": {
                    "objective_title": objective.get("title"),
                    "procedure_title": procedure.get("title"),
                },
            }
        )
    return objectives, procedures, artifacts


def _build_report_catalog_rows(
    magnet_artifacts: list[dict[str, Any]],
    magnet_objectives: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Report-template rows that are not already covered by Magnet artifact names."""
    canon_names = {
        _norm_name(a["artifact_name"])
        for a in magnet_artifacts
        if a.get("platform") == REPORT_PLATFORM
    }
    max_sort = max(
        (int(a.get("sort_order") or 0) for a in magnet_artifacts if a.get("platform") == REPORT_PLATFORM),
        default=0,
    )

    report_artifacts: list[dict[str, Any]] = []
    art_seq = 0
    for art in REPORT_ARTIFACTS:
        if _norm_name(art["name"]) in canon_names:
            continue
        art_seq += 1
        max_sort += 1
        report_artifacts.append(
            {
                "artifact_id": f"RPT-ART-{art_seq:03d}",
                "platform": REPORT_PLATFORM,
                "category": art["category"],
                "artifact_name": art["name"],
                "recovery_method": "Parsing",
                "prompt_question": _artifact_prompt(REPORT_PLATFORM, art["category"], art["name"], art["description"]),
                "critical": False,
                "sort_order": max_sort,
                "observation_focus": art["description"],
                "metadata": {"source": "aetheris_report_template", "report_section": "B. ARTIFACTS"},
            }
        )

    existing_titles = {_norm(o.get("title") or "") for o in magnet_objectives}
    report_objectives: list[dict[str, Any]] = []
    report_procedures: list[dict[str, Any]] = []

    obj_seq = 900
    proc_seq = 900
    for item in REPORT_OBJECTIVES:
        if _norm(item["title"]) in existing_titles:
            continue
        obj_seq += 1
        proc_seq += 1
        oid = f"RPT-O{obj_seq:03d}"
        pid = f"RPT-P{proc_seq:03d}"
        obj_row = {
            "objective_id": oid,
            "procedure_id": pid,
            "domain": item["domain"],
            "title": item["title"],
            "statement": item["statement"],
            "primary_artifact_families": None,
            "required_observation_fields": "Observed facts; counts; timestamps; source paths; corroboration; limitations",
            "minimum_corroboration": "Independent artifact or log entry where available",
            "limitations": "Absence of evidence is not proof of absence.",
            "priority": "Report",
        }
        proc_row = {
            "procedure_id": pid,
            "objective_id": oid,
            "domain": item["domain"],
            "title": f"Procedure for {item['title']}",
            "detailed_procedure": item["procedure"],
            "mandatory_corroboration": "Cross-check with at least one independent artifact where available.",
            "expected_output_fields": "Observed facts; counts; timestamps; users; source paths",
            "limitations": item.get("limitations") or "Interpretation separate from observed facts.",
        }
        obj_row["prompt_question"] = _objective_prompt(obj_row, proc_row)
        proc_row["prompt_question"] = _procedure_prompt(proc_row, obj_row)
        report_objectives.append(obj_row)
        report_procedures.append(proc_row)
        existing_titles.add(_norm(item["title"]))

    return report_artifacts, report_objectives, report_procedures


def _objective_row_sql(row: dict[str, Any]) -> str:
    return (
        f"({_sql_str(row['objective_id'])}, {_sql_str(row.get('procedure_id'))}, {_sql_str(row.get('domain'))}, "
        f"{_sql_str(row.get('title'))}, {_sql_str(row.get('statement'))}, "
        f"{_sql_str(row.get('primary_artifact_families'))}, {_sql_str(row.get('required_observation_fields'))}, "
        f"{_sql_str(row.get('minimum_corroboration'))}, {_sql_str(row.get('limitations'))}, "
        f"{_sql_str(row.get('priority'))}, {_sql_str(row.get('prompt_question'))})"
    )


def _procedure_row_sql(row: dict[str, Any]) -> str:
    return (
        f"({_sql_str(row['procedure_id'])}, {_sql_str(row.get('objective_id'))}, {_sql_str(row.get('domain'))}, "
        f"{_sql_str(row.get('title'))}, {_sql_str(row.get('detailed_procedure'))}, "
        f"{_sql_str(row.get('mandatory_corroboration'))}, {_sql_str(row.get('expected_output_fields'))}, "
        f"{_sql_str(row.get('limitations'))}, {_sql_str(row.get('prompt_question'))})"
    )


def _artifact_row_sql(row: dict[str, Any]) -> str:
    return (
        f"({_sql_str(row['artifact_id'])}, {_sql_str(row['platform'])}, {_sql_str(row['category'])}, "
        f"{_sql_str(row.get('application_or_profile'))}, {_sql_str(row['artifact_name'])}, "
        f"{_sql_str(row.get('recovery_method'))}, {_sql_int(row.get('reference_page'))}, "
        f"{_sql_str(row.get('primary_objective_id'))}, {_sql_str(row.get('secondary_objective_ids'))}, "
        f"{_sql_str(row.get('procedure_id'))}, {_sql_str(row.get('observation_focus'))}, "
        f"{_sql_str(row.get('outline_path'))}, {_sql_str(row.get('prompt_question'))}, "
        f"{_sql_bool(bool(row.get('critical')))}, {_sql_int(row.get('sort_order'))}, "
        f"{_sql_str(row.get('source_version'))}, {_sql_str(row.get('source_published'))}, "
        f"{_sql_str(row.get('source_url'))}, {_sql_str(row.get('mapping_note'))}, "
        f"{_sql_jsonb(row.get('metadata') or {})}, NOW())"
    )


def export_axiom_seed_sql(out_dir: Path) -> list[str]:
    objectives, procedures, artifacts = _load_magnet_catalog()
    report_artifacts, report_objectives, report_procedures = _build_report_catalog_rows(artifacts, objectives)

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    obj_insert = """INSERT INTO public.axiom_objectives
    (objective_id, procedure_id, domain, title, statement,
     primary_artifact_families, required_observation_fields,
     minimum_corroboration, limitations, priority, prompt_question)"""
    obj_conflict = """ON CONFLICT (objective_id) DO UPDATE SET
    procedure_id = EXCLUDED.procedure_id,
    domain = EXCLUDED.domain,
    title = EXCLUDED.title,
    statement = EXCLUDED.statement,
    primary_artifact_families = EXCLUDED.primary_artifact_families,
    required_observation_fields = EXCLUDED.required_observation_fields,
    minimum_corroboration = EXCLUDED.minimum_corroboration,
    limitations = EXCLUDED.limitations,
    priority = EXCLUDED.priority,
    prompt_question = EXCLUDED.prompt_question;"""

    proc_insert = """INSERT INTO public.axiom_procedures
    (procedure_id, objective_id, domain, title, detailed_procedure,
     mandatory_corroboration, expected_output_fields, limitations, prompt_question)"""
    proc_conflict = """ON CONFLICT (procedure_id) DO UPDATE SET
    objective_id = EXCLUDED.objective_id,
    domain = EXCLUDED.domain,
    title = EXCLUDED.title,
    detailed_procedure = EXCLUDED.detailed_procedure,
    mandatory_corroboration = EXCLUDED.mandatory_corroboration,
    expected_output_fields = EXCLUDED.expected_output_fields,
    limitations = EXCLUDED.limitations,
    prompt_question = EXCLUDED.prompt_question;"""

    art_insert = """INSERT INTO public.axiom_artifacts
    (artifact_id, platform, category, application_or_profile, artifact_name,
     recovery_method, reference_page, primary_objective_id, secondary_objective_ids,
     procedure_id, observation_focus, outline_path, prompt_question, critical,
     sort_order, source_version, source_published, source_url, mapping_note,
     metadata, updated_at)"""
    art_conflict = """ON CONFLICT (artifact_id) DO UPDATE SET
    platform = EXCLUDED.platform,
    category = EXCLUDED.category,
    application_or_profile = EXCLUDED.application_or_profile,
    artifact_name = EXCLUDED.artifact_name,
    recovery_method = EXCLUDED.recovery_method,
    reference_page = EXCLUDED.reference_page,
    primary_objective_id = EXCLUDED.primary_objective_id,
    secondary_objective_ids = EXCLUDED.secondary_objective_ids,
    procedure_id = EXCLUDED.procedure_id,
    observation_focus = EXCLUDED.observation_focus,
    outline_path = EXCLUDED.outline_path,
    prompt_question = EXCLUDED.prompt_question,
    critical = EXCLUDED.critical,
    sort_order = EXCLUDED.sort_order,
    source_version = EXCLUDED.source_version,
    source_published = EXCLUDED.source_published,
    source_url = EXCLUDED.source_url,
    mapping_note = EXCLUDED.mapping_note,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();"""

    files = [
        ("01_axiom_objectives.sql", "Magnet AXIOM objectives", obj_insert, [_objective_row_sql(r) for r in objectives], obj_conflict),
        ("02_axiom_procedures.sql", "Magnet AXIOM procedures", proc_insert, [_procedure_row_sql(r) for r in procedures], proc_conflict),
        ("03_axiom_artifacts.sql", "Magnet AXIOM artifacts (all OS/platforms)", art_insert, [_artifact_row_sql(r) for r in artifacts], art_conflict),
        ("04_report_template_objectives.sql", "Aetheris report template objectives (section C)", obj_insert, [_objective_row_sql(r) for r in report_objectives], obj_conflict),
        ("05_report_template_procedures.sql", "Aetheris report template procedures (section C)", proc_insert, [_procedure_row_sql(r) for r in report_procedures], proc_conflict),
        ("06_report_template_artifacts.sql", "Aetheris report template artifacts (section B, non-duplicate names)", art_insert, [_artifact_row_sql(r) for r in report_artifacts], art_conflict),
    ]

    for name, comment, insert_head, rows, conflict in files:
        rel = f"04-seed-axiom/{name}"
        _write_sql_inserts(out_dir / name, comment, insert_head, rows, conflict)
        written.append(rel)

    readme = f"""# AXIOM catalog seed SQL

Generated by `scripts/export_axiom_seed_sql.py` from:

- `data/axiom/grouped_workbook.xlsx` — Magnet AXIOM 10.2.0 objectives, procedures, artifacts (all platforms)
- `report_catalog_sync.py` — Aetheris report template section B/C items

## Row counts

| File | Rows |
|------|------|
| 01_axiom_objectives.sql | {len(objectives)} |
| 02_axiom_procedures.sql | {len(procedures)} |
| 03_axiom_artifacts.sql | {len(artifacts)} |
| 04_report_template_objectives.sql | {len(report_objectives)} |
| 05_report_template_procedures.sql | {len(report_procedures)} |
| 06_report_template_artifacts.sql | {len(report_artifacts)} |

Apply **after** `01-public/03_axiom_catalog.sql` (DDL).

All statements use `ON CONFLICT ... DO UPDATE` (idempotent).
"""
    (out_dir / "README.md").write_text(readme, encoding="utf-8")
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="Export AXIOM catalog INSERT SQL")
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO / "updatedDatabase" / "04-seed-axiom",
        help="Output directory",
    )
    args = parser.parse_args()
    paths = export_axiom_seed_sql(args.out)
    print(f"Wrote {len(paths)} seed files to {args.out}")
    for p in paths:
        print(f"  - {p}")


if __name__ == "__main__":
    main()
