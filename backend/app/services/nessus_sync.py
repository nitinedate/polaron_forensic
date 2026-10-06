"""Scan sync worker — scanner-agnostic (Nessus / OpenVAS) on dedicated nessus-sync queue."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.scanner_adapter import enrich_stub_scan_details, get_scanner_client
from app.services.vuln_finding_ingest import refresh_asset_risk, upsert_finding
from app.services.vuln_helpers import timeline

log = logging.getLogger("nessus_sync")


def preflight_scan_job(db, job: dict, targets: list[dict]) -> dict:
    """FR-6.3 / FR-3.2: validate credentials and policy before scanning."""
    errors: list[str] = []
    if job.get("policy_id"):
        pol = fetchone(db, "SELECT lifecycle_state, name FROM vuln_scan_policies WHERE id = CAST(:id AS uuid)", {"id": str(job["policy_id"])})
        if pol and (pol.get("lifecycle_state") or "draft") != "active":
            errors.append(f"Scan policy '{pol.get('name')}' is not active (lifecycle_state={pol.get('lifecycle_state')})")

    for t in targets:
        cref = t.get("credential_ref")
        if not cref:
            continue
        cred = fetchone(
            db,
            "SELECT id, lifecycle_state, last_test_result FROM vuln_credential_refs WHERE vault_ref = :ref OR name = :ref LIMIT 1",
            {"ref": cref},
        )
        if not cred:
            errors.append(f"Credential ref '{cref}' not found for target {t.get('target')}")
        elif cred.get("lifecycle_state") == "revoked":
            errors.append(f"Credential '{cref}' is revoked")
        elif cred.get("last_test_result") == "failed":
            errors.append(f"Credential '{cref}' last test failed — rotate before scan")

    return {"ok": not errors, "errors": errors}


def _fetch_active_custom_checks(db) -> list[dict]:
    """Return active custom checks; empty if table not yet migrated."""
    try:
        return fetchall(
            db,
            "SELECT id, name, severity_hint, cve_hint, pci_requirement_tag FROM vuln_custom_checks WHERE lifecycle_state = 'active'",
        )
    except Exception as exc:
        if "vuln_custom_checks" in str(exc) and "does not exist" in str(exc):
            log.warning("vuln_custom_checks missing — run apply_firm_vuln_v21; continuing without custom checks")
            return []
        raise


def nessus_scan_sync(schema_name: str, scan_job_id: str) -> dict:
    with firm_session(schema_name) as db:
        job = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": scan_job_id})
        if not job:
            return {"status": "missing", "scan_job_id": scan_job_id}

        targets = fetchall(
            db,
            "SELECT target, target_type, credential_ref, excluded FROM vuln_scan_targets WHERE scan_job_id = CAST(:id AS uuid)",
            {"id": scan_job_id},
        )
        active_targets = [t for t in targets if not t.get("excluded")]

        orch_raw = job.get("orchestration_json")
        if isinstance(orch_raw, str):
            try:
                orch_raw = json.loads(orch_raw)
            except json.JSONDecodeError:
                orch_raw = None
        # Edge-agent jobs are claimed by the laptop agent over HTTPS — do not run here.
        if isinstance(orch_raw, dict) and orch_raw.get("edge_agent"):
            if (job.get("status") or "").lower() in {"pending"}:
                execute(
                    db,
                    "UPDATE vuln_scan_jobs SET status = 'queued', updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                    {"id": scan_job_id},
                )
                db.commit()
            return {"status": "queued_for_edge_agent", "scan_job_id": scan_job_id}

        pf = preflight_scan_job(db, job, active_targets)
        if not pf["ok"]:
            err = "; ".join(pf["errors"])
            execute(
                db,
                "UPDATE vuln_scan_jobs SET status = 'failed', error = :err, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"err": err[:2000], "id": scan_job_id},
            )
            timeline(
                db,
                case_id=str(job["case_id"]),
                source_type="scan_job",
                source_id=scan_job_id,
                event_type="scan.preflight_failed",
                actor="nessus-sync",
                summary=f"Preflight failed: {err[:500]}",
            )
            db.commit()
            return {"status": "failed", "error": err, "preflight": True}

        execute(
            db,
            "UPDATE vuln_scan_jobs SET status = 'running', started_at = NOW(), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
            {"id": scan_job_id},
        )
        db.commit()

        from app.config import get_settings

        settings = get_settings()
        from app.services.scanner_credentials import (
            is_edge_agent_scanner,
            is_remote_scanner_url,
            normalize_scanner_url,
        )

        scanner_url = ""
        scanner_edition = None
        scanner_api_key_ref = None
        scanner_row = None
        if job.get("scanner_id"):
            sc = fetchone(
                db,
                "SELECT url, edition, api_key_ref, connection_mode FROM vuln_scanners WHERE id = CAST(:id AS uuid)",
                {"id": str(job["scanner_id"])},
            )
            if sc:
                scanner_row = sc
                scanner_url = normalize_scanner_url(sc.get("url") or "") or str(sc.get("url") or "")
                scanner_edition = sc.get("edition")
                scanner_api_key_ref = sc.get("api_key_ref")

        if is_edge_agent_scanner(scanner_row):
            execute(
                db,
                "UPDATE vuln_scan_jobs SET status = 'queued', updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"id": scan_job_id},
            )
            db.commit()
            return {"status": "queued_for_edge_agent", "scan_job_id": scan_job_id}

        orch_enabled = False
        if isinstance(orch_raw, dict):
            orch_enabled = bool(orch_raw.get("enabled"))
        elif orch_raw:
            orch_enabled = True
        # Never orchestrate on premise for a remote on-site OpenVAS (nmap would miss client LAN).
        use_orchestrator = (
            (orch_enabled or (orch_raw is None and settings.vuln_orchestration_enabled))
            and not is_remote_scanner_url(scanner_url)
            and not is_edge_agent_scanner(scanner_row)
        )
        if use_orchestrator:
            from app.services.scan_orchestrator import run_orchestrated_scan

            custom_checks = _fetch_active_custom_checks(db)
            custom_payload = [
                {
                    "id": str(c["id"]),
                    "name": c["name"],
                    "severity_hint": c.get("severity_hint"),
                    "cve_hint": c.get("cve_hint"),
                    "pci_requirement_tag": c.get("pci_requirement_tag"),
                }
                for c in custom_checks
            ]
            result = run_orchestrated_scan(
                db,
                schema_name=schema_name,
                job=job,
                scan_job_id=scan_job_id,
                targets=targets,
                scanner_url=scanner_url,
                scanner_edition=scanner_edition,
                custom_checks=custom_payload,
            )
            result_status = str(result.get("status") or "failed").lower()
            timeline(
                db,
                case_id=str(job["case_id"]),
                source_type="scan_job",
                source_id=scan_job_id,
                event_type="scan.completed" if result_status == "completed" else "scan.failed",
                actor="orchestrator",
                summary=(
                    f"Multi-engine scan completed ({result.get('findings_ingested', 0)} findings)"
                    if result_status == "completed"
                    else f"Multi-engine scan failed: {result.get('error') or 'required scanner failed'}"
                )[:500],
            )
            db.commit()
            return result

        target_str = ",".join(t["target"] for t in active_targets)
        credentialed = any(t.get("credential_ref") for t in active_targets)

        custom_checks = _fetch_active_custom_checks(db)
        custom_payload = [
            {
                "id": str(c["id"]),
                "name": c["name"],
                "severity_hint": c.get("severity_hint"),
                "cve_hint": c.get("cve_hint"),
                "pci_requirement_tag": c.get("pci_requirement_tag"),
            }
            for c in custom_checks
        ]

        client = get_scanner_client(
            edition=scanner_edition,
            base_url=scanner_url,
            api_key_ref=scanner_api_key_ref,
        )
        external_id = job.get("external_scan_id")
        try:
            if not external_id:
                created = client.create_scan(name=f"platform-{scan_job_id[:8]}", targets=target_str)
                scan_obj = created.get("scan") or {}
                external_id = str(scan_obj.get("id") or f"stub-{scan_job_id[:8]}")
                execute(
                    db,
                    "UPDATE vuln_scan_jobs SET external_scan_id = :eid, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                    {"eid": external_id, "id": scan_job_id},
                )
                db.commit()
            if not str(external_id).startswith("stub-"):
                client.launch_scan(external_id)
            details = client.scan_details(external_id)
            details = enrich_stub_scan_details(details, credentialed=credentialed, custom_checks=custom_payload)
        except Exception as exc:
            execute(
                db,
                "UPDATE vuln_scan_jobs SET status = 'failed', error = :err, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"err": str(exc)[:2000], "id": scan_job_id},
            )
            timeline(
                db,
                case_id=str(job["case_id"]),
                source_type="scan_job",
                source_id=scan_job_id,
                event_type="scan.failed",
                actor="nessus-sync",
                summary=f"Scan failed: {exc}",
            )
            db.commit()
            return {"status": "failed", "error": str(exc)}

        if details.get("stub") and not bool(getattr(settings, "vuln_allow_stub_findings", False)):
            err = details.get("message") or "Scanner returned stub/test data; live scanner is unavailable"
            execute(
                db,
                "UPDATE vuln_scan_jobs SET status = 'failed', error = :err, completed_at = NOW(), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"err": str(err)[:2000], "id": scan_job_id},
            )
            timeline(
                db,
                case_id=str(job["case_id"]),
                source_type="scan_job",
                source_id=scan_job_id,
                event_type="scan.failed",
                actor="nessus-sync",
                summary=f"Live scanner unavailable: {err}"[:500],
            )
            db.commit()
            return {"status": "failed", "error": str(err), "stub": True}

        info_status = (details.get("info") or {}).get("status") or "completed"
        progress = int((details.get("info") or {}).get("progress") or 0)
        if info_status == "running" and not details.get("stub"):
            execute(
                db,
                """UPDATE vuln_scan_jobs SET status = 'running', updated_at = NOW()
                   WHERE id = CAST(:id AS uuid)""",
                {"id": scan_job_id},
            )
            db.commit()
            try:
                from app.tasks import nessus_scan_sync_task

                nessus_scan_sync_task.apply_async((schema_name, scan_job_id), countdown=60)
            except Exception:
                pass
            return {"status": "running", "scan_job_id": scan_job_id, "progress": progress, "external_scan_id": external_id}

        if job.get("scanner_id"):
            execute(
                db,
                "UPDATE vuln_scanners SET last_heartbeat_at = NOW(), updated_at = NOW() WHERE id = CAST(:sid AS uuid)",
                {"sid": str(job["scanner_id"])},
            )

        case_id = str(job["case_id"])
        policy_pci = False
        if job.get("policy_id"):
            pol = fetchone(
                db,
                "SELECT compliance_framework FROM vuln_scan_policies WHERE id = CAST(:id AS uuid)",
                {"id": str(job["policy_id"])},
            )
            policy_pci = (pol or {}).get("compliance_framework") == "PCI-DSS"

        for t in active_targets:
            existing = fetchone(
                db,
                """SELECT id, criticality, external_exposure FROM vuln_assets
                   WHERE case_id = CAST(:cid AS uuid) AND (primary_ip = :t OR hostname = :t)
                   LIMIT 1""",
                {"cid": case_id, "t": t["target"]},
            )
            if existing:
                asset_id = str(existing["id"])
                asset_meta = {
                    "criticality": existing.get("criticality") or "tier2",
                    "external_exposure": existing.get("external_exposure") or "internal",
                }
            else:
                asset = fetchone(
                    db,
                    """INSERT INTO vuln_assets (case_id, hostname, primary_ip, asset_type, risk_score,
                       criticality, external_exposure)
                       VALUES (CAST(:cid AS uuid), :host, :ip, 'host', 0, 'tier2', 'internal')
                       RETURNING id""",
                    {"cid": case_id, "host": t["target"], "ip": t["target"]},
                )
                asset_id = str(asset["id"])
                asset_meta = {"criticality": "tier2", "external_exposure": "internal"}
                execute(
                    db,
                    """INSERT INTO vuln_asset_identifiers (asset_id, id_type, value, source)
                       VALUES (CAST(:aid AS uuid), 'network', :val, 'scan')""",
                    {"aid": asset_id, "val": t["target"]},
                )

            vulns = details.get("vulnerabilities") or []
            for v in vulns:
                if policy_pci and not v.get("pci_requirement_tag"):
                    from app.services.vuln_pci import infer_pci_requirement

                    req = infer_pci_requirement(v.get("plugin_name") or v.get("synopsis"), v.get("cve"), None)
                    if req:
                        v = dict(v)
                        v["pci_requirement_tag"] = req
                fid = upsert_finding(
                    db,
                    case_id=case_id,
                    scan_job_id=scan_job_id,
                    asset_id=asset_id,
                    vuln=v,
                    asset_meta=asset_meta,
                    credentialed=credentialed,
                    source="scan",
                )
                if fid:
                    try:
                        from app.services.vuln_brd import save_risk_score_history

                        scored_row = fetchone(
                            db,
                            "SELECT enterprise_risk_score, risk_band, risk_factors_json FROM vuln_findings WHERE id = CAST(:id AS uuid)",
                            {"id": fid},
                        )
                        if scored_row:
                            save_risk_score_history(
                                db,
                                finding_id=fid,
                                asset_id=asset_id,
                                scored={
                                    "enterprise_risk_score": scored_row["enterprise_risk_score"],
                                    "risk_band": scored_row["risk_band"],
                                    "risk_factors_json": scored_row.get("risk_factors_json") or {},
                                },
                            )
                    except Exception:
                        log.debug("risk history write skipped", exc_info=True)
            refresh_asset_risk(db, asset_id)

        status = (details.get("info") or {}).get("status") or "completed"
        if status in ("completed", "canceled", "cancelled") or details.get("stub"):
            execute(
                db,
                """UPDATE vuln_scan_jobs
                   SET status = 'completed', completed_at = NOW(), updated_at = NOW()
                   WHERE id = CAST(:id AS uuid)""",
                {"id": scan_job_id},
            )
            timeline(
                db,
                case_id=case_id,
                source_type="scan_job",
                source_id=scan_job_id,
                event_type="scan.completed",
                actor="nessus-sync",
                summary="Scan completed and results ingested",
            )
            try:
                from app.services.vuln_brd import record_scan_result

                record_scan_result(
                    db,
                    scan_job_id=scan_job_id,
                    hosts_attempted=len(active_targets),
                    hosts_assessed=len(active_targets),
                    credential_success=1 if credentialed else 0,
                    result_json={
                        "external_scan_id": external_id,
                        "stub": bool(details.get("stub")),
                        "edition": scanner_edition,
                        "assessment_complete": True,
                        "assessed_hosts": [t["target"] for t in active_targets],
                    },
                )
            except Exception:
                log.debug("scan_result write skipped", exc_info=True)
        db.commit()
        return {
            "status": "completed",
            "scan_job_id": scan_job_id,
            "external_scan_id": external_id,
            "at": datetime.now(timezone.utc).isoformat(),
        }
