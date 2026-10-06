"""The single Disk/Mobile progress coordinator; no voting or competing repairs."""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone

from app.db.sql_helpers import execute, fetchall, fetchone

CHECK_AFTER_SECONDS = 60
MAX_RECOVERY_ATTEMPTS = 3
_SCHEMA_READY = set()
_QUEUE_STATE = (0, None)
PROGRESS_AGENT = {
    "id": "progressAgent", "name": "progressAgent", "role": "control",
    "lane": "control", "stage": "orchestration",
    "action": "Check each job's real progress, classify one-minute stalls and recover its current stage",
    "description": "One coordinator; respects pauses, bounded operations, dependencies and product ownership.",
    "consults": [], "task": "app.tasks.progress_agent_task",
}


def progress_queue(service=None):
    from app.service_identity import current_service
    return {"forensic": "disk-progress", "mobile-android": "android-progress",
            "mobile-ios": "ios-progress", "mobile-extract": "mobile-progress"}.get(service or current_service(), "disk-progress")


def report_queue():
    from app.service_identity import current_service
    return {'mobile-android':'android-report','mobile-ios':'ios-report','mobile-extract':'mobile-build'}.get(current_service(),'report-gen')


def ensure_progress_schema(db):
    from app.services.forensic_serial_pipeline import ensure_serial_schema
    schema=fetchone(db,"SELECT current_schema() AS name")['name']
    key=(str(getattr(db,'bind','')),schema)
    if key in _SCHEMA_READY:
        return
    ensure_serial_schema(db)
    execute(db, """CREATE TABLE IF NOT EXISTS pipeline_progress_events (
        id bigserial PRIMARY KEY,job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        stage text,decision text NOT NULL,reason text NOT NULL,details jsonb NOT NULL DEFAULT '{}',
        created_at timestamptz NOT NULL DEFAULT NOW())""")
    execute(db, "CREATE INDEX IF NOT EXISTS progress_events_job ON pipeline_progress_events(job_id,created_at DESC)")
    execute(db, """CREATE TABLE IF NOT EXISTS pipeline_progress_checks (
        job_id uuid PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
        fingerprint text NOT NULL,last_change_at timestamptz NOT NULL DEFAULT NOW(),
        checked_at timestamptz NOT NULL DEFAULT NOW(),decision text,reason text)""")
    execute(db, 'ALTER TABLE pipeline_stage_runs ADD COLUMN IF NOT EXISTS recovery_dispatches integer NOT NULL DEFAULT 0')
    from app.services.suspicious_activity import ensure_suspicious_schema
    ensure_suspicious_schema(db)
    if fetchone(db,"SELECT to_regclass('report_runs') AS t")['t']:
        for column in ('owner_task_id text','heartbeat_at timestamptz','progress_at timestamptz','operation_deadline timestamptz','cancel_requested_at timestamptz','recovery_dispatches integer NOT NULL DEFAULT 0'):
            execute(db,f'ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS {column}')
        execute(db,"CREATE INDEX IF NOT EXISTS progress_report_active_job ON report_runs(job_id,created_at DESC) WHERE status IN ('running','queued','waiting')")
    db.commit()
    _SCHEMA_READY.add(key)


def _age(value, now):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not value:
        return float("inf")
    return max(0, (now - value.replace(tzinfo=timezone.utc) if value.tzinfo is None else now - value).total_seconds())


def _obj(value):
    return json.loads(value) if isinstance(value, str) else value or {}


def classify_stage(job, stage, *, now=None):
    """A heartbeat proves liveness, never that useful work advanced."""
    now = now or datetime.now(timezone.utc)
    if job.get("stop_requested") or job.get("status") == "paused":
        return "valid_wait", "Paused by the user or thermal protection"
    state = stage.get("status")
    if state in {"done", "skipped"}:
        return "complete", "Stage finished"
    progress_age = _age(stage.get("progress_at") or stage.get("started_at") or stage.get("updated_at"), now)
    if state == "failed":
        error = str(stage.get("error") or "").lower()
        retryable = any(token in error for token in ("deadlock", "connection reset", "server closed", "process exited", "timed out", "stage process", "progressagent"))
        return ("recover", "Transient stage failure") if retryable and int(stage.get("attempt") or 0) <= MAX_RECOVERY_ATTEMPTS else ("blocked", "Failed stage needs a source/dependency correction")
    if state == "running" and progress_age < CHECK_AFTER_SECONDS:
        return "progressing", "Useful work advanced within the last minute"
    if state == "running":
        deadline = stage.get("operation_deadline")
        if deadline and _age(deadline, now) == 0:
            return "valid_wait", f"Bounded operation in progress: {stage.get('operation') or stage['stage']}"
        if _age(stage.get('heartbeat_at'),now)>=CHECK_AFTER_SECONDS:
            return 'recover','Owning stage heartbeat is stale and its operation deadline expired'
        return "cancel", "No useful progress for one minute and no unexpired operation deadline"
    if state == "queued" and _age(stage.get("updated_at"), now) < CHECK_AFTER_SECONDS:
        return "valid_wait", "Delivery is within its one-minute queue grace period"
    if state == "waiting" and _age(stage.get("updated_at"), now) < CHECK_AFTER_SECONDS:
        return "valid_wait", str(stage.get("error") or "Waiting for the next dependency check")
    if state == 'waiting' and any(word in str(stage.get('error') or '').lower() for word in ('gpu','thermal','lease','capacity','model','unavailable','dependency','source key')):
        return 'retry_dependency','A bounded dependency wait is ready to be checked again'
    return "recover", "Current stage has no executing claim or its delivery is stale"


def queue_delivery_state(queue):
    """Bounded, cached broker inspection; no destructive revoke/terminate."""
    global _QUEUE_STATE
    if time.monotonic()-_QUEUE_STATE[0]>30 or _QUEUE_STATE[1] is None:
        try:
            from celery import current_app
            inspect=current_app.control.inspect(timeout=1)
            queues=inspect.active_queues() or {}
            active=inspect.active() or {}
            _QUEUE_STATE=(time.monotonic(),(queues,active))
        except Exception:
            _QUEUE_STATE=(time.monotonic(),({},{}))
    queues,active=_QUEUE_STATE[1]
    consumers=[worker for worker,entries in queues.items() if any(entry.get('name')==queue for entry in entries)]
    if not consumers:
        return 'valid_wait','No responding consumer for '+queue+'; check its worker/dependency'
    if all(active.get(worker) for worker in consumers):
        return 'valid_wait','Consumers are executing bounded process work; delivery is queued'
    return 'recover','A consumer is available but the stage delivery is stale'


def _event(db, job_id, stage, decision, reason, *, details=None):
    previous = fetchone(db, "SELECT decision,reason FROM pipeline_progress_checks WHERE job_id=:jid", {"jid": job_id})
    if not previous or previous.get("decision") != decision or previous.get("reason") != reason:
        execute(db, """INSERT INTO pipeline_progress_events(job_id,stage,decision,reason,details)
            VALUES(:jid,:stage,:decision,:reason,CAST(:details AS jsonb))""",
            {"jid": job_id, "stage": stage, "decision": decision, "reason": reason, "details": json.dumps(details or {})})
        from app.services.disk_build_log import write_disk_log
        write_disk_log(db, job_id, f"progressAgent: {reason}", stage=stage or "progress", level="warning" if decision in {"cancel", "blocked"} else "info")
    execute(db, "UPDATE pipeline_progress_checks SET checked_at=NOW(),decision=:d,reason=:r WHERE job_id=:jid", {"jid": job_id, "d": decision, "r": reason})


def note_operation(db, job_id, stage, operation, *, timeout_seconds=300, advanced=False):
    """Declare a bounded operation; heartbeats never extend this deadline."""
    timeout_seconds = max(1, min(float(timeout_seconds), 3600))
    execute(db, """UPDATE pipeline_stage_runs SET operation=:op,
        operation_deadline=NOW()+make_interval(secs=>CAST(:seconds AS double precision)),
        progress_at=CASE WHEN :advanced THEN NOW() ELSE progress_at END
        WHERE job_id=:jid AND stage=:stage AND status='running'""",
        {"jid": job_id, "stage": stage, "op": operation[:300], "seconds": timeout_seconds, "advanced": advanced})
    db.commit()


def monitor_job(db, job_id, *, schema_name):
    from app.services.forensic_serial_pipeline import (STAGES, stage_rows, first_open_stage,
        pipeline_execution_lock, start_serial_pipeline, dispatch_current_stage, persist_snapshot)
    from app.services.mobile_platform_agents import current_service_owns_job
    job = fetchone(db, "SELECT * FROM jobs WHERE id=:jid", {"jid": job_id})
    if not job or not current_service_owns_job(db, job_id):
        return {"status": "held", "reason": "missing_or_other_product", "job_id": job_id}
    report = _monitor_report(db, job, schema_name=schema_name)
    if report is not None:
        return report
    rows = stage_rows(db, job_id)
    if rows and [r['stage'] for r in rows] != [s[0] for s in STAGES]:
        return start_serial_pipeline(db, job_id, schema_name=schema_name)
    active = first_open_stage(rows) if rows else None
    if not active:
        if rows:
            return {"status": "complete", "job_id": job_id}
        return _monitor_acquisition(db, job, schema_name=schema_name)
    fingerprint = hashlib.sha256(json.dumps([active['id'],active['status'],active.get('completed_items'),
        active.get('failed_items'),active.get('skipped_items'),str(active.get('progress_at'))], default=str).encode()).hexdigest()
    execute(db, """INSERT INTO pipeline_progress_checks(job_id,fingerprint) VALUES(:jid,:fp)
        ON CONFLICT(job_id) DO UPDATE SET last_change_at=CASE WHEN pipeline_progress_checks.fingerprint<>EXCLUDED.fingerprint
        THEN NOW() ELSE pipeline_progress_checks.last_change_at END,fingerprint=EXCLUDED.fingerprint,checked_at=NOW()""", {"jid":job_id,"fp":fingerprint})
    decision, reason = classify_stage(job, active)
    if decision=='recover' and active['status']=='queued':
        from app.services.forensic_serial_pipeline import queue_for_stage
        decision,reason=queue_delivery_state(queue_for_stage(active['stage']))
    _event(db,job_id,active['stage'],decision,reason)
    if decision == 'cancel':
        # The owning parent cancels only its dedicated stage subprocess. No
        # broadcast terminate/revoke can kill a worker now executing another job.
        execute(db, """UPDATE pipeline_stage_runs SET cancel_requested_at=COALESCE(cancel_requested_at,NOW())
            WHERE id=:id AND task_id=:tid AND status='running'""", {'id':active['id'],'tid':active.get('task_id')})
        db.commit()
        return {'status':'recovering','reason':reason,'stage':active['stage'],'job_id':job_id}
    db.commit()
    if decision not in {'recover','retry_dependency'}:
        return {'status':decision,'reason':reason,'stage':active['stage'],'job_id':job_id}
    with pipeline_execution_lock(db,schema_name,job_id) as acquired:
        if not acquired:
            return {'status':'valid_wait','reason':'Owning stage is still releasing its execution lock','job_id':job_id}
        fresh=first_open_stage(stage_rows(db,job_id))
        latest=fetchone(db,'SELECT stop_requested,status FROM jobs WHERE id=:jid',{'jid':job_id})
        if not fresh or classify_stage(latest,fresh)[0] not in {'recover','retry_dependency'}:
            return {'status':'held','reason':'Progress changed during inspection','job_id':job_id}
        if decision=='recover' and int(fresh.get('recovery_dispatches') or 0)>=MAX_RECOVERY_ATTEMPTS:
            execute(db,"UPDATE pipeline_stage_runs SET status='failed',error='progressAgent retry budget exhausted',updated_at=NOW() WHERE id=:id",{'id':fresh['id']})
            persist_snapshot(db,job_id);db.commit()
            return {'status':'blocked','reason':'Retry budget exhausted','job_id':job_id}
        execute(db,"""UPDATE pipeline_stage_runs SET status='waiting',task_id=NULL,cancel_requested_at=NULL,
            operation=NULL,operation_deadline=NULL,recovery_dispatches=recovery_dispatches+:increment,updated_at=NOW() WHERE id=:id""",{'id':fresh['id'],'increment':int(decision=='recover')})
        db.commit()
    return {**dispatch_current_stage(db,job_id,schema_name=schema_name),'job_id':job_id,'coordinator':'progressAgent'}


def progress_events_page(db,job_id,*,limit=100):
    exists=fetchone(db,"SELECT to_regclass('pipeline_progress_events') AS t")
    if not exists or not exists['t']:
        return {'events':[],'coordinator':'progressAgent'}
    return {'events':fetchall(db,"SELECT * FROM pipeline_progress_events WHERE job_id=:jid ORDER BY id DESC LIMIT :lim",{'jid':job_id,'lim':max(1,min(int(limit),200))}),'coordinator':'progressAgent'}


def _monitor_acquisition(db, job, *, schema_name):
    """Recover abandoned extraction claims; never duplicate a live extractor."""
    from app.services.forensic_serial_pipeline import start_serial_pipeline
    from app.services.mobile_os import load_job_disk_source
    from app.services.host_evidence import is_client_upload_pending
    if job.get('stop_requested') or job.get('status')=='paused':
        return {'status':'valid_wait','reason':'Paused','job_id':str(job['id'])}
    if is_client_upload_pending(load_job_disk_source(job)):
        return {'status':'valid_wait','reason':'Evidence transfer incomplete','job_id':str(job['id'])}
    if job.get('extracted_disk_uri') and job.get('status') in {'extracted','indexing','indexed','parsed','artifacts_registered'}:
        return start_serial_pipeline(db,str(job['id']),schema_name=schema_name)
    if _age(job.get('updated_at'),datetime.now(timezone.utc)) < CHECK_AFTER_SECONDS:
        return {'status':'progressing','job_id':str(job['id'])}
    checkpoint=_obj(job.get('extraction_checkpoint'))
    if checkpoint.get('state')=='completed' or checkpoint.get('completed') is True:
        return start_serial_pipeline(db,str(job['id']),schema_name=schema_name)
    # Existing extraction locks and worker heartbeats are examined by the
    # domain engine. This coordinator is the only caller of its stage dispatch.
    from app.services.pipeline_supervisor import analyze_job_pipeline, dispatch_stage_agent
    recommendation=analyze_job_pipeline(db,str(job['id']))
    if recommendation and recommendation.get('agent_id') in {'extract_agent','extract_agent_disk','extract_agent_mobile','extract_agent_android','extract_agent_ios','drive_mount_agent','list_folder_agent','segments_agent','virtual_disk_agent','extraction_agent','report_generator_agent'}:
        return dispatch_stage_agent(db,str(job['id']),schema_name=schema_name,recommendation=recommendation,coordinator='progressAgent')
    return {'status':'valid_wait','reason':'Acquisition source, live extractor or dependency has not released its claim','job_id':str(job['id'])}


def supervise_progress(db, *, schema_name):
    from app.services.forensic_serial_pipeline import pipeline_execution_lock
    ensure_progress_schema(db);db.commit()
    from app.service_identity import current_service
    with pipeline_execution_lock(db,schema_name,'progressAgent:'+current_service()) as acquired:
        if not acquired:
            return {'status':'busy','coordinator':'progressAgent','actions':[]}
        actions=[]
        from app.services.mobile_platform_agents import mobile_os_family_from_job_row
        maximum=max(20,min(int(os.environ.get('PROGRESS_AGENT_JOB_BATCH','200')),1000))
        cursor=None;seen=set()
        while len(actions)<maximum:
            predicate=' AND (updated_at,id)>(:after_time,CAST(:after_id AS uuid))' if cursor else ''
            params={'lim':maximum}
            if cursor:params.update(after_time=cursor['updated_at'],after_id=str(cursor['id']))
            rows=fetchall(db,"""SELECT id,type,disk_source,updated_at FROM jobs WHERE stop_requested=FALSE
                AND (status NOT IN ('ready','completed','report_ready','cancelled','deleted','created','registered','awaiting_segments')
                     OR EXISTS(SELECT 1 FROM report_runs r WHERE r.job_id=jobs.id AND r.status IN ('running','queued','waiting')))
                """+predicate+' ORDER BY updated_at,id LIMIT :lim',params)
            if not rows:break
            for row in rows:
                family=mobile_os_family_from_job_row(row);service=current_service()
                owned=(family is None if service=='forensic' else family=='android' if service=='mobile-android' else family=='ios' if service=='mobile-ios' else family in {'android','ios'})
                if not owned or row['id'] in seen:continue
                seen.add(row['id'])
                try:
                    actions.append(monitor_job(db,str(row['id']),schema_name=schema_name))
                except Exception as exc:
                    db.rollback()
                    actions.append({'job_id':str(row['id']),'status':'error','reason':str(exc)[:300]})
                if len(actions)>=maximum:break
            cursor=rows[-1]
        return {'status':'ok','coordinator':'progressAgent','schema':schema_name,'actions':actions}


def _monitor_report(db,job,*,schema_name):
    exists=fetchone(db,"SELECT to_regclass('report_runs') AS t")
    if not exists or not exists['t']:
        return None
    run=fetchone(db,"SELECT * FROM report_runs WHERE job_id=:jid AND status IN ('running','queued','waiting') ORDER BY created_at DESC LIMIT 1",{'jid':job['id']})
    if not run:
        return None
    stage={**run,'stage':'report','updated_at':run.get('heartbeat_at') or run.get('started_at') or run['created_at'],'attempt':run.get('recovery_dispatches',0)}
    decision,reason=classify_stage(job,stage)
    if decision=='recover' and run['status']=='queued':
        decision,reason=queue_delivery_state(report_queue())
    execute(db,"""INSERT INTO pipeline_progress_checks(job_id,fingerprint) VALUES(:jid,:fp)
        ON CONFLICT(job_id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,checked_at=NOW()""",
        {'jid':job['id'],'fp':'report:'+str(run['id'])+':'+str(run.get('progress_at'))})
    _event(db,str(job['id']),'report',decision,reason)
    db.commit()
    if decision=='cancel':
        execute(db,"UPDATE report_runs SET cancel_requested_at=COALESCE(cancel_requested_at,NOW()) WHERE id=:id AND owner_task_id=:tid AND status='running'",{'id':run['id'],'tid':run.get('owner_task_id')});db.commit()
        return {'status':'recovering','stage':'report','reason':reason,'job_id':str(job['id'])}
    if decision in {'recover','retry_dependency'}:
        from app.services.forensic_serial_pipeline import pipeline_execution_lock
        with pipeline_execution_lock(db,schema_name,'report:'+str(job['id'])) as acquired:
            if not acquired:
                return {'status':'valid_wait','stage':'report','reason':'Report owner is releasing its claim'}
            fresh_job=fetchone(db,'SELECT status,stop_requested FROM jobs WHERE id=:jid',{'jid':job['id']})
            run=fetchone(db,'SELECT * FROM report_runs WHERE id=:id',{'id':run['id']})
            if not run or run['status'] not in {'running','queued','waiting'}:
                return {'status':'complete','stage':'report','reason':'Report state changed while checking its claim'}
            stage={**run,'stage':'report','updated_at':run.get('heartbeat_at') or run.get('started_at') or run['created_at']}
            decision,reason=classify_stage(fresh_job or {},stage)
            if decision not in {'recover','retry_dependency'}:
                return {'status':decision,'stage':'report','reason':reason}
            if decision=='recover' and int(run.get('recovery_dispatches') or 0)>=MAX_RECOVERY_ATTEMPTS:
                execute(db,"UPDATE report_runs SET status='failed',error='progressAgent report retry budget exhausted' WHERE id=:id",{'id':run['id']});db.commit()
                return {'status':'blocked','stage':'report','reason':'Report retry budget exhausted'}
            execute(db,"UPDATE report_runs SET status='queued',owner_task_id=NULL,cancel_requested_at=NULL,operation_deadline=NULL,recovery_dispatches=recovery_dispatches+:increment,heartbeat_at=NOW() WHERE id=:id",{'id':run['id'],'increment':int(decision=='recover')});db.commit()
        from app.tasks import report_gen_task
        report_gen_task.apply_async(args=(schema_name,str(job['id']),str(run['id'])),queue=report_queue())
        return {'status':'queued','stage':'report','reason':'Report resumed from its saved sections','job_id':str(job['id'])}
    return {'status':decision,'stage':'report','reason':reason,'job_id':str(job['id'])}
