"""Execute one stage in an owned subprocess so stuck work can be cancelled."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import logging
import socket
from contextlib import nullcontext

from app.db.sql_helpers import fetchone

log=logging.getLogger('forensic.stage_process')


def _guard_owner():
    """On Linux, an abruptly lost worker must not leave the stage executing."""
    owner=os.environ.pop('AETHERIS_STAGE_OWNER_PID',None)
    if not owner or not sys.platform.startswith('linux'):
        return
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)]
    libc.prctl.restype=ctypes.c_int
    if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(),'Cannot protect stage owner lifetime')
    # Parent loss can precede prctl; checking after registration closes that race.
    if os.getppid()!=int(owner):
        os._exit(70)


def _owned_lease_tokens(pid):
    """Snapshot only this container's owned PID and compare-delete its tokens."""
    from app.services import job_locks, adaptive_semaphore
    found=[]
    try:
        client=job_locks._redis_client()
        for key in [*job_locks._cpu_slot_keys(),*job_locks._gpu_slot_keys()]:
            holder=job_locks._lock_held(key)
            if holder and holder.get('pid')==pid and holder.get('boot_id')==job_locks._container_boot_id() and holder.get('token'):
                found.append((job_locks._atomic_release_heavy,client,key,holder['token']))
    except Exception as exc:
        log.debug('Owned local lease snapshot unavailable: %s',exc)
    try:
        client=adaptive_semaphore._redis_client()
        for resource in ('gpu','cpu_heavy','extract_job','materialize'):
            for index in range(adaptive_semaphore._host_namespace_limit(resource)):
                key=adaptive_semaphore._key(resource,index);raw=client.get(key)
                holder=json.loads(raw) if raw else {}
                if holder.get('pid')==pid and holder.get('host')==socket.gethostname() and holder.get('token'):
                    found.append((adaptive_semaphore._compare_token_and_delete,client,key,holder['token']))
    except Exception as exc:
        log.debug('Owned host lease snapshot unavailable: %s',exc)
    return found


def _stop_owned_process(process):
    if process.poll() is not None:
        return
    tokens=_owned_lease_tokens(process.pid)
    try:
        if os.name=='posix':
            os.killpg(process.pid,signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        process.wait(timeout=5)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if os.name=='posix':
                os.killpg(process.pid,signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
    if process.poll() is not None:
        for release,client,key,token in tokens:
            try:
                release(client,key,token)
            except Exception as exc:
                log.debug('Owned lease release unavailable: %s',exc)


def execute_isolated_stage(db,job_id,stage,*,schema_name,stage_run_id):
    from app.services.forensic_serial_pipeline import StageWaiting
    with tempfile.TemporaryDirectory(prefix='aetheris_stage_') as temporary:
        output=Path(temporary)/'result.json'
        process=subprocess.Popen([sys.executable,'-m','app.services.forensic_stage_worker',schema_name,
            str(job_id),stage,str(stage_run_id),str(output)],start_new_session=os.name=='posix',
            env={**os.environ,'AETHERIS_STAGE_OWNER_PID':str(os.getpid())})
        try:
            while process.poll() is None:
                table='report_runs' if stage=='__report__' else 'pipeline_stage_runs'
                control=fetchone(db,f"""SELECT s.cancel_requested_at,j.stop_requested,j.status
                    FROM {table} s JOIN jobs j ON j.id=s.job_id WHERE s.id=:id""",{'id':stage_run_id})
                if stage=='__report__':
                    from app.db.sql_helpers import execute
                    execute(db,'UPDATE report_runs SET heartbeat_at=NOW() WHERE id=:id',{'id':stage_run_id})
                db.commit()
                if not control or control.get('cancel_requested_at') or control.get('stop_requested') or control.get('status')=='paused':
                    _stop_owned_process(process)
                    raise StageWaiting('Stage process interrupted by progressAgent or user pause')
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            if not output.is_file():
                raise StageWaiting(f'Stage process exited without a result (exit {process.returncode})')
            result=json.loads(output.read_text())
            if result.get('error'):
                if result.get('kind')=='waiting':
                    raise StageWaiting(result['error'])
                raise RuntimeError(result['error'])
            return result['result']
        finally:
            _stop_owned_process(process)


def main(argv=None):
    _guard_owner()
    schema,job_id,stage,stage_id,path=list(argv or sys.argv[1:])
    from app.db.session import firm_session
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.forensic_serial_policy import stage_context
    from app.services.forensic_serial_stages import execute_stage
    from app.services.progress_agent import note_operation

    def interrupted(_signal,_frame):
        raise StageWaiting('Stage process cancelled by progressAgent')
    signal.signal(signal.SIGTERM,interrupted)
    try:
        with firm_session(schema) as db,(nullcontext() if stage=='__report__' else stage_context(stage)):
            if stage=='__report__':
                from app.services.report_generator import generate_report
                result={'result':generate_report(db,job_id,schema_name=schema,report_run_id=stage_id)}
            else:
                note_operation(db,job_id,stage,f'{stage}: bounded evidence operation',timeout_seconds=float(os.environ.get('FORENSIC_STAGE_IDLE_TIMEOUT_SECONDS','300')))
                result={'result':execute_stage(db,job_id,stage,schema_name=schema,stage_run_id=stage_id)}
    except Exception as exc:
        from app.services.db_resilience import is_transient_db_error
        from app.services.storage import is_transient_stream_error
        waiting=isinstance(exc,StageWaiting) or is_transient_db_error(exc) or is_transient_stream_error(exc) or type(exc).__name__ in {
            'GpuHeavySlotTimeout','GpuThermalAbort','ResourceSemaphoreTimeout','CpuHeavySlotTimeout'}
        result={'error':str(exc)[:4000],'kind':'waiting' if waiting else 'failed'}
    finally:
        if stage in {'ocr','media_review'}:
            from app.celery_factory import _release_on_shutdown
            _release_on_shutdown()
        else:
            from app.services.job_locks import release_cpu_heavy_slot
            release_cpu_heavy_slot()
    destination=Path(path)
    destination.write_text(json.dumps(result,default=str));destination.chmod(0o600)
    return 0 if 'result' in result else 1


if __name__=='__main__':
    raise SystemExit(main())


def run_isolated_report(schema_name,job_id,report_run_id=None,*,task_id=None):
    from app.db.session import firm_session
    from app.db.sql_helpers import execute
    from app.services.forensic_serial_pipeline import pipeline_execution_lock, StageWaiting
    from app.services.progress_agent import ensure_progress_schema
    with firm_session(schema_name) as db:
        ensure_progress_schema(db)
        with pipeline_execution_lock(db,schema_name,'report:'+str(job_id)) as acquired:
            if not acquired:
                return {'status':'held','reason':'An existing report process owns this job'}
            if report_run_id is None:
                report_run_id=str(fetchone(db,"INSERT INTO report_runs(job_id,status,started_at) VALUES(:jid,'queued',NOW()) RETURNING id",{'jid':job_id})['id'])
            run=fetchone(db,'SELECT * FROM report_runs WHERE id=:rid AND job_id=:jid',{'rid':report_run_id,'jid':job_id})
            if not run or run['status']=='completed':
                return {'status':'held','reason':'Report missing or already complete'}
            execute(db,"""UPDATE report_runs SET status='running',owner_task_id=:tid,heartbeat_at=NOW(),progress_at=NOW(),
                cancel_requested_at=NULL,operation_deadline=NOW()+INTERVAL '330 seconds' WHERE id=:id""",{'id':report_run_id,'tid':task_id})
            db.commit()
            try:
                return execute_isolated_stage(db,job_id,'__report__',schema_name=schema_name,stage_run_id=report_run_id)
            except Exception as exc:
                db.rollback()
                waiting=isinstance(exc,StageWaiting)
                execute(db,'UPDATE report_runs SET status=:status,error=:error,heartbeat_at=NOW() WHERE id=:id',{'id':report_run_id,'status':'waiting' if waiting else 'failed','error':str(exc)[:2000]})
                db.commit()
                if not waiting:
                    raise
                return {'status':'waiting','error':str(exc),'report_run_id':report_run_id}
