"""One-minute decisions and cancellation confined to a stage's owned process."""
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import subprocess
import sys
import os
import time
from pathlib import Path
import pytest
from app.services import progress_agent as progress
from app.services import forensic_stage_worker as worker
from app.services.forensic_serial_pipeline import StageWaiting

NOW=datetime(2026,10,6,12,tzinfo=timezone.utc)


@pytest.mark.skipif(not sys.platform.startswith('linux'),reason='Linux parent-death protection')
def test_stage_stops_executing_after_abrupt_owner_loss():
    child_code="from app.services.forensic_stage_worker import _guard_owner; import os,time; _guard_owner(); print(os.getpid(),flush=True); time.sleep(30)"
    parent_code=("import os,subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"+repr(child_code)+"],stdout=subprocess.PIPE,text=True,env={**os.environ,'AETHERIS_STAGE_OWNER_PID':str(os.getpid())}); print(p.stdout.readline().strip(),flush=True); os._exit(0)")
    backend=Path(__file__).resolve().parents[1]
    started=time.monotonic()
    result=subprocess.run([sys.executable,'-c',parent_code],capture_output=True,text=True,timeout=10,
        env={**os.environ,'PYTHONPATH':str(backend)})
    assert result.returncode==0,result.stderr
    assert int(result.stdout.strip())>0 and not result.stderr
    # The child inherits the captured stderr descriptor. communicate cannot
    # reach EOF while that 30-second sleeper survives its owning parent.
    assert time.monotonic()-started<5


def stage(**overrides):
    return {'stage':'parse','status':'running','started_at':NOW-timedelta(seconds=100),
            'progress_at':NOW-timedelta(seconds=61),'heartbeat_at':NOW-timedelta(seconds=2),**overrides}


@pytest.mark.parametrize('entry,decision',[
    (stage(progress_at=NOW-timedelta(seconds=59)),'progressing'),
    (stage(),'cancel'),
    (stage(heartbeat_at=NOW-timedelta(seconds=61)),'recover'),
    (stage(operation_deadline=NOW+timedelta(seconds=30),operation='Vision inference'),'valid_wait'),
    (stage(operation_deadline=NOW-timedelta(seconds=1)),'cancel'),
    (stage(status='queued',updated_at=NOW-timedelta(seconds=59)),'valid_wait'),
    (stage(status='waiting',updated_at=NOW-timedelta(seconds=61),error='GPU lease capacity unavailable'),'retry_dependency'),
    (stage(status='failed',error='damaged source database'),'blocked'),
    (stage(status='failed',error='connection reset',attempt=1),'recover'),
    (stage(status='failed',error="('Connection broken: IncompleteRead(874677952 bytes read, 1131901466 more expected)', IncompleteRead(874677952 bytes read, 1131901466 more expected))",attempt=5,recovery_dispatches=0),'recover'),
    (stage(status='failed',error='connection reset',attempt=1,recovery_dispatches=3),'blocked'),
])
def test_meaningful_progress_and_bounded_waits(entry,decision):
    assert progress.classify_stage({},entry,now=NOW)[0]==decision


def test_user_pause_never_recovers_a_process():
    assert progress.classify_stage({'stop_requested':True},stage(),now=NOW)[0]=='valid_wait'
    assert progress.classify_stage({'status':'paused'},stage(),now=NOW)[0]=='valid_wait'


def test_only_one_coordinator_and_no_embedding_or_repair_agent():
    from app.services.action_agents import list_all_process_agents
    roles=list_all_process_agents()
    assert [role['id'] for role in roles if role['role']=='control']==['progressAgent']
    assert len([role for role in roles if role['role']=='action'])==14
    assert not {role['id'] for role in roles}&{'repair_agent','observe_agent','performance_agent','embed_agent'}


def test_queue_inspection_is_cached_and_missing_worker_is_a_valid_dependency(monkeypatch):
    calls=[]
    def inspect(**kwargs):
        calls.append(kwargs);return SimpleNamespace(active_queues=lambda:{},active=lambda:{})
    monkeypatch.setattr('celery.current_app',SimpleNamespace(control=SimpleNamespace(inspect=inspect)))
    monkeypatch.setattr(progress,'_QUEUE_STATE',(0,None))
    assert progress.queue_delivery_state('android-parse')[0]=='valid_wait'
    assert progress.queue_delivery_state('android-parse')[0]=='valid_wait'
    assert len(calls)==1


def test_owned_stage_success_round_trips_json(monkeypatch):
    original=subprocess.Popen;created=[]
    def launch(args,**kwargs):
        code='import json,sys;open(sys.argv[1],"w").write(json.dumps({"result":{"status":"ok","completed":7}}))'
        process=original([sys.executable,'-c',code,args[-1]],**kwargs);created.append(process);return process
    monkeypatch.setattr(worker.subprocess,'Popen',launch)
    monkeypatch.setattr(worker,'fetchone',lambda *a,**kw:{'stop_requested':False,'status':'indexing','cancel_requested_at':None})
    assert worker.execute_isolated_stage(SimpleNamespace(commit=lambda:None),'job','parse',schema_name='schema',stage_run_id='stage')['completed']==7
    assert created[0].poll()==0


def test_cancelled_stage_does_not_kill_unrelated_process(monkeypatch):
    monkeypatch.setattr(worker,'_owned_lease_tokens',lambda pid:[])
    original=subprocess.Popen
    peer=original([sys.executable,'-c','import time;time.sleep(10)'],start_new_session=True)
    created=[]
    def launch(args,**kwargs):
        process=original([sys.executable,'-c','import time;time.sleep(10)'],**kwargs);created.append(process);return process
    monkeypatch.setattr(worker.subprocess,'Popen',launch)
    monkeypatch.setattr(worker,'fetchone',lambda *a,**kw:{'cancel_requested_at':NOW,'stop_requested':False,'status':'indexing'})
    try:
        with pytest.raises(StageWaiting,match='progressAgent'):
            worker.execute_isolated_stage(SimpleNamespace(commit=lambda:None),'job','parse',schema_name='schema',stage_run_id='stage')
        assert created[0].poll() is not None and peer.poll() is None
    finally:peer.terminate();peer.wait(timeout=2)


def test_process_crash_is_retryable_and_no_result_is_not_success(monkeypatch):
    original=subprocess.Popen
    monkeypatch.setattr(worker.subprocess,'Popen',lambda args,**kwargs:original([sys.executable,'-c','raise SystemExit(7)'],**kwargs))
    monkeypatch.setattr(worker,'fetchone',lambda *a,**kw:{'stop_requested':False,'status':'indexing','cancel_requested_at':None})
    with pytest.raises(StageWaiting,match='without a result'):
        worker.execute_isolated_stage(SimpleNamespace(commit=lambda:None),'job','parse',schema_name='schema',stage_run_id='stage')


def test_owned_lease_cleanup_keeps_other_pid_and_replaced_tokens(monkeypatch):
    from app.services import job_locks,adaptive_semaphore
    owned={'pid':1234,'boot_id':'boot-fixture','token':'owned-token'}
    other={'pid':4321,'boot_id':'boot-fixture','token':'other-token'}
    values={'owned':owned,'other':other};removed=[]
    monkeypatch.setattr(job_locks,'_redis_client',lambda:object())
    monkeypatch.setattr(job_locks,'_cpu_slot_keys',lambda:['owned','other'])
    monkeypatch.setattr(job_locks,'_gpu_slot_keys',lambda:[])
    monkeypatch.setattr(job_locks,'_lock_held',lambda key:values.get(key))
    monkeypatch.setattr(job_locks,'_container_boot_id',lambda:'boot-fixture')
    def compare_delete(client,key,token):
        if values.get(key,{}).get('token')==token:removed.append(key)
    monkeypatch.setattr(job_locks,'_atomic_release_heavy',compare_delete)
    monkeypatch.setattr(adaptive_semaphore,'_redis_client',lambda:SimpleNamespace(get=lambda key:None))
    tokens=worker._owned_lease_tokens(1234)
    assert len(tokens)==1 and tokens[0][2]=='owned'
    values['owned']={**owned,'token':'replacement-token'}
    for release,client,key,token in tokens:release(client,key,token)
    assert removed==[] and values['other']['token']=='other-token'


def test_closed_database_connection_is_retryable():
    decision, _reason = progress.classify_stage(
        {},
        stage(status="failed", error="(psycopg2.InterfaceError) connection already closed", recovery_dispatches=0),
        now=NOW,
    )
    assert decision == "recover"


def test_stage_process_keeps_the_worker_idle_timeout(monkeypatch):
    from app.db.session import _idle_in_transaction_timeout

    monkeypatch.setattr(sys, "argv", ["python", "-m", "app.services.forensic_stage_worker", "firm", "job", "parse"])
    monkeypatch.setenv("IDLE_IN_TRANSACTION_SESSION_TIMEOUT", "0")
    monkeypatch.delenv("CELERY_LOADER", raising=False)
    monkeypatch.setenv("AETHERIS_STAGE_OWNER_PID", "4242")
    assert _idle_in_transaction_timeout() == "0"
