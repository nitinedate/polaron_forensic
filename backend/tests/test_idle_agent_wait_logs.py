from unittest.mock import MagicMock, patch

import pytest

from app.services.disk_build_log import write_disk_log, write_disk_logs_batch
from app.services.pipeline_supervisor import dispatch_stage_agent
from app.services.retired_agents import is_idle_agent_wait_message, visible_pipeline_logs_sql


@pytest.mark.parametrize('agent,reason', [
    ('artifacts_agent', 'artifacts to exist'),
    ('ontology_agent', 'Entity Agent / graph'),
    ('annotation_agent', 'Entity Agent / graph'),
    ('neo4j_agent', 'a RAG/chunk baseline'),
    ('entity_agent', 'Neo4j Graph Agent'),
    ('chunk_agent', 'artifacts'),
    ('ocr_agent', 'parsed files'),
])
def test_pending_agent_chatter_never_writes_logs(agent, reason):
    msg = f'[{agent}] wait— blocked: Waiting for {reason}'
    assert is_idle_agent_wait_message(msg)
    db = MagicMock()
    with patch('app.services.disk_build_log.execute') as insert:
        write_disk_log(db, 'job', msg)
    insert.assert_not_called()
    assert not db.mock_calls


@pytest.mark.parametrize('level',['warning','warn','error','critical'])
def test_dependency_warnings_and_errors_remain_visible(level):
    msg='[ocr_agent] wait— blocked: Waiting for parsed files'
    assert not is_idle_agent_wait_message(msg, level)
    db=MagicMock()
    with patch('app.services.disk_build_log.execute') as insert:
        write_disk_log(db,'job',msg,level=level)
    insert.assert_called_once()
    db.flush.assert_called_once()


@pytest.mark.parametrize('msg',[
    '[chunk_agent] started: 20 artifacts',
    '[entity_agent] completed',
    'Suspicious chat says Waiting for artifacts',
    'progressAgent: source database missing',
    '[Supervisor] thermal_wait — GPU too hot',
    '[ocr_agent] wait— blocked: Database connection failed',
])
def test_real_progress_evidence_and_faults_are_kept(msg):
    assert not is_idle_agent_wait_message(msg)
    db=MagicMock()
    with patch('app.services.disk_build_log.execute') as insert:
        write_disk_log(db,'job',msg)
    insert.assert_called_once()


def test_batch_drops_idle_only_and_preserves_error_and_started():
    msg='[artifacts_agent] wait— blocked: Waiting for artifacts to exist'
    db=MagicMock()
    write_disk_logs_batch(db,'job',[
        {'message':msg}, {'message':msg,'level':'debug'},
        {'message':msg,'level':'error'}, {'message':'Serial stage started: inventory'},
    ],flush=True)
    payload=db.execute.call_args.args[1]
    assert [r['level'] for r in payload]==['error','info']
    assert payload[-1]['message']=='Serial stage started: inventory'
    db.flush.assert_called_once()


@pytest.mark.parametrize('action',['wait','waiting','pending','blocked',' WAIT '])
def test_wait_recommendation_cannot_dispatch_repair_or_touch_db(action):
    db=MagicMock()
    with patch('app.services.forensic_serial_pipeline.start_serial_pipeline') as start, \
         patch('app.services.pipeline_supervisor.write_disk_log') as log:
        result=dispatch_stage_agent(db,'job',schema_name='firm',coordinator='progressAgent',
            recommendation={'agent_id':'ontology_agent','action':action,'reason':'Waiting for Entity Agent / graph'})
    assert result['status']=='waiting'
    start.assert_not_called()
    log.assert_not_called()
    assert not db.mock_calls


def test_non_wait_recommendation_still_enters_pipeline():
    db=MagicMock()
    with patch('app.services.forensic_serial_pipeline.stage_rows',return_value=[{'stage':'parse'}]), \
         patch('app.services.forensic_serial_pipeline.start_serial_pipeline',return_value={'status':'queued'}) as start:
        result=dispatch_stage_agent(db,'job',schema_name='firm',coordinator='progressAgent',
            recommendation={'agent_id':'parse_agent','action':'parse','reason':'Extraction finished'})
    assert result['status']=='queued'
    start.assert_called_once_with(db,'job',schema_name='firm')


def test_existing_log_reads_filter_idle_rows_but_not_error_levels():
    sql=visible_pipeline_logs_sql('l.message')
    assert "LOWER(l.level)" in sql
    assert "NOT IN ('info','debug')" in sql
    assert 'Waiting' in sql and 'Observe|Performance|Repair' in sql
    assert 'LOWER(level)' in visible_pipeline_logs_sql()
    with pytest.raises(ValueError):
        visible_pipeline_logs_sql('injected column')
