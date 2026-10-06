"""Acceptance must authenticate real inputs and reject simulated/CPU passes."""
from types import SimpleNamespace
import hashlib
import json
import sqlite3
import sys
import subprocess
import os
from pathlib import Path
import pytest

from app.services import live_acceptance as live
from tests.test_whatsapp_recovery import vector


def plain_database(path, body='Live fixture body is not included in diagnostics'):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE messages(_id INTEGER PRIMARY KEY,key_remote_jid TEXT,key_from_me INTEGER,data TEXT,timestamp INTEGER)')
        connection.execute('INSERT INTO messages VALUES(1,?,?,?,?)',
                           ('contact@s.whatsapp.net',0,body,1700000000000))
    return path


def check_by_name(report, name):
    return next(c for c in report['checks'] if c['name']==name)


@pytest.mark.parametrize('version',['crypt12','crypt14','crypt15'])
def test_independent_backup_authentication_parsing_and_no_secret_diagnostic(tmp_path,version):
    source=tmp_path/'source';source.mkdir()
    backup,key=vector(version)
    (source/('msgstore.db.'+version)).write_bytes(backup)
    (source/'key').write_bytes(key)
    report=live.verify_whatsapp(source,tmp_path/'derived')
    assert report['status']=='passed'
    assert check_by_name(report,'backup_authentication')['evidence']['authenticated_backups']==1
    assert check_by_name(report,'readable_messages')['evidence']['messages']==1
    assert check_by_name(report,'input_integrity')['status']=='pass'
    encoded=json.dumps(report)
    assert key.hex() not in encoded and 'independent crypt fixture chat' not in encoded
    assert hashlib.sha256((source/('msgstore.db.'+version)).read_bytes()).digest()==hashlib.sha256(backup).digest()


@pytest.mark.parametrize('key',[None,b'run-as: package not debuggable\n',b'wrong'.ljust(32,b'!')])
def test_absent_invalid_or_unmatched_key_never_passes(tmp_path,key):
    source=tmp_path/'source';source.mkdir()
    backup,_right=vector('crypt14');(source/'msgstore.db.crypt14').write_bytes(backup)
    if key is not None:(source/'key').write_bytes(key)
    report=live.verify_whatsapp(source,tmp_path/'derived')
    assert report['status']=='blocked' and report['live_execution_claimed'] is False
    assert check_by_name(report,'backup_authentication')['status']=='blocked'


def test_plaintext_database_passes_without_key_and_alias_rows_are_not_doubled(tmp_path):
    source=tmp_path/'source';database=plain_database(source/'original'/'msgstore.db')
    alias=source/'alias'/'msgstore.db';alias.parent.mkdir();alias.write_bytes(database.read_bytes())
    before=live.sha256(database)
    report=live.verify_whatsapp(source,tmp_path/'derived')
    assert report['status']=='passed' and check_by_name(report,'readable_messages')['evidence']['messages']==1
    assert live.sha256(database)==before
    assert 'Live fixture body' not in json.dumps(report)


def test_partial_decryption_does_not_mark_backup_coverage_complete(tmp_path):
    source=tmp_path/'source';source.mkdir()
    good,key=vector('crypt14');bad,_=vector('crypt15')
    bad=bad[:-1]+bytes([bad[-1]^1])
    (source/'key').write_bytes(key)
    (source/'msgstore.db.crypt14').write_bytes(good)
    (source/'msgstore.db.crypt15').write_bytes(bad)
    report=live.verify_whatsapp(source,tmp_path/'derived')
    assert report['status']=='blocked'
    assert check_by_name(report,'backup_authentication')['evidence']['state']=='partial'
    assert check_by_name(report,'readable_messages')['status']=='pass'


def test_selective_staging_keeps_source_readonly_and_rejects_error_key(tmp_path):
    source=tmp_path/'source';database=plain_database(source/'WhatsApp'/'msgstore.db')
    (source/'irrelevant.apk').write_bytes(b'not a chat')
    before=live.sha256(database)
    records=live.stage_inputs(source,(),tmp_path/'raw')
    assert len(records)==1 and not (tmp_path/'raw'/'external'/'irrelevant.apk').exists()
    assert live.sha256(database)==before
    key=tmp_path/'error-key';key.write_text('run-as: package not debuggable')
    with pytest.raises(ValueError):live.stage_inputs(None,[key],tmp_path/'bad')
    with pytest.raises(ValueError):live.stage_inputs(source,(),source/'output')


def test_device_authorization_and_ambiguous_phone_fail_closed(monkeypatch):
    def reply(text):
        monkeypatch.setattr(live.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout='List of devices attached\n'+text))
    reply('phone-a device\n');assert live.connected_device('adb')=='phone-a'
    reply('phone-a unauthorized\n')
    with pytest.raises(RuntimeError,match='authorize'):live.connected_device('adb')
    reply('phone-a device\nphone-b device\n')
    with pytest.raises(RuntimeError,match='Exactly one'):live.connected_device('adb')
    assert live.connected_device('adb','phone-b')=='phone-b'


def test_missing_phone_cannot_be_hidden_by_supplied_acquisition(tmp_path,monkeypatch):
    monkeypatch.setattr(live,'connected_device',lambda *a: (_ for _ in ()).throw(RuntimeError('No phone')))
    source=tmp_path/'source';plain_database(source/'msgstore.db')
    result=live.capture_phone(adb='missing',serial='',output=tmp_path/'acceptance',source=source)
    assert result['status']=='blocked' and result['live_execution_claimed'] is False
    assert (tmp_path/'acceptance'/'raw'/'external'/'msgstore.db').is_file()


def test_cpu_fallback_cannot_pass_gpu_checks(monkeypatch):
    monkeypatch.setitem(sys.modules,'torch',SimpleNamespace(cuda=SimpleNamespace(is_available=lambda:False),version=SimpleNamespace(cuda=None)))
    result=live.verify_gpu()
    assert result['status']=='blocked'
    assert check_by_name(result,'cuda_execution')['status']=='blocked'


def test_vision_response_without_gpu_memory_cannot_pass():
    assert live.loaded_vision_gpu([{'name':'model:9b','size_vram':0}],'model:9b') is None
    assert live.loaded_vision_gpu([{'name':'different:9b','size_vram':8192}],'model:9b') is None
    assert live.loaded_vision_gpu([{'model':'model:9b','size_vram':8192}],'model:9b')['size_vram']==8192
    assert live.marker_present('Verify 7392') and not live.marker_present('VERIFY739?')


def test_no_required_checks_or_optional_passes_do_not_claim_complete():
    report=live.new_report('fixture')
    live.check(report,'optional','pass','optional',required=False)
    assert live.finish(report)['status']=='blocked'


def test_host_reader_and_key_validator_load_without_worker_dependencies():
    backend=Path(__file__).resolve().parents[1]
    code="from app.services.mobile_acquire import privileged_app_pull; from app.services.mobile_forensic.whatsapp_crypt import parse_key_material; import sys; assert 'sqlalchemy' not in sys.modules; assert parse_key_material(b'run-as: package not debuggable') is None; print('host-only validation passed')"
    result=subprocess.run([sys.executable,'-S','-c',code],capture_output=True,text=True,timeout=15,
        env={**os.environ,'PYTHONPATH':str(backend)})
    assert result.returncode==0,result.stderr
    assert 'host-only validation passed' in result.stdout
