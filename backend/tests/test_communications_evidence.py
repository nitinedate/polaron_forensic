"""Real acquired-format fixtures, source integrity and complete readable content."""
import hashlib
import json
import plistlib
import sqlite3
from email.message import EmailMessage

import pytest
from app.parsers import run_parser
from app.parsers.communications import iter_mail_records,iter_structured_records,iter_binary_strings,iter_protobuf_fields
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext,get_plugin_registry
from app.services.mobile_forensic.parsers.communications import CommunicationEvidenceParser,GenericMessageSqliteParser


def email(body='Message tail नमस्ते',subject='Fixture',attachment=False):
    msg=EmailMessage();msg['From']='sender@example.test';msg['To']='reader@example.test';msg['Subject']=subject
    msg['Date']='Tue, 06 Oct 2026 12:00:00 +0530';msg.set_content(body)
    if attachment:msg.add_attachment(b'fixture attachment',maintype='application',subtype='octet-stream',filename='evidence.bin')
    return msg.as_bytes()


@pytest.mark.parametrize('ext',['.eml','.emlx'])
def test_email_full_body_attachment_and_source(ext):
    body='नमस्ते '*30000+'FINAL_BODY_TAIL';raw=email(body,attachment=True)
    data=str(len(raw)).encode()+b'\n'+raw+b'\n<plist/>' if ext=='.emlx' else raw
    before=hashlib.sha256(data).hexdigest()
    records=list(iter_mail_records(data,'source'+ext))
    message=next(r for r in records if r['record_type']=='email_message')
    assert 'FINAL_BODY_TAIL' in message['body_text']
    assert message['attachment_count']==1 and message['attachments'][0]['filename']=='evidence.bin'
    assert message['source_pointer']=='message/0/root/email_message'
    assert hashlib.sha256(data).hexdigest()==before


def test_mbox_each_message_not_first_only():
    data=b''.join(b'From sender@example.test Tue Oct 6 12:00:00 2026\n'+email(f'message {index}')+b'\n' for index in range(12))
    records=[r for r in iter_mail_records(data,'export.mbox') if r['record_type']=='email_message']
    assert len(records)==12 and records[-1]['message_index']==11
    assert 'message 11' in records[-1]['body_text']


def test_attached_message_has_own_headers_body_and_mime_pointer():
    msg=EmailMessage();msg['From']='parent@example.test';msg['To']='reader@example.test';msg['Subject']='Parent';msg.set_content('Parent only')
    child=EmailMessage();child['From']='child@example.test';child['To']='reader@example.test';child['Subject']='Forwarded';child.set_content('Child body')
    msg.add_attachment(child)
    records=[r for r in iter_mail_records(msg.as_bytes(),'mail.eml') if r['record_type']=='email_message']
    assert len(records)==2 and records[1]['from']=='child@example.test'
    assert records[1]['attached_message'] and '/mime/' in records[1]['source_pointer']


@pytest.mark.parametrize('ext',['.json','.jsonl','.ndjson','.plist','.bplist','.csv','.tsv','.xml'])
def test_structured_message_exports(ext):
    row={'from':'Alice','body':'WhatsApp full message नमस्ते','chat_id':'conversation','date':'2026-10-06T12:00:00+05:30'}
    if ext in {'.plist','.bplist'}:data=plistlib.dumps([row],fmt=plistlib.FMT_BINARY if ext=='.bplist' else plistlib.FMT_XML)
    elif ext=='.xml':data=('<sms from="Alice" body="WhatsApp full message नमस्ते" chat_id="conversation" />').encode()
    elif ext in {'.csv','.tsv'}:
        delimiter='\t' if ext=='.tsv' else ',';data=(delimiter.join(row)+'\n'+delimiter.join(row.values())+'\n').encode()
    else:data=json.dumps([row] if ext=='.json' else row,ensure_ascii=False).encode()
    records=list(iter_structured_records(data,'whatsapp-export'+ext))
    message=next(r for r in records if r['record_type']=='exported_message')
    assert message['body']=='WhatsApp full message नमस्ते' and message['sender']=='Alice'
    assert message['application']=='whatsapp' and message['source_pointer']


def test_formatted_telegram_text_is_not_split_away_from_sender():
    data=json.dumps({'messages':[{'type':'message','from':'Alice','text':['Hello ',{'type':'bold','text':'world'}]}]}).encode()
    messages=[r for r in iter_structured_records(data,'telegram.json') if r['record_type']=='exported_message']
    assert messages[0]['body']=='Hello world'


def test_utf16_and_large_native_text_are_not_silently_truncated():
    body='अभिलेख '*20000+'TAIL_RECORD'
    key,records=run_parser('evidence.txt',body.encode('utf-16'))
    assert 'TAIL_RECORD' in records[0]['text']
    data=json.dumps({'from':'Alice','body':body},ensure_ascii=False).encode('utf-16')
    assert next(iter_structured_records(data,'export.json'))['body']==body


def test_binary_spans_have_exact_offsets_and_are_not_claimed_chats():
    raw=b'\x00\x01'+b'ASCII readable evidence'+b'\x00'+('प्राप्त संदेश अभिलेख').encode()+b'\x00'+('UTF16 readable evidence').encode('utf-16-le')
    records=list(iter_binary_strings(raw,'raw.bin'))
    assert {r['encoding'] for r in records}>={'ascii','utf-8','utf-16-le'}
    for record in records:
        span=raw[record['source_offset']:record['source_offset']+record['byte_length']]
        assert span.decode(record['encoding'])==record['text']
        assert 'Unverified' in record['note']


def test_protobuf_wire_fields_and_truncated_rejection():
    rows=list(iter_protobuf_fields(b'\x08\x96\x01\x12\x05hello','raw.pb'))
    assert [(r['field_number'],r['value'],r['source_offset']) for r in rows]==[(1,150,0),(2,'hello',3)]
    with pytest.raises(ValueError,match='Truncated'):
        list(iter_protobuf_fields(b'\x12\x05he','raw.pb'))


def test_xml_external_entities_rejected():
    with pytest.raises(ValueError,match='DOCTYPE'):
        list(iter_structured_records(b'<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///etc/passwd">]><x>&leak;</x>','source.xml'))


def test_full_generic_message_sqlite_over_8000_rows_and_encrypted_state(tmp_path):
    path=tmp_path/'unknown-chat.db'
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE Messages(id integer PRIMARY KEY,body text,sender text,thread_id integer)')
        conn.executemany('INSERT INTO Messages VALUES(?,?,?,?)',[(i,f'message {i}','Alice',1) for i in range(8104)])
    blob=path.read_bytes();item=InventoryItem(path=str(path),size=len(blob),sha256=hashlib.sha256(blob).hexdigest())
    context=ParseContext(job_id='fixture',platform='Android',read_bytes=lambda *a,**kw:blob)
    routed=get_plugin_registry().route(item,context)
    assert any(p.name=='generic_message_sqlite' for p in routed)
    rows=list(GenericMessageSqliteParser().parse(item,context))
    assert len(rows)==8104 and rows[-1].data['body']=='message 8103'
    assert rows[0].forensic['source_sha256']==item.sha256
    encrypted=ParseContext(job_id='fixture',platform='Android',read_bytes=lambda *a,**kw:b'encrypted bytes')
    result=list(GenericMessageSqliteParser().parse(InventoryItem(path='unknown.db'),encrypted))
    assert result[0].forensic['state']=='unverified'
    assert result[0].artifact_type=='encrypted_or_unreadable_database'


def test_mobile_email_plugin_and_partial_read_rejection():
    blob=email();item=InventoryItem(path='/data/mail/cur/message',size=len(blob),mime_hint='message/rfc822',sha256=hashlib.sha256(blob).hexdigest())
    context=ParseContext(job_id='fixture',platform='Android',read_bytes=lambda *a,**kw:blob)
    parser=CommunicationEvidenceParser();assert parser.supports(item,context)
    result=list(parser.parse(item,context))
    assert result[0].source_domain=='email' and result[0].timestamp_utc=='2026-10-06T06:30:00+00:00'
    with pytest.raises(ValueError,match='partially'):
        list(parser.parse(item,ParseContext(job_id='fixture',platform='Android',read_bytes=lambda *a,**kw:blob[:50])))


def test_cached_read_reuses_exact_request_and_preserves_companions():
    from app.services.mobile_forensic.parsers._sqlite_util import SqliteEvidenceBytes
    calls=[];blob=SqliteEvidenceBytes(b'SQLite format 3\x00',{'-wal':b'WAL'})
    def read(path,**kwargs):calls.append((path,kwargs));return blob
    context=ParseContext(job_id='fixture',platform='Android',read_bytes=read)
    assert context.read_artifact_bytes('db',max_bytes=100) is context.read_artifact_bytes('db',max_bytes=100)
    assert context.read_artifact_bytes('db',max_bytes=200).companions['-wal']==b'WAL'
    assert len(calls)==2
    context.clear_byte_cache();context.read_artifact_bytes('db',max_bytes=100);assert len(calls)==3


def test_package_capture_distinguishes_current_from_retained_entries():
    from app.services.mobile_forensic.parsers.app_accounts import AppAccountsParser
    blob=b'package:/data/app/org.torproject.android/base.apk=org.torproject.android\n'
    context=ParseContext(job_id='fixture',platform='Android',read_bytes=lambda *a,**kw:blob)
    parser=AppAccountsParser()
    current=list(parser.parse(InventoryItem(path='packages_installed.txt',size=len(blob)),context))[0]
    retained=list(parser.parse(InventoryItem(path='packages_all.txt',size=len(blob)),context))[0]
    assert current.artifact_type=='installed_app' and retained.artifact_type=='application_record'
    assert retained.data['reference_only'] and 'uninstalled' in retained.data['note']
    assert current.forensic['source_row_id']=='line/1'


def test_accounts_sqlite_preserves_identity_without_copying_passwords(tmp_path):
    from app.services.mobile_forensic.parsers.app_accounts import AppAccountsParser
    path=tmp_path/'accounts_ce.db'
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE accounts(_id INTEGER,name TEXT,type TEXT,password TEXT)')
        conn.execute('INSERT INTO accounts VALUES(1,?,?,?)',('user@example.test','com.google','sensitive-fixture-password'))
    blob=path.read_bytes();context=ParseContext(job_id='fixture',platform='Android',read_bytes=lambda *a,**kw:blob)
    rows=list(AppAccountsParser().parse(InventoryItem(path='accounts_ce.db',size=len(blob)),context))
    assert len(rows)==1 and rows[0].data['name']=='user@example.test'
    assert 'sensitive-fixture-password' not in json.dumps(rows[0].data)
