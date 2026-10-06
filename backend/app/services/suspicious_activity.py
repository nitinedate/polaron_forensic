"""Review candidates with exact source attribution, never findings of guilt."""
from __future__ import annotations

import hashlib
import html
import json
import re

from app.db.sql_helpers import execute, fetchall, fetchone

REVIEW_NOTE = ('These are source-linked review candidates. Rule matches and visual model descriptions '
               'require examiner verification; they do not establish intent or an offence. Video coverage is sampled.')
TEXT_RULES = (
    ('credential_request', re.compile(r'\b(?:send|share|give|forward)\b.{0,70}\b(?:otp|one.time password|password|verification code|bank pin)\b', re.I | re.S),
     'The quoted source requests a credential or verification code; check the conversation and authorization.'),
    ('payment_pressure', re.compile(r'\b(?:pay|transfer|send money|payment)\b.{0,90}\b(?:urgent|immediately|account.{0,15}(?:blocked|closed)|avoid arrest)\b', re.I | re.S),
     'The quoted source combines payment instructions with pressure; review the full conversation and linked records.'),
    ('concealment_request', re.compile(r'\b(?:delete|erase|wipe)\b.{0,70}\b(?:chat|messages?|evidence|history|logs?)\b', re.I | re.S),
     'The source requests removal of records. Context may be legitimate; verify against the acquired evidence.'),
    ('remote_access_request', re.compile(r'\b(?:install|download|enable)\b.{0,70}\b(?:anydesk|teamviewer|remote access|screen sharing)\b', re.I | re.S),
     'A remote access or screen sharing request appears in the source; verify the purpose and related activity.'),
)


def ensure_suspicious_schema(db):
    execute(db, """CREATE TABLE IF NOT EXISTS forensic_suspicious_activity (
        id text PRIMARY KEY,job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        job_artifact_id uuid REFERENCES job_artifacts(id) ON DELETE CASCADE,
        category text NOT NULL,source_record_id text,source_path text NOT NULL,
        source_sha256 text,timestamp_utc timestamptz,data jsonb NOT NULL,
        created_at timestamptz NOT NULL DEFAULT NOW())""")
    execute(db, 'CREATE INDEX IF NOT EXISTS suspicious_job_category ON forensic_suspicious_activity(job_id,category,id)')


def review_signals(record):
    data = record.get('data') or {}
    if isinstance(data, str):
        data = json.loads(data)
    # Binary fragments have no verified message semantics. They remain in the
    # binary category rather than being promoted to conversational evidence.
    if record.get('artifact_type') in {'binary_string','binary_field','recovered_chat_candidate','encrypted_or_unreadable_database'}:
        return []
    body = str(data.get('body') or data.get('body_text') or data.get('text') or data.get('url') or '')
    signals = []
    for category, pattern, explanation in TEXT_RULES:
        match = pattern.search(body)
        if match:
            start, end = max(0, match.start()-100), min(len(body),match.end()+200)
            signals.append({'category':category,'explanation':explanation,'excerpt':body[start:end],
                            'method':'explicit_text_rule','excerpt_only':start>0 or end<len(body)})
    path = str(data.get('path') or data.get('local_path') or data.get('file_path') or '')
    download = data.get('is_download') is True or data.get('source_bucket') == 'download' or record.get('artifact_type') in {'browser_download','download'}
    if download and re.search(r'\.(?:apk|exe|msi|ps1|bat|cmd|scr)$',path,re.I):
        signals.append({'category':'executable_download','explanation':'An executable or application package was downloaded. This is a review cue, not proof of malware; inspect its origin, hash and execution records.',
                        'excerpt':path,'method':'download_type_rule'})
    if re.search(r'\.(?:pdf|jpg|png|docx|xlsx)\.(?:exe|scr|apk)$',path,re.I):
        signals.append({'category':'disguised_extension','explanation':'The source name ends in a document/image extension followed by an executable extension. Verify the acquired file type and origin.',
                        'excerpt':path,'method':'filename_rule'})
    package = str(data.get('package') or data.get('package_name') or data.get('bundle_id') or '')
    if record.get('artifact_type') in {'installed_app','installed_application','app_install','application','application_record'} and package in {'com.anydesk.anydeskandroid','com.teamviewer.quicksupport.market','org.torproject.android','com.kms.free'}:
        signals.append({'category':'application_review','explanation':'An acquired package record references a remote access, anonymization or monitoring application. A retained package record does not prove current installation or misuse.',
                        'excerpt':package,'method':'installation_record_rule'})
    return signals


def _save(db, job_id, file_id, record_id, path, sha, timestamp, details):
    identity = hashlib.sha256(f'{job_id}:{record_id}:{details["category"]}'.encode()).hexdigest()
    execute(db, """INSERT INTO forensic_suspicious_activity
        (id,job_id,job_artifact_id,category,source_record_id,source_path,source_sha256,timestamp_utc,data)
        VALUES(:id,:jid,:aid,:cat,:record,:path,:sha,:ts,CAST(:data AS jsonb))
        ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,source_sha256=EXCLUDED.source_sha256""",
        {'id':identity,'jid':job_id,'aid':file_id,'cat':details['category'],'record':record_id,
         'path':path,'sha':sha,'ts':timestamp,'data':json.dumps({**details,'review_status':'pending_examiner_review'},ensure_ascii=False,default=str)})
    if file_id:
        execute(db,"""UPDATE job_artifacts SET metadata=COALESCE(metadata,'{}'::jsonb)
            || jsonb_build_object('suspicious_activity',true,'suspicious_activity_description',CAST(:description AS text)) WHERE id=:aid""",
            {'aid':file_id,'description':details['explanation']})


def collect_suspicious_activity(db,job_id):
    from app.services.forensic_priority_evidence import priority_record_table
    ensure_suspicious_schema(db)
    table = priority_record_table(db,job_id)
    written = 0
    after = ''
    if table:
        while True:
            rows = fetchall(db,f'SELECT * FROM {table} WHERE job_id=:jid AND artifact_id>:after ORDER BY artifact_id LIMIT 500',{'jid':job_id,'after':after})
            if not rows:
                break
            for row in rows:
                signals=review_signals(row)
                if not signals:
                    continue
                forensic = row.get('forensic') or {}
                if isinstance(forensic,str):
                    forensic=json.loads(forensic)
                file_id=row.get('job_artifact_id')
                if not file_id:
                    source=fetchone(db,"""SELECT id FROM job_artifacts WHERE job_id=:jid
                        AND replace(file_path,chr(92),'/')=:path LIMIT 1""",{'jid':job_id,'path':forensic.get('source_path') or ''})
                    file_id=source['id'] if source else None
                for signal in signals:
                    _save(db,job_id,file_id,row['artifact_id'],forensic.get('source_path') or '',
                          forensic.get('source_sha256'),row.get('timestamp_utc'),{**signal,'source_state':row.get('state'),
                          'source_pointer':forensic.get('source_row_id'),'source_table':forensic.get('source_table'),
                          'parser':forensic.get('parser'),'confidence':forensic.get('confidence')})
                    written += 1
            after=rows[-1]['artifact_id'];db.commit()
            from app.services.progress_agent import note_operation
            note_operation(db,job_id,'inventory','Suspicious Activity source rules reviewed',advanced=True)
    exists=fetchone(db,"SELECT to_regclass('forensic_media_observations') AS t")
    if exists and exists['t']:
        for row in fetchall(db,'SELECT * FROM forensic_media_observations WHERE job_id=:jid AND flagged ORDER BY job_artifact_id',{'jid':job_id}):
            details=row['details'] or {}
            if isinstance(details,str):
                details=json.loads(details)
            for index,frame in enumerate(details.get('frames') or []):
                if not frame.get('signals') and not details.get('ocr_signals'):
                    continue
                _save(db,job_id,row['job_artifact_id'],str(row['job_artifact_id'])+f'/frame/{index}',row['source_path'],row['source_sha256'],None,
                      {'category':row['media_kind'],'explanation':frame['description'], 'excerpt':'',
                       'method':'visual_model','frame_index':index,'timestamp_seconds':frame.get('timestamp_seconds'),
                       'frame_sha256':frame['frame_sha256'],'derived_frame_uri':frame['derived_frame_uri'],
                       'model':frame.get('model'),'signals':frame.get('signals',[]),'ocr_signals':details.get('ocr_signals',[]),
                       'coverage':details.get('coverage',{})})
                written += 1
    db.commit()
    return {'review_candidates':written}


def suspicious_activity_page(db,job_id,*,page=1,page_size=50):
    exists=fetchone(db,"SELECT to_regclass('forensic_suspicious_activity') AS t")
    if not exists or not exists['t']:
        return {'items':[],'total':0,'page':page,'note':REVIEW_NOTE}
    total=fetchone(db,'SELECT count(*) AS c FROM forensic_suspicious_activity WHERE job_id=:jid',{'jid':job_id})['c']
    rows=fetchall(db,'SELECT * FROM forensic_suspicious_activity WHERE job_id=:jid ORDER BY category,id LIMIT :lim OFFSET :off',
                 {'jid':job_id,'lim':page_size,'off':(page-1)*page_size})
    return {'items':rows,'total':total,'page':page,'note':REVIEW_NOTE}


def suspicious_report_section(db,job_id):
    exists=fetchone(db,"SELECT to_regclass('forensic_suspicious_activity') AS t")
    rows=fetchall(db,'SELECT * FROM forensic_suspicious_activity WHERE job_id=:jid ORDER BY category,id',{'jid':job_id}) if exists and exists['t'] else []
    cards=[]
    for row in rows:
        data=row['data'] if isinstance(row['data'],dict) else json.loads(row['data'])
        cards.append(json.loads(json.dumps({**row,**data,'job_id':job_id,'data':None},default=str)))
    md='## SUSPICIOUS ACTIVITY\n\n'+REVIEW_NOTE+'\n\n'
    if not cards:
        md+='No review candidates were identified by the enabled source rules and completed media review. This does not establish that unacquired or unreviewed evidence is clear.'
    else:
        for card in cards:
            md+=f"\n### {card['category']}\nSource: {card['source_path']}\nSHA256: {card.get('source_sha256') or 'Unavailable'}\nRecord: {card['source_record_id']}\nExplanation: {card['explanation']}\nExcerpt: {card.get('excerpt','')}\nReview: pending examiner review\n"
    return md,{'review_note':REVIEW_NOTE,'suspicious_activity':cards,
               'examiner_observations_md':'### Examiner observations\n\nNo examiner observations recorded.'}


def examiner_observations(section):
    """Keep examiner interpretation separate from immutable source captions."""
    return str((section.get('structured_json') or {}).get('examiner_observations_md')
               or '### Examiner observations\n\nNo examiner observations recorded.')


def evidence_image_bytes(card):
    """Read only the retained derivative; verify its exact content hash."""
    from app.services.storage import get_bytes, _local_root
    from app.config import get_settings
    from pathlib import Path
    uri=card.get('derived_frame_uri')
    expected=card.get('frame_sha256')
    if not uri or not expected:
        return None
    # Only the job's own retained forensic observation object is eligible.
    expected_key=f"forensic-observations/{card['job_id']}/{card['source_sha256']}/{expected}.png"
    valid_s3=str(uri)==f's3://{get_settings().minio_bucket}/{expected_key}'
    valid_local=str(uri).startswith('file://') and Path(str(uri)[7:]).resolve()==(_local_root()/expected_key).resolve()
    if not (valid_s3 or valid_local):
        raise ValueError('Evidence image reference is outside its source observation')
    blob=get_bytes(uri,max_bytes=10*1024*1024)
    if not blob or hashlib.sha256(blob).hexdigest()!=expected:
        raise ValueError('Evidence image hash verification failed')
    return blob


def card_lines(card):
    # Reports contain explicitly labelled excerpts; complete source records
    # remain available through their IDs, without inventing missing content.
    path=str(card['source_path'])
    return [f"Category: {card['category']} — pending examiner review",
            'Source: '+path[:400]+(' (path excerpt; full path in artifact)' if len(path)>400 else ''), 'Source SHA256: '+str(card.get('source_sha256') or 'Unavailable'),
            'Artifact: '+str(card.get('job_artifact_id') or 'Unavailable')+'; record: '+str(card['source_record_id']),
            'Time: '+str(card.get('timestamp_utc') or 'Unavailable'),
            'Explanation (excerpt): '+str(card['explanation'])[:800],
            'Source excerpt: '+str(card.get('excerpt') or '')[:400],
            'Method: '+str(card.get('method'))+'; model: '+str(card.get('model') or 'Not applicable')]+(
            ['Frame time: '+str(card.get('timestamp_seconds'))+'s; SHA256: '+str(card['frame_sha256'])] if card.get('frame_sha256') else [])


def suspicious_html(section):
    import base64
    structured=section.get('structured_json') or {}
    parts=[]
    for card in structured.get('suspicious_activity') or []:
        image=evidence_image_bytes(card)
        picture=("<img style='max-width:100%;max-height:55mm;object-fit:contain' src='data:image/png;base64,"+base64.b64encode(image).decode()+"' alt='Source evidence derivative'>") if image else ''
        parts.append("<div class='report-a4-sheet section-block'><h2>SUSPICIOUS ACTIVITY</h2><p>"+html.escape(REVIEW_NOTE)+"</p>"+picture+''.join('<p style="overflow-wrap:anywhere">'+html.escape(line)+'</p>' for line in card_lines(card))+'</div>')
    parts.append("<div class='report-a4-sheet section-block'><h2>SUSPICIOUS ACTIVITY</h2><div style='white-space:pre-wrap'>"+html.escape(examiner_observations(section))+"</div></div>")
    return ''.join(parts)
