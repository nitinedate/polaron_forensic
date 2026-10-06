"""Mail, structured exports, generic message SQLite and binary evidence plugins."""
from __future__ import annotations

from pathlib import PurePosixPath

from app.parsers.communications import (EMAIL_EXTENSIONS,STRUCTURED_EXTENSIONS,BINARY_EXTENSIONS,
    MAX_READABLE_BYTES,iter_mail_records,iter_structured_records,iter_binary_strings,iter_protobuf_fields,utc_timestamp)
from app.services.mobile_forensic.models import NormalizedArtifact,Confidence
from app.services.mobile_forensic.plugins import ArtifactParser


def _ext(item):
    return PurePosixPath(item.path.replace('\\','/').lower()).suffix


def _read(item,context):
    if item.size and item.size>MAX_READABLE_BYTES:
        raise ValueError(f'Source exceeds the supported {MAX_READABLE_BYTES}-byte communication read limit')
    data=context.read_artifact_bytes(item.path,max_bytes=MAX_READABLE_BYTES)
    if data is None or item.size and len(data)<item.size:
        raise ValueError('Communication source was unavailable or only partially read')
    return data


class CommunicationEvidenceParser(ArtifactParser):
    name='communication_evidence';version='1.0.0';domains=('email','messaging_apps','files')

    def supports(self,item,context):
        mime=(item.mime_hint or str((item.meta or {}).get('detected_mime') or '')).lower()
        if _ext(item) in EMAIL_EXTENSIONS|STRUCTURED_EXTENSIONS|BINARY_EXTENSIONS or mime=='message/rfc822':
            return True
        if not _ext(item) and any(marker in item.path.lower().replace('\\','/') for marker in ('/mail/','/maildir/','/cur/','/new/')):
            from app.parsers.email_mime_parser import is_extensionless_email_candidate
            return is_extensionless_email_candidate(context.read_artifact_bytes(item.path,max_bytes=65536) or b'')
        return False

    def parse(self,item,context):
        data=_read(item,context);ext=_ext(item)
        mime=(item.mime_hint or str((item.meta or {}).get('detected_mime') or '')).lower()
        from app.parsers.email_mime_parser import is_extensionless_email_candidate
        mail=ext in EMAIL_EXTENSIONS or mime=='message/rfc822' or not ext and is_extensionless_email_candidate(data)
        structured=ext in STRUCTURED_EXTENSIONS or data.startswith(b'bplist00')
        iterator=iter_mail_records(data,item.path) if mail else iter_structured_records(data,item.path) if structured else iter_protobuf_fields(data,item.path) if ext in {'.pb','.protobuf'} else iter_binary_strings(data,item.path)
        for index,record in enumerate(iterator):
            kind=record['record_type'];message=kind=='exported_message'
            binary=kind in {'binary_string','binary_field'}
            artifact_type='app_message' if message else kind
            family='whatsapp_messages' if message and record.get('application')=='whatsapp' else 'messages' if message else 'emails' if mail else 'binary' if binary else 'structured_data'
            timestamp=utc_timestamp(record.get('date') or record.get('timestamp_local'))
            body=record.get('body_text') or record.get('body') or record.get('text') or ''
            normalized={**record,'body':body,'artifact_family':family,'source_format':ext or mime,
                'has_attachment':bool(record.get('attachments'))}
            if message and not normalized.get('conversation_id'):
                normalized['conversation_id']='export:'+item.path
            artifact = NormalizedArtifact.create(artifact_type=artifact_type,source_domain='email' if mail else 'messaging_apps' if message else 'files',
                data=normalized,state='fragment' if binary else 'historical' if message else 'allocated',
                recovery_source='readable_binary_span' if binary else 'owner_export' if message else 'native_source',
                timestamp_utc=timestamp,source_path=item.path,source_row_id=str(record.get('source_pointer') or f"{record.get('message_index',0)}/{index}"),
                source_offset=record.get('source_offset'),source_sha256=item.sha256,parser=self.name,parser_version=self.version,
                confidence=Confidence(label='LOW' if binary else 'HIGH',score=.35 if binary else .95,
                    validation=['exact_byte_span'] if binary else ['structured_source_parse']),job_id=context.job_id,source_id=context.source_id)
            from app.services.mobile_forensic.models import attach_decryption_provenance
            yield attach_decryption_provenance(artifact, item)


class GenericMessageSqliteParser(ArtifactParser):
    """Fallback only: stream all recognizable message rows from readable SQLite."""
    name='generic_message_sqlite';version='1.0.0';domains=('messaging_apps',)

    def supports(self,item,context):
        return _ext(item) in {'.db','.sqlite','.sqlite3'}

    def parse(self,item,context):
        from app.services.mobile_forensic.parsers._sqlite_util import open_sqlite_bytes,table_names,iter_query,column_name_map
        data=context.read_artifact_bytes(item.path,max_bytes=768_000_000)
        if not data or not data.startswith(b'SQLite format 3\x00'):
            yield NormalizedArtifact.create(artifact_type='encrypted_or_unreadable_database',source_domain='messaging_apps',
                data={'artifact_family':'parser_exceptions','body':'Database is not readable SQLite. A matching format/decryption step is required before message parsing.'},
                state='unverified',source_path=item.path,source_sha256=item.sha256,parser=self.name,job_id=context.job_id)
            return
        if item.size and len(data)<item.size:
            raise ValueError('Incomplete SQLite message source')
        with open_sqlite_bytes(data) as conn:
            if conn is None:
                raise ValueError('Message SQLite could not be opened')
            for name in table_names(conn):
                if not any(marker in name.lower() for marker in ('message','chat','conversation','sms','mms')) or any(marker in name.lower() for marker in ('fts','index','search','schema')):
                    continue
                columns=column_name_map(conn,name)
                body=next((columns[k] for k in ('body','text','text_data','content','message','message_text','smsbody') if k in columns),None)
                if not body:
                    continue
                quoted='"'+name.replace('"','""')+'"'
                for index,row in enumerate(iter_query(conn,f'SELECT * FROM {quoted}')):
                    fields=dict(row);lower={str(k).lower():v for k,v in fields.items()}
                    text=fields.get(body)
                    if text is None:
                        continue
                    if isinstance(text,bytes):
                        continue
                    sender=next((lower[k] for k in ('sender','from','address','author','sender_id') if lower.get(k) is not None),None)
                    conversation=next((lower[k] for k in ('conversation_id','thread_id','chat_id','peer','jid') if lower.get(k) is not None),None)
                    yield NormalizedArtifact.create(artifact_type='app_message',source_domain='messaging_apps',
                        data={'artifact_family':'messages','application':'unresolved_database','body':str(text),'sender':sender,
                            'conversation_id':str(conversation) if conversation is not None else None,'fields':fields,
                            'note':'Generic schema match; application and time semantics require examiner validation.'},
                        source_path=item.path,source_table=name,source_row_id=str(lower.get('_id') or lower.get('id') or index),
                        source_sha256=item.sha256,parser=self.name,parser_version=self.version,job_id=context.job_id,
                        confidence=Confidence(label='MEDIUM',score=.7,validation=['sqlite_row','generic_column_match']))
