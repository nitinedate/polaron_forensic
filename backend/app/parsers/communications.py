"""Readable mailboxes, structured exports and bounded, labelled binary strings."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import mailbox
from pathlib import Path, PurePosixPath
import plistlib
import re
import tempfile
import struct
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from app.parsers.email_mime_parser import parse_email_file, extract_rfc_message_bytes

EMAIL_EXTENSIONS={'.eml','.emlx','.msg','.mbox','.mbx'}
STRUCTURED_EXTENSIONS={'.json','.jsonl','.ndjson','.xml','.plist','.bplist','.csv','.tsv'}
BINARY_EXTENSIONS={'.bin','.dat','.pb','.protobuf','.cache','.blob'}
MAX_READABLE_BYTES=256*1024*1024


def decode_text(data):
    if data.startswith((b'\xff\xfe',b'\xfe\xff')):
        return data.decode('utf-16')
    if data.startswith(b'\xef\xbb\xbf'):
        return data.decode('utf-8-sig')
    return data.decode('utf-8')


def utc_timestamp(value):
    try:
        parsed=parsedate_to_datetime(str(value)) if not isinstance(value,datetime) else value
    except (ValueError,TypeError,OverflowError):
        try:
            parsed=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        except (ValueError,TypeError):
            return None
    return parsed.astimezone(timezone.utc).isoformat() if parsed.tzinfo is not None else None


def iter_mail_records(data,path):
    ext=PurePosixPath(path.lower()).suffix
    if ext=='.msg':
        from app.parsers.outlook_msg_parser import build_msg_preview_details
        details=build_msg_preview_details(data,path)
        if not details.get('parse_ok'):
            raise ValueError('MSG parser unavailable or message damaged: '+str(details.get('error')))
        headers=details['headers']
        yield {'record_type':'email_message','path':path,'message_index':0,**headers,
            'body_text':details['body_text'],'body_html':details['body_html'],
            'attachments':details.get('attachments',[]),'text':details['body_text']}
        return
    if ext in {'.mbox','.mbx'} or data.startswith(b'From '):
        # mailbox receives a disposable copy; it never opens the acquired file.
        with tempfile.TemporaryDirectory(prefix='aetheris_mail_') as temporary:
            copied=Path(temporary)/'source.mbox';copied.write_bytes(data)
            box=mailbox.mbox(str(copied),create=False)
            try:
                for index,key in enumerate(box.iterkeys()):
                    raw=box.get_bytes(key)
                    for record in _mime_records(raw,path,index):
                        yield record
            finally:
                box.close()
        return
    yield from _mime_records(data,path,0)


def _mime_records(data,path,index):
    records=parse_email_file(data,path)
    if not records:
        raise ValueError('MIME email could not be parsed within the supported message-size limit')
    for record in records:
        record['message_index']=index
        record['message_sha256']=hashlib.sha256(extract_rfc_message_bytes(data,path)).hexdigest()
        record['source_pointer']=f'message/{index}/root/{record["record_type"]}'
        yield record
    message=BytesParser(policy=policy.default).parsebytes(extract_rfc_message_bytes(data,path))
    for part_index,part in enumerate(message.walk()):
        if part.get_content_type()=='message/rfc822':
            for child_index,child in enumerate(part.get_payload() if isinstance(part.get_payload(),list) else []):
                for record in parse_email_file(child.as_bytes(policy=policy.default),path+'.eml'):
                    record.update(message_index=index,source_pointer=f'message/{index}/mime/{part_index}/{child_index}/{record["record_type"]}',
                                  message_sha256=hashlib.sha256(child.as_bytes(policy=policy.default)).hexdigest(),attached_message=True,path=path)
                    yield record


def _serializable(value):
    if isinstance(value,bytes):
        return {'binary_length':len(value),'sha256':hashlib.sha256(value).hexdigest(),'hex':value.hex()}
    if isinstance(value,datetime):
        return value.isoformat()
    if isinstance(value,plistlib.UID):
        return {'plist_uid':value.data}
    raise TypeError(type(value).__name__)


def _walk(value,pointer='root',depth=0):
    if depth>128:
        raise ValueError('Structured export exceeds the supported nesting depth')
    if isinstance(value,dict):
        simple={key:item for key,item in value.items() if not isinstance(item,(dict,list))}
        # Telegram exports can interleave text and formatting objects. Retain
        # their complete message body on the parent record as well as raw fields.
        if isinstance(value.get('text'), list):
            simple['text']=''.join(part if isinstance(part,str) else str(part.get('text','')) if isinstance(part,dict) else str(part) for part in value['text'])
        if simple:
            yield pointer,simple
        for key,item in value.items():
            if isinstance(item,(dict,list)):
                yield from _walk(item,f'{pointer}/{key}',depth+1)
    elif isinstance(value,list):
        for index,item in enumerate(value):
            yield from _walk(item,f'{pointer}/{index}',depth+1)
    else:
        yield pointer,{'value':value}


def _export_record(pointer,fields,application):
    lower={str(key).lower():value for key,value in fields.items()}
    body=next((lower[key] for key in ('body','text','text_data','message','content','smsbody') if lower.get(key) is not None),'')
    sender=next((lower[key] for key in ('sender','from','address','author','from_id','participant') if lower.get(key) is not None),None)
    conversation=next((lower[key] for key in ('conversation_id','chat_id','thread_id','chat','channel','peer') if lower.get(key) is not None),None)
    kind=str(lower.get('type') or lower.get('record_type') or '').lower()
    message=bool(body) and (sender is not None or conversation is not None or kind in {'message','sms','mms','chat','email'})
    return {'record_type':'exported_message' if message else 'structured_record','source_pointer':pointer,
        'application':application,'body':str(body) if message else '', 'sender':sender,
        'conversation_id':str(conversation) if conversation is not None else None,
        'timestamp_local':str(lower.get('date') or lower.get('timestamp') or lower.get('time') or ''),
        'fields':json.loads(json.dumps(fields,default=_serializable,ensure_ascii=False)),
        'text':json.dumps(fields,default=_serializable,ensure_ascii=False)}


def iter_structured_records(data,path):
    ext=PurePosixPath(path.lower()).suffix
    application=next((name for name in ('whatsapp','telegram','signal','discord','slack','teams','messenger','instagram','skype') if name in path.lower()),'export')
    if ext in {'.plist','.bplist'} or data.startswith(b'bplist00'):
        value=plistlib.loads(data)
    elif ext in {'.jsonl','.ndjson'}:
        for index,line in enumerate(decode_text(data).splitlines(),1):
            if line.strip():
                for pointer,fields in _walk(json.loads(line),f'line/{index}'):
                    yield _export_record(pointer,fields,application)
        return
    elif ext in {'.csv','.tsv'}:
        for index,row in enumerate(csv.DictReader(io.StringIO(decode_text(data)),delimiter='\t' if ext=='.tsv' else ','),2):
            yield _export_record(f'line/{index}',row,application)
        return
    elif ext=='.xml':
        text=decode_text(data)
        if re.search(r'<!\s*(?:DOCTYPE|ENTITY)',text,re.I):
            raise ValueError('External entities/DOCTYPE are not supported in evidence XML')
        tree=ET.fromstring(text)
        for index,node in enumerate(tree.iter()):
            fields=dict(node.attrib)
            for child in node:
                if not list(child):
                    fields[child.tag.split('}')[-1]]=child.text or ''
            if node.text and node.text.strip():
                fields.setdefault('value',node.text.strip())
            if fields:
                yield _export_record(f'xml/{index}/{node.tag.split("}")[-1]}',fields,application)
        return
    else:
        value=json.loads(decode_text(data))
    for pointer,fields in _walk(value):
        yield _export_record(pointer,fields,application)


def iter_binary_strings(data,path):
    """Readable byte spans, never decoded messages or proof of an application."""
    patterns=[('ascii',re.compile(rb'[\x20-\x7e]{8,4096}')),
        ('utf-16-le',re.compile(rb'(?:[\x20-\x7e]\x00){8,4096}')),
        ('utf-16-be',re.compile(rb'(?:\x00[\x20-\x7e]){8,4096}'))]
    for encoding,pattern in patterns:
        for match in pattern.finditer(data):
            text=match.group().decode(encoding)
            if not text.strip():
                continue
            yield {'record_type':'binary_string','text':text,'source_offset':match.start(),
                'byte_length':match.end()-match.start(),'encoding':encoding,'path':path,
                'note':'Unverified readable bytes. Message boundaries, sender and meaning are not established.'}

    # UTF-8 runs include Hindi/Marathi and other non-Latin text. Invalid bytes
    # separate runs; offsets remain offsets in the acquired byte stream.
    utf8=re.compile(rb'(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}){8,4096}')
    for match in utf8.finditer(data):
        try:
            text=match.group().decode('utf-8')
        except UnicodeDecodeError:
            continue
        if any(ord(char)>127 for char in text) and all(char.isprintable() for char in text):
            yield {'record_type':'binary_string','text':text,'source_offset':match.start(),
                'byte_length':match.end()-match.start(),'encoding':'utf-8','path':path,
                'note':'Unverified readable bytes. Message boundaries, sender and meaning are not established.'}


def iter_protobuf_fields(data,path):
    """Schema-free wire fields, not identified chats. Validate every byte span."""
    def varint(offset):
        value=0
        for shift in range(0,70,7):
            if offset>=len(data):
                raise ValueError('Truncated protobuf varint')
            byte=data[offset];offset+=1
            value|=(byte&127)<<shift
            if byte<128:
                if shift==63 and byte>1:
                    raise ValueError('Protobuf varint exceeds 64 bits')
                return value,offset
        raise ValueError('Invalid protobuf varint')
    offset=0
    while offset<len(data):
        start=offset;tag,offset=varint(offset);number,wire=tag>>3,tag&7
        if number==0 or number>(1<<29)-1 or wire not in {0,1,2,5}:
            raise ValueError('Unsupported or invalid protobuf field tag')
        if wire==0:
            value,offset=varint(offset)
        elif wire in {1,5}:
            length=8 if wire==1 else 4
            if offset+length>len(data):
                raise ValueError('Truncated protobuf fixed-width field')
            value=struct.unpack('<Q' if wire==1 else '<I',data[offset:offset+length])[0];offset+=length
        else:
            length,offset=varint(offset)
            if offset+length>len(data):
                raise ValueError('Truncated protobuf byte field')
            raw=data[offset:offset+length];offset+=length
            try:
                text=raw.decode('utf-8')
                value=text if all(char.isprintable() or char in '\r\n\t' for char in text) else {'byte_length':length,'sha256':hashlib.sha256(raw).hexdigest()}
            except UnicodeDecodeError:
                value={'byte_length':length,'sha256':hashlib.sha256(raw).hexdigest()}
        yield {'record_type':'binary_field','path':path,'field_number':number,'wire_type':wire,'value':value,
               'text':str(value),'source_offset':start,'byte_length':offset-start,
               'source_pointer':f'wire/{start}','note':'Validated protobuf wire field. A schema is required to establish message type and semantics.'}


def parse_communications_file(data,path):
    if len(data)>MAX_READABLE_BYTES:
        raise ValueError(f'Communication source exceeds {MAX_READABLE_BYTES} bytes; split or export readable records')
    ext=PurePosixPath(path.lower()).suffix
    if ext in EMAIL_EXTENSIONS:
        return list(iter_mail_records(data,path))
    if ext in STRUCTURED_EXTENSIONS or data.startswith(b'bplist00'):
        return list(iter_structured_records(data,path))
    if ext in {'.pb','.protobuf'}:
        return list(iter_protobuf_fields(data,path))
    return list(iter_binary_strings(data,path))
