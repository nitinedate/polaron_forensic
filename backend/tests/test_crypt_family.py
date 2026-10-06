"""Format-derived synthetic legacy fixtures, plus independent modern format vectors."""
import gzip
import hashlib
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from app.services.mobile_forensic.crypt_formats import is_crypt_file
from app.services.mobile_forensic.whatsapp_crypt import decrypt_with_candidates, last_decrypt_diagnostics, WhatsAppKeyCandidate, try_decrypt_whatsapp_crypt
from app.services.mobile_forensic.whatsapp_case_decrypt import decrypt_case_folder
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
from tests.test_whatsapp_recovery import vector, SQLITE_SHA256
KEY32 = bytes(range(32))
KEY24 = bytes(range(24))
IV = bytes(range(16))

def plaintext():
    raw,key = vector('crypt14')
    return try_decrypt_whatsapp_crypt(raw,key,path='msgstore.db.crypt14')

def encrypt(body,key,mode,pad=False):
    if pad:
        n=16-len(body)%16;body+=bytes([n])*n
    enc=Cipher(algorithms.AES(key),mode).encryptor()
    result=enc.update(body)+enc.finalize()
    return result, getattr(enc,'tag',None)

def legacy_fixture(fmt, *, authenticated=True):
    plain=plaintext()
    if fmt=='crypt':
        body,_=encrypt(plain,b'4j#e*F9+Ms%|g1~5.3rH!we,',modes.ECB(),True)
        return body,None
    if fmt=='crypt5':
        body,_=encrypt(plain,KEY24,modes.CBC(bytes.fromhex('1e39f369e90db33aa73b442bbbb6b0b9')),True)
        return body,KEY24
    if fmt in {'crypt7','crypt8'}:
        body,_=encrypt(gzip.compress(plain) if fmt=='crypt8' else plain,KEY32,modes.CBC(IV),True)
    else:
        body,tag=encrypt(gzip.compress(plain),KEY32,modes.GCM(IV))
        if authenticated:body+=tag
    return bytes(51)+IV+body,KEY32

@pytest.mark.parametrize('fmt',['crypt','crypt5','crypt7','crypt8','crypt9','crypt10','crypt11','crypt12','crypt14','crypt15'])
def test_all_implemented_database_formats_decode_expected_bytes(fmt):
    if fmt in {'crypt12','crypt14','crypt15'}:raw,key=vector(fmt)
    else:raw,key=legacy_fixture(fmt)
    candidates=[WhatsAppKeyCandidate(key,'collected-key')] if key else []
    value=decrypt_with_candidates(raw,candidates,path='WhatsApp/msgstore.db.'+fmt)
    assert hashlib.sha256(value).hexdigest()==SQLITE_SHA256
    diag=last_decrypt_diagnostics()
    assert diag['container']==fmt and diag['payload_kind']=='sqlite'
    if fmt in {'crypt','crypt5','crypt7','crypt8'}:
        assert not diag['authenticated'] and diag['validation']=='legacy_structural_only'
    else:assert diag['authenticated']

@pytest.mark.parametrize('fmt',['crypt9','crypt10','crypt11'])
def test_untagged_legacy_gcm_is_explicitly_unverified(fmt):
    raw,key=legacy_fixture(fmt,authenticated=False)
    expected=plaintext()
    assert decrypt_with_candidates(raw,[WhatsAppKeyCandidate(key,'collected')],path='msgstore.db.'+fmt)==expected
    diag=last_decrypt_diagnostics()
    assert not diag['authenticated'] and diag['validation']=='legacy_structural_only'

@pytest.mark.parametrize('fmt',['crypt5','crypt7','crypt8','crypt9','crypt10','crypt11'])
def test_legacy_wrong_key_is_blocked(fmt):
    raw,key=legacy_fixture(fmt)
    assert decrypt_with_candidates(raw,[WhatsAppKeyCandidate(b'!'*len(key),'wrong')],path='msgstore.db.'+fmt) is None

@pytest.mark.parametrize('name',['msgstore.db.CRYPT7','msgstore.db.crypt16','wa.db.crypt','sticker.webp.crypt14','db.cryptfoo'])
def test_crypt_wildcard_is_discovered(name):assert is_crypt_file(name)

@pytest.mark.parametrize('name',['msgstore.db.crypt14.bak','crypt14','report.crypto.pdf'])
def test_not_a_crypt_extension(name):assert not is_crypt_file(name)

def test_unknown_version_not_silently_decoded_as_modern():
    raw,key=vector('crypt14')
    assert decrypt_with_candidates(raw,[WhatsAppKeyCandidate(key,'key')],path='msgstore.db.crypt99') is None
    assert last_decrypt_diagnostics()['reason']=='unsupported_crypt_version'
    assert WhatsAppParser().supports(InventoryItem(path='msgstore.db.crypt99',size=len(raw)),ParseContext(job_id='j',platform='Android'))

def modern_resource(payload):
    # Length-prefixed protobuf IV, independent cryptography encryption, standard tag.
    body,tag=encrypt(payload,KEY32,modes.GCM(IV))
    header=b'\x0a\x10'+IV
    return bytes([len(header)])+header+body+tag

@pytest.mark.parametrize('kind',['zip','binary'])
def test_authenticated_resource_preserved_without_chat_records(tmp_path,kind):
    if kind=='zip':
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:z.writestr('sticker.webp',b'RIFF synthetic sticker')
        payload=stream.getvalue()
    else:payload=b'RIFF'+b'\x10\x00\x00\x00WEBPVP8 '+b'synthetic resource'
    raw=modern_resource(payload)
    case=tmp_path/'case';case.mkdir();(case/'sticker.webp.crypt14').write_bytes(raw)
    (case/'key').write_bytes(KEY32)
    report=decrypt_case_folder(case,tmp_path/'out',export_key_hex=True)
    row=report['results'][0]
    assert row['diagnostics']['payload_kind']==('webp' if kind=='binary' else kind) and row['diagnostics']['authenticated']
    assert Path(row['payload_output']).read_bytes()==payload
    artifacts=[json.loads(x) for x in Path(row['artifacts_output']).read_text().splitlines()]
    assert not any(x['artifact_type']=='app_message' for x in artifacts)
    assert 'database_output' not in row
    assert try_decrypt_whatsapp_crypt(raw,KEY32,path='msgstore.db.crypt14') is None

def test_tampered_modern_resource_never_exported(tmp_path):
    case=tmp_path/'case';case.mkdir()
    raw=bytearray(modern_resource(b'RIFF synthetic image'));raw[-1]^=1
    (case/'picture.webp.crypt14').write_bytes(raw);(case/'key').write_bytes(KEY32)
    result=decrypt_case_folder(case,tmp_path/'out')
    assert result['blocked_count']==1
    assert not list((tmp_path/'out').rglob('payload.bin'))

def test_unknown_file_reported_without_any_key(tmp_path):
    case=tmp_path/'case';case.mkdir();(case/'unknown.crypt999').write_bytes(b'x'*100)
    result=decrypt_case_folder(case,tmp_path/'out')
    assert result['backup_count']==1 and result['blocked_count']==1
    assert result['results'][0]['diagnostics']['reason']=='unsupported_crypt_version'

def test_legacy_status_and_plaintext_preservation_are_not_verified(tmp_path):
    raw,key=legacy_fixture('crypt8')
    ctx=ParseContext(job_id='j',platform='Android',whatsapp_key_candidates=[WhatsAppKeyCandidate(key,'collected')],read_bytes=lambda *_a,**_k:raw,extra={'preserve_whatsapp_plaintext':True})
    with patch('app.services.storage.put_bytes',return_value='s3://case/plain.db'):
        records=list(WhatsAppParser().parse(InventoryItem(path='msgstore.db.crypt8',size=len(raw)),ctx))
    row=ctx.extra['whatsapp_backup_results'][0]
    assert row['validation']=='legacy_structural_only' and not row['authenticated']
    assert any(x.artifact_type=='app_message' for x in records)
    from app.services.mobile_forensic.key_intake import key_capture_status
    assert not key_capture_status({'case_intake':{'whatsapp_backup_results':[row]}})['backup_match_verified']

def test_acquisition_detects_all_crypt_and_scope_retains_unknown():
    from app.services.mobile_acquire.android_readable import _is_whatsapp_crypt_backup
    from app.services.forensic_handbook_scope import is_handbook_evidence_path
    from app.services.phase1_artifact_scope import is_phase1_evidence_path
    assert _is_whatsapp_crypt_backup('wa.db.crypt7','WhatsApp/Backups/wa.db.crypt7')
    assert _is_whatsapp_crypt_backup('sticker.webp.crypt14','WhatsApp/stickers/sticker.webp.crypt14')
    assert is_handbook_evidence_path('WhatsApp/msgstore.db.crypt99')
    assert is_phase1_evidence_path('WhatsApp/msgstore.db.crypt99')


@pytest.mark.parametrize('fmt',['crypt9','crypt10','crypt11'])
def test_failed_tag_is_not_discarded_by_legacy_fallback(fmt):
    raw,key=legacy_fixture(fmt,authenticated=True)
    damaged=bytearray(raw);damaged[-1]^=1
    assert decrypt_with_candidates(bytes(damaged),[WhatsAppKeyCandidate(key,'collected')],path='msgstore.db.'+fmt) is None


def test_offline_recovery_cannot_write_inside_original_case(tmp_path):
    case=tmp_path/'case';case.mkdir()
    with pytest.raises(ValueError,match='outside'):
        decrypt_case_folder(case,case/'derived')
