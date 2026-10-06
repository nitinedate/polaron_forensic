"""Independent-format CRYPT14 vectors through capture, parser, preservation and CLI."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from app.services.mobile_forensic import key_intake
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
from app.services.mobile_forensic.whatsapp_case_decrypt import decrypt_case_folder
from tests.test_whatsapp_recovery import vector, SQLITE_SHA256


def case_files(tmp_path, include_key=True):
    backup, key = vector("crypt14")
    root = tmp_path/"case"
    p = root/"WhatsApp"/"Databases"/"msgstore.db.crypt14"
    p.parent.mkdir(parents=True); p.write_bytes(backup)
    if include_key:
        k = root/"data"/"data"/"com.whatsapp"/"files"/"key"
        k.parent.mkdir(parents=True); k.write_bytes(key)
    return root, backup, key


def test_real_format_case_exports_database_artifacts_and_collected_key(tmp_path):
    root, backup, key = case_files(tmp_path)
    result = decrypt_case_folder(root, tmp_path/"output", export_key_hex=True)
    row = result["results"][0]
    assert result["decrypted_count"] == 1 and result["blocked_count"] == 0
    assert row["decrypted_sha256"] == SQLITE_SHA256
    assert hashlib.sha256(Path(row["database_output"]).read_bytes()).hexdigest() == SQLITE_SHA256
    assert Path(row["key_output"]).read_text().strip() == bytes(range(32)).hex()
    artifacts = [json.loads(x) for x in Path(row["artifacts_output"]).read_text().splitlines()]
    assert any(x["artifact_type"] == "app_message" and x["data"].get("body") == "independent crypt fixture chat" for x in artifacts)
    assert (root/"WhatsApp"/"Databases"/"msgstore.db.crypt14").read_bytes() == backup
    assert key.hex() not in json.dumps(result) and bytes(range(32)).hex() not in json.dumps(result)
    if os.name == "posix":
        assert Path(row["key_output"]).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("problem", ["missing", "wrong", "tampered"])
def test_ciphertext_alone_or_bad_key_produces_no_plaintext_or_key(tmp_path, problem):
    root, backup, key = case_files(tmp_path, include_key=problem != "missing")
    if problem == "wrong": (root/"data/data/com.whatsapp/files/key").write_bytes(b"!"*32)
    if problem == "tampered":
        changed=bytearray(backup);changed[-17] ^= 1
        (root/"WhatsApp/Databases/msgstore.db.crypt14").write_bytes(changed)
    result = decrypt_case_folder(root, tmp_path/"output", export_key_hex=True)
    assert result["blocked_count"] == 1 and result["decrypted_count"] == 0
    assert not list((tmp_path/"output").rglob("msgstore.db"))
    assert not list((tmp_path/"output").rglob("matched_key.hex"))


def test_multiple_accounts_are_matched_per_backup(tmp_path):
    root, backup, key = case_files(tmp_path)
    (root/"wrong.key").write_bytes(b"!"*32)
    result=decrypt_case_folder(root,tmp_path/"out",key_files=[root/"wrong.key"])
    assert result["results"][0]["diagnostics"]["keys_tried"] == 2
    assert result["results"][0]["diagnostics"]["key_source"].endswith("com.whatsapp/files/key")


def test_pipeline_parser_preserves_authenticated_bytes_and_outcomes():
    from app.services.mobile_forensic.whatsapp_crypt import WhatsAppKeyCandidate
    raw,key=vector("crypt14")
    item=InventoryItem(path="WhatsApp/msgstore.db.crypt14",size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    ctx=ParseContext(job_id="j",platform="Android",whatsapp_key_candidates=[WhatsAppKeyCandidate(key,"files/key")],
                     read_bytes=lambda *_a,**_k:raw,extra={"preserve_whatsapp_plaintext":True})
    with patch("app.services.storage.put_bytes",return_value="s3://bucket/jobs/j/derived/msgstore.db") as put:
        records=list(WhatsAppParser().parse(item,ctx))
    assert hashlib.sha256(put.call_args.args[1]).hexdigest()==SQLITE_SHA256
    result=ctx.extra["whatsapp_backup_results"][0]
    assert result["authenticated"] and result["export_state"]=="preserved"
    assert any(r.data.get("decrypted_storage_uri") for r in records if r.artifact_type=="app_backup_encrypted")


def test_storage_failure_keeps_chats_but_reports_failed_export():
    from app.services.mobile_forensic.whatsapp_crypt import WhatsAppKeyCandidate
    raw,key=vector("crypt14")
    ctx=ParseContext(job_id="j",platform="Android",whatsapp_key_candidates=[WhatsAppKeyCandidate(key,"files/key")],
                     read_bytes=lambda *_a,**_k:raw,extra={"preserve_whatsapp_plaintext":True})
    item=InventoryItem(path="msgstore.db.crypt14",size=len(raw))
    with patch("app.services.storage.put_bytes",side_effect=OSError("test")):
        records=list(WhatsAppParser().parse(item,ctx))
    assert any(r.artifact_type=="app_message" for r in records)
    assert ctx.extra["whatsapp_backup_results"][0]["export_state"]=="failed"


def test_verified_intake_status_is_per_backup_and_replaced_each_run(monkeypatch):
    state={"ds":{"case_intake":{"whatsapp_key_hex":"ab"*32}}}
    monkeypatch.setattr(key_intake,"fetchone",lambda *_a,**_k:{"disk_source":state["ds"]})
    def update(_db,_sql,params):state["ds"]=json.loads(params["ds"])
    monkeypatch.setattr(key_intake,"execute",update)
    successful={"source_path":"msgstore.db.crypt14","authenticated":True,"state":"decrypted",
                "key_source":"files/key","raw_secret":"do-not-store","decrypted_storage_uri":"s3://private"}
    status=key_intake.persist_decryption_results(object(),"j",[successful])
    assert status["backup_match_verified"] and status["verified_backup_count"]==1
    assert "raw_secret" not in json.dumps(state["ds"])
    assert "s3://private" not in json.dumps(status)
    blocked={"source_path":"msgstore.db.crypt14","authenticated":False,"state":"blocked","reason":"key_material_missing_or_invalid"}
    status=key_intake.persist_decryption_results(object(),"j",[blocked])
    assert not status["backup_match_verified"] and status["blocked_backup_count"]==1


def test_no_key_but_plaintext_named_crypt14_is_not_falsely_blocked():
    from app.services.mobile_forensic.whatsapp_crypt import try_decrypt_whatsapp_crypt
    raw,key=vector("crypt14");plain=try_decrypt_whatsapp_crypt(raw,key,path="msgstore.db.crypt14")
    ctx=ParseContext(job_id="j",platform="Android",read_bytes=lambda *_a,**_k:plain)
    records=list(WhatsAppParser().parse(InventoryItem(path="msgstore.db.crypt14",size=len(plain)),ctx))
    assert any(r.artifact_type=="app_message" for r in records)
    assert not ctx.extra["whatsapp_backup_results"][0]["authenticated"]


def test_changing_intake_key_invalidates_previous_match_status(monkeypatch):
    from app.services.mobile_forensic import integrity
    from app.db import sql_helpers
    state={"ds":{"case_intake":{"whatsapp_key_hex":"ab"*32,
        "whatsapp_backup_results":[{"source_path":"msgstore.db.crypt14","state":"decrypted","authenticated":True}]}}}
    monkeypatch.setattr(sql_helpers,"fetchone",lambda *_a,**_k:{"disk_source":state["ds"]})
    def update(_db,_sql,params):state["ds"]=json.loads(params["ds"])
    monkeypatch.setattr(sql_helpers,"execute",update)
    integrity.persist_forensic_keys_to_disk_source(object(),"j",{"whatsapp_key_hex":"cd"*32})
    assert not key_intake.key_capture_status(state["ds"])["backup_match_verified"]
