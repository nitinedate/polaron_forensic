#!/usr/bin/env python3
"""Run a portable synthetic extraction/decryption acceptance case (no phone)."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from whatsapp_qa_fixtures import DEVICE_SECRET, KEYFILE, LEGACY_ACCOUNT, build_fixtures  # noqa: E402
from app.services.mobile_acquire.android_readable import _materialize_whatsapp_decrypted  # noqa: E402
from app.services.mobile_forensic.whatsapp_crypt import decrypt_with_candidates, last_decrypt_diagnostics, parse_key_material  # noqa: E402
from app.services.mobile_forensic.models import InventoryItem  # noqa: E402
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser  # noqa: E402
from app.services.mobile_forensic.plugins import ParseContext  # noqa: E402
from app.services.mobile_forensic.mobile_rag import artifact_to_rag_text  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="Empty folder for public synthetic fixtures and test output")
    args = parser.parse_args()
    fixture_root = args.out / "synthetic_inputs"
    expected = build_fixtures(fixture_root)
    checks = []

    def check(name, passed):
        checks.append({"name": name, "passed": bool(passed)})

    classic = fixture_root / "data/data/com.whatsapp/files/key"
    backup_key = fixture_root / "data/data/com.whatsapp/files/encrypted_backup.key"
    check("intake_extracts_64_hex_from_matching_keyfile_bytes_126_157", parse_key_material(KEYFILE).raw32 == DEVICE_SECRET and len(DEVICE_SECRET.hex()) == 64)
    crypt14 = fixture_root / "WhatsApp/Databases/msgstore.db.crypt14"
    check("crypt14_alone_does_not_reveal_key_or_plaintext", decrypt_with_candidates(crypt14.read_bytes(), [], path=str(crypt14)) is None)
    check("keyless_reason_is_explicit", last_decrypt_diagnostics().get("reason") == "key_material_missing_or_invalid")
    result = {"copied": [], "errors": [], "limitations": []}
    crypts = sorted(fixture_root.rglob("*.crypt*"))
    _materialize_whatsapp_decrypted(crypts, [classic, backup_key], args.out / "derived", result, legacy_account=LEGACY_ACCOUNT)
    check("all_supported_fixtures_decode", result["whatsapp_decryption_state"] == "decrypted" and result["whatsapp_decrypted_files"] == 14)
    check("sqlite_payload_matches_original_hash", any(hashlib.sha256(Path(item["dest"]).read_bytes()).hexdigest() == expected["expected_sqlite_sha256"] for item in result["copied"]))
    check("zip_email_image_json_and_binary_are_recovered", all(any(Path(item["dest"]).suffix == suffix for item in result["copied"]) for suffix in (".zip", ".eml", ".png", ".json", ".bin")))
    raw = crypt14.read_bytes()
    item = InventoryItem(path=str(crypt14), size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    context = ParseContext(job_id="synthetic-qa", platform="Android", whatsapp_key_hex=DEVICE_SECRET.hex(), read_bytes=lambda *_args, **_kwargs: raw)
    records = list(WhatsAppParser().parse(item, context))
    messages = [record for record in records if record.artifact_type == "app_message"]
    check("three_chat_rows_recovered", len(messages) == 3)
    check("surviving_deleted_row_label_preserved", any(record.forensic["state"] == "database_deleted" for record in messages))
    check("attachment_reference_preserved", any(record.data.get("media_name") == "fixture.png" for record in messages))
    check("decrypted_chat_text_is_available_to_rag", any("Synthetic CRYPT14 QA message" in artifact_to_rag_text(record.to_dict()) for record in messages))
    check("no_raw_key_in_recovery_results", DEVICE_SECRET.hex() not in json.dumps(result))
    check("input_hashes_unchanged", all(hashlib.sha256((fixture_root / name).read_bytes()).hexdigest() == digest for name, digest in expected["files_sha256"].items()))
    report = {"synthetic_test_only": True, "live_phone_verified": False, "checks": checks, "recovery": result,
              "status": "passed" if all(item["passed"] for item in checks) else "failed"}
    output = args.out / "whatsapp_synthetic_test_results.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(checks), "report": str(output), "key_recovered_from_ciphertext": False}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
