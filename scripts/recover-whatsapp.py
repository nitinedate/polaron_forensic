#!/usr/bin/env python3
"""Decode collected WhatsApp backups locally; input evidence is read-only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.mobile_acquire.android_readable import _materialize_whatsapp_decrypted  # noqa: E402
from app.services.mobile_forensic.whatsapp_crypt import crypt_extension, SUPPORTED_BACKUP_FORMATS  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description="Recover collected WhatsApp databases and payloads using matching key material")
    parser.add_argument("--source", required=True, type=Path, help="Acquired WhatsApp directory or CRYPT backup file")
    parser.add_argument("--key", action="append", type=Path, default=[], help="Collected key file or hex-text file; repeat for other installs")
    parser.add_argument("--out", required=True, type=Path, help="Directory for derived databases and provenance manifest")
    parser.add_argument("--legacy-account", help="CRYPT5 only: exact original Android Google account email")
    args = parser.parse_args(argv)
    if not args.source.exists():
        parser.error("Source does not exist")
    inputs = list(args.source.rglob("*")) if args.source.is_dir() else [args.source]
    output_root = args.out.resolve()
    evidence_root = args.source.resolve() if args.source.is_dir() else args.source.resolve().parent
    if args.source.resolve().is_relative_to(output_root) or output_root.is_relative_to(evidence_root):
        parser.error("Choose an output directory outside the input evidence directory")
    inputs = [path for path in inputs if path.is_file() and not path.is_symlink() and not path.resolve().is_relative_to(output_root)]
    crypts = [path for path in inputs if crypt_extension(path.name)]
    names = {"key", "encrypted_backup.key", "whatsapp.key", "whatsapp_key.hex"}
    keys = list(dict.fromkeys([*args.key, *(path for path in inputs if path.name.lower() in names)]))
    result = {"copied": [], "errors": [], "limitations": [], "whatsapp_decryption_state": "not_applicable"}
    _materialize_whatsapp_decrypted(crypts, keys, args.out / "whatsapp_decrypted", result, legacy_account=args.legacy_account)
    result["source"] = str(args.source)
    result["encrypted_backups"] = len(crypts)
    result["key_candidate_files"] = len(keys)
    result["input_evidence_modified"] = False
    result["supported_formats"] = list(SUPPORTED_BACKUP_FORMATS)
    result["key_recovered_from_ciphertext"] = False
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = args.out / "whatsapp_recovery_manifest.json"
    manifest.write_text(json.dumps(result, indent=2), encoding="utf-8")
    manifest.chmod(0o600)
    print(json.dumps({"manifest": str(manifest), "state": result["whatsapp_decryption_state"],
                      "decrypted_databases": result.get("whatsapp_decrypted_backups", 0),
                      "decrypted_files": result.get("whatsapp_decrypted_files", 0), "derived_files": len(result["copied"]),
                      "failed_backups": result.get("whatsapp_decrypt_failed", 0)}))
    return 0 if result["whatsapp_decryption_state"] == "decrypted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
