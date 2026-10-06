#!/usr/bin/env python3
"""Run a supplied CRYPT-family case folder against the production mobile parser."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.mobile_forensic.whatsapp_case_decrypt import decrypt_case_folder

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-folder", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--key-file", action="append", default=[], type=Path)
    parser.add_argument("--export-key-hex", action="store_true",
                        help="Write the already-collected matching key to a private local file; never print it")
    args = parser.parse_args()
    result = decrypt_case_folder(args.case_folder, args.output, key_files=args.key_file,
                                 export_key_hex=args.export_key_hex)
    print(f"Backups={result['backup_count']} decrypted={result['decrypted_count']} blocked={result['blocked_count']}")
    print(f"Authenticated={result['authenticated_count']} legacy_unverified={result['legacy_unverified_count']}")
    print(f"Report: {args.output / 'decryption_report.json'}")
    return 2 if result["blocked_count"] or not result["backup_count"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
