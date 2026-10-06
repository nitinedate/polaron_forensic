"""Unpack an unencrypted Android ``.ab`` (adb backup) into a folder.

Encrypted backups (AES-256 header) cannot be opened without the password the
examiner typed on the phone. This module does not brute-force or bypass that.
"""

from __future__ import annotations

import argparse
import io
import tarfile
import zlib
from pathlib import Path


def extract_android_backup(ab_path: Path, dest: Path) -> dict:
    path = Path(ab_path)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if not path.is_file() or path.stat().st_size < 64:
        return {"ok": False, "error": "backup file missing or empty", "files": 0}

    raw = path.read_bytes()
    # Header is four newline-terminated lines: ANDROID BACKUP / version / compress / encryption
    parts = raw.split(b"\n", 4)
    if len(parts) < 5 or not parts[0].startswith(b"ANDROID BACKUP"):
        return {"ok": False, "error": "not an ANDROID BACKUP file", "files": 0}
    encryption = parts[3].decode("ascii", "replace").strip().lower()
    if encryption not in ("none", ""):
        return {
            "ok": False,
            "error": f"backup is encrypted ({encryption}); enter the password used on the phone",
            "files": 0,
        }
    payload = parts[4]
    try:
        tar_bytes = zlib.decompress(payload)
    except zlib.error:
        # Some tools write uncompressed tar after the header.
        tar_bytes = payload
    extracted = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                tar.extract(member, path=dest, set_attrs=False)
                extracted += 1
    except tarfile.TarError as exc:
        return {"ok": False, "error": f"tar extract failed: {exc}", "files": extracted}
    return {"ok": extracted > 0, "files": extracted, "dest": str(dest)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract an unencrypted adb backup (.ab)")
    parser.add_argument("--ab", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = extract_android_backup(Path(args.ab), Path(args.out))
    print(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
