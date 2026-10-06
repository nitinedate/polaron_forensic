"""Offline case-folder validation using collected keys, never key recovery from ciphertext."""
from __future__ import annotations

from app.services.mobile_forensic.crypt_formats import is_crypt_file
import hashlib
import json
import os
import tempfile
from pathlib import Path

from app.services.mobile_forensic.whatsapp_crypt import (
    MAX_PAYLOAD_BYTES, WhatsAppKeyCandidate, decrypt_with_candidates, last_decrypt_diagnostics, parse_key_material,
)
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser


def _check_output(path: Path, root: Path) -> None:
    if path.is_symlink() or not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("Output symlink/path escapes the recovery directory")


def _write_private(path: Path, data: bytes, *, root: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_output(path, root)
    fd, temp_name = tempfile.mkstemp(prefix=".whatsapp-", dir=path.parent)
    try:
        os.chmod(temp_name, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temp_name, path)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def decrypt_case_folder(case_folder: Path, output: Path, *, key_files=(), export_key_hex=False) -> dict:
    """Write verified DBs and parsed artifacts. Return only nonsecret status metadata.

    Does not alter the source folder. A matching key is scoped to each backup,
    not assumed to decrypt other accounts, apps, media formats or device storage.
    """
    root = case_folder.resolve(strict=True)
    dest = output.resolve()
    if not root.is_dir() or dest.is_relative_to(root) or root.is_relative_to(dest):
        raise ValueError("Output must be outside the source folder and not its parent")
    candidates = []
    sources = []

    def read_key(path):
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            return
        if not 24 <= path.stat().st_size <= 512:
            return
        material = path.read_bytes()
        km = parse_key_material(material)
        if km:
            candidate = WhatsAppKeyCandidate(material, str(path))
            candidates.append(candidate)
            sources.append({"source": str(path), "key_kind": km.kind,
                            "sha256": hashlib.sha256(material).hexdigest()})

    for path in key_files:
        read_key(path)
    backups = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = [name for name in sorted(directories)
                          if not (Path(current)/name).is_symlink()
                          and not (Path(current)/name).resolve().is_relative_to(dest)]
        for name in sorted(names):
            path = Path(current)/name
            if path.is_symlink() or not path.is_file() or path.resolve().is_relative_to(dest):
                continue
            relative = str(path.relative_to(root)).replace("\\", "/")
            if name.lower() in {"encrypted_backup.key", "whatsapp.key", "whatsapp_key.hex"} or (
                name.lower() == "key" and (path.parent == root or "whatsapp" in relative.lower())
            ):
                read_key(path)
            if is_crypt_file(name):
                backups.append(path)

    dest.mkdir(parents=True, exist_ok=True)
    report = {"backup_count": len(backups), "key_sources": sources, "results": [],
              "scope": "CRYPT-family files; supported WhatsApp layouts only; legacy decoding is unauthenticated"}
    for source in backups:
        if source.stat().st_size > MAX_PAYLOAD_BYTES:
            report["results"].append({"source_path": str(source.relative_to(root)), "state": "blocked",
                                      "diagnostics": {"reason": "source_size_limit", "authenticated": False}})
            continue
        raw = source.read_bytes()
        relative = str(source.relative_to(root)).replace("\\", "/")
        digest = hashlib.sha256(raw).hexdigest()
        plain = decrypt_with_candidates(raw, candidates, path=str(source), expected_size=source.stat().st_size, allow_resources="msgstore" not in source.name.lower())
        diag = last_decrypt_diagnostics()
        result = {"source_path": relative, "source_sha256": digest,
                  "state": "decrypted" if plain is not None else "blocked", "diagnostics": diag}
        if plain is not None:
            folder = dest / hashlib.sha256(relative.encode()).hexdigest()[:16]
            from app.services.mobile_forensic.whatsapp_derivation import decoded_filename
            output_name = "msgstore.db" if diag.get("payload_kind") == "sqlite" else decoded_filename(relative, diag.get("payload_kind") or "binary")
            _write_private(folder / output_name, plain, root=dest)
            result["database_output" if diag.get("payload_kind") == "sqlite" else "payload_output"] = str(folder / output_name)
            result["decrypted_sha256"] = hashlib.sha256(plain).hexdigest()
            item = InventoryItem(path=relative, size=len(raw), sha256=digest)
            context = ParseContext(job_id="offline-crypt14-test", platform="Android",
                                   whatsapp_key_candidates=candidates, read_bytes=lambda *_a, **_kw: raw)
            artifact_path = folder / "artifacts.jsonl"
            _check_output(artifact_path, dest)
            count = 0
            # This can run the same production parser without DB/MinIO.
            fd = os.open(artifact_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.chmod(artifact_path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                for art in WhatsAppParser().parse(item, context):
                    stream.write(json.dumps({"artifact_type": art.artifact_type, "data": art.data,
                                             "forensic": art.forensic}, ensure_ascii=False, default=str) + "\n")
                    count += 1
            result["artifacts_output"] = str(artifact_path)
            result["artifact_count"] = count
            if export_key_hex and diag.get("authenticated"):
                matching = next((c for c in candidates if c.source == diag.get("key_source")), None)
                if matching:
                    # Opt-in local export of an ALREADY COLLECTED key; never logs it.
                    _write_private(folder / "matched_key.hex", parse_key_material(matching.material).raw32.hex().encode() + b"\n", root=dest)
                    result["key_output"] = str(folder / "matched_key.hex")
        report["results"].append(result)
    report["decrypted_count"] = sum(r["state"] == "decrypted" for r in report["results"])
    report["authenticated_count"] = sum(bool(r["diagnostics"].get("authenticated")) for r in report["results"] if r["state"] == "decrypted")
    report["legacy_unverified_count"] = sum(r["diagnostics"].get("validation") == "legacy_structural_only" for r in report["results"] if r["state"] == "decrypted")
    report["blocked_count"] = sum(r["state"] == "blocked" for r in report["results"])
    _write_private(dest / "decryption_report.json", json.dumps(report, indent=2).encode(), root=dest)
    return report
