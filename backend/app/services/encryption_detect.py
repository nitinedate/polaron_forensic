"""Detect password-protected / encrypted files from content headers."""

from __future__ import annotations

import struct
import zipfile
import io


def count_encrypted_zip_entries(data: bytes) -> int:
    """Return number of encrypted member entries inside a ZIP archive.

    Prefers a full ZipFile parse when the buffer looks complete; otherwise scans
    local-file headers in-place so truncated prefix reads still work.
    """
    if not data or not data.startswith(b"PK"):
        return 0
    # Complete archives usually end with end-of-central-directory signature.
    if b"PK\x05\x06" in data[-65557:] or b"PK\x06\x06" in data[-65557:]:
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                total = 0
                for info in zf.infolist():
                    if info.is_dir() or (info.filename or "").endswith("/"):
                        continue
                    if info.flag_bits & 0x1:
                        total += 1
                return total
        except Exception:
            pass

    # Prefix-friendly scan — find every local-file header in the buffer.
    total = 0
    off = 0
    limit = len(data)
    while off + 30 <= limit:
        idx = data.find(b"PK\x03\x04", off)
        if idx < 0 or idx + 30 > limit:
            break
        flag = struct.unpack_from("<H", data, idx + 6)[0]
        if flag & 0x1:
            total += 1
        off = idx + 4
    return total


def _zip_has_encryption(data: bytes) -> bool:
    return count_encrypted_zip_entries(data) > 0


def is_encrypted_file(data: bytes, path: str = "") -> bool:
    if not data or len(data) < 16:
        return False
    low = (path or "").replace("\\", "/").lower()
    ext = low.rsplit(".", 1)[-1] if "." in low else ""
    sample = data[:65536]
    pdf_sample = data[: min(len(data), 524288)]

    if ext in ("aes", "enc", "gpg", "pgp", "kdbx", "hc", "tc", "vhdx", "dmg"):
        return True

    if sample[:4] == b"FILE":
        return True

    if b"%PDF" in sample[:2048] and (b"/Encrypt" in pdf_sample or b"/Filter/Standard" in pdf_sample):
        return True

    if b"EncryptedPackage" in sample or b"EncryptionInfo" in sample:
        return True

    if sample[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        if b"EncryptedPackage" in sample or b"EncryptionInfo" in sample or b"StrongEncryption" in sample:
            return True

    if ext in ("zip", "docx", "xlsx", "pptx", "jar", "odt", "ods") or sample[:2] == b"PK":
        if _zip_has_encryption(data[: min(len(data), 262144)]):
            return True
        if ext in ("docx", "xlsx", "pptx") and (b"EncryptedPackage" in sample or b"EncryptionInfo" in sample):
            return True

    if ext == "7z" and len(sample) >= 6 and sample[:6] == b"\x37\x7a\xbc\xaf\x27\x1c":
        if b"7zAES" in sample or b"\x06\xf1\x07\x01" in sample[:512]:
            return True

    if ext == "pdf" and (b"/Encrypt" in pdf_sample or b"/Filter/Standard" in pdf_sample):
        return True

    return False
