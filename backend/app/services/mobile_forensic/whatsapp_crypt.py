"""WhatsApp historical and modern CRYPT-family database/payload decryption.

Fail-closed, deterministic, no brute force. Only decrypts with key material the
examiner actually collected or entered:

  * the 158-byte Android ``/data/data/com.whatsapp/files/key`` file
    (crypt7 / crypt8 / crypt9 / crypt10 / crypt11 / crypt12 / crypt14) — AES-256 is the LAST 32 bytes (offset 126),
    NOT offset 30 (that is the ``t1`` header-match checksum; the pre-V45
    implementation used it as the key and therefore never decrypted anything);
  * the 32-byte ``encrypted_backup.key`` or the 64-digit end-to-end backup key
    the user sees in WhatsApp (crypt15) — the real AES key is derived with
    HKDF-SHA256 (zero salt, info ``"backup encryption"``, L=32);
  * a raw 32-byte AES key or 64-hex string;
  * an already-derived 24-byte/48-hex CRYPT5 secret, or its original Google account;
  * the public historical AES-192 ECB format key for original unnumbered .crypt.

Layouts (reference: public crypt12/14/15 research, e.g. wa-crypt-tools docs):

  crypt12 : [51 B header incl. t1 at 3:35][16 B IV][ciphertext][tag][optional MD5][4 B]
  crypt14/15 : [1 B protobuf length][optional 0x01 feature flag]
               [BackupPrefix protobuf containing IV][ciphertext][tag][optional MD5]

Because WhatsApp changes the prefix layout between releases, decryption is
treated as documented protobuf fields with historical-layout fallbacks. Modern
AES-GCM authentication and any MD5 footer must pass. Payloads include SQLite,
ZIP changesets, settings, images and binary files, with bounded decompression.
Legacy AES-CBC databases require SQLite size/structural checks and are explicitly
labelled as lacking authentication; these checks cannot prove their authenticity.

The compatibility API returns only SQLite. The payload API returns other verified
payloads too. Unsupported CRYPT versions remain encrypted with explicit reasons.
Key material cannot be recovered from modern backup ciphertext. Failure records
explain *why* in
``last_decrypt_diagnostics()`` so the UI/report can show the examiner the gap.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import sqlite3
import threading
import zlib
from dataclasses import dataclass, field

log = logging.getLogger("mobile_forensic.whatsapp_crypt")

SQLITE_MAGIC = b"SQLite format 3\x00"
SUPPORTED_BACKUP_FORMATS = ("crypt", "crypt5", "crypt7", "crypt8", "crypt9", "crypt10", "crypt11", "crypt12", "crypt14", "crypt15")
MAX_PAYLOAD_BYTES = 768_000_000
_CRYPT_SUFFIX = re.compile(r"\.(crypt[a-z0-9_-]*)$", re.IGNORECASE)


def crypt_extension(path: str) -> str | None:
    """Recognize every numbered CRYPT suffix, including unsupported versions."""
    match = _CRYPT_SUFFIX.search(path or "")
    return match.group(1).lower() if match else None


def is_whatsapp_crypt_path(path: str) -> bool:
    normalized = (path or "").replace("\\", "/").lower()
    return bool(crypt_extension(normalized)) and (
        "whatsapp" in normalized or "msgstore" in normalized.rsplit("/", 1)[-1]
    )

# --- key file layout ---------------------------------------------------------
KEYFILE_LEN = 158
KEYFILE_T1_OFFSET = 30        # 32-byte "t1" — must equal crypt12 header[3:35]
KEYFILE_KEY_OFFSET = 126      # 32-byte AES-256 key (LAST 32 bytes)
KEY_LEN = 32
IV_LEN = 16
GCM_TAG_LEN = 16

# --- crypt12 layout ----------------------------------------------------------
CRYPT12_HEADER_LEN = 51
CRYPT12_T1_SLICE = slice(3, 35)
CRYPT12_IV_SLICE = slice(51, 67)
CRYPT12_BODY_START = 67
CRYPT12_TRAILER_LEN = 20      # 16-byte GCM tag + 4 bytes

# Historical crypt14 body offsets observed across releases (IV = 16 bytes before).
_LEGACY_CRYPT14_BODY_OFFSETS = (67, 99, 162, 184, 191, 200, 227, 249)

# crypt15 HKDF info string (HKDF-SHA256, zero salt, one 32-byte block => "info || 0x01").
_C15_HKDF_INFO = b"backup encryption"


@dataclass
class DecryptDiagnostics:
    """Examiner-facing explanation of the last decrypt attempt in this thread."""

    key_kind: str = "none"            # keyfile158 | raw32 | hex64 | invalid
    key_sha256_prefix: str = ""
    container: str = "unknown"        # crypt12 | crypt14 | crypt15 | sqlite | unknown
    candidates_tried: int = 0
    strategy: str = ""                # which candidate succeeded
    reason: str = ""                  # failure reason when result is None
    t1_match: bool | None = None
    authenticated: bool = False
    checksum_verified: bool | None = None
    keys_tried: int = 0
    key_source: str | None = None
    payload_kind: str | None = None
    integrity: str = "unverified"
    payload_hint: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "key_kind": self.key_kind,
            "key_sha256_prefix": self.key_sha256_prefix,
            "container": self.container,
            "candidates_tried": self.candidates_tried,
            "strategy": self.strategy,
            "reason": self.reason,
            "t1_match": self.t1_match,
            "authenticated": self.authenticated,
            "checksum_verified": self.checksum_verified,
            "keys_tried": self.keys_tried,
            "key_source": self.key_source,
            "payload_kind": self.payload_kind,
            "integrity": self.integrity,
            "validation": "legacy_structural_only" if self.integrity.startswith("legacy_") else "authenticated" if self.authenticated else "plaintext" if self.integrity == "plaintext" else "unverified",
            "notes": list(self.notes),
        }


_tls = threading.local()


def last_decrypt_diagnostics() -> dict:
    diag = getattr(_tls, "diag", None)
    return diag.as_dict() if isinstance(diag, DecryptDiagnostics) else {}


def _set_diag(diag: DecryptDiagnostics) -> None:
    _tls.diag = diag


# -----------------------------------------------------------------------------
# Key material
# -----------------------------------------------------------------------------

def looks_like_sqlite(data: bytes | None) -> bool:
    return bool(data) and data[:16] == SQLITE_MAGIC


@dataclass(frozen=True)
class KeyMaterial:
    kind: str                 # keyfile158 | raw32 | hex64
    raw32: bytes = field(repr=False)  # the 32-byte secret as collected/entered
    t1: bytes | None = None   # crypt12 header check (keyfile only)

    @property
    def key_crypt12_14(self) -> bytes:
        return self.raw32

    @property
    def key_crypt15(self) -> bytes:
        """HKDF-SHA256(salt=0^32, ikm=raw32, info="backup encryption", L=32)."""
        prk = hmac.new(b"\x00" * 32, self.raw32, hashlib.sha256).digest()
        return hmac.new(prk, _C15_HKDF_INFO + b"\x01", hashlib.sha256).digest()


@dataclass(frozen=True)
class WhatsAppKeyCandidate:
    # Keep secrets out of repr/logs. Only source paths enter evidence diagnostics.
    material: bytes | str = field(repr=False)
    source: str = "case_intake"


def is_acquisition_error(data: bytes) -> bool:
    head = data[:512].lstrip(b"\xef\xbb\xbf \r\n\t").lower()
    return head.startswith((b"run-as", b"error:", b"adb:", b"su:", b"cat:", b"/system/bin/sh:", b"sh:")) or any(
        text in head for text in (b"not debuggable", b"permission denied", b"device unauthorized", b"no devices/emulators found")
    )


def _java_byte_array(blob: bytes) -> bytes | None:
    """Decode only Java's primitive byte[] envelope, never arbitrary objects."""
    prefix = bytes.fromhex("aced0005757200025b42acf317f8060854e00200007870")
    if not blob.startswith(prefix) or len(blob) < len(prefix) + 4:
        return None
    size = int.from_bytes(blob[len(prefix):len(prefix) + 4], "big")
    start = len(prefix) + 4
    if size not in (32, 131) or len(blob) != start + size:
        return None
    return blob[start:]


def parse_key_material(key_material: bytes | str | None) -> KeyMaterial | None:
    """Accept device/backup secrets and already-derived CRYPT5 24-byte keys."""
    if key_material is None:
        return None
    if isinstance(key_material, str):
        s = "".join(ch for ch in key_material if ch not in " \n\r\t-:")
        if not s:
            return None
        try:
            blob = bytes.fromhex(s)
        except ValueError:
            log.warning("whatsapp key text is not hex (len=%d)", len(s))
            return None
        if len(blob) == 24:
            return KeyMaterial("legacy_hex48", blob)
        if len(blob) == KEY_LEN:
            return KeyMaterial("hex64", blob)
        key_material = blob  # could be a hex-encoded key file
    if not isinstance(key_material, (bytes, bytearray)):
        return None
    blob = bytes(key_material)
    if not blob:
        return None
    # adb `run-as` error text sometimes gets saved as files/key by naive pullers.
    if is_acquisition_error(blob):
        return None
    if blob.startswith(b"\xac\xed"):
        payload = _java_byte_array(blob)
        if payload is None:
            return None
        if len(payload) == 32:
            return KeyMaterial("java_backup_key32", payload)
        return KeyMaterial("java_keyfile158", payload[-32:], t1=payload[3:35])
    # Keys copied to a text file are common; bytes must take the same hex path
    # as the intake field (including whitespace, separators and UTF-8 BOM).
    if len(blob) != KEY_LEN:
        try:
            text = blob.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = ""
        compact = "".join(ch for ch in text if ch not in " \n\r\t-:")
        if len(compact) in (48, 64, 316) and all(ch in "0123456789abcdefABCDEF" for ch in compact):
            return parse_key_material(compact)
    if len(blob) == 24:
        return KeyMaterial("legacy_raw24", blob)
    if len(blob) == KEY_LEN:
        return KeyMaterial("raw32", blob)
    if len(blob) == KEYFILE_LEN:
        return KeyMaterial(
            "keyfile158",
            blob[KEYFILE_KEY_OFFSET : KEYFILE_KEY_OFFSET + KEY_LEN],
            t1=blob[KEYFILE_T1_OFFSET : KEYFILE_T1_OFFSET + KEY_LEN],
        )
    if len(blob) == 131:
        return KeyMaterial("key_payload131", blob[-32:], t1=blob[3:35])
    # Do not silently accept an arbitrary damaged/truncated key suffix.
    if KEYFILE_LEN < len(blob) <= KEYFILE_LEN + 2 and blob[KEYFILE_LEN:] in (b"\n", b"\r\n"):
        core = blob[:KEYFILE_LEN]
        return KeyMaterial(
            "keyfile158",
            core[KEYFILE_KEY_OFFSET : KEYFILE_KEY_OFFSET + KEY_LEN],
            t1=core[KEYFILE_T1_OFFSET : KEYFILE_T1_OFFSET + KEY_LEN],
        )
    return None


def cipher_key_from_material(key_material: bytes | str | None) -> bytes | None:
    """Backwards-compatible helper (callers in android_readable/package_inventory).

    Returns the 32-byte *base* secret. crypt15 derivation happens inside
    ``try_decrypt_whatsapp_crypt``; passing this value back in is fine because a
    32-byte raw key is re-wrapped as ``raw32`` and derived again when needed.
    """
    km = parse_key_material(key_material)
    return km.raw32 if km else None


# -----------------------------------------------------------------------------
# Minimal protobuf wire-format walker (no protobuf dependency)
# -----------------------------------------------------------------------------

def _read_varint(buf: bytes, pos: int) -> tuple[int, int] | None:
    result = 0
    shift = 0
    while pos < len(buf) and shift <= 63:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return None


def _protobuf_length_delimited_fields(buf: bytes, *, depth: int = 0, max_depth: int = 4) -> list[bytes]:
    """Return every length-delimited field value, recursing into sub-messages.

    Tolerant: stops at the first malformed byte instead of raising. Used only
    to harvest IV candidates (16-byte values) from the BackupPrefix header.
    """
    out: list[bytes] = []
    pos = 0
    n = len(buf)
    while pos < n:
        tag = _read_varint(buf, pos)
        if tag is None:
            break
        key, pos = tag
        wire = key & 0x07
        if wire == 0:           # varint
            v = _read_varint(buf, pos)
            if v is None:
                break
            _, pos = v
        elif wire == 1:         # 64-bit
            pos += 8
        elif wire == 2:         # length-delimited
            ln = _read_varint(buf, pos)
            if ln is None:
                break
            length, pos = ln
            if length < 0 or pos + length > n:
                break
            val = buf[pos : pos + length]
            out.append(val)
            if depth < max_depth and length > 2:
                out.extend(_protobuf_length_delimited_fields(val, depth=depth + 1, max_depth=max_depth))
            pos += length
        elif wire == 5:         # 32-bit
            pos += 4
        else:
            break
    return out


# -----------------------------------------------------------------------------
# AES-GCM + inflate with the SQLite oracle
# -----------------------------------------------------------------------------

def _protobuf_named_bytes(buf: bytes) -> list[tuple[int, bytes]]:
    """Read one protobuf message; retain field numbers rather than guessing IVs."""
    pos, fields = 0, []
    while pos < len(buf):
        tag = _read_varint(buf, pos)
        if not tag or tag[0] >> 3 == 0:
            return []
        number, wire = tag[0] >> 3, tag[0] & 7
        pos = tag[1]
        if wire == 0:
            value = _read_varint(buf, pos)
            if not value:
                return []
            pos = value[1]
        elif wire == 2:
            length = _read_varint(buf, pos)
            if not length or length[1] + length[0] > len(buf):
                return []
            start, size = length[1], length[0]
            fields.append((number, buf[start:start + size]))
            pos = start + size
        elif wire in (1, 5):
            pos += 8 if wire == 1 else 4
            if pos > len(buf):
                return []
        else:
            return []
    return fields


def _documented_ivs(header: bytes, container: str) -> list[bytes]:
    versions = ((2, 5),) if container == "crypt14" else ((3, 1),) if container == "crypt15" else ((2, 5), (3, 1))
    fields = _protobuf_named_bytes(header)
    # Compatibility with the historical single-field protobuf IV prefix. GCM
    # authentication still decides whether this structural candidate is valid.
    if len(fields) == 1 and fields[0][0] == 1 and len(fields[0][1]) == IV_LEN:
        return [fields[0][1]]
    return [iv for root_field, crypto in fields
            for message_field, iv_field in versions if root_field == message_field
            for field_number, iv in _protobuf_named_bytes(crypto) if field_number == iv_field and len(iv) == IV_LEN]

def payload_kind(plain: bytes) -> str:
    if looks_like_sqlite(plain):
        return "sqlite"
    if plain.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if plain.lstrip(b"\xef\xbb\xbf \r\n\t").startswith((b"{", b"[")):
        import json
        try:
            json.loads(plain.decode("utf-8-sig"))
            return "json"
        except (ValueError, UnicodeError, RecursionError):
            pass
    if plain[:4] == b"RIFF" and plain[8:12] == b"WEBP":
        return "webp"
    if plain.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if plain.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    return "binary"


def _inflate_payload(plain: bytes | None) -> bytes | None:
    """Bound expansion and require a complete compressed stream."""
    if plain is None:
        return None
    if len(plain) > MAX_PAYLOAD_BYTES:
        return None
    zlib_header = len(plain) > 1 and plain[0] == 0x78 and int.from_bytes(plain[:2], "big") % 31 == 0
    gzip_header = plain.startswith(b"\x1f\x8b")
    if not zlib_header and not gzip_header:
        return plain
    try:
        d = zlib.decompressobj(15 | 32)
        out = d.decompress(plain, MAX_PAYLOAD_BYTES + 1)
    except zlib.error:
        return None
    return out if len(out) <= MAX_PAYLOAD_BYTES and d.eof and not d.unused_data and not d.unconsumed_tail else None


def _inflate_to_sqlite(plain: bytes | None) -> bytes | None:
    hit = _inflate_payload(plain)
    return hit if looks_like_sqlite(hit) else None


def _legacy_sqlite_valid(plain: bytes) -> bool:
    """CBC has no MAC: require exact database size and SQLite structural checks."""
    if not looks_like_sqlite(plain) or len(plain) < 100:
        return False
    page_size = int.from_bytes(plain[16:18], "big") or 0
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1) or len(plain) % page_size:
        return False
    pages = int.from_bytes(plain[28:32], "big")
    if pages and pages * page_size != len(plain):
        return False
    try:
        con = sqlite3.connect(":memory:")
        try:
            con.deserialize(plain)
            con.execute("PRAGMA query_only=ON")
            con.set_progress_handler(lambda: 1, 10_000_000)
            return con.execute("PRAGMA quick_check(1)").fetchall() == [("ok",)]
        finally:
            con.close()
    except (sqlite3.Error, AttributeError):
        return False


def _legacy_decrypt(data: bytes, km: KeyMaterial | None, diag: DecryptDiagnostics, legacy_account: str | None) -> bytes | None:
    container = diag.container
    if container == "crypt5" and km is not None and len(km.raw32) == 24:
        key, iv, body = km.raw32, bytes.fromhex("1e39f369e90db33aa73b442bbbb6b0b9"), data
    elif container == "crypt5":
        if not legacy_account or "@" not in legacy_account or len(legacy_account) > 320:
            diag.reason = "legacy_account_required"
            diag.notes.append("CRYPT5 requires the exact original Android Google account name; it is not stored in the backup")
            return None
        account_digest = hashlib.md5(legacy_account.strip().encode("utf-8")).digest()
        base = bytes.fromhex("8d4b155cc9ff81e5cbf6fa7819366a3ec621a656416cd793")
        key = bytes(byte ^ account_digest[index % 16] for index, byte in enumerate(base))
        iv = bytes.fromhex("1e39f369e90db33aa73b442bbbb6b0b9")
        body = data
        diag.key_kind = "legacy_account_derived"
    else:
        if km is None:
            diag.reason = "key_material_missing_or_invalid"
            return None
        key, iv, body = km.raw32, data[51:67], data[67:]
    if not body or len(body) % 16 or len(iv) != 16:
        diag.reason = "legacy_container_truncated"
        return None
    diag.candidates_tried = 1
    try:
        try:
            from Crypto.Cipher import AES
            plain = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(body)
        except ImportError:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            plain = dec.update(body) + dec.finalize()
    except Exception:
        diag.reason = "aes_provider_unavailable" if not _aes_provider_available() else "legacy_decrypt_failed"
        return None
    # Historical writers use either whole SQLite pages or PKCS#7 padding.
    options = [plain]
    padding = plain[-1]
    if 1 <= padding <= 16 and plain[-padding:] == bytes([padding]) * padding:
        options.insert(0, plain[:-padding])
    for option in options:
        hit = _inflate_payload(option) if container == "crypt8" else option
        if hit and _legacy_sqlite_valid(hit):
            diag.payload_kind = "sqlite"
            diag.strategy = f"{container}/aes_cbc/sqlite_quick_check"
            diag.integrity = "legacy_structure_checked_no_mac"
            diag.notes.append("Legacy CBC backup has no authentication tag: SQLite structural validation does not prove authenticity")
            diag.reason = ""
            return hit
    diag.reason = "key_mismatch_or_damaged_backup"
    return None


def _retained_legacy(data: bytes, km: KeyMaterial | None, diag: DecryptDiagnostics, key_material=None) -> bytes | None:
    """Preserve validated historical formats without claiming authentication."""
    from app.services.mobile_forensic.whatsapp_legacy import decode_legacy
    if isinstance(key_material, str):
        key_material = bytes.fromhex("".join(ch for ch in key_material if ch not in " \n\r\t-:"))
    try:
        hit = decode_legacy(data, km.raw32 if km else None, diag.container, _inflate_to_sqlite, key_file=key_material)
    except Exception:
        hit = None
    if hit is not None and _legacy_sqlite_valid(hit):
        diag.payload_kind = "sqlite"
        diag.integrity = "legacy_structure_checked_no_mac"
        diag.strategy = f"{diag.container}/legacy/sqlite_quick_check"
        diag.authenticated = False
        diag.reason = ""
        diag.notes.append("Historical payload structurally checked; authenticity is not verified")
        return hit
    diag.reason = "key_mismatch_or_damaged_backup" if _aes_provider_available() else "aes_provider_unavailable"
    return None


def _aes_gcm_decrypt(key32: bytes, iv: bytes, blob: bytes, tag: bytes) -> bytes | None:
    """Return only authenticated plaintext, using either supported AES provider."""
    if len(key32) != KEY_LEN or len(iv) != IV_LEN or len(tag) != GCM_TAG_LEN:
        return None
    try:
        from Crypto.Cipher import AES  # type: ignore
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
            dec = Cipher(algorithms.AES(key32), modes.GCM(iv, tag)).decryptor()
            return dec.update(blob) + dec.finalize()
        except Exception:
            return None
    try:
        return AES.new(key32, AES.MODE_GCM, nonce=iv).decrypt_and_verify(blob, tag)
    except Exception:
        return None


def _aes_provider_available() -> bool:
    try:
        from Crypto.Cipher import AES  # noqa: F401

        return True
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401

            return True
        except ImportError:
            return False


def _candidate_prefix_matches(key32: bytes, iv: bytes, prefix: bytes, *, hint: str = "sqlite") -> bool:
    """Cheap layout/key probe. Never return this unauthenticated data to callers."""
    try:
        try:
            from Crypto.Cipher import AES

            plain = AES.new(key32, AES.MODE_GCM, nonce=iv).decrypt(prefix)
        except ImportError:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            plain = Cipher(algorithms.AES(key32), modes.GCM(iv)).decryptor().update(prefix)
        if plain.startswith(b"\x1f\x8b") or len(plain) > 1 and plain[0] == 0x78 and int.from_bytes(plain[:2], "big") % 31 == 0:
            head = zlib.decompressobj(15 | 32).decompress(plain, 64)
        else:
            head = plain[:64]
        if hint in {"sqlite", "sqlite_or_zip"}:
            return looks_like_sqlite(head) or hint == "sqlite_or_zip" and head.startswith((b"PK\x03\x04", b"PK\x05\x06"))
        if hint == "zip":
            return head.startswith((b"PK\x03\x04", b"PK\x05\x06"))
        if hint == "json":
            return head.lstrip(b"\xef\xbb\xbf \r\n\t").startswith((b"{", b"["))
        if hint == "webp":
            return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
        if hint == "png":
            return head.startswith(b"\x89PNG\r\n\x1a\n")
        if hint == "jpeg":
            return head.startswith(b"\xff\xd8\xff")
        return False
    except Exception:
        return False


def _try_candidate(key32: bytes, iv: bytes, data: bytes, start: int, diag: DecryptDiagnostics, label: str, *, allow_payloads: bool = False, skip_prefix: bool = False) -> bytes | None:
    # crypt12 can carry an extra four-byte JID trailer; modern single-file
    # backups have a 16-byte MD5 footer, multi-file/older layouts have only a tag.
    trailers = (4, 0) if diag.container in ("crypt9", "crypt10", "crypt11", "crypt12", "unknown") else (0,)
    hint = diag.payload_hint if allow_payloads else "sqlite"
    if not skip_prefix and hint and len(data) - start > 36 and not _candidate_prefix_matches(key32, iv, data[start:start + 4096], hint=hint):
        diag.candidates_tried += 1
        return None
    for trailer in trailers:
        end = len(data) - trailer
        known_checksum = hashlib.md5(data[:end - 16]).digest() == data[end - 16:end] if end - 16 >= start else False
        for checksum in ((16,) if known_checksum else (16, 0)):
            tag_start = end - checksum - GCM_TAG_LEN
            if tag_start < start:
                continue
            diag.candidates_tried += 1
            plain = _aes_gcm_decrypt(key32, iv, data[start:tag_start], data[tag_start:tag_start + GCM_TAG_LEN])
            if plain is None:
                continue
            if checksum and hashlib.md5(data[:end - checksum]).digest() != data[end - checksum:end]:
                diag.reason = "backup_checksum_mismatch"
                continue
            hit = _inflate_payload(plain) if allow_payloads else _inflate_to_sqlite(plain)
            if hit is not None:
                diag.strategy = f"{label}/tag+md5" if checksum else f"{label}/tag"
                diag.authenticated = True
                diag.payload_kind = payload_kind(hit)
                diag.integrity = "aes_gcm_authenticated"
                diag.checksum_verified = True if checksum else None
                diag.reason = ""
                return hit
            diag.reason = "authenticated_payload_invalid_or_over_limit" if allow_payloads else "authenticated_payload_not_sqlite"
    return None


# -----------------------------------------------------------------------------
# Container classification
# -----------------------------------------------------------------------------

def classify_container(data: bytes, path: str = "") -> str:
    if looks_like_sqlite(data):
        return "sqlite"
    extension = crypt_extension(path)
    if extension:
        return extension
    # Heuristic when the extension was stripped: crypt12 starts with 0x00 0x01? no fixed magic,
    # but its header is exactly 51 bytes with t1 at 3:35; crypt14/15 start with the protobuf length byte.
    if len(data) > 67 and data[:1] == b"\x00":
        return "crypt12"
    return "unknown"


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def _decrypt_whatsapp(
    data: bytes,
    key_material: str | bytes | None,
    *,
    path: str = "",
    allow_payloads: bool = False,
    legacy_account: str | None = None,
) -> bytes | None:
    """Decode supported WhatsApp containers using collected or entered material."""
    diag = DecryptDiagnostics()
    _set_diag(diag)
    if not data:
        diag.reason = "empty_input"
        return None
    if len(data) > MAX_PAYLOAD_BYTES:
        diag.reason = "source_size_limit"
        return None
    diag.container = classify_container(data, path)
    extension = crypt_extension(path)
    base = path[:-(len(extension) + 1)].lower() if extension else ""
    if base.endswith((".db", ".sqlite", ".sqlite3")) or "msgstore" in base.rsplit("/", 1)[-1]:
        diag.payload_hint = "sqlite_or_zip"
    else:
        diag.payload_hint = next((kind for suffix, kind in ((".json", "json"), (".zip", "zip"), (".png", "png"), (".webp", "webp"), (".jpg", "jpeg"), (".jpeg", "jpeg")) if base.endswith(suffix)), None)
    if diag.container == "sqlite":
        diag.strategy = "already_plaintext"
        diag.payload_kind = "sqlite"
        diag.integrity = "plaintext"
        return data
    if diag.container not in (*SUPPORTED_BACKUP_FORMATS, "unknown"):
        diag.reason = "unsupported_crypt_version"
        diag.notes.append("No validated decoder for this version; retained as encrypted evidence")
        return None

    km = parse_key_material(key_material)
    if diag.container == "crypt":
        hit = _retained_legacy(data, None, diag)
        if hit is not None:
            return hit
    if diag.container == "crypt5":
        if km:
            diag.key_kind = km.kind
            diag.key_sha256_prefix = hashlib.sha256(km.raw32).hexdigest()[:12]
        return _legacy_decrypt(data, km, diag, legacy_account)
    if km is None:
        diag.key_kind = "invalid" if key_material else "none"
        diag.reason = "key_material_missing_or_invalid"
        return None
    diag.key_kind = km.kind
    diag.keys_tried = 1
    diag.key_sha256_prefix = hashlib.sha256(km.raw32).hexdigest()[:12]
    if not _aes_provider_available():
        diag.reason = "aes_provider_unavailable"
        diag.notes.append("Use a Python environment containing cryptography (backend requirements) or pycryptodome")
        return None
    if len(data) < 32:
        diag.reason = "file_too_small"
        return None
    if len(km.raw32) != 32:
        diag.reason = "key_length_not_valid_for_format"
        return None
    if diag.container in ("crypt7", "crypt8"):
        hit = _legacy_decrypt(data, km, diag, legacy_account)
        return hit if hit is not None else _retained_legacy(data, km, diag, key_material)
    if diag.container in ("crypt9", "crypt10", "crypt11"):
        hit = _try_candidate(km.raw32, data[51:67], data, 67, diag, "historical_gcm", allow_payloads=allow_payloads)
        if hit is not None:
            return hit
        # Exact compressed EOF is required for tagless historical streams.
        # Never strip a failed tag/footer and downgrade authenticated evidence.
        if _candidate_prefix_matches(km.raw32, data[51:67], data[67:67 + 4096]):
            return _retained_legacy(data, km, diag, key_material)
        diag.reason = "key_mismatch_or_damaged_backup"
        return None

    # Which AES keys to try, most likely first.
    keys: list[tuple[str, bytes]] = []
    if diag.container == "crypt15":
        keys = [("c15_hkdf", km.key_crypt15), ("raw", km.key_crypt12_14)]
    elif diag.container in ("crypt12", "crypt14"):
        keys = [("raw", km.key_crypt12_14), ("c15_hkdf", km.key_crypt15)]
    else:
        keys = [("raw", km.key_crypt12_14), ("c15_hkdf", km.key_crypt15)]

    # ---- crypt12 fixed layout -------------------------------------------------
    if diag.container in ("crypt12", "unknown"):
        if km.t1 is not None:
            diag.t1_match = data[CRYPT12_T1_SLICE] == km.t1
            if diag.container == "crypt12" and diag.t1_match is False:
                diag.notes.append("crypt12 header t1 does not match key file t1 — wrong device key?")
        iv = data[CRYPT12_IV_SLICE]
        for klabel, key32 in keys:
            hit = _try_candidate(key32, iv, data, CRYPT12_BODY_START, diag, f"crypt12/{klabel}", allow_payloads=allow_payloads)
            if hit is not None:
                return hit

    # ---- crypt14 / crypt15 protobuf-prefixed layout --------------------------
    candidates: list[tuple[str, bytes, int]] = []
    declared_candidates: list[tuple[str, bytes, int]] = []
    first = data[0]
    header_len_variants: list[tuple[int, int]] = []
    if 0 < first <= 255 and 1 + first < len(data):
        header_len_variants.append((1, first))             # 1-byte length prefix (observed)
    vl = _read_varint(data, 0)
    if vl and 0 < vl[0] < 4096 and vl[1] + vl[0] < len(data) and (vl[1], vl[0]) not in header_len_variants:
        header_len_variants.append((vl[1], vl[0]))         # varint length prefix (defensive)
    for prefix_len, hlen in header_len_variants:
        # WhatsApp's feature marker is OUTSIDE the protobuf length. Starting
        # the wire walker at that marker used to lose both the IV and body.
        header_starts = [prefix_len]
        if data[prefix_len:prefix_len + 1] == b"\x01":
            header_starts.insert(0, prefix_len + 1)
        for header_start in header_starts:
            hdr_end = header_start + hlen
            header = data[header_start:hdr_end]
            for iv in _documented_ivs(header, diag.container):
                declared_candidates.append(("documented_protobuf_iv", iv, hdr_end))
            iv_fields = [f for f in _protobuf_length_delimited_fields(header) if len(f) == IV_LEN]
            for iv in iv_fields:
                candidates.append(("protobuf_iv", iv, hdr_end))
            # Preserve old raw-IV backup compatibility, still authenticated.
            candidates.append(("raw_iv_after_header", data[hdr_end:hdr_end + IV_LEN], hdr_end + IV_LEN))
    # Historical fixed offsets (IV immediately precedes the body).
    for start in _LEGACY_CRYPT14_BODY_OFFSETS:
        if start + 32 <= len(data):
            candidates.append((f"legacy_body@{start}", data[start - IV_LEN : start], start))

    seen: set[tuple[bytes, int]] = set()
    # A valid, versioned protobuf IV supersedes historical offset guesses.
    # Generic binary payloads then require only the documented cipher layout.
    for label, iv, start in declared_candidates or candidates:
        if len(iv) != IV_LEN or len(data) - start < GCM_TAG_LEN:
            continue
        sig = (iv, start)
        if sig in seen:
            continue
        seen.add(sig)
        for klabel, key32 in keys:
            hit = _try_candidate(key32, iv, data, start, diag, f"{label}/{klabel}", allow_payloads=allow_payloads)
            if hit is not None:
                return hit

    if allow_payloads and diag.payload_hint and declared_candidates:
        # Filename hints are only a fast probe. Renaming a valid payload must
        # never defeat authentication-based recovery. Bound this fallback to
        # declared protobuf IVs instead of repeating every historical offset.
        for label, iv, start in declared_candidates:
            for klabel, key32 in keys:
                hit = _try_candidate(key32, iv, data, start, diag, f"{label}/{klabel}/generic_payload",
                                     allow_payloads=True, skip_prefix=True)
                if hit is not None:
                    return hit

    diag.reason = diag.reason or "key_mismatch_or_damaged_backup"
    if km.kind in ("keyfile158", "java_keyfile158", "key_payload131") and diag.container == "crypt15":
        diag.notes.append("crypt15 needs the 32-byte encrypted_backup.key / 64-digit backup key, not files/key")
    if km.kind in ("hex64", "raw32") and diag.container in ("crypt12", "crypt14"):
        diag.notes.append("crypt12/14 need the device files/key (158 bytes); a 64-digit backup key only opens crypt15")
    log.info(
        "WhatsApp %s decrypt failed: key=%s candidates=%d t1_match=%s",
        diag.container, diag.key_kind, diag.candidates_tried, diag.t1_match,
    )
    return None


def try_decrypt_whatsapp_crypt(data: bytes, key_material: str | bytes | None, *, path: str = "", legacy_account: str | None = None, allow_resources: bool = False) -> bytes | None:
    """Compatibility API: return only SQLite, never reinterpret other payloads as chats."""
    return _decrypt_whatsapp(data, key_material, path=path, legacy_account=legacy_account, allow_payloads=allow_resources)


def try_decrypt_whatsapp_payload(data: bytes, key_material: str | bytes | None, *, path: str = "", legacy_account: str | None = None) -> bytes | None:
    """Return a verified modern payload or a structurally checked legacy SQLite DB."""
    return _decrypt_whatsapp(data, key_material, path=path, allow_payloads=True, legacy_account=legacy_account)


def decrypt_with_candidates(data: bytes, candidates: list[WhatsAppKeyCandidate], *, path: str = "", expected_size: int | None = None, allow_payloads: bool = False, legacy_account: str | None = None, allow_resources: bool = False) -> bytes | None:
    """Try every distinct collected/intake key against this specific backup."""
    seen: set[bytes] = set()
    attempts = 0
    best = None
    allow_payloads = allow_payloads or allow_resources
    if not candidates and not data:
        _set_diag(DecryptDiagnostics(container=classify_container(b"", path), reason="key_material_missing_or_invalid"))
        return None
    if not data or (expected_size and len(data) < int(expected_size)):
        _set_diag(DecryptDiagnostics(container=classify_container(data, path),
                                    reason="source_read_incomplete" if data else "source_unreadable",
                                    notes=[f"Read {len(data)} bytes; expected {int(expected_size or 0)} bytes"]))
        return None
    if looks_like_sqlite(data):
        return try_decrypt_whatsapp_crypt(data, None, path=path)
    container = classify_container(data, path)
    if container not in (*SUPPORTED_BACKUP_FORMATS, "unknown"):
        return _decrypt_whatsapp(data, None, path=path, allow_payloads=allow_payloads, legacy_account=legacy_account)
    if container == "crypt":
        plain = _decrypt_whatsapp(data, None, path=path, allow_payloads=allow_payloads)
        if plain is not None:
            return plain
    for candidate in candidates:
        km = parse_key_material(candidate.material)
        if km is None or km.raw32 in seen:
            continue
        seen.add(km.raw32)
        attempts += 1
        plain = _decrypt_whatsapp(data, candidate.material, path=path, allow_payloads=allow_payloads, legacy_account=legacy_account)
        diag = _tls.diag
        diag.keys_tried = attempts
        if plain is not None:
            diag.key_source = candidate.source
            return plain
        if best is None or diag.reason in ("backup_checksum_mismatch", "authenticated_payload_not_sqlite"):
            best = diag
    if container == "crypt5" and (legacy_account or not candidates):
        return _decrypt_whatsapp(data, None, path=path, legacy_account=legacy_account)
    if best is None:
        best = DecryptDiagnostics(container=classify_container(data, path), reason="key_material_missing_or_invalid")
    best.keys_tried = attempts
    _set_diag(best)
    return None


# -----------------------------------------------------------------------------
# Test-support encoder (also lets QA build fixtures without a device).
# -----------------------------------------------------------------------------

def _encrypt_fixture(sqlite_bytes: bytes, km: KeyMaterial, *, container: str, iv: bytes) -> bytes:  # pragma: no cover
    """Build a synthetic crypt12/14/15 file using the documented layouts (QA only)."""
    from Crypto.Cipher import AES  # type: ignore

    body_plain = zlib.compress(sqlite_bytes)
    if container == "crypt12":
        c = AES.new(km.key_crypt12_14, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(body_plain)
        header = bytearray(CRYPT12_HEADER_LEN)
        header[3:35] = km.t1 or b"\x00" * 32
        return bytes(header) + iv + ct + tag + b"\x00\x00\x00\x00"
    if container == "crypt14":
        c = AES.new(km.key_crypt12_14, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(body_plain)
        proto = b"\x0a\x04\x08\x0e\x10\x01\x1a\x02\x08\x01"  # info{key_version=14,...} feature{}
        return bytes([len(proto)]) + proto + iv + ct + tag
    if container == "crypt15":
        c = AES.new(km.key_crypt15, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(body_plain)
        # BackupPrefix{ info(1){key_version=15} ; c15_iv(2){ IV(1)=iv } }
        c15 = b"\x0a" + bytes([len(iv)]) + iv
        proto = b"\x0a\x02\x08\x0f" + b"\x12" + bytes([len(c15)]) + c15
        return bytes([len(proto)]) + proto + ct + tag
    raise ValueError(container)
