"""Legacy WhatsApp layouts; successful decoding does NOT authenticate CBC/ECB.
Protocol references: andreas-mausch/whatsapp-viewer Crypt7.cpp and
 den4uk/andriller andriller/decrypts.py. Implemented independently.
CRYPT5 accepts an already-derived 24-byte AES key; it does not guess account emails.
"""
import sqlite3
import tempfile
from pathlib import Path

def _cipher(key, iv, body, mode):
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB) if mode == "ecb" else AES.new(key, AES.MODE_CBC, iv) if mode == "cbc" else AES.new(key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt(body)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        m = modes.ECB() if mode == "ecb" else modes.CBC(iv) if mode == "cbc" else modes.GCM(iv)
        dec = Cipher(algorithms.AES(key), m).decryptor()
        # Legacy GCM stream decode intentionally remains explicitly unauthenticated.
        return dec.update(body) if mode == "gcm" else dec.update(body) + dec.finalize()

def _sqlite_complete(data):
    if not data or data[:16] != b"SQLite format 3\0": return None
    page_size = int.from_bytes(data[16:18], "big")
    if page_size == 1: page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size-1) or len(data) % page_size: return None
    with tempfile.TemporaryDirectory(prefix="wa-legacy-") as folder:
        p = Path(folder)/"check.db";p.write_bytes(data);p.chmod(0o600)
        try:
            with sqlite3.connect(p.as_uri()+"?mode=ro&immutable=1", uri=True) as db:
                if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]: return None
        except sqlite3.Error: return None
    return data

def decode_legacy(data, key, container, inflate, *, key_file=None):
    """Return structurally checked SQLite bytes, with no authenticity assertion."""
    if container == "crypt":
        if not data or len(data)%16: return None
        historical_key = b"4j#e*F9+Ms%|g1~5.3rH!we,"
        if _cipher(historical_key, None, data[:16], "ecb") != b"SQLite format 3\0": return None
        plain = _cipher(historical_key, None, data, "ecb")
    elif container == "crypt5":
        if not key or len(key)!=24 or len(data)%16: return None
        plain = _cipher(key, bytes.fromhex("1e39f369e90db33aa73b442bbbb6b0b9"), data, "cbc")
    elif container in {"crypt7", "crypt8"}:
        if len(data)<=67 or (len(data)-67)%16 or not key or len(key)!=32: return None
        ivs=[data[51:67]]
        if container=="crypt7" and isinstance(key_file,bytes) and len(key_file)==158:
            ivs.append(key_file[110:126])
        for iv in ivs:
            plain = _cipher(key,iv,data[67:],"cbc")
            variants=[plain]
            n=plain[-1]
            if 1<=n<=16 and plain[-n:]==bytes([n])*n:variants.insert(0,plain[:-n])
            for variant in variants:
                hit=_sqlite_complete(inflate(variant))
                if hit:return hit
        return None
    elif container in {"crypt9", "crypt10", "crypt11"}:
        if len(data)<=67 or not key or len(key)!=32:return None
        # Only exact compressed EOF is accepted without authentication. Failed
        # modern tags are not discarded to obtain a legacy structural success.
        plain=_cipher(key,data[51:67],data[67:],"gcm")
        hit=_sqlite_complete(inflate(plain))
        if hit:return hit
        return None
    else:return None
    n=plain[-1] if plain else 0
    if 1<=n<=16 and plain[-n:]==bytes([n])*n:plain=plain[:-n]
    return _sqlite_complete(inflate(plain))
