"""Shared CRYPT-family discovery. Extension recognition is not decoder support."""
import re
from pathlib import PurePosixPath
_CRYPT = re.compile(r"\.(crypt[a-z0-9_-]*)$", re.I)
SUPPORTED_CRYPT_FORMATS = frozenset({"crypt", "crypt5", "crypt7", "crypt8", "crypt9", "crypt10", "crypt11", "crypt12", "crypt14", "crypt15"})
def crypt_extension(path: str) -> str | None:
    match = _CRYPT.search(PurePosixPath(str(path).replace("\\", "/")).name)
    return match.group(1).lower() if match else None
def is_crypt_file(path: str) -> bool:
    return crypt_extension(path) is not None
def is_msgstore_crypt(path: str) -> bool:
    return is_crypt_file(path) and "msgstore" in PurePosixPath(str(path).replace("\\", "/")).name.lower()
def strip_crypt_extension(path: str) -> str:
    ext = crypt_extension(path)
    return str(path)[:-(len(ext)+1)] if ext else str(path)
