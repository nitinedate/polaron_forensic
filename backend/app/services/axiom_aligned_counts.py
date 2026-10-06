"""Compatibility shim — prefer ``catalog_aligned_counts``.

``from module import *`` never copies underscore names, so leftover callers
(``from axiom_aligned_counts import _DOCUMENT_EXTENSIONS``) used to crash
Open / browse. Copy every non-dunder name into this module so both
``DOCUMENT_EXTENSIONS`` and ``_DOCUMENT_EXTENSIONS`` resolve.
"""
from __future__ import annotations

from app.services import catalog_aligned_counts as _impl

for _name in dir(_impl):
    if _name.startswith("__"):
        continue
    globals()[_name] = getattr(_impl, _name)

# Explicit aliases — star-import leftovers and public callers both work.
DOCUMENT_EXTENSIONS = _impl._DOCUMENT_EXTENSIONS
_DOCUMENT_EXTENSIONS = _impl._DOCUMENT_EXTENSIONS
_norm_axiom_name = _impl._norm_axiom_name
