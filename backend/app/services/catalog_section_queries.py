"""AXIOM-aligned SQL fragments for report section B artifact counting.

Magnet AXIOM counts parsed records (messages, attachments, log entries) — not just
container files. These queries mirror that intent using job_artifacts + parse results
where full mailbox parsers are not yet available.

Extension and extensionless path rules are sourced from handbook_query_sql
(Forensic Phase 1-40 handbook scope).
"""

from __future__ import annotations

from app.services.handbook_query_sql import (
    EMAIL_ATTACHMENT_WHERE,
    EML_EMLX_FILE_WHERE,
    LOGFILE_ANALYSIS_WHERE,
    MBOX_EMAIL_WHERE,
    OUTLOOK_EMAIL_WHERE,
    WEB_RELATED_WHERE,
)

# Backward-compatible alias used across email inventory and browse queries.
EMLX_FILE_WHERE = EML_EMLX_FILE_WHERE

WINDOWS_MAIL_WHERE = """
(
  file_path ILIKE '%windowscommunicationsapps%'
  AND (
    file_path ILIKE '%HxStore%'
    OR file_path ILIKE '%store.vol%'
    OR file_path ILIKE '%.eml'
    OR file_path ILIKE '%/Mail/%'
  )
)
"""

# Real Outlook .msg messages — exclude Program Files encoding/resource .msg stubs.
OUTLOOK_MSG_WHERE = """
(
  (lower(coalesce(extension,''))='.msg' OR file_path ILIKE '%.msg')
  AND file_path NOT ILIKE '%/Program Files%'
  AND file_path NOT ILIKE '%/Windows/%'
  AND file_path NOT ILIKE '%/perl/%'
  AND file_path NOT ILIKE '%/Encodings/%'
  AND file_name NOT ILIKE 'FPEXT.MSG'
)
"""

JUMP_LIST_WHERE = """
(
  file_path ILIKE '%.automaticdestinations-ms'
  OR file_path ILIKE '%.customdestinations-ms'
  OR encyclopedia_artifact_id = 'WFS-SHL-0002'
)
"""

LNK_FILE_WHERE = """
(
  lower(coalesce(extension,''))='.lnk'
  OR file_path ILIKE '%.lnk'
  OR encyclopedia_artifact_id = 'WFS-SHL-0001'
)
"""

WINDOWS_CREDENTIALS_WHERE = """
(
  file_path ILIKE '%Microsoft/Credentials/%'
  OR file_path ILIKE '%CredentialManager%'
  OR file_path ILIKE '%Web Credentials%'
  OR file_name ILIKE 'Policy.vpol'
  OR (file_path ILIKE '%Microsoft/Protect/%' AND size_bytes BETWEEN 100 AND 65536)
)
AND file_path NOT ILIKE '%Program Files%'
"""

__all__ = [
    "EMAIL_ATTACHMENT_WHERE",
    "EMLX_FILE_WHERE",
    "EML_EMLX_FILE_WHERE",
    "MBOX_EMAIL_WHERE",
    "OUTLOOK_EMAIL_WHERE",
    "OUTLOOK_MSG_WHERE",
    "LOGFILE_ANALYSIS_WHERE",
    "JUMP_LIST_WHERE",
    "LNK_FILE_WHERE",
    "WEB_RELATED_WHERE",
    "WINDOWS_MAIL_WHERE",
    "WINDOWS_CREDENTIALS_WHERE",
]
