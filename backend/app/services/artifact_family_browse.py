"""SQL / evidence-mode filters so mobile board Open lists forensic content, not app junk."""

from __future__ import annotations

from typing import Any

_TRASH_SQL = """(
  coalesce(metadata->>'is_deleted','') IN ('true','1','t')
  OR metadata ? 'deleted_at'
  OR lower(replace(file_path,'\\\\','/')) LIKE '%$recycle.bin%'
  OR lower(replace(file_path,'\\\\','/')) LIKE '%/.trash%'
  OR lower(replace(file_path,'\\\\','/')) LIKE '%/trash/%'
  OR lower(replace(file_path,'\\\\','/')) LIKE '%deleted_recovery%'
  OR lower(file_name) LIKE '.trashed-%'
  OR lower(file_name) LIKE '.$trashed%'
)"""

_IMAGE_SQL = """(
  lower(coalesce(extension,'')) IN ('.jpg','.jpeg','.png','.gif','.webp','.heic','.bmp','.tif','.tiff','jpg','jpeg','png','gif','webp','heic','bmp','tif','tiff')
  OR lower(file_name) ~* '\\.(jpe?g|png|gif|webp|heic|bmp|tiff?)$'
)"""

_VIDEO_SQL = """(
  lower(coalesce(extension,'')) IN ('.mp4','.mkv','.3gp','.mov','.avi','.m4v','.webm','mp4','mkv','3gp','mov','avi','m4v','webm')
  OR lower(file_name) ~* '\\.(mp4|mkv|3gp|mov|avi|m4v|webm)$'
)"""

_AUDIO_SQL = """(
  lower(coalesce(extension,'')) IN ('.opus','.mp3','.m4a','.wav','.aac','.amr','.ogg','.flac','opus','mp3','m4a','wav','aac','amr','ogg','flac')
  OR lower(file_name) ~* '\\.(opus|mp3|m4a|wav|aac|amr|ogg|flac)$'
)"""

_DOC_SQL = """(
  lower(coalesce(extension,'')) IN ('.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.txt','.csv','.rtf','pdf','doc','docx','xls','xlsx','ppt','pptx','txt','csv','rtf')
  OR lower(file_name) ~* '\\.(pdf|docx?|xlsx?|pptx?|txt|csv|rtf)$'
)"""

# Android package / ART / dalvik runtime noise — never chat/media evidence.
_APP_RUNTIME_EXCLUDE_SQL = """(
  lower(file_name) NOT LIKE '%.apk'
  AND lower(file_name) NOT LIKE '%.odex'
  AND lower(file_name) NOT LIKE '%.vdex'
  AND lower(file_name) NOT LIKE '%.art'
  AND lower(file_name) NOT LIKE '%.prof'
  AND lower(file_name) NOT LIKE '%.dex'
  AND lower(file_name) NOT LIKE '%.jar'
  AND lower(file_name) NOT LIKE '%.so'
  AND lower(file_name) NOT LIKE '%.oat'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/data/app/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/oat/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/dalvik-cache/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/preload/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/app_chrome/%'
  AND lower(file_name) NOT LIKE 'classes%.dex'
  AND lower(file_name) NOT LIKE '%.apk@%'
)"""

# Back-compat alias used by WhatsApp filters.
_WA_EXCLUDE_SQL = _APP_RUNTIME_EXCLUDE_SQL

# Messaging app databases under private app data (not package install trees).
# Android: /databases/… ; iOS UFED: AppDomain-*/Documents|Library/*.db (no /databases/).
_SOCIAL_DB_SQL = """(
  (
    lower(replace(file_path,'\\\\','/')) LIKE '%/databases/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/db/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%appdomain-%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/readable_artifacts/%'
  )
  AND (
    lower(file_name) LIKE '%.db'
    OR lower(file_name) LIKE '%.db-%'
    OR lower(file_name) LIKE '%.sqlite%'
    OR lower(file_name) LIKE '%.sqlitedb'
  )
  AND lower(file_name) NOT LIKE '%-wal'
  AND lower(file_name) NOT LIKE '%-shm'
  AND lower(file_name) NOT LIKE '%-journal'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/webkit/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%resourceloadstatistics%'
  AND lower(file_name) NOT LIKE 'observations.db%'
  AND lower(file_name) NOT LIKE 'localstorage%'
)"""

# Real WhatsApp chat / account databases examiners care about.
# Exclude encrypted cloud backups (.crypt12/14/15) — those need device keys.
_WA_PLAIN_DB_SQL = """(
  (
    lower(file_name) IN ('msgstore.db', 'wa.db', 'chatstorage.sqlite', 'messages.db')
    OR lower(file_name) LIKE 'msgstore.db-%'
    OR lower(file_name) LIKE 'wa.db-%'
    OR lower(file_name) LIKE 'chatstorage.sqlite%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/databases/msgstore.db%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/databases/wa.db%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%chatstorage.sqlite%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%extchatdatabase%'
  )
  AND lower(file_name) NOT LIKE '%.crypt%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/files/wam/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/chrome/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%favicons%'
)"""

_WA_CONTACTS_SQL = """(
  (
    lower(file_name) LIKE 'wa.db%'
    OR lower(file_name) LIKE '%wa_contacts%'
    OR (lower(replace(file_path,'\\\\','/')) LIKE '%whatsapp%' AND lower(file_name) LIKE '%contact%')
  )
  AND lower(file_name) NOT LIKE '%.crypt%'
  AND lower(file_name) NOT LIKE '%.apk'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/files/wam/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/chrome/%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%favicons%'
)"""

_WA_CALLS_SQL = """(
  (
    lower(file_name) LIKE '%callhistory%'
    OR lower(file_name) LIKE '%call_log%'
    OR (lower(replace(file_path,'\\\\','/')) LIKE '%whatsapp%' AND lower(file_name) LIKE '%call%')
  )
  AND lower(file_name) NOT LIKE '%.crypt%'
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/files/wam/%'
)"""

# Back-compat alias used by chat/message families.
_WA_DB_SQL = _WA_PLAIN_DB_SQL

# Actual WhatsApp media files only — never media.db / WAL / .nomedia placeholders.
_WA_MEDIA_SQL = """(
  (
    lower(replace(file_path,'\\\\','/')) LIKE '%whatsapp%media%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp/media/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%com.whatsapp%/media%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp images/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp video/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp audio/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp documents/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp animated gifs/%'
    OR lower(replace(file_path,'\\\\','/')) LIKE '%/whatsapp voice notes/%'
  )
  AND (
    lower(coalesce(extension,'')) IN (
      '.jpg','.jpeg','.png','.gif','.webp','.heic','.bmp',
      '.mp4','.3gp','.mov','.m4v','.mkv','.webm',
      '.opus','.m4a','.aac','.mp3','.wav','.ogg','.amr',
      '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
      'jpg','jpeg','png','gif','webp','heic','bmp',
      'mp4','3gp','mov','m4v','mkv','webm',
      'opus','m4a','aac','mp3','wav','ogg','amr',
      'pdf','doc','docx','xls','xlsx','ppt','pptx'
    )
    OR lower(file_name) ~* '\\.(jpe?g|png|gif|webp|heic|bmp|mp4|3gp|mov|m4v|mkv|webm|opus|m4a|aac|mp3|wav|ogg|amr|pdf|docx?|xlsx?|pptx?)$'
  )
  AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%/databases/%'
  AND lower(file_name) NOT LIKE '%.db'
  AND lower(file_name) NOT LIKE '%.db-%'
  AND lower(file_name) NOT LIKE '%.wal'
  AND lower(file_name) NOT LIKE '%.shm'
  AND lower(file_name) NOT LIKE '%.tmp'
  AND lower(file_name) NOT IN ('.nomedia', 'nomedia')
  AND lower(file_name) NOT LIKE 'media.db%'
)"""

# Board families that should open as parsed message/chat evidence (virtual rows),
# not as a raw path dump of every file under com.whatsapp.
# Contacts / calls / groups stay on SQL filters (wa.db / CallHistory) — they must
# NOT reuse the message browser (that was surfacing WAM metrics + Chrome junk).
_FAMILY_EVIDENCE_NAMES: dict[str, str] = {
    "whatsapp_messages": "WhatsApp Messages",
    "whatsapp_chats": "WhatsApp Chats",
    "whatsapp_deleted_messages": "WhatsApp Deleted Messages",
    "sms": "SMS Messages",
    "sms_chats": "SMS Messages",
    "telegram": "Telegram",
    "telegram_deleted": "Telegram",
    "signal": "Signal",
    "signal_deleted": "Signal",
    "instagram": "Instagram",
    "instagram_deleted": "Instagram",
    "facebook": "Facebook Messenger",
    "facebook_deleted": "Facebook Messenger",
    "linkedin": "LinkedIn",
    "emails": "Email",
    "contacts": "Contacts",
    "deleted_social": "Deleted Social / Chat Data",
    "deleted_chat_residuals": "Deleted Chat Residuals",
    "sms_attachments": "SMS / MMS Attachments",
    "email_attachments": "Email Attachments",
    "browser": "Browser History",
}


def family_evidence_artifact_name(family: str) -> str | None:
    """If this board family should use virtual evidence browse, return AXIOM name."""
    return _FAMILY_EVIDENCE_NAMES.get((family or "").strip().lower())


def family_prefers_deleted_only(family: str) -> bool:
    key = (family or "").strip().lower()
    return key.endswith("_deleted") or "deleted_messages" in key or key in {
        "deleted_social",
        "deleted_chat_residuals",
    }


def family_where_sql(family: str) -> tuple[str, dict]:
    """Return (AND … SQL fragment, params) for a mobile board family key."""
    key = (family or "").strip().lower()
    if not key:
        return "", {}

    if key == "deleted_photos":
        return f" AND {_TRASH_SQL} AND {_IMAGE_SQL}", {}
    if key == "deleted_videos":
        return f" AND {_TRASH_SQL} AND {_VIDEO_SQL}", {}
    if key == "deleted_documents":
        return f" AND {_TRASH_SQL} AND {_DOC_SQL}", {}
    if key == "deleted_files":
        return f" AND {_TRASH_SQL}", {}
    if key == "deleted_with_dates":
        return " AND metadata ? 'deleted_at'", {}
    if key == "critical_files":
        from app.services.artifact_file_forensics import critical_files_where_sql

        return critical_files_where_sql()
    if key == "anomalous_files":
        from app.services.artifact_file_forensics import anomalous_files_where_sql

        return anomalous_files_where_sql()
    if key == "modified_files":
        from app.services.artifact_file_forensics import modified_files_where_sql

        return modified_files_where_sql()
    if key in {"deleted_social", "deleted_chat_residuals"}:
        return (
            f""" AND {_TRASH_SQL} AND (
              lower(replace(file_path,'\\\\','/')) LIKE ANY (ARRAY[
                '%whatsapp%','%telegram%','%signal%','%instagram%','%facebook%',
                '%messenger%','%snapchat%','%discord%','%viber%','%wechat%'
              ])
              OR coalesce(metadata->>'social_app','') <> ''
            )
            AND {_WA_EXCLUDE_SQL}""",
            {},
        )

    # WhatsApp chat/message families → plaintext chat DBs only (never APK/ART/crypt).
    if key in {
        "whatsapp_messages",
        "whatsapp_chats",
        "whatsapp_deleted_messages",
        "whatsapp_groups",
    }:
        return f" AND {_WA_PLAIN_DB_SQL} AND {_WA_EXCLUDE_SQL}", {}
    if key == "whatsapp_contacts":
        return f" AND {_WA_CONTACTS_SQL} AND {_WA_EXCLUDE_SQL}", {}
    if key == "whatsapp_calls":
        return f" AND {_WA_CALLS_SQL} AND {_WA_EXCLUDE_SQL}", {}
    if key == "whatsapp_media":
        return f" AND {_WA_MEDIA_SQL} AND {_WA_EXCLUDE_SQL} AND NOT {_TRASH_SQL}", {}
    if key == "whatsapp_encrypted_backups":
        # Chat backups only. Payment-theme and sticker *.webp.crypt14 files are not msgstore.
        return """ AND (
          (
            lower(file_name) LIKE '%msgstore%'
            OR lower(replace(file_path,'\\\\','/')) LIKE '%/databases/msgstore%'
          )
          AND (
            lower(file_name) LIKE '%.crypt%'
            OR lower(replace(file_path,'\\\\','/')) LIKE '%.crypt%'
            OR lower(file_name) LIKE '%.enc'
            OR lower(replace(file_path,'\\\\','/')) LIKE '%.sqlite.enc'
          )
        )""", {}
    if key.startswith("whatsapp"):
        return f" AND ({_WA_PLAIN_DB_SQL} OR {_WA_MEDIA_SQL}) AND {_WA_EXCLUDE_SQL}", {}

    if key in {"sms", "sms_chats"}:
        return (
            " AND (lower(replace(file_path,'\\\\','/')) LIKE '%mmssms%' "
            "OR lower(file_name) LIKE '%mmssms%' "
            "OR lower(file_name) LIKE '%sms.db%' "
            "OR lower(replace(file_path,'\\\\','/')) LIKE '%imessage%')",
            {},
        )
    if key == "call_logs":
        return (
            " AND (lower(replace(file_path,'\\\\','/')) LIKE '%calllog%' "
            "OR lower(replace(file_path,'\\\\','/')) LIKE '%call_log%' "
            "OR lower(file_name) LIKE '%calllog%')",
            {},
        )
    if key == "browser":
        return (
            """ AND (
              lower(file_name) IN (
                'history', 'history.db', 'browser2.db', 'places.sqlite', 'browserstate.db'
              )
              OR lower(replace(file_path,'\\\\','/')) LIKE '%/safari%/history%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%chrome%/history%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%/history.db'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%places.sqlite%'
            )""",
            {},
        )
    # Existing media/docs exclude trash — deleted_* families hold recovered copies.
    if key == "pictures":
        return f" AND {_IMAGE_SQL} AND NOT {_TRASH_SQL}", {}
    if key == "videos":
        return f" AND {_VIDEO_SQL} AND NOT {_TRASH_SQL}", {}
    if key == "audio":
        return f" AND {_AUDIO_SQL} AND NOT {_TRASH_SQL}", {}
    if key == "documents":
        return f" AND {_DOC_SQL} AND NOT {_TRASH_SQL}", {}
    if key == "emails":
        return (
            " AND (lower(replace(file_path,'\\\\','/')) LIKE '%mail%' "
            "OR lower(coalesce(extension,'')) IN ('.eml','.emlx','.msg','.mbox','eml','emlx','msg','mbox'))",
            {},
        )
    if key in {"telegram", "telegram_deleted"}:
        return (
            f" AND (lower(replace(file_path,'\\\\','/')) LIKE '%telegram%' "
            f"OR lower(replace(file_path,'\\\\','/')) LIKE '%org.telegram%') "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key in {"signal", "signal_deleted"}:
        return (
            f" AND (lower(replace(file_path,'\\\\','/')) LIKE '%signal%' "
            f"OR lower(replace(file_path,'\\\\','/')) LIKE '%thoughtcrime%') "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key in {"instagram", "instagram_deleted"}:
        return (
            f" AND (lower(replace(file_path,'\\\\','/')) LIKE '%instagram%' "
            f"OR lower(replace(file_path,'\\\\','/')) LIKE '%com.instagram%') "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key in {"facebook", "facebook_deleted"}:
        # Messenger / Facebook app private databases — Android orca/katana + iOS com.facebook.Facebook.
        return (
            f""" AND (
              lower(replace(file_path,'\\\\','/')) LIKE '%com.facebook.orca%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%com.facebook.katana%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%com.facebook.mlite%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%com.facebook.messaging%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%com.facebook.facebook%'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%/readable_artifacts/facebook/%'
              OR lower(file_name) LIKE 'fb-msys-%'
              OR (
                (lower(replace(file_path,'\\\\','/')) LIKE '%facebook%'
                 OR lower(replace(file_path,'\\\\','/')) LIKE '%messenger%')
                AND (
                  lower(replace(file_path,'\\\\','/')) LIKE '%/data/data/%'
                  OR lower(replace(file_path,'\\\\','/')) LIKE '%appdomain-%'
                )
              )
            )
            AND {_SOCIAL_DB_SQL}
            AND {_APP_RUNTIME_EXCLUDE_SQL}
            AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%facebook.appmanager%'
            AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%facebook-services%'
            AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%facebook-installer%'
            AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%facebook-appmanager%'
            """,
            {},
        )
    if key == "snapchat_deleted":
        return (
            f" AND lower(replace(file_path,'\\\\','/')) LIKE '%snapchat%' "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key == "discord_deleted":
        return (
            f" AND lower(replace(file_path,'\\\\','/')) LIKE '%discord%' "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key == "viber_deleted":
        return (
            f" AND lower(replace(file_path,'\\\\','/')) LIKE '%viber%' "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key == "wechat_deleted":
        return (
            f" AND lower(replace(file_path,'\\\\','/')) LIKE '%wechat%' "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key == "linkedin":
        return (
            f" AND lower(replace(file_path,'\\\\','/')) LIKE '%linkedin%' "
            f"AND {_SOCIAL_DB_SQL} AND {_APP_RUNTIME_EXCLUDE_SQL}",
            {},
        )
    if key == "installed_apps":
        return (
            " AND (lower(file_name) LIKE '%.apk' OR lower(replace(file_path,'\\\\','/')) LIKE '%/data/app/%' "
            "OR lower(file_name) = 'packages.xml')",
            {},
        )
    if key == "device_info":
        return (
            " AND (lower(file_name) IN ('build.prop','info.plist','device_info.json','acquisition_manifest.json') "
            "OR lower(replace(file_path,'\\\\','/')) LIKE '%device_info%')",
            {},
        )
    if key == "sim_info":
        return (
            " AND (lower(replace(file_path,'\\\\','/')) LIKE '%iccid%' "
            "OR lower(replace(file_path,'\\\\','/')) LIKE '%imsi%' "
            "OR lower(replace(file_path,'\\\\','/')) LIKE '%siminfo%')",
            {},
        )
    if key == "sms_attachments":
        return (
            " AND ("
            " lower(file_name) IN ('sms.db', 'mmssms.db')"
            " OR lower(replace(file_path,'\\\\','/')) LIKE '%/library/sms/%'"
            ")",
            {},
        )
    if key == "contacts":
        # Device address book DBs only — never generic '%contacts%' token match.
        return (
            """ AND (
              lower(file_name) IN (
                'addressbook.sqlitedb', 'contacts2.db', 'contacts.db', 'contact.db'
              )
              OR lower(file_name) LIKE 'addressbook%.sqlitedb'
              OR lower(replace(file_path,'\\\\','/')) LIKE '%/addressbook/addressbook.sqlitedb%'
              OR (
                lower(replace(file_path,'\\\\','/')) LIKE '%/com.android.providers.contacts/%'
                AND lower(file_name) LIKE '%.db'
              )
            )
            AND lower(file_name) NOT LIKE '%shadow%'
            AND lower(file_name) NOT LIKE '%duplicate%'
            AND lower(file_name) NOT LIKE '%serverstate%'
            AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%webkit%'
            AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%resourceloadstatistics%'
            """,
            {},
        )
    if key == "email_attachments":
        from app.services.email_inventory import email_attachment_browse_where_sql

        return (
            f" AND ({email_attachment_browse_where_sql().strip()})"
            " AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%webkit%'"
            " AND lower(replace(file_path,'\\\\','/')) NOT LIKE '%resourceloadstatistics%'"
            " AND lower(file_name) NOT IN ('observations.db', 'pcm.db', 'tips-store.db')"
            " AND lower(file_name) NOT LIKE '%.js'",
            {},
        )

    token = key.split("_")[0]
    # Avoid broad token matches that dump unrelated SQLite/hex (contacts→%contacts%, email→%email%).
    if token and token not in {"contacts", "email", "emails"}:
        return " AND lower(replace(file_path,'\\\\','/')) LIKE :fam_tok", {"fam_tok": f"%{token}%"}
    return "", {}


def is_runtime_junk_row(row: dict[str, Any]) -> bool:
    """True if this list row is APK/DEX/ART/dalvik noise (never show in messaging Open)."""
    path = str(row.get("source_path") or row.get("file_path") or row.get("title") or "")
    name = str(row.get("file_name") or row.get("title") or path.rsplit("/", 1)[-1] or "")
    p = path.replace("\\", "/").lower()
    n = name.lower()
    if any(
        n.endswith(ext)
        for ext in (".apk", ".dex", ".odex", ".vdex", ".art", ".oat", ".so", ".jar", ".prof")
    ):
        return True
    if ".apk@" in n or "@classes" in n:
        return True
    if any(
        x in p
        for x in (
            "/dalvik-cache/",
            "/oat/",
            "/data/app/",
            "/preload/",
            "facebook-appmanager",
            "facebook.appmanager",
            "facebook-services",
            "facebook-installer",
        )
    ):
        return True
    return False


_MESSAGING_FAMILIES = frozenset({
    "whatsapp_messages",
    "whatsapp_chats",
    "whatsapp_deleted_messages",
    "whatsapp_contacts",
    "whatsapp_calls",
    "whatsapp_groups",
    "whatsapp_media",
    "sms",
    "sms_chats",
    "telegram",
    "telegram_deleted",
    "signal",
    "signal_deleted",
    "instagram",
    "instagram_deleted",
    "facebook",
    "facebook_deleted",
    "linkedin",
    "snapchat_deleted",
    "discord_deleted",
    "viber_deleted",
    "wechat_deleted",
})


def strip_runtime_junk(rows: list[dict[str, Any]], *, family: str | None = None) -> list[dict[str, Any]]:
    """Drop APK/DEX/ART rows. Always applied for messaging families; installed_apps keeps APKs."""
    key = (family or "").strip().lower()
    if key == "installed_apps":
        return rows
    if key and key not in _MESSAGING_FAMILIES and not key.startswith("whatsapp"):
        # Still strip obvious dalvik-cache noise from other board families except installed_apps.
        if key in {"pictures", "videos", "audio", "documents", "emails", "device_info", "sim_info"}:
            return [r for r in rows if not is_runtime_junk_row(r)]
    return [r for r in rows if not is_runtime_junk_row(r)]


def no_chat_data_notice(family: str, job_id: str, *, db=None) -> dict[str, Any]:
    """Single virtual row when a messaging family has no recoverable chat DBs/messages."""
    key = (family or "").strip().lower()
    if key in {"whatsapp_messages", "whatsapp_chats", "whatsapp_deleted_messages"}:
        from app.services.whatsapp_evidence_browse import whatsapp_recovery_notice

        return whatsapp_recovery_notice(job_id, key, db=db)
    if key == "email_attachments":
        body = (
            "No email attachment files were found in this dump.\n\n"
            "Email Attachments only lists MIME/mail-store files "
            "(not SMS/MMS attachment rows from sms.db, and not WebKit observations.db).\n"
            "For MMS/iMessage attachments open “SMS / MMS Attachments”."
        )
        return {
            "id": f"ev-notice-{key}",
            "job_id": job_id,
            "artifact_type": "notice",
            "title": "No email attachments in this dump",
            "source_path": None,
            "metadata": {
                "evidence_kind": "email_attachment_file",
                "preview_body": body,
                "body": body,
            },
            "tags": ["notice", "no_email_attachments"],
        }
    if key == "sms_attachments":
        body = (
            "No SMS/MMS attachment records were recovered from sms.db in this dump."
        )
        return {
            "id": f"ev-notice-{key}",
            "job_id": job_id,
            "artifact_type": "notice",
            "title": "No SMS/MMS attachments",
            "source_path": None,
            "metadata": {
                "evidence_kind": "sms_attachment",
                "preview_body": body,
                "body": body,
            },
            "tags": ["notice"],
        }
    if key in {"deleted_social", "deleted_chat_residuals"}:
        body = (
            "No recoverable deleted/residual chat message text was extracted yet.\n\n"
            "Raw SQLite files under deleted_recovery are intentionally not shown as hex dumps. "
            "Re-run mobile inventory to carve freelist/WAL residuals from messaging databases."
        )
        return {
            "id": f"ev-notice-{key}",
            "job_id": job_id,
            "artifact_type": "notice",
            "title": "No deleted chat residuals recovered",
            "source_path": None,
            "metadata": {
                "evidence_kind": "deleted_chat_residual",
                "preview_body": body,
                "body": body,
            },
            "tags": ["notice"],
        }
    if key == "contacts":
        body = (
            "No parsed contacts were recovered from AddressBook.sqlitedb / contacts2.db "
            "in this dump.\n\n"
            "Expected: HomeDomain AddressBook.sqlitedb or "
            "com.android.providers.contacts/databases/contacts2.db"
        )
        return {
            "id": f"ev-notice-{key}",
            "job_id": job_id,
            "artifact_type": "notice",
            "title": "No contacts in this dump",
            "source_path": None,
            "metadata": {
                "evidence_kind": "contact",
                "preview_body": body,
                "body": body,
            },
            "tags": ["notice", "no_contact_data"],
        }
    if key == "whatsapp_deleted_messages":
        body = (
            "No recovered/deleted WhatsApp message text was found.\n\n"
            "Deleted rows come from SQLite freelist/WAL carving of a plaintext "
            "ChatStorage.sqlite or msgstore.db. Encrypted msgstore.crypt14 backups "
            "are not deleted messages, and they cannot be carved until the device key "
            "is in the acquisition.\n"
            "Open WhatsApp Encrypted Backups to see the crypt files that were collected."
        )
        return {
            "id": f"ev-notice-{key}",
            "job_id": job_id,
            "artifact_type": "notice",
            "title": "No deleted WhatsApp messages recovered",
            "source_path": None,
            "metadata": {
                "evidence_kind": "whatsapp_deleted_message",
                "preview_body": body,
                "body": body,
            },
            "tags": ["notice", "no_deleted_data"],
        }
    hints = {
        "facebook": "Messenger chat DBs (threads_db / msys_database under com.facebook.orca)",
        "facebook_deleted": "Messenger chat DBs (threads_db / msys_database under com.facebook.orca)",
        "instagram": "Instagram Direct databases under com.instagram.android/databases",
        "telegram": "Telegram cache4.db under org.telegram.messenger/databases",
        "signal": "Signal databases under org.thoughtcrime.securesms/databases",
        "whatsapp_messages": (
            "plaintext msgstore.db / ChatStorage.sqlite. This Android pull has the "
            "encrypted msgstore.crypt14 backups instead. Those open under "
            "WhatsApp Encrypted Backups and stay unreadable without "
            "/data/data/com.whatsapp/files/key (about 158 bytes). An adb run-as "
            "error saved as a key file cannot decrypt them"
        ),
        "whatsapp_chats": (
            "plaintext msgstore.db / ChatStorage.sqlite under com.whatsapp/databases"
        ),
    }
    need = hints.get(key, "the app's private SQLite databases under /data/data/.../databases/")
    body = (
        f"No recoverable conversation data for “{family}” in this dump.\n\n"
        f"Expected: {need}\n\n"
        "APK / DEX / ART / dalvik-cache files are not chats and are intentionally hidden.\n"
        "Re-acquire with a full file-system / UFED Advanced Logical dump that includes "
        "private app databases if chat content is required."
    )
    return {
        "id": f"ev-notice-{key or 'family'}",
        "job_id": job_id,
        "artifact_type": "notice",
        "title": "No conversation data in this dump",
        "source_path": None,
        "metadata": {
            "evidence_kind": "chat_message",
            "preview_body": body,
            "body": body,
            "sender": "system",
            "conversation": family,
        },
        "tags": ["notice", "no_chat_data"],
    }


def filter_evidence_rows_for_family(family: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Post-filter virtual evidence rows (e.g. keep deleted WhatsApp messages only)."""
    key = (family or "").strip().lower()
    rows = strip_runtime_junk(rows, family=key)
    if not rows:
        return rows
    if key in {"deleted_social", "deleted_chat_residuals"}:
        kept = [
            r
            for r in rows
            if str((r.get("metadata") or {}).get("evidence_kind") or "")
            in {"deleted_chat_residual", "whatsapp_deleted_message", "chat_message"}
            and (r.get("metadata") or {}).get("is_deleted")
        ]
        return kept
    if key == "whatsapp_deleted_messages" or family_prefers_deleted_only(key):
        kept: list[dict[str, Any]] = []
        for r in rows:
            meta = r.get("metadata") or {}
            if not isinstance(meta, dict):
                meta = {}
            kind = str(meta.get("evidence_kind") or "").lower()
            tags = [str(t).lower() for t in (r.get("tags") or [])]
            path = str(r.get("source_path") or meta.get("source_path") or "").lower()
            # Never mix SMS/iMessage into WhatsApp deleted.
            if "sms.db" in path or "sms_imessage" in path or "/sms/" in path:
                continue
            # Only true recovered/deleted message rows — never chat DBs or carve JSON dumps.
            if kind in {"whatsapp_deleted_message", "deleted_chat_residual"}:
                kept.append(r)
                continue
            if meta.get("is_deleted") and kind in {
                "whatsapp_message",
                "chat_message",
            }:
                kept.append(r)
                continue
            if "deleted" in tags and kind.endswith("message") and "sms" not in kind:
                kept.append(r)
        return kept
    # For normal WhatsApp chats/messages: prefer parsed message rows first, then DB stores.
    # Keep live/current only — deleted/recovered rows belong in whatsapp_deleted_messages.
    if key in {"whatsapp_messages", "whatsapp_chats"}:
        messages = []
        for r in rows:
            meta = r.get("metadata") or {}
            if not isinstance(meta, dict):
                meta = {}
            kind = str(meta.get("evidence_kind") or "")
            path = str(r.get("source_path") or meta.get("source_path") or "").lower()
            app = str(meta.get("social_app") or "").lower()
            tags = [str(t).lower() for t in (r.get("tags") or [])]
            # Hard block SMS/iMessage leakage into WhatsApp Open.
            if (
                "sms.db" in path
                or "sms_imessage" in path
                or "/library/sms/" in path
                or app in {"sms", "imessage"}
                or kind in {"sms_message", "sms_store"}
                or "App: SMS" in str(meta.get("preview_body") or "")
            ):
                continue
            if (
                meta.get("is_deleted")
                or "deleted" in tags
                or kind in {"whatsapp_deleted_message", "deleted_chat_residual"}
            ):
                continue
            if kind == "whatsapp_message" or str(r.get("artifact_type") or "") == "whatsapp_message":
                messages.append(r)
        stores = [
            r
            for r in rows
            if str((r.get("metadata") or {}).get("evidence_kind") or "") == "whatsapp_store"
        ]
        # Drop APK/runtime junk that slipped into stores.
        clean_stores = []
        for r in stores:
            path = str(r.get("source_path") or r.get("title") or "").lower()
            if any(x in path for x in (".apk", ".odex", ".vdex", ".art", ".prof", "/data/app/", "/oat/")):
                continue
            if "sms" in path:
                continue
            clean_stores.append(r)
        return messages + clean_stores
    return rows
