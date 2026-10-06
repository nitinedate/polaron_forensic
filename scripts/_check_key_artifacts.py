from sqlalchemy import text
from app.db.session import firm_session_readonly

NAMES = [
    "USB Devices",
    "Remote Desktop Protocol (RDP)",
    "Your Phone Device",
    "Picture",
    "PDF Documents",
    "RTF Documents",
    "Jump Lists",
    "LNK Files",
    "Web Related Files",
    "Outlook Emails",
    "Email Attachments",
    "Web Chat URLs",
    "Social Media URLs",
    "Photoshop Files",
    "$LogFile Analysis",
    "Prefetch Files - Windows 8/10/11",
    "Windows Event Logs",
    "Windows Viber Chat Messages",
]

with firm_session_readonly("firm_aetheris") as db:
    jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
    for name in NAMES:
        row = db.execute(
            text(
                """
          SELECT r.artifact_count, r.count_domain, left(coalesce(r.answer,''),100) ans
          FROM job_axiom_artifact_results r
          JOIN public.axiom_artifacts a ON a.artifact_id=r.artifact_id
          WHERE r.job_id=:j AND a.artifact_name=:n
          LIMIT 1
        """
            ),
            {"j": jid, "n": name},
        ).mappings().first()
        print(f"{name!r}: {dict(row) if row else None}")
