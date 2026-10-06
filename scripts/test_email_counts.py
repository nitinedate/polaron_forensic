from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.email_inventory import collect_email_artifact, build_email_section_items
from app.services.artifact_sections import build_job_artifact_sections

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

titles = [
    "Email Attachments", "EML(X) Files", "Outlook Emails", "Windows Mail",
    "Gmail Webmail", "Hotmail Webmail", "Outlook Web App Email Inbox",
]
for t in titles:
    d = collect_email_artifact(db, job, t)
    print(f"{d.get('count'):>6}  {t}")

inv = build_job_artifact_sections(db, job)
for sec in inv["sections"]:
    if "email" in sec["title"].lower():
        print("==", sec["title"])
        for it in sec["items"]:
            if int(it.get("count") or 0) > 0:
                print(f"  {it['title']}: {it['count']}")

db.close()
