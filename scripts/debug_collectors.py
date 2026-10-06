from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.forensic_inventory import (
    collect_feature_usage_artifacts,
    collect_browser_urls,
    collect_usb_devices,
    collect_installed_programs,
)
from app.services.artifact_sections import (
    _collect_jump_lists,
    _collect_lnk,
    _collect_logfile_analysis,
    _collect_social,
    _collect_web_chat,
)

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

print("feature", collect_feature_usage_artifacts(db, job))
print("usb", len(collect_usb_devices(db, job)))
print("programs", collect_installed_programs(db, job))
print("browser_urls_sample", len(collect_browser_urls(db, job, limit=10000)))
print("web_chat", _collect_web_chat(db, job))
print("social", _collect_social(db, job))
print("jump", _collect_jump_lists(db, job))
print("lnk", _collect_lnk(db, job))
print("logfile", _collect_logfile_analysis(db, job))
db.close()
