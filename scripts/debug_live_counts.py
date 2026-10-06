from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_live_counts import (
    count_browser_url_hits,
    count_jump_list_destinations,
    scan_registry_inventory,
)
import re

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

print("registry", scan_registry_inventory(db, job))
social = count_browser_url_hits(
    db, job, [re.compile(r"youtube\.com|facebook\.com|instagram\.com", re.I)], count_visits=True
)
print("social_sample", social)
print("jump", count_jump_list_destinations(db, job))
db.close()
