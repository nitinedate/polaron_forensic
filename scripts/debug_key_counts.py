from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_sections import _collect_lnk, _collect_logfile_analysis
from app.services.artifact_live_counts import count_browser_url_hits
import re

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

print("lnk", _collect_lnk(db, job))
print("logfile", _collect_logfile_analysis(db, job))

social_pats = [
    re.compile(
        r"facebook\.com|instagram\.com|twitter\.com|x\.com|linkedin\.com|"
        r"tiktok\.com|reddit\.com|pinterest\.com|youtube\.com",
        re.I,
    ),
]
web_pats = [
    re.compile(r"web\.whatsapp\.com|whatsapp", re.I),
    re.compile(r"messenger\.com|facebook\.com/messages", re.I),
    re.compile(r"teams\.microsoft\.com|chat\.google\.com|slack\.com|discord\.com|telegram", re.I),
]
print("social", count_browser_url_hits(db, job, social_pats, count_visits=True))
print("webchat", count_browser_url_hits(db, job, web_pats, count_visits=True))
db.close()
