"""Run report catalog sync against database."""
from app.db.session import SessionLocal
from app.services.report_catalog_sync import sync_report_catalog_to_db
from sqlalchemy import text

db = SessionLocal()
try:
    result = sync_report_catalog_to_db(db, platform="Windows")
    print("sync:", result)
    arts = db.execute(
        text("SELECT count(*) c FROM public.axiom_artifacts WHERE metadata->>'source' = 'aetheris_report_template'")
    ).mappings().first()
    objs = db.execute(
        text("SELECT count(*) c FROM public.axiom_objectives WHERE domain = 'Aetheris Report Template'")
    ).mappings().first()
    print("report artifacts in db:", arts["c"], "report objectives:", objs["c"])
finally:
    db.close()
