from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.encryption_inventory import compute_all_encryption_counts, scan_encrypted_files

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

detail = scan_encrypted_files(db, job)
print("scan detail", detail)
print("all counts", compute_all_encryption_counts(db, job))
db.close()
