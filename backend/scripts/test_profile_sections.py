from app.db.session import SessionLocal, apply_firm_search_path
from app.services.report_profile_sections import (
    build_os_report_markdown,
    build_user_report_markdown,
    _merge_os_facts,
    _merge_user_accounts,
)
from app.config import get_settings

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
settings = get_settings()
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")

print("OS facts", _merge_os_facts(db, JOB))
print("Users", _merge_user_accounts(db, JOB))
print("\n=== OS MD ===")
print(build_os_report_markdown(db, JOB, schema_name="firm_aetheris", primary_model=settings.llm_fast_model))
print("\n=== USER MD ===")
print(build_user_report_markdown(db, JOB, schema_name="firm_aetheris", primary_model=settings.llm_fast_model))
db.close()
