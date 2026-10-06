"""Reset MFA for a firm user so they can sign in and re-enroll from Security."""
from __future__ import annotations

import sys

from sqlalchemy import select, text

from app.db.session import SessionLocal, apply_firm_search_path
from app.models.firm import FirmUser
from app.services.auth_service import AuthService


def main() -> int:
    email = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()
    firm = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"
    if not email:
        print("Usage: python reset_user_mfa.py <email> [firm_schema]")
        print("Example: python reset_user_mfa.py you@company.com firm_aetheris")
        return 1

    auth = AuthService()
    with SessionLocal() as db:
        apply_firm_search_path(db, firm)
        user = db.execute(select(FirmUser).where(FirmUser.email == email)).scalar_one_or_none()
        if not user:
            print(f"No user found: {email} in {firm}")
            return 1
        auth.set_user_mfa_enabled(db, user, False)
        db.commit()
        print(f"MFA reset for {email} in {firm}. User can sign in with password only.")
        print("Next: Security & MFA -> Set up authenticator (scan new QR; delete old app entry first).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
