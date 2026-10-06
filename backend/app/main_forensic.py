"""Service 1 — disk and mobile forensic analysis API."""

from app.app_factory import create_app
from app.service_identity import FORENSIC

app = create_app(FORENSIC)
