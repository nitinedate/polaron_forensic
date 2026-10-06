"""Service 3 — vulnerabilities + laptop scanner API."""

from app.app_factory import create_app
from app.service_identity import VULN

app = create_app(VULN)
