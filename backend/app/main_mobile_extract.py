"""Service 2 — mobile extraction to .pas / .ufd / .ufdx / .zip."""

from app.app_factory import create_app
from app.service_identity import MOBILE_EXTRACT

app = create_app(MOBILE_EXTRACT)
