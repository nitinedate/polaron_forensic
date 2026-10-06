"""Process dispatcher — loads the product selected by AETHERIS_SERVICE.

Default is forensic (Service 1). The monolith no longer mounts all domains
in one process.
"""

from app.app_factory import create_app
from app.service_identity import current_service

app = create_app(current_service())
