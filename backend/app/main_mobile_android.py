"""Android mobile-forensics API.  Never serves iOS or disk jobs."""
from app.app_factory import create_app
from app.service_identity import MOBILE_ANDROID

app = create_app(MOBILE_ANDROID)
