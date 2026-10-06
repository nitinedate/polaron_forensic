"""iOS mobile-forensics API.  Never serves Android or disk jobs."""
from app.app_factory import create_app
from app.service_identity import MOBILE_IOS

app = create_app(MOBILE_IOS)
