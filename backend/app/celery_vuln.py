from app.celery_factory import create_celery
from app.service_identity import VULN

celery = create_celery(VULN)
import app.tasks  # noqa: E402,F401
