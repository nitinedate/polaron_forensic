from app.celery_factory import create_celery
from app.service_identity import FORENSIC

celery = create_celery(FORENSIC)
import app.tasks  # noqa: E402,F401
