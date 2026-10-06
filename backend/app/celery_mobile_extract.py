from app.celery_factory import create_celery
from app.service_identity import MOBILE_EXTRACT

celery = create_celery(MOBILE_EXTRACT)
import app.tasks  # noqa: E402,F401
