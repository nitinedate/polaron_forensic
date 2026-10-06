"""Android Celery entrypoint bound to the Android product app/registry."""

import os

from app.service_identity import MOBILE_ANDROID

# Force the product identity before importing celery_app.  app.tasks imports
# this same module-level Celery object, so workers and task decorators share
# one registry and one Android broker/route table.
os.environ["AETHERIS_SERVICE"] = MOBILE_ANDROID

from app.celery_app import celery  # noqa: E402,F401
