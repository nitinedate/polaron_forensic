"""Disk-only forensic pipeline (E01/EWF/Windows). Mobile must not import collectors from here."""

from app.disk_forensic.detection import is_disk_job
from app.disk_forensic.segments import DISK_IMAGE_EXT_RE, is_disk_image_filename

__all__ = [
    "DISK_IMAGE_EXT_RE",
    "is_disk_image_filename",
    "is_disk_job",
]
