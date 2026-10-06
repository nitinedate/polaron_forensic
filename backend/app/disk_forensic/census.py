"""Disk extension census — Windows host-disk only. Never call from mobile inventory."""

from app.services.disk_ext_census import ensure_disk_extension_censuses  # noqa: F401

__all__ = ["ensure_disk_extension_censuses"]