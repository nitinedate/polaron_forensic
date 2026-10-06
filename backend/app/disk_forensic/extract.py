"""Disk extract entrypoints (E01/EWF)."""

from app.services.disk import build_extracted_disk, evaluate_segment_readiness  # noqa: F401

__all__ = ["build_extracted_disk", "evaluate_segment_readiness"]
