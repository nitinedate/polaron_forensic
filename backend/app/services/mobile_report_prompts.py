"""Prompt templates for mobile forensic report sections (Cellebrite PA–style)."""

from __future__ import annotations

DEVICE_INFORMATION_PROMPT = (
    "Provide mobile DEVICE INFORMATION matching an Aetheris mobile forensic report. "
    "Use a two-column markdown table (Field | Value) with exactly these fields when known: "
    "Make, Model, Serial Number, IMEI (comma-separate dual SIM), Operating System "
    "(e.g. Android 15 — keep the OS name spelling from evidence), Capacity. "
    "Use only evidence from the indexed mobile extraction; mark unavailable fields as —."
)

EXTRACTION_SUMMARY_PROMPT = (
    "Provide an EXTRACTION SUMMARY matching an Aetheris mobile forensic report. "
    "Use a two-column markdown table (Field | Value) with: "
    "Extraction start date/time, Extraction end date/time, UFED version (or acquisition tool), "
    "Selected manufacturer, Selected device name, Extraction type "
    "(e.g. File System (Android ADB)), Time zone settings (ID), Hash Value (SHA256). "
    "Ground every value and hash in the indexed extraction evidence; mark unknowns as —."
)

OBJECTIVE_OBSERVATION_MOBILE_HINT = (
    "Mobile forensic examination — correlate findings with chat apps, media, "
    "contacts, calls, location, and file handling on the extracted device."
)
