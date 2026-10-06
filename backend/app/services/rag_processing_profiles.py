"""Image Evidence processing profiles (intensity knobs only — never strip PIPELINE_AGENTS)."""

from __future__ import annotations

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "FAST": {
        "id": "FAST",
        "label": "Fast",
        "description": "Hash + metadata + thumbnail + GLM-OCR (quality retained, lower parallelism) + image embed + minimal lexical",
        "stages": "hash + metadata + thumbnail + high-quality OCR + image embed + minimal lexical",
        "ocr": True,
        "ocr_high_quality": True,
        "ocr_max_pages": 50,
        "ocr_max_new_tokens": 1024,
        "text_embed": True,
        "image_embed": True,
        "vlm_caption": False,
        "opensearch": False,
        "graph_enrich": False,
    },
    "STANDARD": {
        "id": "STANDARD",
        "label": "Standard",
        "description": "FAST + full OCR coverage + text embed + OpenSearch/FTS + graph/enrich",
        "stages": "FAST + OCR + text embed + OpenSearch + enrich + Neo4j",
        "ocr": True,
        "ocr_high_quality": True,
        "ocr_max_pages": 200,
        "ocr_max_new_tokens": 2048,
        "text_embed": True,
        "image_embed": True,
        "vlm_caption": False,
        "opensearch": True,
        "graph_enrich": True,
    },
    "DEEP": {
        "id": "DEEP",
        "label": "Deep",
        "description": "STANDARD + higher OCR budget + optional VLM captions (AI-derived, never authoritative)",
        "stages": "STANDARD + high-quality OCR + optional VLM description + richer enrich",
        "ocr": True,
        "ocr_high_quality": True,
        "ocr_max_pages": 500,
        "ocr_max_new_tokens": 4096,
        "text_embed": True,
        "image_embed": True,
        "vlm_caption": True,
        "opensearch": True,
        "graph_enrich": True,
    },
    "VISUAL-SIMILARITY": {
        "id": "VISUAL-SIMILARITY",
        "label": "Visual similarity",
        "description": "Image-embed prioritized; OCR still on for document-like files",
        "stages": "hash + metadata + thumbnail + image embed + OCR for document-like",
        "ocr": True,
        "ocr_high_quality": True,
        "ocr_max_pages": 100,
        "ocr_max_new_tokens": 1024,
        "ocr_document_like_only": True,
        "text_embed": True,
        "image_embed": True,
        "vlm_caption": False,
        "opensearch": True,
        "graph_enrich": False,
    },
}

DEFAULT_PROFILE = "STANDARD"


def normalize_profile(name: str | None) -> str:
    key = (name or DEFAULT_PROFILE).strip().upper().replace("_", "-")
    if key in ("VISUAL", "VISUALSIMILARITY", "VISUAL-SIM"):
        key = "VISUAL-SIMILARITY"
    return key if key in PROFILES else DEFAULT_PROFILE


def get_profile(name: str | None) -> dict[str, Any]:
    return dict(PROFILES[normalize_profile(name)])


def list_profiles() -> list[dict[str, Any]]:
    return [dict(p) for p in PROFILES.values()]
