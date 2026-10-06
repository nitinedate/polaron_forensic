#!/usr/bin/env python3
"""Prefetch Hugging Face models into the shared huggingface_cache volume.

Usage (from host after stack is up):
  docker compose exec -T worker-rag-gpu python /scripts/hf_ensure_models.py
"""

from __future__ import annotations

import os
import sys

# sentence-transformers short names → Hugging Face repo ids
_ALIASES = {
    "clip-ViT-B-32": "sentence-transformers/clip-ViT-B-32",
}

# Required by RAG / OCR / image-embed / optional rerank (non-Ollama).
_DEFAULTS = (
    "BAAI/bge-m3",
    "zai-org/GLM-OCR",
    "sentence-transformers/clip-ViT-B-32",
    "cross-encoder/ms-marco-MiniLM-L-6-v2",
)


def _normalize(name: str) -> str:
    name = (name or "").strip()
    return _ALIASES.get(name, name)


def _models() -> list[str]:
    models: list[str] = []
    for key in ("RAG_EMBEDDING_MODEL", "OCR_MODEL", "RAG_IMAGE_EMBED_MODEL", "HF_PULL_MODELS"):
        raw = (os.environ.get(key) or "").strip()
        if not raw:
            continue
        if key == "HF_PULL_MODELS":
            models.extend(_normalize(m) for m in raw.split(",") if m.strip())
        else:
            models.append(_normalize(raw))
    models.extend(_DEFAULTS)
    seen: set[str] = set()
    out: list[str] = []
    for m in models:
        if m and m not in seen:
            seen.add(m)
            out.append(m)
    return out


def main() -> int:
    models = _models()
    print(f"HF models to ensure: {', '.join(models)}", flush=True)
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        print(f"huggingface_hub unavailable: {exc}", file=sys.stderr)
        return 1

    failed = 0
    for model_id in models:
        print(f"Ensuring HF model: {model_id}", flush=True)
        try:
            # Single-worker downloads resume more reliably under bandwidth contention
            # (e.g. while ollama-init is also pulling large models).
            path = snapshot_download(repo_id=model_id, max_workers=1)
            print(f"  ready: {model_id} -> {path}", flush=True)
        except Exception as exc:
            failed += 1
            print(f"  FAILED: {model_id}: {exc}", file=sys.stderr, flush=True)

    if failed:
        print(f"HF ensure finished with {failed} failure(s).", file=sys.stderr)
        return 1
    print("HF model ensure complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
