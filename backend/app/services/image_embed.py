"""Optional vision embeddings for Image Evidence RAG (additive to agentic base)."""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any

import numpy as np

from app.config import get_settings

log = logging.getLogger("image_embed")

_clip_model = None
_clip_failed = False
_clip_lock = threading.Lock()


def _load_clip():
    global _clip_model, _clip_failed
    if _clip_failed:
        return None
    if _clip_model is not None:
        return _clip_model
    with _clip_lock:
        if _clip_failed:
            return None
        if _clip_model is not None:
            return _clip_model
        try:
            from sentence_transformers import SentenceTransformer

            settings = get_settings()
            model_name = getattr(settings, "rag_image_embed_model", None) or "clip-ViT-B-32"
            device = "cpu"
            if str(getattr(settings, "rag_embedding_device", "") or "").lower().startswith("cuda"):
                device = "cuda"
            _clip_model = SentenceTransformer(model_name, device=device)
            return _clip_model
        except Exception as exc:
            _clip_failed = True
            log.warning("CLIP image embed unavailable: %s", exc)
            return None



def unload_clip_model() -> bool:
    """Release resident CLIP CUDA memory before the shared GPU lease is freed."""
    global _clip_model
    with _clip_lock:
        if _clip_model is None:
            return False
        _clip_model = None
    try:
        import gc
        gc.collect()
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            try:
                torch.cuda.synchronize()
            except Exception:
                pass
        log.info("Unloaded CLIP image model from GPU memory")
    except Exception as exc:
        log.debug("CLIP unload cleanup: %s", exc)
    return True


def _fallback_vector(seed: bytes, dim: int) -> list[float]:
    """Deterministic weak vector when CLIP is unavailable — searchable placeholder only."""
    h = hashlib.sha256(seed).digest()
    rng = np.random.default_rng(int.from_bytes(h[:8], "little"))
    vec = rng.standard_normal(dim).astype(np.float32)
    norm = float(np.linalg.norm(vec)) or 1.0
    return (vec / norm).tolist()


def embed_images(pil_images: list[Any], *, dim: int | None = None) -> list[list[float]]:
    settings = get_settings()
    target_dim = int(dim or getattr(settings, "rag_image_embed_dim", 512) or 512)
    model = _load_clip()
    if model is None:
        return [_fallback_vector(f"img-{i}".encode(), target_dim) for i in range(len(pil_images))]
    try:
        batch = max(int(getattr(settings, "rag_image_embed_batch_size", 8) or 8), 1)
        vectors = model.encode(pil_images, batch_size=batch, normalize_embeddings=True)
        out: list[list[float]] = []
        for v in vectors:
            arr = np.asarray(v, dtype=np.float32).reshape(-1)
            if arr.shape[0] != target_dim:
                # Pad/truncate to configured dim for pgvector consistency
                fixed = np.zeros(target_dim, dtype=np.float32)
                n = min(target_dim, arr.shape[0])
                fixed[:n] = arr[:n]
                arr = fixed
                norm = float(np.linalg.norm(arr)) or 1.0
                arr = arr / norm
            out.append(arr.tolist())
        return out
    except Exception as exc:
        log.warning("CLIP encode failed, using fallback: %s", exc)
        return [_fallback_vector(f"fail-{i}".encode(), target_dim) for i in range(len(pil_images))]


def embed_query(query: str, *, dim: int | None = None) -> list[float]:
    settings = get_settings()
    target_dim = int(dim or getattr(settings, "rag_image_embed_dim", 512) or 512)
    model = _load_clip()
    if model is None:
        return _fallback_vector(query.encode("utf-8"), target_dim)
    try:
        vec = model.encode([query], normalize_embeddings=True)[0]
        arr = np.asarray(vec, dtype=np.float32).reshape(-1)
        if arr.shape[0] != target_dim:
            fixed = np.zeros(target_dim, dtype=np.float32)
            n = min(target_dim, arr.shape[0])
            fixed[:n] = arr[:n]
            arr = fixed
            norm = float(np.linalg.norm(arr)) or 1.0
            arr = arr / norm
        return arr.tolist()
    except Exception as exc:
        log.warning("CLIP query embed failed: %s", exc)
        return _fallback_vector(query.encode("utf-8"), target_dim)


def model_fingerprint() -> tuple[str, str]:
    settings = get_settings()
    name = getattr(settings, "rag_image_embed_model", None) or "clip-ViT-B-32"
    return name, "1"
