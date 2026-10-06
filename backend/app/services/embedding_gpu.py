"""GPU-safe embedding with VRAM caps to avoid thermal/OOM host shutdowns."""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from pathlib import Path

log = logging.getLogger("embedding_gpu")

_model = None
_device: str | None = None
_lock = threading.Lock()
_cuda_configured = False


def _configure_cuda_runtime() -> None:
    """Limit process VRAM so Ollama + embedder can coexist without melting the laptop."""
    global _cuda_configured
    if _cuda_configured:
        return
    _cuda_configured = True
    try:
        import torch

        if not torch.cuda.is_available():
            return
        # Leave headroom for Ollama / display / OS.
        frac = float(os.environ.get("RAG_CUDA_MEMORY_FRACTION", "0.45"))
        # Also honor Settings if injected without env (compose sets both).
        try:
            from app.config import get_settings

            frac = float(getattr(get_settings(), "rag_cuda_memory_fraction", frac) or frac)
        except Exception:
            pass
        frac = max(0.15, min(frac, 0.70))
        torch.cuda.set_per_process_memory_fraction(frac, 0)
        # Reduce fragmentation OOMs
        os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
        log.info("CUDA memory fraction capped at %.2f for embeddings", frac)
    except Exception as exc:
        log.warning("Could not configure CUDA memory fraction: %s", exc)


def _npu_device_label() -> str | None:
    """DirectML / Intel NPU when CUDA is not the right target."""
    try:
        import torch

        if hasattr(torch, "xpu") and torch.xpu.is_available():  # type: ignore[attr-defined]
            return "xpu (Intel NPU/GPU)"
    except Exception:
        pass
    try:
        import torch_directml  # type: ignore

        _ = torch_directml.device()
        return "directml (NPU/iGPU)"
    except Exception:
        pass
    return None


def resolve_device(requested: str = "auto") -> tuple[str, bool]:
    """Return (device_label, gpu_enabled). Prefer CUDA, then NPU, then CPU."""
    req = (requested or "auto").strip().lower()
    try:
        import torch

        cuda_ok = torch.cuda.is_available()
    except ImportError:
        return "cpu", False

    if req == "cpu":
        return "cpu", False
    if req in ("cuda", "gpu") and cuda_ok:
        name = torch.cuda.get_device_name(0)
        return f"cuda:0 ({name})", True
    if req == "npu":
        npu = _npu_device_label()
        if npu:
            return npu, False
        if cuda_ok:
            name = torch.cuda.get_device_name(0)
            return f"cuda:0 ({name})", True
        return "cpu", False
    if req == "auto" and cuda_ok:
        name = torch.cuda.get_device_name(0)
        return f"cuda:0 ({name})", True
    if req == "auto":
        npu = _npu_device_label()
        if npu:
            return npu, False
    return "cpu", False


def _safe_batch_size(requested: int, *, gpu: bool) -> int:
    if not gpu:
        return min(max(int(requested or 1), 1), 4)
    cap = int(os.environ.get("RAG_BATCH_SIZE_CAP", "12"))
    try:
        from app.config import get_settings

        cap = int(getattr(get_settings(), "rag_batch_size_cap", cap) or cap)
    except Exception:
        pass
    # Cross-worker live plan (Performance agent) may lower batches under heat.
    try:
        from app.services.perf_broadcast import live_rag_batch, live_rag_batch_cap

        cap = min(cap, live_rag_batch_cap(cap))
        requested = min(int(requested or 8), live_rag_batch(int(requested or 8)))
    except Exception:
        pass
    base = min(max(int(requested or 8), 1), max(cap, 4))
    from app.services.gpu_thermal import adaptive_embed_batch_size

    return adaptive_embed_batch_size(base, gpu=True)


def _hf_model_cache_dir(model_name: str) -> Path:
    safe = model_name.replace("/", "--")
    return Path.home() / ".cache" / "huggingface" / "hub" / f"models--{safe}"


def _scrub_hf_no_exist_placeholders(model_name: str) -> None:
    """Remove zero-byte .no_exist HF Hub placeholders that break transformers json.load."""
    no_exist = _hf_model_cache_dir(model_name) / ".no_exist"
    if no_exist.is_dir():
        shutil.rmtree(no_exist, ignore_errors=True)
        log.info("Removed corrupted HF .no_exist cache for %s", model_name)


def _purge_hf_model_cache(model_name: str) -> None:
    cache_dir = _hf_model_cache_dir(model_name)
    if cache_dir.is_dir():
        shutil.rmtree(cache_dir, ignore_errors=True)
        log.warning("Purged HF model cache for %s (will re-download)", model_name)


def _is_hf_cache_json_error(exc: BaseException) -> bool:
    if isinstance(exc, json.JSONDecodeError):
        return True
    return "Expecting value" in str(exc)


def unload_embedder() -> bool:
    """Free BGE embedder VRAM before OCR reclaims the exclusive GPU slot."""
    global _model, _device
    with _lock:
        if _model is None:
            return False
        _model = None
        _device = None
    try:
        import gc

        gc.collect()
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
        log.info("Unloaded embedding model from GPU memory")
        return True
    except Exception as exc:
        log.debug("Embedder unload cleanup: %s", exc)
        return True


def get_embedder(model_name: str, device: str = "auto"):
    global _model, _device
    with _lock:
        if _model is not None:
            return _model, _device
        from sentence_transformers import SentenceTransformer

        device_label, gpu = resolve_device(device)
        if gpu:
            # Same worker hosts GLM-OCR — must free it before BGE or CUDA OOM.
            try:
                from app.services.ocr_gpu import unload_glm_ocr

                unload_glm_ocr()
            except Exception as exc:
                log.debug("OCR unload before embed skipped: %s", exc)
            _configure_cuda_runtime()
        if gpu:
            torch_device = "cuda"
        elif "directml" in device_label:
            import torch_directml  # type: ignore

            torch_device = torch_directml.device()
        elif device_label.startswith("xpu"):
            torch_device = "xpu"
        else:
            torch_device = "cpu"
        last_exc: BaseException | None = None
        for attempt in (1, 2):
            try:
                _scrub_hf_no_exist_placeholders(model_name)
                log.info("Loading embedding model %s on %s", model_name, device_label)
                _model = SentenceTransformer(model_name, device=torch_device)
                _device = device_label
                return _model, _device
            except Exception as exc:
                if attempt == 1 and _is_hf_cache_json_error(exc):
                    last_exc = exc
                    log.warning(
                        "HF cache JSON corrupt for %s (attempt %d): %s",
                        model_name,
                        attempt,
                        exc,
                    )
                    _purge_hf_model_cache(model_name)
                    continue
                raise
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"Failed to load embedding model {model_name}")


def embed_texts(texts: list[str], *, model_name: str, device: str, batch_size: int) -> list[list[float]]:
    if not texts:
        return []
    _, gpu = resolve_device(device)
    batch_size = _safe_batch_size(batch_size, gpu=gpu)
    model, actual_device = get_embedder(model_name, device)
    from app.services.forensic_serial_policy import current_stage

    if current_stage() == "embedding" and (not gpu or not str(getattr(model, "device", actual_device)).startswith("cuda")):
        raise RuntimeError("Serial embedding requires a model resident on CUDA")
    out: list[list[float]] = []
    try:
        import torch
    except ImportError:
        torch = None  # type: ignore

    start = 0
    batch_num = 0
    while start < len(texts):
        from app.services.gpu_thermal import (
            adaptive_embed_batch_size,
            thermal_guard_after_batch,
            thermal_guard_before_batch,
        )

        effective = adaptive_embed_batch_size(batch_size, gpu=gpu) if gpu else batch_size
        thermal_guard_before_batch(reason="embed")
        chunk = texts[start : start + effective]
        vectors = model.encode(
            chunk,
            batch_size=effective,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        out.extend(v.tolist() for v in vectors)
        start += effective
        batch_num += 1
        if gpu and torch is not None:
            try:
                from app.services.gpu_thermal import should_empty_cuda_cache

                torch.cuda.synchronize()
                if should_empty_cuda_cache(batch_num=batch_num):
                    torch.cuda.empty_cache()
            except Exception:
                pass
            thermal_guard_after_batch(reason="embed")
        else:
            import gc

            gc.collect()
    return out
