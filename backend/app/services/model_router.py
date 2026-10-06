"""Ollama model router — VRAM-aware selection, concurrency, audit logging."""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any

from app.config import get_settings

log = logging.getLogger("model_router")

_lock = threading.Lock()
_active_heavy = 0


def _ollama_post(path: str, payload: dict, *, timeout: int = 300) -> dict:
    settings = get_settings()
    url = f"{settings.ollama_base_url.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ollama_get(path: str, *, timeout: int = 30) -> dict | list:
    settings = get_settings()
    url = f"{settings.ollama_base_url.rstrip('/')}{path}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_models() -> list[str]:
    try:
        data = _ollama_get("/api/tags")
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    except Exception as exc:
        log.warning("Ollama list models failed: %s", exc)
        return []


def model_health() -> dict[str, Any]:
    settings = get_settings()
    models = list_models()
    configured = {
        "primary": settings.llm_primary_model,
        "review": settings.llm_review_model,
        "review_large": settings.llm_review_model_large,
        "fast": settings.llm_fast_model,
        "embedding": settings.rag_embedding_fallback,
        "gap_report": settings.gap_report_llm_model,
        "mobile_report": getattr(settings, "mobile_report_llm_model", settings.llm_primary_model),
        "mobile_report_fallback": getattr(
            settings, "mobile_report_llm_fallback_model", settings.llm_fast_model
        ),
    }
    status = {}
    for role, name in configured.items():
        status[role] = {"model": name, "available": any(name in m or m.startswith(name.split(":")[0]) for m in models)}
    status["ollama_reachable"] = bool(models) or _ping_ollama()
    status["loaded_models"] = models
    return status


def _ping_ollama() -> bool:
    try:
        _ollama_get("/api/tags", timeout=5)
        return True
    except Exception:
        return False


def ollama_unload_all_models() -> list[str]:
    """Unload all models from Ollama VRAM (frees GPU before RAG embedding)."""
    unloaded: list[str] = []
    try:
        ps = _ollama_get("/api/ps", timeout=10)
        models = ps.get("models") if isinstance(ps, dict) else []
        for entry in models or []:
            name = entry.get("name") or entry.get("model")
            if not name:
                continue
            try:
                _ollama_post("/api/generate", {"model": name, "prompt": "", "keep_alive": 0}, timeout=30)
                try:
                    _ollama_post("/api/chat", {"model": name, "messages": [], "keep_alive": 0}, timeout=15)
                except Exception:
                    pass
                unloaded.append(name)
            except Exception as exc:
                log.debug("Ollama unload %s failed: %s", name, exc)
    except Exception as exc:
        log.debug("Ollama /api/ps failed: %s", exc)
    return unloaded


def select_review_model() -> str:
    settings = get_settings()
    if settings.llm_vram_profile == "high-stakes":
        models = list_models()
        if any(settings.llm_review_model_large in m for m in models):
            return settings.llm_review_model_large
    return settings.llm_review_model


def select_section_models(section_key: str) -> tuple[str, str | None]:
    """Return (primary_model, review_model_or_none)."""
    settings = get_settings()
    fast_sections = {
        "cover_page",
        "table_of_contents",
        "introduction",
        "scope_of_work",
        "tools_used",
    }
    high_stakes = settings.llm_dual_review_section_set
    if section_key in fast_sections:
        return settings.llm_fast_model, None
    if section_key in high_stakes and settings.llm_dual_review_enabled:
        return settings.llm_primary_model, select_review_model()
    return settings.llm_primary_model, None


def generate_text(
    prompt: str,
    *,
    model: str,
    system: str | None = None,
    temperature: float = 0.2,
    timeout: int | None = None,
) -> str:
    global _active_heavy
    heavy = any(x in model for x in ("32b", "70b", "32B", "70B"))
    wait = timeout if timeout is not None else 300
    with _lock:
        if heavy:
            _active_heavy += 1
    try:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            out = _ollama_post(
                "/api/chat",
                {"model": model, "messages": messages, "stream": False, "options": {"temperature": temperature}},
                timeout=wait,
            )
            return (out.get("message") or {}).get("content") or ""
        except urllib.error.HTTPError:
            out = _ollama_post(
                "/api/generate",
                {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": temperature}},
                timeout=wait,
            )
            return out.get("response") or ""
    except Exception as exc:
        log.warning("Ollama generate failed model=%s: %s", model, exc)
        # Never return the prompt itself — callers must fall back to plain text.
        return ""
    finally:
        with _lock:
            if heavy and _active_heavy > 0:
                _active_heavy -= 1


def embed_ollama(texts: list[str], *, model: str | None = None) -> list[list[float]]:
    settings = get_settings()
    model = model or settings.rag_embedding_fallback
    vectors: list[list[float]] = []
    for text in texts:
        try:
            out = _ollama_post("/api/embeddings", {"model": model, "prompt": text[:8000]})
            vectors.append(out.get("embedding") or [])
        except Exception as exc:
            log.debug("Ollama embed failed: %s", exc)
            vectors.append([])
    return vectors
