"""Health checks including Ollama model registry."""

from __future__ import annotations

from fastapi import APIRouter

from app.services.model_router import model_health
from app.services.neo4j_sync import neo4j_available
from app.services.opensearch_sync import opensearch_available

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
def health():
    return {"status": "ok"}


@router.get("/models")
def health_models():
    models = model_health()
    models["neo4j"] = {"available": neo4j_available()}
    models["opensearch"] = {"available": opensearch_available()}
    return models


@router.get("/gpu")
def health_gpu():
    from app.services.gpu_thermal import get_gpu_stats

    stats = get_gpu_stats()
    return stats.to_dict()


@router.get("/capacity")
def health_capacity():
    """Host CPU/RAM/GPU room + dynamic performance plan currently applied."""
    from app.services.host_capacity import apply_dynamic_performance, get_last_plan, probe_host

    plan = get_last_plan() or apply_dynamic_performance()
    return {
        "status": "ok",
        "snapshot": plan.snapshot.__dict__ if plan else probe_host().__dict__,
        "profile": plan.profile if plan else None,
        "env": plan.env if plan else {},
        "notes": plan.notes if plan else [],
    }
