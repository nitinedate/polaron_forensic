"""Tests for dynamic host-capacity performance planner."""

from __future__ import annotations

import os

from app.services.host_capacity import HostSnapshot, apply_dynamic_performance, build_capacity_plan, cpu_thermal_pace


def test_build_plan_laptop_gpu():
    snap = HostSnapshot(
        cpu_logical=12,
        mem_total_mb=32000,
        mem_available_mb=18000,
        load_1m=2.0,
        cpu_temp_c=60,
        gpu_available=True,
        gpu_name="NVIDIA GeForce RTX 4070 Laptop GPU",
        gpu_vram_total_mb=8188,
        gpu_vram_free_mb=6000,
        gpu_temp_c=55,
        profile="laptop",
    )
    # Force profile classification path via explicit profile on snap used by build
    plan = build_capacity_plan(snap)
    assert plan.profile == "laptop"
    assert plan.env["RAG_EMBEDDING_DEVICE"] == "cuda"
    assert plan.env["OCR_DEVICE"] == "cuda"
    assert int(plan.env["PARSE_WORKERS"]) >= 3
    assert float(plan.env["RAG_CUDA_MEMORY_FRACTION"]) <= 0.45
    assert plan.env["GPU_THERMAL_ENABLED"] == "true"
    assert 1 <= int(plan.env["MAX_CONCURRENT_DISK_BUILDS"]) <= 6
    assert 1 <= int(plan.env["FORENSIC_WORKER_CONCURRENCY"]) <= 6
    assert 1 <= int(plan.env["MOBILE_WORKER_CONCURRENCY"]) <= 4
    assert 1 <= int(plan.env["NESSUS_WORKER_CONCURRENCY"]) <= 8
    assert plan.env["EXTRACT_THEN_PROCESS"] == "true"
    assert plan.env["PHASE3_STREAM_DURING_EXTRACT"] == "false"
    assert plan.env["PHASE3_STREAM_OCR_DURING_EXTRACT"] == "false"
    assert plan.env["PHASE3_STREAM_RAG_DURING_EXTRACT"] == "false"


def test_build_plan_laptop_12gb_uses_larger_exclusive_batches():
    plan = build_capacity_plan(
        HostSnapshot(
            cpu_logical=16,
            mem_total_mb=32000,
            mem_available_mb=18000,
            load_1m=2.0,
            cpu_temp_c=55,
            gpu_available=True,
            gpu_name="NVIDIA GeForce RTX 5070 Ti Laptop GPU",
            gpu_vram_total_mb=12282,
            gpu_vram_free_mb=10000,
            gpu_temp_c=52,
            profile="laptop",
        )
    )
    assert int(plan.env["RAG_BATCH_SIZE"]) >= 24
    assert int(plan.env["RAG_BATCH_SIZE_CAP"]) >= 48
    assert float(plan.env["RAG_CUDA_MEMORY_FRACTION"]) >= 0.50
    assert int(plan.env["OCR_CPU_WORKERS"]) >= 6
    assert int(plan.env["OCR_CELERY_CONCURRENCY"]) >= 5
    assert int(plan.env["OCR_PARALLEL_BUCKETS"]) == 3
    assert int(plan.env["GPU_THERMAL_PAUSE_C"]) == 92
    assert int(plan.env["GPU_THERMAL_ABORT_C"]) == 94
    assert int(plan.env["EXTRACT_DISK_WORKERS"]) >= 6
    assert int(plan.env["EXTRACT_SHARD_COUNT"]) >= 8
    assert int(plan.env["AXIOM_INVENTORY_WORKERS"]) >= 6
    assert int(plan.env["AXIOM_INVENTORY_BATCH_SIZE"]) >= 200


def test_build_plan_no_gpu_cpu_fallback():
    snap = HostSnapshot(
        cpu_logical=8,
        mem_total_mb=16000,
        mem_available_mb=9000,
        gpu_available=False,
        profile="laptop",
    )
    plan = build_capacity_plan(snap)
    assert plan.env["RAG_EMBEDDING_DEVICE"] == "cpu"
    assert int(plan.env["RAG_BATCH_SIZE"]) <= 4


def test_hot_gpu_reduces_batch():
    cool = build_capacity_plan(
        HostSnapshot(
            cpu_logical=16,
            mem_total_mb=64000,
            mem_available_mb=40000,
            gpu_available=True,
            gpu_name="RTX 4090",
            gpu_vram_total_mb=24576,
            gpu_temp_c=50,
            profile="workstation",
        )
    )
    hot = build_capacity_plan(
        HostSnapshot(
            cpu_logical=16,
            mem_total_mb=64000,
            mem_available_mb=40000,
            gpu_available=True,
            gpu_name="RTX 4090",
            gpu_vram_total_mb=24576,
            gpu_temp_c=78,
            profile="workstation",
        )
    )
    assert int(hot.env["RAG_BATCH_SIZE"]) <= int(cool.env["RAG_BATCH_SIZE"])


def test_apply_respects_disable(monkeypatch):
    monkeypatch.setenv("DYNAMIC_PERF_ENABLED", "false")
    plan = apply_dynamic_performance()
    assert plan.profile == "manual"


def test_cpu_thermal_pace_bounds():
    pace = cpu_thermal_pace()
    assert 0.0 < pace <= 1.0


def test_npu_raises_shared_worker_budget():
    base = HostSnapshot(
        cpu_logical=16,
        mem_total_mb=64000,
        mem_available_mb=40000,
        gpu_available=True,
        gpu_name="RTX 4090",
        gpu_vram_total_mb=24576,
        gpu_temp_c=50,
        profile="workstation",
    )
    without = build_capacity_plan(base)
    with_npu = build_capacity_plan(
        HostSnapshot(
            **{**base.__dict__, "npu_available": True, "npu_name": "Intel AI Boost"}
        )
    )
    assert with_npu.env["NPU_AVAILABLE"] == "true"
    assert int(with_npu.env["NESSUS_WORKER_CONCURRENCY"]) >= int(without.env["NESSUS_WORKER_CONCURRENCY"])


def test_shared_host_gpu_slots_split_per_product(monkeypatch):
    snap = HostSnapshot(
        cpu_logical=16,
        mem_total_mb=32000,
        mem_available_mb=18000,
        gpu_available=True,
        gpu_name="RTX 5070 Ti",
        gpu_vram_total_mb=12282,
        gpu_vram_free_mb=10000,
        gpu_temp_c=52,
        profile="laptop",
    )
    monkeypatch.setenv("AETHERIS_SHARE_HOST", "true")
    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    forensic = build_capacity_plan(snap)
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-extract")
    mobile = build_capacity_plan(snap)
    assert int(forensic.env["GPU_HEAVY_MAX_CONCURRENT"]) == 1
    assert int(mobile.env["GPU_HEAVY_MAX_CONCURRENT"]) == 1
    assert int(forensic.env["VULN_OPENVAS_IP_WORKERS"]) >= 2
    monkeypatch.setenv("AETHERIS_SHARE_HOST", "false")
    exclusive = build_capacity_plan(snap)
    assert int(exclusive.env["GPU_HEAVY_MAX_CONCURRENT"]) == 2


def test_long_job_timeout_unlimited_by_default(monkeypatch):
    from app.services.mobile_acquire.adapters.base import long_job_timeout

    monkeypatch.delenv("LONG_JOB_TIMEOUT_SEC", raising=False)
    assert long_job_timeout() is None
    monkeypatch.setenv("LONG_JOB_TIMEOUT_SEC", "0")
    assert long_job_timeout() is None
    monkeypatch.setenv("LONG_JOB_TIMEOUT_SEC", "3600")
    assert long_job_timeout() == 3600
