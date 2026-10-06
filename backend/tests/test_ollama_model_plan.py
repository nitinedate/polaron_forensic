from app.services.ollama_model_plan import plan_ollama_models


def test_cpu_required_only():
    plan = plan_ollama_models(vram_mb=0, gpu_available=False)
    assert "nomic-embed-text" in plan.required
    assert "qwen2.5:7b" in plan.required
    assert "qwen2.5:32b" not in plan.pull_models
    assert plan.primary == "qwen2.5:7b"


def test_laptop_12gb_required_no_32b():
    plan = plan_ollama_models(vram_mb=12288, gpu_available=True)
    assert "qwen2.5:14b" in plan.required
    assert "deepseek-r1:14b" in plan.required
    assert "gemma4:12b" in plan.required
    assert "qwen2.5:32b" not in plan.accuracy
    assert plan.primary == "qwen2.5:14b"


def test_desktop_24gb_adds_accuracy_32b():
    plan = plan_ollama_models(vram_mb=24576, gpu_available=True)
    assert "qwen2.5:14b" in plan.required
    assert "qwen2.5:32b" in plan.accuracy
    assert "deepseek-r1:32b" in plan.accuracy
    assert plan.primary == "qwen2.5:32b"
    assert plan.review == "deepseek-r1:32b"


def test_workstation_40gb_adds_72b():
    plan = plan_ollama_models(vram_mb=40960, gpu_available=True)
    assert "qwen2.5:72b" in plan.accuracy
    assert plan.primary == "qwen2.5:72b"
