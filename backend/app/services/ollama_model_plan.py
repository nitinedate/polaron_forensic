"""GPU-capacity Ollama model plan.

Required models are always pulled for the detected tier. Extra higher-accuracy
models are added only when VRAM can load them without swapping the laptop
into thermal shutdown.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class OllamaModelPlan:
    profile: str
    vram_mb: int
    gpu_available: bool
    required: list[str]
    accuracy: list[str]
    primary: str
    review: str
    fast: str
    embed: str
    notes: list[str] = field(default_factory=list)

    @property
    def pull_models(self) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for name in [*self.required, *self.accuracy]:
            if name in seen:
                continue
            seen.add(name)
            ordered.append(name)
        return ordered

    def csv(self) -> str:
        return ",".join(self.pull_models)


def plan_ollama_models(*, vram_mb: int = 0, gpu_available: bool = False) -> OllamaModelPlan:
    notes: list[str] = []
    vram = max(int(vram_mb or 0), 0)
    gpu = bool(gpu_available and vram > 0)

    required = ["nomic-embed-text", "qwen2.5:7b"]
    accuracy: list[str] = []
    primary = "qwen2.5:7b"
    review = "qwen2.5:7b"
    fast = "qwen2.5:7b"
    embed = "nomic-embed-text"
    profile = "cpu"

    if not gpu:
        required.append("llama3.1:8b")
        notes.append("no GPU — CPU-safe required set only")
        return OllamaModelPlan(
            profile=profile,
            vram_mb=vram,
            gpu_available=False,
            required=required,
            accuracy=accuracy,
            primary=primary,
            review=review,
            fast="llama3.1:8b",
            embed=embed,
            notes=notes,
        )

    if vram < 8000:
        profile = "gpu-tight"
        required.extend(["llama3.1:8b", "qwen3.5:9b"])
        fast = "llama3.1:8b"
        notes.append(f"{vram}MB VRAM — skip 14b+ required models")
    elif vram < 10000:
        profile = "gpu-8"
        required.extend(["llama3.1:8b", "qwen3.5:9b"])
        primary = "qwen3.5:9b"
        review = "qwen3.5:9b"
        fast = "qwen3.5:9b"
        notes.append(f"{vram}MB VRAM — 9b required, no 14b")
    elif vram < 12000:
        profile = "gpu-10"
        required.extend(["llama3.1:8b", "qwen3.5:9b", "qwen2.5:14b", "deepseek-r1:14b"])
        primary = "qwen2.5:14b"
        review = "deepseek-r1:14b"
        fast = "qwen3.5:9b"
        notes.append(f"{vram}MB VRAM — 14b required set")
    else:
        profile = "gpu-12"
        required.extend(
            ["llama3.1:8b", "qwen3.5:9b", "qwen2.5:14b", "deepseek-r1:14b", "gemma4:12b"]
        )
        primary = "qwen2.5:14b"
        review = "deepseek-r1:14b"
        fast = "qwen3.5:9b"
        notes.append(f"{vram}MB VRAM — full 12GB required set")

    # Higher-accuracy extras: only when the card can hold the weights.
    if vram >= 20000:
        accuracy.append("qwen2.5:32b")
        primary = "qwen2.5:32b"
        notes.append("accuracy extra: qwen2.5:32b (report draft)")
        profile = "gpu-20"
    if vram >= 24000:
        accuracy.append("deepseek-r1:32b")
        review = "deepseek-r1:32b"
        notes.append("accuracy extra: deepseek-r1:32b (reasoning review)")
        profile = "gpu-24"
    if vram >= 40000:
        accuracy.append("qwen2.5:72b")
        primary = "qwen2.5:72b"
        notes.append("accuracy extra: qwen2.5:72b (highest-accuracy draft)")
        profile = "gpu-40"

    return OllamaModelPlan(
        profile=profile,
        vram_mb=vram,
        gpu_available=True,
        required=required,
        accuracy=accuracy,
        primary=primary,
        review=review,
        fast=fast,
        embed=embed,
        notes=notes,
    )
