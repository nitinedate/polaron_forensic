"""Acquisition adapter contract — Architecture §5 and §7.

An adapter owns one device-access technology (ADB, lockdownd/AFC, SIM reader,
card reader). It is responsible for detect -> identify -> preflight -> acquire,
and for reporting honestly when it cannot do something.

Design rule inherited from §20: an adapter NEVER returns an empty result set to
mean "nothing was there". If it could not read something it says so, and the
orchestrator turns that into a reported limitation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from app.services.mobile_acquire.device_profile import DeviceProfile
from app.services.mobile_acquire.methods import CollectionMethod

ProgressFn = Callable[..., None]
"""progress(current_item, bytes_done, bytes_total_or_None, files_seen=None)"""


class ToolUnavailable(RuntimeError):
    """A required external binary is not installed on the workstation."""


@dataclass
class AcquisitionOutcome:
    ok: bool
    adapter: str
    method: CollectionMethod | None = None
    files_written: list[str] = field(default_factory=list)
    bytes_written: int = 0
    device_metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    interrupted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "adapter": self.adapter,
            "method": self.method.value if self.method else None,
            "file_count": len(self.files_written),
            "bytes_written": self.bytes_written,
            "device_metadata": self.device_metadata,
            "warnings": self.warnings,
            "errors": self.errors,
            "coverage_gaps": self.coverage_gaps,
            "interrupted": self.interrupted,
        }


class AcquisitionAdapter(Protocol):
    """§7 collection orchestrator calls these in order."""

    name: str
    os_family: str

    def tool_available(self) -> bool: ...

    def detect(self) -> list[str]:
        """Return identifiers of connected devices this adapter can see."""

    def identify(self, device_id: str) -> DeviceProfile: ...

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]: ...

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        """Return blocking problems. Empty list means ready to acquire."""

    def acquire(
        self,
        *,
        profile: DeviceProfile,
        method: CollectionMethod,
        destination: Path,
        progress: ProgressFn | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> AcquisitionOutcome: ...


# --------------------------------------------------------------------------
# External tool helpers
# --------------------------------------------------------------------------

def which(binary: str) -> str | None:
    return shutil.which(binary)


def long_job_timeout() -> int | None:
    """Wall-clock for extract/acquire/scan steps. 0 or unset = no timeout."""
    raw = (os.environ.get("LONG_JOB_TIMEOUT_SEC") or "0").strip()
    try:
        value = int(raw)
    except ValueError:
        return None
    return None if value <= 0 else value


def run_tool(
    args: list[str],
    *,
    timeout: int | None = 120,
    check: bool = False,
    binary_output: bool = False,
) -> subprocess.CompletedProcess:
    """Run an external forensic tool.

    Pass ``timeout=None`` (or ``long_job_timeout()``) for multi-hour pulls.
    Short probes still use a bounded default so a hung detect does not stall.
    """
    if not which(args[0]):
        raise ToolUnavailable(
            f"Required tool '{args[0]}' is not installed or not on PATH. "
            "Install it on the acquisition workstation and re-run validation (§15)."
        )
    return subprocess.run(
        args,
        capture_output=True,
        text=not binary_output,
        timeout=timeout,
        check=check,
    )


def stream_tool(args: list[str], *, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    """Stream a tool's stdout in chunks (for `adb exec-out` style pipelines)."""
    if not which(args[0]):
        raise ToolUnavailable(f"Required tool '{args[0]}' is not installed or not on PATH.")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        while True:
            chunk = proc.stdout.read(chunk_size)
            if not chunk:
                break
            yield chunk
    finally:
        proc.stdout.close()
        stderr = proc.stderr.read().decode("utf-8", "replace")
        proc.stderr.close()
        code = proc.wait()
        if code != 0:
            raise RuntimeError(f"{args[0]} exited {code}: {stderr.strip()[:400]}")
