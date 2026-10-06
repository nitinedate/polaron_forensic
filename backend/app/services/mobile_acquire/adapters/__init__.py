"""Device-access adapters — one per connection technology (Architecture §5)."""

from app.services.mobile_acquire.adapters.android_adb import AndroidAdbAdapter
from app.services.mobile_acquire.adapters.android_mtp import AndroidMtpAdapter
from app.services.mobile_acquire.adapters.base import (
    AcquisitionAdapter,
    AcquisitionOutcome,
    ToolUnavailable,
)
from app.services.mobile_acquire.adapters.ios_lockdown import IosLockdownAdapter
from app.services.mobile_acquire.adapters.removable_media import (
    RemovableMediaAdapter,
    SimReaderAdapter,
)

__all__ = [
    "AcquisitionAdapter", "AcquisitionOutcome", "AndroidAdbAdapter",
    "AndroidMtpAdapter", "IosLockdownAdapter", "RemovableMediaAdapter",
    "SimReaderAdapter", "ToolUnavailable",
]
