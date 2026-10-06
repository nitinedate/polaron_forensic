"""Mobile-only forensic services separated from Disk/EWF orchestration.

Android and iOS run in independent service processes, brokers and databases.
Only low-level evidence/image primitives are shared with Disk forensics.
"""

from importlib import import_module

# Host-side key validation must not import the database/FastAPI worker stack.
# Public convenience exports retain their names and load only when requested.
_EXPORT_MODULES = {
    'is_mobile_job': 'detection',
    'mobile_platform': 'detection',
    'count_mobile_axiom_artifact': 'inventory',
    'build_mobile_inventory_snapshot': 'inventory',
    'is_mobile_segment_filename': 'segments',
}


def __getattr__(name):
    module = _EXPORT_MODULES.get(name)
    if module is None:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    value = getattr(import_module(f'{__name__}.{module}'), name)
    globals()[name] = value
    return value

__all__ = [
    "is_mobile_job",
    "mobile_platform",
    "count_mobile_axiom_artifact",
    "build_mobile_inventory_snapshot",
    "is_mobile_segment_filename",
]
