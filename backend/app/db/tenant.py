from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Scope(str, Enum):
    PLATFORM = "platform"
    FIRM = "firm"


@dataclass
class TenantContext:
    slug: str
    scope: Scope
    schema_name: Optional[str] = None
    firm_id: Optional[str] = None
    firm_status: Optional[str] = None


_tenant_ctx: ContextVar[TenantContext | None] = ContextVar("_tenant_ctx", default=None)


def set_tenant_context(ctx: TenantContext | None) -> None:
    _tenant_ctx.set(ctx)


def get_tenant_context() -> TenantContext | None:
    return _tenant_ctx.get()
