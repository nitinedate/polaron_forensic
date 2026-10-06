from collections.abc import Generator
from contextlib import contextmanager
import os
import sys

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()


def _create_dbapi_connection():
    from app.services.db_resilience import connect_psycopg2_with_retry

    return connect_psycopg2_with_retry(attempts=36, delay_sec=1.0)


engine = create_engine(
    settings.database_url,
    creator=_create_dbapi_connection,
    pool_pre_ping=True,
    pool_size=int(os.environ.get("DB_POOL_SIZE") or 4),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW") or 6),
    pool_timeout=int(os.environ.get("DB_POOL_TIMEOUT") or 60),
    pool_recycle=int(os.environ.get("DB_POOL_RECYCLE") or 1800),
    pool_use_lifo=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def _idle_in_transaction_timeout() -> str:
    """Use a short guardrail for the API but never kill long forensic workers.

    The compose worker environment is shared with the API and historically set
    AETHERIS_WORKER=1 plus IDLE_IN_TRANSACTION_SESSION_TIMEOUT=0 for every service.
    That accidentally disabled PostgreSQL idle-transaction cleanup for uvicorn too,
    allowing abandoned API snapshots to block maintenance/index operations.
    """
    import re

    argv = " ".join(sys.argv).lower()
    valid = re.compile(r"0|\d+(ms|s|min)?", flags=re.I)

    # API must win over the shared worker-env anchor. A request should never hold an
    # abandoned transaction indefinitely. Long Celery I/O is handled below.
    if "uvicorn" in argv or "gunicorn" in argv:
        api_value = (os.environ.get("API_IDLE_IN_TRANSACTION_SESSION_TIMEOUT") or "60s").strip()
        return api_value if valid.fullmatch(api_value) else "60s"

    explicit = (os.environ.get("IDLE_IN_TRANSACTION_SESSION_TIMEOUT") or "").strip()
    is_worker = "celery" in argv or bool(os.environ.get("CELERY_LOADER"))
    if is_worker:
        return explicit if explicit and valid.fullmatch(explicit) else "0"

    # The API compose service inherits the worker-env anchor.  During startup its
    # command first runs ordinary `python ...` bootstrap/migration scripts before
    # uvicorn, so argv alone does not identify those processes as API.  Treat an
    # inherited explicit zero as unsafe for every non-Celery process.
    if explicit and valid.fullmatch(explicit) and explicit != "0":
        return explicit
    api_value = (os.environ.get("API_IDLE_IN_TRANSACTION_SESSION_TIMEOUT") or "60s").strip()
    return api_value if valid.fullmatch(api_value) else "60s"


@event.listens_for(engine, "connect")
def _set_session_guardrails(dbapi_connection, _connection_record) -> None:
    """Release abandoned API transactions; do not kill long-running workers."""
    try:
        timeout = _idle_in_transaction_timeout()
        with dbapi_connection.cursor() as cur:
            # SET does not take bind params reliably across drivers.
            cur.execute(f"SET idle_in_transaction_session_timeout = '{timeout}'")
    except Exception:
        pass

def bind_firm_schema(db: Session, schema_name: str) -> None:
    """Pin firm schema on session; search_path is restored after each commit."""
    db.info["firm_schema"] = schema_name
    db.execute(text(f'SET search_path TO "{schema_name}", public'))


def reset_search_path(db: Session) -> None:
    db.info.pop("firm_schema", None)
    db.execute(text("SET search_path TO public"))


def apply_firm_search_path(db: Session, schema_name: str | None = None) -> str | None:
    """Re-apply firm schema search_path (survives commits that recycle pooled connections)."""
    if not schema_name:
        schema_name = db.info.get("firm_schema")
    if not schema_name:
        from app.db.tenant import get_tenant_context

        ctx = get_tenant_context()
        schema_name = ctx.schema_name if ctx else None
    if not schema_name:
        return None
    bind_firm_schema(db, schema_name)
    return schema_name


@event.listens_for(Session, "after_begin")
def _apply_firm_search_path_on_transaction_begin(session: Session, _transaction, connection) -> None:
    schema_name = session.info.get("firm_schema")
    if schema_name:
        connection.execute(text(f'SET search_path TO "{schema_name}", public'))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        reset_search_path(db)
        yield db
    finally:
        db.close()


@contextmanager
def firm_session(schema_name: str):
    """Yield a session scoped to a firm schema via search_path."""
    db = SessionLocal()
    try:
        bind_firm_schema(db, schema_name)
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def firm_session_readonly(schema_name: str):
    """Read-only firm session for parallel counters.

    Uses AUTOCOMMIT so SELECTs do not leave AccessShareLocks held across
    long non-SQL work (S3/zip scans) — that pattern caused lock storms with
    runtime ALTER TABLE ensure paths.
    """
    db = SessionLocal()
    try:
        db.connection(execution_options={"isolation_level": "AUTOCOMMIT"})
        bind_firm_schema(db, schema_name)
        yield db
    finally:
        try:
            db.rollback()
        except Exception:
            pass
        db.close()


@contextmanager
def platform_session():
    db = SessionLocal()
    try:
        db.execute(text("SET search_path TO public"))
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
