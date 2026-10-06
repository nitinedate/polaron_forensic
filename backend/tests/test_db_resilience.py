from app.services.db_resilience import TransientDatabaseError, is_transient_db_error


def test_recovery_error_is_transient():
    exc = TransientDatabaseError(
        'connection to server at "postgres" (172.18.0.2), port 5432 failed: '
        "FATAL: the database system is not yet accepting connections "
        "DETAIL: Consistent recovery state has not been yet reached."
    )
    assert is_transient_db_error(exc)


def test_wrapped_operational_error_is_transient():
    cause = RuntimeError("the database system is starting up")
    outer = Exception("background on this error")
    outer.__cause__ = cause
    assert is_transient_db_error(outer)


def test_unrelated_error_is_not_transient():
    assert not is_transient_db_error(ValueError("shard 3 failed: bad ewf read"))
