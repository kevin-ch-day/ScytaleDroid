from scytaledroid.Database.db_core import db_engine


def test_transient_errno_includes_mysql_disconnect_timeouts() -> None:
    assert 2013 in db_engine.TRANSIENT_ERRNOS
    assert 2014 in db_engine.TRANSIENT_ERRNOS
