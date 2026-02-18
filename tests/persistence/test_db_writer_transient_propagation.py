from __future__ import annotations

import pytest

from scytaledroid.Persistence import db_writer
from scytaledroid.Database.db_core import db_engine


def test_write_buckets_raises_transient_db_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(db_writer, "_has_column", lambda *_args, **_kwargs: False)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("Lost connection to MySQL server during query (2013)")

    monkeypatch.setattr(db_writer.core_q, "run_sql", _boom)

    with pytest.raises(db_engine.TransientDbError):
        db_writer.write_buckets(1, {"permissions": (1.0, 20.0)}, static_run_id=1)
