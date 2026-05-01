from __future__ import annotations

import main


class _Outcome:
    def __init__(self, failed=None):
        self.failed = failed or []

    def as_lines(self):
        return []


def test_db_truncate_static_requires_token(monkeypatch):
    monkeypatch.setattr(main, "status_messages", main.status_messages)
    try:
        main.main(["db", "--truncate-static"])
    except SystemExit as exc:
        assert int(exc.code) == 2
    else:
        raise AssertionError("expected SystemExit when confirmation token is missing")


def test_db_truncate_static_runs_with_token(monkeypatch):
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.reset_static.reset_static_analysis_data",
        lambda **_k: _Outcome(),
    )
    rc = main.main(["db", "--truncate-static", "--i-understand", "DESTROY_DATA"])
    assert rc == 0

