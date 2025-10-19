from __future__ import annotations

from contextlib import contextmanager

from scytaledroid.Database.db_utils import reset_static


class FakeEngine:
    def __init__(self, existing_tables: set[str]):
        self.existing_tables = existing_tables
        self.commands: list[tuple[str, str, tuple | None]] = []

    def execute(self, query: str, params: tuple | None = None) -> None:
        self.commands.append(("exec", query, params))

    def fetch_one(self, query: str, params: tuple | None = None):
        self.commands.append(("fetch", query, params))
        table = params[0] if params else ""
        if table in self.existing_tables:
            return (1,)
        return None


def test_reset_static_truncates_tables(monkeypatch):
    existing_tables = {
        *reset_static.STATIC_ANALYSIS_TABLES,
        *reset_static.HARVEST_TABLES,
    }
    # Simulate missing optional table
    existing_tables.discard("string_match_cache")

    engine = FakeEngine(existing_tables)

    @contextmanager
    def fake_session(*args, **kwargs):
        yield engine

    monkeypatch.setattr(reset_static, "database_session", fake_session)

    outcome = reset_static.reset_static_analysis_data(include_harvest=True)

    expected_truncate_tables = [
        table
        for table in (*reset_static.STATIC_ANALYSIS_TABLES, *reset_static.HARVEST_TABLES)
        if table not in reset_static.PROTECTED_TABLES and table != "string_match_cache"
    ]

    exec_commands = [cmd for cmd in engine.commands if cmd[0] == "exec"]
    assert exec_commands[0][1] == "SET FOREIGN_KEY_CHECKS=0"
    assert exec_commands[-1][1] == "SET FOREIGN_KEY_CHECKS=1"
    truncate_execs = [cmd for cmd in exec_commands[1:-1]]
    assert [sql for _, sql, _ in truncate_execs] == [f"TRUNCATE TABLE `{name}`" for name in expected_truncate_tables]

    assert outcome.truncated == expected_truncate_tables
    assert "string_match_cache" in outcome.skipped_missing


def test_reset_static_respects_exclusions(monkeypatch):
    existing_tables = set(reset_static.STATIC_ANALYSIS_TABLES)
    existing_tables.discard("string_match_cache")

    engine = FakeEngine(existing_tables)

    @contextmanager
    def fake_session(*args, **kwargs):
        yield engine

    monkeypatch.setattr(reset_static, "database_session", fake_session)

    outcome = reset_static.reset_static_analysis_data(extra_exclusions=["runs"])

    assert "runs" not in outcome.truncated
    assert "runs" in outcome.skipped_protected
    assert "string_match_cache" in outcome.skipped_missing
