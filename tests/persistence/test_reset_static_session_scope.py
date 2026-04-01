from __future__ import annotations

from contextlib import contextmanager

from scytaledroid.Database.db_utils import reset_static as reset_mod
from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data

def test_reset_static_session_scoped_requires_session_label():
    outcome = reset_static_analysis_data(include_harvest=False, truncate_all=False, session_label=None)
    assert outcome.failed
    assert "session_label required" in outcome.failed[0][1]


def test_reset_static_session_scoped_clears_local_session_metadata(monkeypatch, tmp_path):
    session_dir = tmp_path / "sessions" / "sess-1"
    session_dir.mkdir(parents=True)
    (session_dir / "run_map.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(reset_mod.app_config, "DATA_DIR", str(tmp_path))

    class _FakeEngine:
        def fetch_all(self, *_args, **_kwargs):
            return []

        def fetch_one(self, *_args, **_kwargs):
            return None

        def execute(self, *_args, **_kwargs):
            return None

    @contextmanager
    def _fake_session(**_kwargs):
        yield _FakeEngine()

    monkeypatch.setattr(reset_mod, "database_session", _fake_session)
    monkeypatch.setattr(reset_mod, "_table_exists", lambda *_a, **_k: False)

    outcome = reset_static_analysis_data(
        include_harvest=False,
        truncate_all=False,
        session_label="sess-1",
    )

    assert not outcome.failed
    assert not session_dir.exists()
