from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import run_writers


def test_identity_conflict_blocks_canonical(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setattr(run_writers, "_ensure_app_version", lambda **_k: 7)
    monkeypatch.setattr(run_writers, "_identity_mode", lambda **_k: "full_hash")
    monkeypatch.setattr(run_writers, "_detect_identity_conflict", lambda **_k: True)

    def _create_static_run(**kwargs):
        captured.update(kwargs)
        return 101

    monkeypatch.setattr(run_writers, "_create_static_run", _create_static_run)
    monkeypatch.setattr(run_writers, "_update_static_run_metadata", lambda **_k: None)
    monkeypatch.setattr(
        run_writers,
        "_maybe_set_canonical_static_run",
        lambda **_k: (_ for _ in ()).throw(AssertionError("should not set canonical on conflict")),
    )
    monkeypatch.setattr(run_writers.core_q, "run_sql", lambda *_a, **_k: (0,))

    run_id = run_writers.create_static_run_ledger(
        package_name="com.example.app",
        display_name="Example",
        version_name="1.0",
        version_code=1,
        min_sdk=24,
        target_sdk=34,
        session_stamp="20260220-1",
        session_label="20260220-1",
        scope_label="Example Scope",
        category="Test",
        profile="full",
        profile_key="test",
        scenario_id="static_default",
        device_serial=None,
        tool_semver="2.0.1",
        tool_git_commit="deadbeef",
        schema_version="0.2.6",
        findings_total=0,
        run_started_utc="2026-02-20 00:00:00",
        status="STARTED",
        is_canonical=True,
        canonical_set_at_utc="2026-02-20 00:00:00",
        canonical_reason="replace",
        base_apk_sha256="a" * 64,
    )

    assert run_id == 101
    assert captured["is_canonical"] is False
    assert captured["canonical_reason"] == "identity_conflict"
    assert captured["identity_conflict_flag"] is True

