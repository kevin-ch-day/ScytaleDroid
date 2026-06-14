from __future__ import annotations

import json

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import post_run_cohort_quick_check as prq


def test_post_run_grain_summary_enabled_respects_env_always(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "1")
    ctx = SimpleNamespace(batch=False, noninteractive=False)
    assert prq.post_run_grain_summary_enabled(ctx) is True


def test_post_run_grain_summary_enabled_respects_env_never(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "0")
    ctx = SimpleNamespace(batch=True, noninteractive=True)
    assert prq.post_run_grain_summary_enabled(ctx) is False


def test_post_run_grain_summary_enabled_auto_batch(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", raising=False)
    assert prq.post_run_grain_summary_enabled(SimpleNamespace(batch=True, noninteractive=False)) is True
    assert prq.post_run_grain_summary_enabled(SimpleNamespace(batch=False, noninteractive=True)) is True
    assert prq.post_run_grain_summary_enabled(SimpleNamespace(batch=False, noninteractive=False)) is False
    assert prq.post_run_grain_summary_enabled(None) is False


def test_maybe_emit_post_run_grain_summary_skips_when_disabled(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "0")
    prq.maybe_emit_post_run_grain_summary(
        "sess-x",
        scope_label=None,
        run_ctx=SimpleNamespace(batch=True, noninteractive=True),
    )
    assert capsys.readouterr().out == ""


def test_maybe_emit_post_run_grain_summary_collects_for_run_health_when_stdout_disabled(
    monkeypatch, capsys
) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "0")

    def _fake_grain(_run_sql, *, session_stamp, scope_label=None, top_packages=20):
        _ = scope_label, top_packages
        assert session_stamp == "sess-hidden"
        return {
            "session_stamp": session_stamp,
            "static_run_rows": 2,
            "status_breakdown": [("COMPLETED", 2)],
            "canonical_findings_rows": 10,
            "permission_matrix_rows": 5,
            "persistence_failure_rows": 0,
            "top_packages": [],
        }

    monkeypatch.setattr(prq, "collect_session_grain", _fake_grain)
    monkeypatch.setattr(prq, "count_json_files_in_dir", lambda _p: 7)

    metrics: dict[str, object] = {}
    prq.maybe_emit_post_run_grain_summary(
        "sess-hidden",
        scope_label="Lab",
        run_ctx=SimpleNamespace(batch=False, noninteractive=False),
        session_metrics=metrics,
    )

    assert capsys.readouterr().out == ""
    grain = metrics.get("post_run_grain")
    assert isinstance(grain, dict)
    assert grain.get("session_stamp") == "sess-hidden"
    assert grain.get("archive_json_files") == 7


def test_maybe_emit_post_run_grain_summary_prints_on_mock_data(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "1")

    def _fake_grain(_run_sql, *, session_stamp, scope_label=None, top_packages=20):
        _ = scope_label, top_packages
        assert session_stamp == "sess-a"
        return {
            "session_stamp": session_stamp,
            "static_run_rows": 2,
            "status_breakdown": [("COMPLETED", 2)],
            "canonical_findings_rows": 10,
            "permission_matrix_rows": 5,
            "persistence_failure_rows": 0,
            "top_packages": [],
        }

    monkeypatch.setattr(prq, "collect_session_grain", _fake_grain)
    monkeypatch.setattr(prq, "count_json_files_in_dir", lambda _p: 3)

    metrics: dict[str, object] = {}
    prq.maybe_emit_post_run_grain_summary(
        "sess-a",
        scope_label="Lab",
        run_ctx=SimpleNamespace(batch=False, noninteractive=False),
        session_metrics=metrics,
    )
    out = capsys.readouterr().out
    assert "Post-run cohort quick check" in out
    assert "sess-a" in out
    assert "static_runs=2" in out
    assert "archive_json_files=3" in out
    assert "report_static_session_grain_integrity.py" in out
    grain = metrics.get("post_run_grain")
    assert isinstance(grain, dict)
    assert grain.get("session_stamp") == "sess-a"
    assert grain.get("static_run_rows") == 2
    assert grain.get("canonical_findings_rows") == 10


def test_merge_post_run_grain_into_run_health_json(tmp_path) -> None:
    health = tmp_path / "sess_run_health.json"
    health.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "final_run_status": "partial",
                "post_run_grain_present": False,
                "post_run_grain_merged_at_utc": None,
                "run_health_revision": 1,
                "post_run_merge_status": "pending",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    outcome = SimpleNamespace(
        session_metrics={"post_run_grain": {"session_stamp": "sess", "static_run_rows": 3}},
        run_health_json_path=str(health),
    )
    prq.merge_post_run_grain_into_run_health_json(outcome)
    doc = json.loads(health.read_text(encoding="utf-8"))
    assert doc.get("post_run_grain", {}).get("static_run_rows") == 3
    assert doc.get("final_run_status") == "partial"
    assert doc.get("post_run_grain_present") is True
    assert doc.get("post_run_merge_status") == "merged"
    assert doc.get("run_health_revision") == 2
    assert doc.get("post_run_grain_merged_at_utc")
    assert "tmp" not in str(health.name)


def test_merge_post_run_grain_failure_warns_and_marks_failed(tmp_path, monkeypatch, capsys) -> None:
    health = tmp_path / "bad_run_health.json"
    health.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "run_health_revision": 1,
                "post_run_merge_status": "pending",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    outcome = SimpleNamespace(
        session_metrics={"post_run_grain": {"session_stamp": "sess", "static_run_rows": 1}},
        run_health_json_path=str(health),
    )

    calls = {"n": 0}
    real_atomic = prq._atomic_write_run_health_json

    def _first_boom_then_real(path: object, doc: object) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("simulated disk full")
        real_atomic(path, doc)  # type: ignore[arg-type]

    monkeypatch.setattr(prq, "_atomic_write_run_health_json", _first_boom_then_real)
    prq.merge_post_run_grain_into_run_health_json(outcome)
    out = capsys.readouterr().out
    assert "post_run_grain merge failed" in out
    doc = json.loads(health.read_text(encoding="utf-8"))
    assert doc.get("post_run_merge_status") == "failed"
    assert doc.get("post_run_merge_error")
    assert doc.get("run_health_revision") == 2


def test_maybe_emit_post_run_grain_summary_prints_partial_note(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SCYTALEDROID_STATIC_POST_RUN_GRAIN_SUMMARY", "1")

    def _fake_grain(_run_sql, *, session_stamp, scope_label=None, top_packages=20):
        _ = scope_label, top_packages
        return {
            "session_stamp": session_stamp,
            "static_run_rows": 1,
            "status_breakdown": [("COMPLETED", 1)],
            "canonical_findings_rows": 1,
            "permission_matrix_rows": 1,
            "persistence_failure_rows": 0,
            "top_packages": [],
        }

    monkeypatch.setattr(prq, "collect_session_grain", _fake_grain)
    monkeypatch.setattr(prq, "count_json_files_in_dir", lambda _p: 0)

    prq.maybe_emit_post_run_grain_summary(
        "sess-partial",
        scope_label=None,
        run_ctx=SimpleNamespace(batch=False, noninteractive=False),
        run_aggregate_status="partial",
    )
    out = capsys.readouterr().out
    assert "package rollup is partial" in out
