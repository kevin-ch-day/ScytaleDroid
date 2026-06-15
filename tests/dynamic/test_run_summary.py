from __future__ import annotations

import json
from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.core.session import DynamicSessionResult
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.Utils.DisplayUtils import colors


def _blocked_result(tmp_path) -> DynamicSessionResult:
    return DynamicSessionResult(
        package_name="com.example.app",
        duration_seconds=30,
        started_at=datetime.now(UTC),
        ended_at=datetime.now(UTC),
        status="blocked",
        notes="Dynamic execution blocked by plan validation.",
        errors=["fallback blocker", "secondary blocker"],
        dynamic_run_id="run-123",
        evidence_path=str(tmp_path),
    )


def test_print_run_summary_surfaces_plan_validation_blocker_from_event(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "plan.validation",
        "details": {
            "validation_result": "FAIL",
            "reasons": ["missing required fields: run_signature"],
            "warnings": ["base_apk_sha256 mismatch"],
            "summary": {
                "reason_count": 1,
                "warning_count": 1,
                "mismatch_count": 2,
                "db_row_found": True,
                "has_static_link": True,
            },
        },
    }
    (notes_dir / "run_events.jsonl").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation." in out
    assert "missing required fields: run_signature" in out
    assert "mismatches=2" in out
    assert "warnings=1" in out


def test_print_run_summary_falls_back_to_result_errors_when_event_missing(tmp_path, capsys) -> None:
    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation. fallback blocker" in out


def test_print_run_summary_separates_run_mode_from_wall_clock(tmp_path, capsys) -> None:
    print_run_summary(_blocked_result(tmp_path), "Cohort")

    out = colors.strip(capsys.readouterr().out)
    assert "Run mode" in out
    assert "Cohort" in out
    assert "Session wall-clock" in out
    assert "Cohort (30s)" not in out


def test_print_run_summary_distinguishes_missing_tools_blockers(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "preflight.tools_missing",
        "details": {
            "missing_tools": ["tshark", "capinfos"],
            "tier": "dataset",
        },
    }
    (notes_dir / "run_events.jsonl").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked: missing required host tools." in out
    assert "missing_tools=tshark,capinfos" in out


def test_print_run_summary_ignores_malformed_event_lines_when_resolving_blocker(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    valid_payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "plan.validation",
        "details": {
            "validation_result": "FAIL",
            "reasons": ["unsupported run_signature_version: v0"],
            "warnings": [],
            "summary": {
                "reason_count": 1,
                "warning_count": 0,
                "mismatch_count": 0,
                "db_row_found": True,
                "has_static_link": False,
            },
        },
    }
    (notes_dir / "run_events.jsonl").write_text(
        "{not-json}\n" + json.dumps(valid_payload) + "\n",
        encoding="utf-8",
    )

    print_run_summary(_blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation." in out
    assert "unsupported run_signature_version: v0" in out
