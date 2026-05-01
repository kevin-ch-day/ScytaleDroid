from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.StaticAnalysis.audit.run_log_audit import (
    persistence_audit_candidates,
    scan_log_tail,
    summarize_persistence_audit,
    tail_text_lines,
)


def test_tail_text_lines_returns_suffix(tmp_path: Path) -> None:
    path = tmp_path / "sample.log"
    lines = "\n".join(f"line-{idx}" for idx in range(5))
    path.write_text(lines + "\n", encoding="utf-8")

    tail = tail_text_lines(path, max_lines=3)
    assert tail == ["line-2", "line-3", "line-4"]


def test_scan_log_tail_matches_session(tmp_path: Path) -> None:
    path = tmp_path / "static.log"
    path.write_text("noise\nstamp 20260101-unit-test-session ok\nnoise\n", encoding="utf-8")

    hits = scan_log_tail(
        path,
        session="20260101-unit-test-session",
        tail_lines=100,
        markers=("zzznomatchmarker",),
        extras=(),
        max_report=10,
    )
    assert len(hits) == 1
    assert "20260101-unit-test-session" in hits[0]


def test_persistence_audit_candidates(tmp_path: Path) -> None:
    a, b = persistence_audit_candidates("sess-x", output_root=tmp_path)
    assert a == tmp_path / "audit" / "persistence" / "sess-x_persistence_audit.json"
    assert b == tmp_path / "audit" / "persistence" / "sess-x_missing_run_ids.json"


def test_summarize_persistence_audit_prints_outcome(
    tmp_path: Path, capsys,
) -> None:
    audit = tmp_path / "audit.json"
    audit.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "total_apps": 2,
                "summary": {
                    "outcome": {
                        "canonical_failed": False,
                        "persistence_failed": True,
                        "compat_export_failed": False,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    summarize_persistence_audit(audit)
    out = capsys.readouterr().out
    assert "persistence_failed=True" in out
    assert "schema_version" in out
