from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from scripts.publication import generate_android_publication_alignment as alignment


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def test_publication_alignment_static_selection_and_reconciliation(tmp_path: Path) -> None:
    cutoff_rows = [
        {
            "package_name": "example.app",
            "selected_base_apk_sha256": "a" * 64,
            "selected_static_run_ids": "1,2,3",
        }
    ]
    run_by_id = {
        1: {
            "id": 1,
            "base_apk_sha256": "a" * 64,
            "status": "COMPLETED",
            "run_class": "CANONICAL",
            "identity_valid": 1,
            "run_started_at_utc": "2026-07-08T00:00:00+00:00",
        },
        2: {
            "id": 2,
            "base_apk_sha256": "a" * 64,
            "status": "COMPLETED",
            "run_class": "CANONICAL",
            "identity_valid": 1,
            "run_started_at_utc": "2026-07-09T00:00:00+00:00",
        },
        3: {
            "id": 3,
            "base_apk_sha256": "b" * 64,
            "status": "COMPLETED",
            "run_class": "CANONICAL",
            "identity_valid": 1,
            "run_started_at_utc": "2026-07-10T00:00:00+00:00",
        },
    }
    assert alignment._choose_contributing_static_ids(cutoff_rows, run_by_id) == {"example.app": 2}

    old_export = tmp_path / "old_per_run_summary.csv"
    with old_export.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id"])
        writer.writeheader()
        writer.writerow({"run_id": "kept-run"})
    dynamic_rows = [
        {
            "dynamic_run_id": "kept-run",
            "app": "Example",
            "package": "example.app",
            "selected_version": "1.0",
            "evidence_class": "strict_idle",
            "pcap_status": "present",
            "analytic_eligibility": "eligible",
        },
        {
            "dynamic_run_id": "missing-run",
            "app": "Example",
            "package": "example.app",
            "selected_version": "1.0",
            "evidence_class": "interactive",
            "pcap_status": "present",
            "analytic_eligibility": "eligible",
        },
    ]
    result = alignment._dynamic_reconciliation(tmp_path / "out", dynamic_rows, old_export)
    rows = _read_csv(tmp_path / "out" / "report" / "dynamic_107_123_reconciliation.csv")
    assert result["old_selected_run_coverage"] == 1
    assert result["selected_runs_missing_from_old_export"] == 1
    assert rows[0]["dynamic_run_id"] == "missing-run"


def test_generate_android_publication_alignment_final_cutoff(tmp_path: Path) -> None:
    repo = Path.cwd()
    cutoff = repo / "output" / "paper" / "dynamic_paper_cutoff_final_20260709T202819Z"
    script = repo / "scripts" / "publication" / "generate_android_publication_alignment.py"
    if not (cutoff / "paper_freeze_manifest.csv").exists():
        pytest.skip("final publication cutoff fixture is not available")

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--cutoff-dir",
            str(cutoff),
            "--output-dir",
            str(tmp_path / "alignment"),
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if proc.returncode != 0 and (
        "SCYTALEDROID_DB" in proc.stderr
        or "connect" in proc.stderr.lower()
        or "sqlite3.OperationalError" in proc.stderr
    ):
        pytest.skip("local ScytaleDroid research database is not available")
    assert proc.returncode == 0, proc.stdout + proc.stderr

    out = tmp_path / "alignment"
    summary = json.loads((out / "alignment_summary.json").read_text(encoding="utf-8"))
    manifest = _read_csv(out / "publication_cohort_manifest.csv")
    dynamic = _read_csv(out / "data" / "publication_dynamic_run_metrics.csv")
    dynamic_apps = _read_csv(out / "data" / "publication_dynamic_app_metrics.csv")
    static_apps = _read_csv(out / "data" / "publication_static_app_metrics.csv")
    app_dataset = _read_csv(out / "data" / "publication_app_analysis_dataset.csv")
    static_alignment = _read_csv(out / "static_run_alignment_report.csv")
    reconciliation = _read_csv(out / "report" / "dynamic_107_123_reconciliation.csv")

    assert summary["mutation_scope"] == "read_only"
    assert len(manifest) == 15
    assert len(dynamic) == 123
    assert Counter(row["evidence_class"] for row in dynamic) == {
        "strict_idle": 44,
        "qfg": 23,
        "interactive": 56,
    }
    dynamic_ids = [row["dynamic_run_id"] for row in dynamic]
    assert len(dynamic_ids) == len(set(dynamic_ids))
    assert len(static_apps) == 15
    assert len(dynamic_apps) == 15
    assert len(app_dataset) == 15
    assert len(static_alignment) == 30
    assert len(reconciliation) == 16
    assert sum(row["contributes_app_level_metrics"] == "yes" for row in static_alignment) == 15
    assert {row["static_dynamic_same_build"] for row in manifest} == {"yes"}
    assert summary["dynamic_107_123_reconciliation"]["selected_runs_missing_from_old_export"] == 16
