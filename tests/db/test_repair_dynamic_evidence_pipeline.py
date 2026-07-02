from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.db import repair_dynamic_evidence_pipeline as pipeline


def test_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "repair_dynamic_evidence_pipeline.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage:")
    assert "--apply" in proc.stdout


def test_dry_run_skips_db_reindex_and_writes_combined_receipt(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[str, bool]] = []

    def fake_pcap(**kwargs):
        calls.append(("pcap", bool(kwargs["apply"])))
        return {"candidate_rows": 1, "applied_rows": 0}

    def fake_validity(**kwargs):
        calls.append((str(kwargs["output_dir"].name), bool(kwargs["apply"])))
        return {"ok": True, "candidate_rows": 1, "applied_rows": 0}

    def fake_reindex(**kwargs):
        calls.append(("reindex", bool(kwargs["apply"])))
        return {"skipped": True, "reason": "dry_run"}

    monkeypatch.setattr(pipeline, "_run_pcap_artifact_registration", fake_pcap)
    monkeypatch.setattr(pipeline, "_run_dataset_validity_repair", fake_validity)
    monkeypatch.setattr(pipeline, "_run_db_reindex", fake_reindex)
    monkeypatch.setattr(pipeline, "_run_db_snapshot", lambda: {"available": False})

    summary = pipeline.run_pipeline(
        evidence_root=tmp_path / "evidence",
        output_dir=tmp_path / "audit",
        run_ids=["run-1"],
        apply=False,
    )

    assert calls == [
        ("pcap", False),
        ("02_dataset_validity_repair", False),
        ("reindex", False),
        ("04_post_repair_dataset_validity_check", False),
    ]
    assert summary["apply"] is False
    assert summary["stages"]["db_reindex"]["reason"] == "dry_run"
    assert (tmp_path / "audit" / "summary.json").is_file()


def test_apply_runs_db_reindex_unless_skipped(tmp_path: Path, monkeypatch) -> None:
    reindex_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        pipeline,
        "_run_pcap_artifact_registration",
        lambda **kwargs: {"candidate_rows": 0, "applied_rows": 0},
    )
    monkeypatch.setattr(
        pipeline,
        "_run_dataset_validity_repair",
        lambda **kwargs: {"ok": True, "candidate_rows": 0, "applied_rows": 0},
    )

    def fake_reindex(**kwargs):
        reindex_calls.append(dict(kwargs))
        return {"scanned": 2, "ok": 2}

    monkeypatch.setattr(pipeline, "_run_db_reindex", fake_reindex)
    monkeypatch.setattr(pipeline, "_run_db_snapshot", lambda: {"available": True, "tables": {}})

    summary = pipeline.run_pipeline(
        evidence_root=tmp_path / "evidence",
        output_dir=tmp_path / "audit",
        apply=True,
        skip_db_reindex=False,
    )

    assert reindex_calls == [
        {
            "evidence_root": tmp_path / "evidence",
            "output_dir": tmp_path / "audit" / "03_db_reindex",
            "apply": True,
            "skip_db_reindex": False,
        }
    ]
    assert summary["stages"]["db_reindex"]["ok"] == 2
