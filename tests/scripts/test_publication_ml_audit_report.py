from __future__ import annotations

from pathlib import Path

import pytest
from scripts.publication import publication_ml_audit_report as ml_audit
from scytaledroid.DynamicAnalysis import research_cohort_archive
from scytaledroid.DynamicAnalysis.utils import path_utils


def test_ml_audit_uses_configured_dynamic_evidence_root(monkeypatch, tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    evidence_root = data_dir / "evidence" / "dynamic"
    monkeypatch.setattr(path_utils.app_config, "DATA_DIR", str(data_dir), raising=False)
    monkeypatch.setattr(path_utils.app_config, "DYNAMIC_EVIDENCE_ROOT", str(evidence_root), raising=False)

    assert ml_audit._evidence_root() == evidence_root


def test_ml_audit_missing_freeze_mentions_current_evidence_root(monkeypatch, tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    evidence_root = data_dir / "evidence" / "dynamic"
    monkeypatch.setattr(path_utils.app_config, "DATA_DIR", str(data_dir), raising=False)
    monkeypatch.setattr(path_utils.app_config, "DYNAMIC_EVIDENCE_ROOT", str(evidence_root), raising=False)
    monkeypatch.setattr(research_cohort_archive.app_config, "DATA_DIR", str(data_dir), raising=False)

    with pytest.raises(SystemExit) as excinfo:
        ml_audit.main()

    message = str(excinfo.value)
    assert "Missing freeze anchor" in message
    assert str(evidence_root) in message
