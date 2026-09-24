"""Keep Dynamic evidence fixtures inside explicitly configured temporary roots."""

from __future__ import annotations

import pytest
from scytaledroid.Config import app_config


@pytest.fixture(autouse=True)
def isolated_dynamic_evidence_roots(monkeypatch, tmp_path):
    """Readers enforce containment; temporary fixture packs need an allowed root.

    Individual path-contract tests may override these defaults. Production and
    repository-local evidence must never be a fallback for a unit-test fixture.
    """
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(app_config, "DYNAMIC_EVIDENCE_ROOT", "data/evidence/dynamic")
