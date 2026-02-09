"""Centralized Phase E path conventions.

Contract (Paper #2):
- data/ is for inputs and regenerable intermediates (developer/analyst-facing).
- output/ is for operator-facing deliverables and paper-ready bundles.
"""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config

from . import ml_parameters_paper2 as config


def freeze_anchor_path() -> Path:
    """Canonical checksummed freeze anchor (authoritative input)."""
    return Path(app_config.DATA_DIR) / "archive" / config.FREEZE_CANONICAL_FILENAME


def dataset_tables_dir() -> Path:
    """Dataset-level derived tables written by the Phase E runner (regenerable)."""
    return Path(app_config.DATA_DIR)


def output_paper_root() -> Path:
    """Paper-ready deliverables root (zip-and-share)."""
    return Path(app_config.OUTPUT_DIR) / "paper" / "paper2" / "phase_e"


def output_paper_figures_dir() -> Path:
    return output_paper_root() / "figures"


def output_paper_tables_dir() -> Path:
    return output_paper_root() / "tables"


def output_paper_appendix_dir() -> Path:
    return output_paper_root() / "appendix"


def output_paper_manifest_dir() -> Path:
    return output_paper_root() / "manifest"


def output_paper_freeze_copy_path() -> Path:
    """Convenience copy of the freeze anchor inside the deliverable bundle."""
    return output_paper_manifest_dir() / "dataset_freeze.json"


def output_paper_artifacts_manifest_path() -> Path:
    return output_paper_manifest_dir() / "phase_e_artifacts_manifest.json"


def output_paper_readme_path() -> Path:
    return output_paper_root() / "README.md"
