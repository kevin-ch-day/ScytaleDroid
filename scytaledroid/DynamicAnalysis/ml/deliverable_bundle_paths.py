"""Centralized paper artifact path conventions.

Policy (Paper #2):
- The *canonical* paper output directory is `output/paper/` with stable paths:
  - output/paper/tables
  - output/paper/figures
  - output/paper/appendix
  - output/paper/manifests
- Phase/snapshot separation exists only under `output/paper/internal/` so paper
  writing never has to navigate phase trees.

Important:
- Phase E regression/no-drift uses the *internal* Phase E baseline bundle under
  `output/paper/internal/baseline/` so it remains deterministic and isolated
  from operational snapshot tables.
"""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config

from . import ml_parameters_paper2 as paper2_config


def freeze_anchor_path() -> Path:
    """Canonical checksummed freeze anchor (authoritative input)."""
    return Path(app_config.DATA_DIR) / "archive" / paper2_config.FREEZE_CANONICAL_FILENAME


def dataset_tables_dir() -> Path:
    """Dataset-level derived tables written by the Phase E runner (regenerable)."""
    return Path(app_config.DATA_DIR)


# Canonical paper directory (stable paths for LaTeX and humans).
def output_paper_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "paper"


def output_paper_tables_dir() -> Path:
    return output_paper_root() / "tables"


def output_paper_figures_dir() -> Path:
    return output_paper_root() / "figures"


def output_paper_appendix_dir() -> Path:
    return output_paper_root() / "appendix"


def output_paper_manifests_dir() -> Path:
    return output_paper_root() / "manifests"


def output_paper_internal_root() -> Path:
    return output_paper_root() / "internal"


def output_paper_internal_provenance_dir() -> Path:
    return output_paper_internal_root() / "provenance"


def output_paper_internal_snapshots_root() -> Path:
    return output_paper_internal_root() / "snapshots"


def output_paper_internal_snapshot_dir(snapshot_id: str) -> Path:
    return output_paper_internal_snapshots_root() / snapshot_id


# Internal Phase E baseline bundle (deterministic, used for regression gates).
def output_phase_e_bundle_root() -> Path:
    return output_paper_internal_root() / "baseline"


def output_phase_e_bundle_figures_dir() -> Path:
    return output_phase_e_bundle_root() / "figures"


def output_phase_e_bundle_tables_dir() -> Path:
    return output_phase_e_bundle_root() / "tables"


def output_phase_e_bundle_appendix_dir() -> Path:
    return output_phase_e_bundle_root() / "appendix"


def output_phase_e_bundle_manifest_dir() -> Path:
    return output_phase_e_bundle_root() / "manifest"


def output_phase_e_bundle_freeze_copy_path() -> Path:
    return output_phase_e_bundle_manifest_dir() / "dataset_freeze.json"


def output_phase_e_bundle_artifacts_manifest_path() -> Path:
    return output_phase_e_bundle_manifest_dir() / "phase_e_artifacts_manifest.json"


def output_phase_e_bundle_readme_path() -> Path:
    return output_phase_e_bundle_root() / "README.md"

