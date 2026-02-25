"""Centralized publication bundle path conventions.

Policy:
- The canonical publication output directory is `output/publication/` with stable paths:
  - output/publication/tables
  - output/publication/figures
  - output/publication/appendix
  - output/publication/manifests
- Provenance and internal regression artifacts must NOT live under `output/publication/`.
  They are written under `output/_internal/` to keep the publication bundle minimal.

Note:
- Some older modules still refer to these as "paper" paths. Legacy helper names remain
  as thin aliases to avoid breaking existing workflows, but new code should use the
  publication-prefixed helpers.
"""

from __future__ import annotations

import os
from pathlib import Path

from scytaledroid.Config import app_config

from . import ml_parameters_profile as profile_config


def freeze_anchor_path() -> Path:
    """Canonical checksummed freeze anchor (authoritative input)."""
    override = str(os.environ.get("SCYTALEDROID_FREEZE_ANCHOR_PATH") or "").strip()
    if override:
        return Path(override)
    return Path(app_config.DATA_DIR) / "archive" / profile_config.FREEZE_CANONICAL_FILENAME


def dataset_tables_dir() -> Path:
    """Dataset-level derived tables written by the publication runner (regenerable)."""
    return Path(app_config.DATA_DIR)


# Canonical publication directory (stable paths for manuscripts and humans).
def output_publication_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "publication"


def output_publication_tables_dir() -> Path:
    return output_publication_root() / "tables"


def output_publication_figures_dir() -> Path:
    return output_publication_root() / "figures"


def output_publication_appendix_dir() -> Path:
    return output_publication_root() / "appendix"


def output_publication_manifests_dir() -> Path:
    return output_publication_root() / "manifests"

def output_publication_qa_dir() -> Path:
    return output_publication_root() / "qa"


def output_internal_root() -> Path:
    """Non-paper internal outputs (provenance, regressions, snapshots)."""
    return Path(app_config.OUTPUT_DIR) / "_internal"


def output_publication_internal_root() -> Path:
    # Keep legacy function name, but move internal artifacts out of the canonical paper bundle.
    return output_internal_root() / "publication"


def output_publication_internal_provenance_dir() -> Path:
    return output_publication_internal_root() / "provenance"


def output_publication_internal_snapshots_root() -> Path:
    return output_publication_internal_root() / "snapshots"


def output_publication_internal_snapshot_dir(snapshot_id: str) -> Path:
    return output_publication_internal_snapshots_root() / snapshot_id


# Internal Phase E baseline bundle (deterministic, used for regression gates).
def output_phase_e_bundle_root() -> Path:
    # Keep deterministic Phase E artifacts outside the paper bundle.
    return output_internal_root() / "paper2" / "baseline"


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
