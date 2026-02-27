"""Profile v3 publication bundle contract (additive under output/publication/profile_v3/)."""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Publication.profile_v3_metrics import ALLOWED_CATEGORIES


@dataclass(frozen=True)
class ProfileV3Lint:
    ok: bool
    errors: list[str]
    warnings: list[str]


REQUIRED_DIRS = {"tables", "manifests", "qa"}

REQUIRED_FILES = {
    Path("tables") / "per_app_dynamic_summary_v3.csv",
    Path("tables") / "per_app_dynamic_summary_v3.tex",
    Path("tables") / "per_category_summary_v3.csv",
    Path("tables") / "per_category_summary_v3.tex",
    Path("qa") / "profile_v3_category_tests.json",
    Path("manifests") / "profile_v3_manifest.json",
}

REQUIRED_PER_APP_COLUMNS = (
    "profile_id",
    "package",
    "app",
    "app_category",
    "n_idle_runs",
    "n_interactive_runs",
    "idle_windows_total",
    "interactive_windows_total",
    "mu_idle_rdi",
    "sigma_idle_rdi",
    "mu_interactive_rdi",
    "delta_rdi",
    "isc",
    "isc_reason",
    "bsi",
    "bsi_reason",
)


def lint_profile_v3_bundle(root: Path) -> ProfileV3Lint:
    errors: list[str] = []
    warnings: list[str] = []
    if not root.exists():
        return ProfileV3Lint(ok=False, errors=[f"missing_root:{root}"], warnings=[])

    for d in sorted(REQUIRED_DIRS):
        if not (root / d).exists():
            errors.append(f"missing_dir:{d}")

    for rel in sorted(REQUIRED_FILES):
        if not (root / rel).exists():
            errors.append(f"missing_file:{rel.as_posix()}")
    # Optional QA artifacts (may be skipped if SciPy is unavailable).
    if not (root / "qa" / "profile_v3_correlations.csv").exists():
        warnings.append("missing_optional_file:qa/profile_v3_correlations.csv")

    # Schema check: per-app CSV headers must match required set (order ignored; presence required).
    per_app_csv = root / "tables" / "per_app_dynamic_summary_v3.csv"
    if per_app_csv.exists():
        try:
            with per_app_csv.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames or []
                hs = {str(h).strip() for h in headers}
            missing = [c for c in REQUIRED_PER_APP_COLUMNS if c not in hs]
            if missing:
                errors.append(f"bad_schema:per_app_dynamic_summary_v3.csv:missing_cols:{','.join(missing)}")
            else:
                # Determinism + basic data hygiene checks.
                last_key = None
                row_idx = 0
                for row in reader:
                    row_idx += 1
                    cat = str(row.get("app_category") or "").strip()
                    pkg = str(row.get("package") or "").strip()
                    if cat and cat not in ALLOWED_CATEGORIES:
                        errors.append(f"bad_value:app_category:{cat}:{pkg}")
                    # Primary metric columns must not be NaN/inf or empty.
                    for col in ("mu_idle_rdi", "sigma_idle_rdi", "mu_interactive_rdi", "delta_rdi"):
                        raw = row.get(col)
                        if raw in (None, ""):
                            errors.append(f"missing_value:{col}:{pkg}")
                            continue
                        try:
                            v = float(str(raw))
                        except Exception:
                            errors.append(f"bad_value:{col}:{pkg}")
                            continue
                        if math.isnan(v) or math.isinf(v):
                            errors.append(f"bad_value:{col}:{pkg}")
                    # Sorted order: (app_category, package) must be non-decreasing.
                    cur_key = (cat, pkg)
                    if last_key is not None and cur_key < last_key:
                        errors.append(f"nondeterministic_order:row{row_idx}:{cur_key}<{last_key}")
                    last_key = cur_key
        except Exception as exc:  # noqa: BLE001
            errors.append(f"bad_schema:per_app_dynamic_summary_v3.csv:{type(exc).__name__}")

    return ProfileV3Lint(ok=(len(errors) == 0), errors=errors, warnings=warnings)


__all__ = ["ProfileV3Lint", "lint_profile_v3_bundle"]
