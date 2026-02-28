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


REQUIRED_DIRS = {"tables", "manifests", "qa", "figures"}

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
    if not (root / "figures" / "fig_v3_stability_sensitivity_plane.png").exists():
        warnings.append("missing_optional_file:figures/fig_v3_stability_sensitivity_plane.png")

    import os

    strict = str(os.environ.get("SCYTALEDROID_PAPER_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}
    if strict:
        # In strict paper/demo mode, missing stats outputs should block READY.
        cat_tests = root / "qa" / "profile_v3_category_tests.json"
        if not cat_tests.exists():
            errors.append("strict_missing_file:qa/profile_v3_category_tests.json")
        else:
            try:
                import json

                payload = json.loads(cat_tests.read_text(encoding="utf-8"))
                if payload.get("stats_available") is not True:
                    reason = str(payload.get("reason") or "stats_unavailable").strip() or "stats_unavailable"
                    errors.append(f"strict_stats_unavailable:{reason}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"strict_invalid_json:qa/profile_v3_category_tests.json:{type(exc).__name__}")
        if not (root / "qa" / "profile_v3_correlations.csv").exists():
            errors.append("strict_missing_file:qa/profile_v3_correlations.csv")
        if not (root / "figures" / "fig_v3_stability_sensitivity_plane.png").exists():
            errors.append("strict_missing_file:figures/fig_v3_stability_sensitivity_plane.png")

    # Schema check: per-app CSV headers must match required set (order ignored; presence required).
    per_app_csv = root / "tables" / "per_app_dynamic_summary_v3.csv"
    if per_app_csv.exists():
        try:
            rows: list[dict[str, str]] = []
            with per_app_csv.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames or []
                hs = {str(h).strip() for h in headers}
                missing = [c for c in REQUIRED_PER_APP_COLUMNS if c not in hs]
                if missing:
                    errors.append(f"bad_schema:per_app_dynamic_summary_v3.csv:missing_cols:{','.join(missing)}")
                else:
                    rows = [dict(r) for r in reader]

            if rows:
                # Determinism + basic data hygiene checks.
                last_key = None
                row_idx = 0
                seen_pkgs: set[str] = set()
                for row in rows:
                    row_idx += 1
                    cat = str(row.get("app_category") or "").strip()
                    pkg = str(row.get("package") or "").strip()
                    if pkg:
                        seen_pkgs.add(pkg)
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

                # Cohort enforcement (paper-safety): if manifest includes catalog packages, enforce exact match.
                manifest_path = root / "manifests" / "profile_v3_manifest.json"
                if manifest_path.exists():
                    try:
                        import json

                        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                        inputs = payload.get("inputs") if isinstance(payload, dict) else {}
                        catalog_pkgs = inputs.get("catalog_packages") if isinstance(inputs, dict) else None
                        if isinstance(catalog_pkgs, list) and catalog_pkgs:
                            expected = {str(x).strip() for x in catalog_pkgs if str(x).strip()}
                            if expected:
                                if len(rows) != len(expected):
                                    errors.append(f"bad_cohort:row_count:{len(rows)}!=expected:{len(expected)}")
                                extra = sorted(seen_pkgs - expected)
                                missing_pkgs = sorted(expected - seen_pkgs)
                                if extra:
                                    errors.append(f"bad_cohort:unexpected_packages:{','.join(extra)}")
                                if missing_pkgs:
                                    errors.append(f"bad_cohort:missing_packages:{','.join(missing_pkgs)}")
                    except Exception as exc:  # noqa: BLE001
                        warnings.append(f"cohort_check_unavailable:{type(exc).__name__}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"bad_schema:per_app_dynamic_summary_v3.csv:{type(exc).__name__}")

    return ProfileV3Lint(ok=(len(errors) == 0), errors=errors, warnings=warnings)


__all__ = ["ProfileV3Lint", "lint_profile_v3_bundle"]
