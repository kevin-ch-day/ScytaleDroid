"""Publication bundle contract.

This module defines what *must* exist under `output/publication/` for a
submission-grade publication bundle. Keeping this centralized prevents brittle
allowlists from drifting.

Bundle policy:
- `output/publication/` is manuscript-facing and must remain minimal.
- Figures are PNG-only (we do not ship PDFs in the publication bundle).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PublicationLint:
    ok: bool
    errors: list[str]
    warnings: list[str]


# Minimal, manuscript-facing required structure.
REQUIRED_DIRS = {
    "appendix",
    "figures",
    "manifests",
    "qa",
    "tables",
}

# Minimal required files for "publication bundle ready".
#
# Keep this list manuscript-facing: no internal baseline tables, no exploratory outputs.
REQUIRED_FILES = {
    # Manifests (reproducibility anchors).
    Path("manifests") / "dataset_freeze.json",
    Path("manifests") / "paper_results_v1.json",
    Path("manifests") / "canonical_receipt.json",
    Path("manifests") / "toolchain.txt",
    # Paste-ready text blocks.
    Path("appendix") / "results_section_V.md",
    Path("appendix") / "publication_paste_blocks.md",
    # Paper-facing tables (authoritative for writing Section V).
    Path("tables") / "paper_cohort_summary_v1.csv",
    Path("tables") / "baseline_stability_summary.csv",
    Path("tables") / "interaction_delta_summary.csv",
    Path("tables") / "static_dynamic_correlation.csv",
    Path("tables") / "static_feature_groups_v1.csv",
    Path("tables") / "stimulus_coverage_v1.csv",
    Path("tables") / "appendix_table_a1_ocsvm_robustness.csv",
    # LaTeX renderings for manuscript inclusion.
    Path("tables") / "table_dynamic_summary_v1.tex",
    Path("tables") / "table_static_components_v1.tex",
    Path("tables") / "table_appendix_a1_ocsvm_robustness_v1.tex",
    # Core paper figures (the manuscript must cite one of the Fig B2 variants).
    Path("figures") / "fig_b4_static_vs_rdi_social.png",
    Path("figures") / "fig_b4_static_vs_rdi_messaging.png",
}

# Figure contract: require at least one valid "Fig B2" representation.
REQUIRED_ONE_OF: list[set[Path]] = [
    {Path("figures") / "fig_b2_rdi_social_by_app.png", Path("figures") / "fig_b2_rdi_messaging_by_app.png"},
]

# Extra artifacts that are strongly recommended but not strictly required to declare READY.
SHOULD_HAVE_FILES = {
    Path("qa") / "qa_stats_validation.json",
    Path("qa") / "qa_threshold_validation.csv",
    Path("qa") / "qa_distribution_summary.csv",
    Path("qa") / "pipeline_audit_v1.json",
    Path("qa") / "qa_interactive_consistency.csv",
    # Optional depth artifacts (derived only).
    Path("tables") / "delta_distribution_summary.csv",
    Path("tables") / "table_delta_distribution_summary_v1.tex",
    Path("tables") / "table_cohort_variance_summary_v1.tex",
    Path("tables") / "table_effect_size_summary_v1.tex",
    Path("tables") / "table_interaction_consistency_v1.tex",
    Path("tables") / "phase_dispersion_stats_summary.csv",
    Path("tables") / "table_phase_dispersion_stats_v1.tex",
}

# Hard-banned top-level directories inside the canonical publication bundle.
# These belong in output/_internal or output/experimental.
NOT_ALLOWED_TOP_DIRS = {
    "internal",
    "explore",
    "experimental",
    "_internal",
    "review",
}

# Hard-banned file suffixes inside the canonical publication bundle.
# This keeps the submission surface small and avoids toolchain drift issues.
HARD_BANNED_SUFFIXES = {".pdf"}


def _cohort_enforcement_v2(pub_root: Path) -> list[str]:
    """Fail-closed cohort enforcement for Profile v2 (Paper #2) publication bundle.

    Contract:
    - `manifests/dataset_freeze.json` is the source of truth for the v2 cohort packages.
    - The publication results manifest must describe exactly the same package set.

    This prevents accidental "scope drift" (e.g., exporting results for >12 apps or mixing cohorts).
    """

    errs: list[str] = []
    freeze_path = pub_root / "manifests" / "dataset_freeze.json"
    results_path = pub_root / "manifests" / "paper_results_v1.json"

    try:
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"invalid_json:manifests/dataset_freeze.json:{type(exc).__name__}"]
    try:
        results = json.loads(results_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"invalid_json:manifests/paper_results_v1.json:{type(exc).__name__}"]

    apps = freeze.get("apps")
    if not isinstance(apps, dict) or not apps:
        return ["cohort_invalid_freeze_schema:missing_apps_dict"]
    freeze_pkgs = {str(k).strip().lower() for k in apps.keys() if str(k).strip()}
    if len(freeze_pkgs) != len(apps):
        errs.append("cohort_invalid_freeze_schema:empty_or_duplicate_package_keys")

    # v2 frozen cohort is locked to 12 apps. Keep this explicit and fail-closed.
    if len(freeze_pkgs) != 12:
        errs.append(f"cohort_expected_n_packages_v2:12:got:{len(freeze_pkgs)}")

    per_app = results.get("per_app")
    if not isinstance(per_app, list) or not per_app:
        errs.append("cohort_invalid_results_schema:missing_per_app_list")
        return errs
    results_pkgs = set()
    for item in per_app:
        if not isinstance(item, dict):
            continue
        pkg = str(item.get("package_name") or "").strip().lower()
        if pkg:
            results_pkgs.add(pkg)
    if len(results_pkgs) != len(per_app):
        errs.append("cohort_invalid_results_schema:per_app_package_name_missing_or_duplicate")

    n_apps = results.get("n_apps")
    if n_apps is not None:
        try:
            n = int(n_apps)
        except Exception:
            n = None
        if n is None:
            errs.append("cohort_invalid_results_schema:n_apps_not_int")
        elif n != 12:
            errs.append(f"cohort_expected_n_apps_v2:12:got:{n}")

    missing = sorted(freeze_pkgs - results_pkgs)
    extra = sorted(results_pkgs - freeze_pkgs)
    if missing or extra:
        # Keep the error short but actionable: show a bounded list.
        miss_s = ",".join(missing[:5])
        extra_s = ",".join(extra[:5])
        errs.append(
            "cohort_package_mismatch_v2:"
            + f"missing={len(missing)}({miss_s})"
            + f":extra={len(extra)}({extra_s})"
        )

    return errs


def lint_publication_bundle(pub_root: Path) -> PublicationLint:
    errors: list[str] = []
    warnings: list[str] = []

    if not pub_root.exists():
        return PublicationLint(ok=False, errors=[f"missing_root:{pub_root}"], warnings=[])

    # Top-level dirs must be present.
    for d in sorted(REQUIRED_DIRS):
        if not (pub_root / d).exists():
            errors.append(f"missing_dir:{d}")

    # Required files must be present.
    for rel in sorted(REQUIRED_FILES):
        if not (pub_root / rel).exists():
            errors.append(f"missing_file:{rel.as_posix()}")

    # At least one B2 variant must exist.
    if REQUIRED_ONE_OF:
        ok_any = False
        for group in REQUIRED_ONE_OF:
            if all((pub_root / rel).exists() for rel in group):
                ok_any = True
                break
        if not ok_any:
            groups = ["+".join(p.as_posix() for p in sorted(g)) for g in REQUIRED_ONE_OF]
            errors.append(f"missing_required_one_of:fig_b2_variants:{'|'.join(groups)}")

    for rel in sorted(SHOULD_HAVE_FILES):
        if not (pub_root / rel).exists():
            warnings.append(f"missing_recommended:{rel.as_posix()}")

    # Unexpected top-level directories add noise and often indicate accidental mixing of layers.
    #
    # `profile_v3/` is an additive publication surface for a distinct profile and must not
    # affect v2 bundle readiness checks.
    allowed_top = set(REQUIRED_DIRS) | {"README.md", "profile_v3"}
    for p in sorted(pub_root.iterdir()):
        if p.name in allowed_top:
            continue
        if p.is_dir() and p.name in NOT_ALLOWED_TOP_DIRS:
            errors.append(f"not_allowed_dir:{p.name}")
            continue
        # Keep the top-level strict: extra files/dirs rot quickly and confuse submissions.
        if p.is_dir():
            errors.append(f"unexpected_dir:{p.name}")
        else:
            errors.append(f"unexpected_file:{p.name}")

    # Enforce "PNG-only" policy in publication/ to prevent bundle bloat.
    for p in sorted(pub_root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() in HARD_BANNED_SUFFIXES:
            errors.append(f"banned_suffix:{p.relative_to(pub_root).as_posix()}")

    # Cohort enforcement is a correctness guardrail for the submission-facing v2 bundle.
    # It should never "expand" beyond the frozen cohort.
    if (pub_root / "manifests" / "dataset_freeze.json").exists() and (pub_root / "manifests" / "paper_results_v1.json").exists():
        errors.extend(_cohort_enforcement_v2(pub_root))

    return PublicationLint(ok=(len(errors) == 0), errors=errors, warnings=warnings)


__all__ = [
    "PublicationLint",
    "REQUIRED_DIRS",
    "REQUIRED_FILES",
    "REQUIRED_ONE_OF",
    "SHOULD_HAVE_FILES",
    "NOT_ALLOWED_TOP_DIRS",
    "HARD_BANNED_SUFFIXES",
    "lint_publication_bundle",
]
