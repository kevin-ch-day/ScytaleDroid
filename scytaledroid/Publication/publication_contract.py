"""Publication bundle contract.

This module defines what *must* exist under `output/publication/` for a submission-grade
paper bundle. Keeping this centralized prevents brittle allowlists from drifting.

Bundle policy:
- `output/publication/` is paper-facing and must remain minimal.
- Figures are PNG-only (we do not ship PDFs in the publication bundle).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PublicationLint:
    ok: bool
    errors: list[str]
    warnings: list[str]


# Minimal, paper-facing required structure.
REQUIRED_DIRS = {
    "appendix",
    "figures",
    "manifests",
    "qa",
    "tables",
}

# Minimal required files for "publication bundle ready".
#
# Keep this list paper-facing: no internal baseline tables, no exploratory outputs.
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
