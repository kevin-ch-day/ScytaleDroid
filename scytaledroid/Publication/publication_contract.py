"""Publication bundle contract (Paper #2).

This module defines what *must* exist under `output/publication/` for a submission-grade
paper bundle. Keeping this centralized prevents brittle allowlists from drifting.
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

# Minimal required files for "paper bundle ready" (PM-locked, ICECCO Paper #2).
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
    Path("appendix") / "paper2_ieee_paste_blocks.md",
    # Paper-facing tables (authoritative for writing Section V).
    Path("tables") / "paper_cohort_summary_v1.csv",
    Path("tables") / "baseline_stability_summary.csv",
    Path("tables") / "interaction_delta_summary.csv",
    Path("tables") / "static_dynamic_correlation.csv",
    Path("tables") / "appendix_table_a1_ocsvm_robustness.csv",
    # Core paper figures (the manuscript must cite one of the Fig B2 variants).
    Path("figures") / "fig_b4_static_vs_rdi_social.pdf",
    Path("figures") / "fig_b4_static_vs_rdi_messaging.pdf",
}

# Figure contract: require at least one valid "Fig B2" representation.
REQUIRED_ONE_OF: list[set[Path]] = [
    {Path("figures") / "fig_b2_rdi_by_app.pdf"},
    {Path("figures") / "fig_b2_rdi_social_by_app.pdf", Path("figures") / "fig_b2_rdi_messaging_by_app.pdf"},
]

# Extra artifacts that are strongly recommended but not strictly required to declare READY.
SHOULD_HAVE_FILES = {
    Path("qa") / "qa_stats_validation.json",
    Path("qa") / "qa_threshold_validation.csv",
    Path("qa") / "qa_distribution_summary.csv",
    Path("qa") / "paper2_pipeline_audit_v1.json",
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
    allowed_top = set(REQUIRED_DIRS) | {"README.md"}
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

    return PublicationLint(ok=(len(errors) == 0), errors=errors, warnings=warnings)


__all__ = [
    "PublicationLint",
    "REQUIRED_DIRS",
    "REQUIRED_FILES",
    "REQUIRED_ONE_OF",
    "SHOULD_HAVE_FILES",
    "NOT_ALLOWED_TOP_DIRS",
    "lint_publication_bundle",
]
