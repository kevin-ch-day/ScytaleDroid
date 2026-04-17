from __future__ import annotations

from pathlib import Path

import pytest

from scytaledroid.Publication.publication_contract import lint_publication_bundle


pytestmark = [pytest.mark.contract, pytest.mark.report_contract]


def _touch(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x", encoding="utf-8")

def _write_json(p: Path, payload: object) -> None:
    import json

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_publication_contract_lint_minimal_ok(tmp_path: Path) -> None:
    pub = tmp_path / "publication"
    pub.mkdir(parents=True, exist_ok=True)

    # Required dirs.
    for d in ("appendix", "figures", "manifests", "qa", "tables"):
        (pub / d).mkdir(parents=True, exist_ok=True)
    _touch(pub / "README.md")

    # Minimal required files.
    _touch(pub / "appendix" / "results_section_V.md")
    _touch(pub / "appendix" / "publication_paste_blocks.md")
    _touch(pub / "figures" / "fig_b4_static_vs_rdi_social.png")
    _touch(pub / "figures" / "fig_b4_static_vs_rdi_messaging.png")
    _touch(pub / "figures" / "fig_b2_rdi_social_by_app.png")
    _touch(pub / "figures" / "fig_b2_rdi_messaging_by_app.png")

    # Cohort enforcement requires parseable manifests.
    pkgs = [f"com.example.pkg{i}" for i in range(12)]
    _write_json(pub / "manifests" / "dataset_freeze.json", {"apps": {p: {} for p in pkgs}})
    _write_json(pub / "manifests" / "paper_results_v1.json", {"n_apps": 12, "per_app": [{"package_name": p} for p in pkgs]})
    _touch(pub / "manifests" / "canonical_receipt.json")
    _touch(pub / "manifests" / "toolchain.txt")
    _touch(pub / "tables" / "paper_cohort_summary_v1.csv")
    _touch(pub / "tables" / "baseline_stability_summary.csv")
    _touch(pub / "tables" / "interaction_delta_summary.csv")
    _touch(pub / "tables" / "static_dynamic_correlation.csv")
    _touch(pub / "tables" / "static_feature_groups_v1.csv")
    _touch(pub / "tables" / "stimulus_coverage_v1.csv")
    _touch(pub / "tables" / "appendix_table_a1_ocsvm_robustness.csv")
    _touch(pub / "tables" / "table_dynamic_summary_v1.tex")
    _touch(pub / "tables" / "table_static_components_v1.tex")
    _touch(pub / "tables" / "table_appendix_a1_ocsvm_robustness_v1.tex")

    lint = lint_publication_bundle(pub)
    assert lint.ok
    assert lint.errors == []


def test_publication_contract_lint_cohort_mismatch_fails(tmp_path: Path) -> None:
    pub = tmp_path / "publication"
    pub.mkdir(parents=True, exist_ok=True)

    # Required dirs.
    for d in ("appendix", "figures", "manifests", "qa", "tables"):
        (pub / d).mkdir(parents=True, exist_ok=True)
    _touch(pub / "README.md")

    # Minimal required files.
    _touch(pub / "appendix" / "results_section_V.md")
    _touch(pub / "appendix" / "publication_paste_blocks.md")
    _touch(pub / "figures" / "fig_b4_static_vs_rdi_social.png")
    _touch(pub / "figures" / "fig_b4_static_vs_rdi_messaging.png")
    _touch(pub / "figures" / "fig_b2_rdi_social_by_app.png")
    _touch(pub / "figures" / "fig_b2_rdi_messaging_by_app.png")
    _touch(pub / "manifests" / "canonical_receipt.json")
    _touch(pub / "manifests" / "toolchain.txt")
    _touch(pub / "tables" / "paper_cohort_summary_v1.csv")
    _touch(pub / "tables" / "baseline_stability_summary.csv")
    _touch(pub / "tables" / "interaction_delta_summary.csv")
    _touch(pub / "tables" / "static_dynamic_correlation.csv")
    _touch(pub / "tables" / "static_feature_groups_v1.csv")
    _touch(pub / "tables" / "stimulus_coverage_v1.csv")
    _touch(pub / "tables" / "appendix_table_a1_ocsvm_robustness.csv")
    _touch(pub / "tables" / "table_dynamic_summary_v1.tex")
    _touch(pub / "tables" / "table_static_components_v1.tex")
    _touch(pub / "tables" / "table_appendix_a1_ocsvm_robustness_v1.tex")

    pkgs = [f"com.example.pkg{i}" for i in range(12)]
    freeze_pkgs = pkgs[:]
    results_pkgs = pkgs[:]
    results_pkgs[-1] = "com.example.other"  # mismatch
    _write_json(pub / "manifests" / "dataset_freeze.json", {"apps": {p: {} for p in freeze_pkgs}})
    _write_json(pub / "manifests" / "paper_results_v1.json", {"n_apps": 12, "per_app": [{"package_name": p} for p in results_pkgs]})

    lint = lint_publication_bundle(pub)
    assert not lint.ok
    assert any(e.startswith("cohort_package_mismatch_v2:") for e in lint.errors)


def test_publication_contract_lint_missing_fails(tmp_path: Path) -> None:
    pub = tmp_path / "publication"
    pub.mkdir(parents=True, exist_ok=True)
    lint = lint_publication_bundle(pub)
    assert not lint.ok
    assert any(e.startswith("missing_dir:") for e in lint.errors)
