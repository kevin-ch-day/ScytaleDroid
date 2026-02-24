from __future__ import annotations

from pathlib import Path

from scytaledroid.Publication.publication_contract import lint_publication_bundle


def _touch(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x", encoding="utf-8")


def test_publication_contract_lint_minimal_ok(tmp_path: Path) -> None:
    pub = tmp_path / "publication"
    pub.mkdir(parents=True, exist_ok=True)

    # Required dirs.
    for d in ("appendix", "figures", "manifests", "qa", "tables"):
        (pub / d).mkdir(parents=True, exist_ok=True)
    _touch(pub / "README.md")

    # Minimal required files.
    _touch(pub / "appendix" / "results_section_V.md")
    _touch(pub / "appendix" / "paper2_ieee_paste_blocks.md")
    _touch(pub / "figures" / "fig_b4_static_vs_rdi_social.pdf")
    _touch(pub / "figures" / "fig_b4_static_vs_rdi_messaging.pdf")
    _touch(pub / "figures" / "fig_b2_rdi_by_app.pdf")
    _touch(pub / "manifests" / "dataset_freeze.json")
    _touch(pub / "manifests" / "paper_results_v1.json")
    _touch(pub / "manifests" / "canonical_receipt.json")
    _touch(pub / "manifests" / "toolchain.txt")
    _touch(pub / "tables" / "paper_cohort_summary_v1.csv")
    _touch(pub / "tables" / "baseline_stability_summary.csv")
    _touch(pub / "tables" / "interaction_delta_summary.csv")
    _touch(pub / "tables" / "static_dynamic_correlation.csv")
    _touch(pub / "tables" / "appendix_table_a1_ocsvm_robustness.csv")

    lint = lint_publication_bundle(pub)
    assert lint.ok
    assert lint.errors == []


def test_publication_contract_lint_missing_fails(tmp_path: Path) -> None:
    pub = tmp_path / "publication"
    pub.mkdir(parents=True, exist_ok=True)
    lint = lint_publication_bundle(pub)
    assert not lint.ok
    assert any(e.startswith("missing_dir:") for e in lint.errors)
