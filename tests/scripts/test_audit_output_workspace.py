from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path("scripts/reporting/audit_output_workspace.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_output_workspace", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[str(spec.name)] = module
    spec.loader.exec_module(module)
    return module


def test_output_workspace_classifier_marks_known_roots(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    output = tmp_path / "output"
    (output / "reports" / "static_exposure_privacy" / "run-1").mkdir(parents=True)
    (output / "reports" / "static_exposure_privacy" / "run-1" / "summary.json").write_text("{}", encoding="utf-8")
    (output / "paper" / "dynamic_paper_cutoff_final_test").mkdir(parents=True)
    (output / "audit" / "repair").mkdir(parents=True)
    (output / "tmp").mkdir(parents=True)

    payload = mod.inspect_output_workspace(output)
    by_path = {Path(row["path"]).name: row for row in payload["entries"]}

    assert by_path["reports"]["cleanup_class"] == "generated_report_bundles"
    assert by_path["reports"]["recommendation"] == "safe_to_prune_after_review"
    assert by_path["paper"]["cleanup_class"] == "legacy_publication_workspace"
    assert by_path["paper"]["recommendation"] == "review_before_delete"
    assert by_path["audit"]["cleanup_class"] == "audit_receipts"
    assert by_path["audit"]["recommendation"] == "age_gate_and_review"
    assert by_path["tmp"]["cleanup_class"] == "empty_output_placeholder"
    assert by_path["tmp"]["recommendation"] == "safe_to_remove_empty_dir"


def test_output_workspace_audit_marks_empty_quarantine_removable(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    output = tmp_path / "output"
    (output / "quarantine").mkdir(parents=True)

    payload = mod.inspect_output_workspace(output)
    quarantine = payload["entries"][0]

    assert quarantine["path"] == "output/quarantine"
    assert quarantine["cleanup_class"] == "empty_output_placeholder"
    assert quarantine["recommendation"] == "safe_to_remove_empty_dir"


def test_output_workspace_audit_counts_broken_dynamic_evidence_symlink(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    legacy_dynamic = tmp_path / "output" / "evidence" / "dynamic"
    legacy_dynamic.mkdir(parents=True)
    target = tmp_path / "data" / "evidence" / "dynamic" / "run-good"
    target.mkdir(parents=True)
    (legacy_dynamic / "run-good").symlink_to(target, target_is_directory=True)
    (legacy_dynamic / "run-broken").symlink_to(tmp_path / "missing", target_is_directory=True)

    payload = mod.inspect_output_workspace(tmp_path / "output")
    evidence = next(row for row in payload["entries"] if Path(row["path"]).name == "evidence")

    assert evidence["cleanup_class"] == "compatibility_evidence_links"
    assert evidence["recommendation"] == "keep_or_recreate_only"
    assert evidence["symlink_count"] == 2
    assert evidence["broken_symlink_count"] == 1
    assert payload["summary"]["broken_symlink_count"] == 1


def test_output_workspace_cli_json_is_read_only(tmp_path: Path, capsys) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    output = tmp_path / "output"
    (output / "reports").mkdir(parents=True)

    assert mod.main(["--output-root", str(output), "--json"]) == 0

    out = capsys.readouterr().out
    assert '"generated_report_bundles"' in out
    assert sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")) == [
        "output",
        "output/reports",
    ]


def test_output_workspace_audit_flags_legacy_static_report_noise(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    family = tmp_path / "output" / "reports" / "static_exposure_privacy"
    old_bundle = family / "old"
    new_bundle = family / "new"
    (old_bundle / "figures").mkdir(parents=True)
    (old_bundle / "latex").mkdir()
    (old_bundle / "report").mkdir()
    (old_bundle / "figures" / "permission_profile.pdf").write_text("pdf", encoding="utf-8")
    (old_bundle / "figures" / "permission_profile.svg").write_text("svg", encoding="utf-8")
    (old_bundle / "figures" / "permission_profile_caption.txt").write_text("caption", encoding="utf-8")
    (old_bundle / "latex" / "figure_inputs.tex").write_text("% fig", encoding="utf-8")
    (old_bundle / "report" / "layout_fit_report.txt").write_text("layout", encoding="utf-8")
    (new_bundle / "figures").mkdir(parents=True)
    (new_bundle / "figures" / "permission_profile.png").write_text("png", encoding="utf-8")

    payload = mod.inspect_output_workspace(tmp_path / "output")
    family_summary = payload["report_families"][0]

    assert family_summary["family"] == "static_exposure_privacy"
    assert family_summary["bundle_count"] == 2
    assert family_summary["incomplete_bundle_count"] == 2
    assert sorted(Path(path).name for path in family_summary["incomplete_bundle_paths"]) == ["new", "old"]
    assert family_summary["zero_row_bundle_count"] == 0
    assert family_summary["latest_bundle_complete"] is False
    assert family_summary["legacy_noise_file_count"] == 5
    assert family_summary["bundles_with_legacy_noise"] == 1
    assert [Path(path).name for path in family_summary["bundles_with_legacy_noise_paths"]] == ["old"]
    assert family_summary["latest_bundle_legacy_noise_file_count"] == 0
    assert family_summary["recommendation"] == "latest_bundle_incomplete_review_before_pruning"


def test_output_workspace_audit_distinguishes_complete_latest_report(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    family = tmp_path / "output" / "reports" / "static_exposure_privacy"
    old_bundle = family / "old"
    new_bundle = family / "new"
    (old_bundle / "manifest").mkdir(parents=True)
    (old_bundle / "figures").mkdir()
    (old_bundle / "figures" / "permission_profile.pdf").write_text("pdf", encoding="utf-8")
    (new_bundle / "manifest").mkdir(parents=True)
    (new_bundle / "manifest" / "report_manifest.json").write_text("{}", encoding="utf-8")

    payload = mod.inspect_output_workspace(tmp_path / "output")
    family_summary = payload["report_families"][0]

    assert family_summary["bundle_count"] == 2
    assert family_summary["incomplete_bundle_count"] == 1
    assert [Path(path).name for path in family_summary["incomplete_bundle_paths"]] == ["old"]
    assert family_summary["zero_row_bundle_count"] == 0
    assert family_summary["latest_bundle_complete"] is True
    assert family_summary["latest_bundle_legacy_noise_file_count"] == 0
    assert family_summary["recommendation"] == "latest_bundle_matches_cleaner_defaults_or_has_no_detected_legacy_noise"


def test_output_workspace_audit_flags_zero_row_report_bundle(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    bundle = tmp_path / "output" / "reports" / "static_exposure_privacy" / "zero"
    (bundle / "manifest").mkdir(parents=True)
    (bundle / "manifest" / "report_manifest.json").write_text(
        '{"row_counts": {"applications": 0, "application_builds": 0, "selected_static_runs": 0}}',
        encoding="utf-8",
    )

    payload = mod.inspect_output_workspace(tmp_path / "output")
    family_summary = payload["report_families"][0]

    assert family_summary["zero_row_bundle_count"] == 1
    assert [Path(path).name for path in family_summary["zero_row_bundle_paths"]] == ["zero"]
    assert family_summary["latest_bundle_zero_row"] is True
    assert family_summary["recommendation"] == "latest_bundle_zero_row_review_before_pruning"


def test_output_workspace_audit_summarizes_largest_audit_families(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    small = tmp_path / "output" / "audit" / "small_audit"
    large = tmp_path / "output" / "audit" / "large_audit"
    small.mkdir(parents=True)
    large.mkdir(parents=True)
    (small / "summary.json").write_text("{}", encoding="utf-8")
    (large / "rows.csv").write_bytes(b"x" * (1024 * 1024 + 1))

    payload = mod.inspect_output_workspace(tmp_path / "output")
    families = payload["audit_families"]

    assert [row["family"] for row in families] == ["large_audit", "small_audit"]
    assert families[0]["recommendation"] == "review_large_audit_family"
    assert families[1]["recommendation"] == "retain_or_age_gate"
