from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path("scripts/reporting/prune_generated_report_bundles.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("prune_generated_report_bundles", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[str(spec.name)] = module
    spec.loader.exec_module(module)
    return module


def _write_manifest(bundle: Path, *, selected_static_runs: int) -> None:
    (bundle / "manifest").mkdir(parents=True)
    (bundle / "manifest" / "report_manifest.json").write_text(
        f'{{"row_counts": {{"applications": {selected_static_runs}, "application_builds": {selected_static_runs}, "selected_static_runs": {selected_static_runs}}}}}',
        encoding="utf-8",
    )


def test_prune_generated_report_bundles_dry_run_finds_incomplete_and_zero_row(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    family = tmp_path / "output" / "reports" / "static_exposure_privacy"
    incomplete = family / "incomplete"
    zero = family / "zero"
    keep = family / "keep"
    (incomplete / "data").mkdir(parents=True)
    _write_manifest(zero, selected_static_runs=0)
    _write_manifest(keep, selected_static_runs=2)

    candidates = mod.collect_candidates(reports_root=tmp_path / "output" / "reports")

    assert [(Path(row.path).name, row.reason) for row in candidates] == [
        ("incomplete", "incomplete_missing_report_manifest"),
        ("zero", "zero_row_report"),
    ]
    assert incomplete.exists()
    assert zero.exists()
    assert keep.exists()


def test_prune_generated_report_bundles_apply_removes_only_candidates(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    family = tmp_path / "output" / "reports" / "static_exposure_privacy"
    incomplete = family / "incomplete"
    keep = family / "keep"
    (incomplete / "data").mkdir(parents=True)
    _write_manifest(keep, selected_static_runs=1)

    assert mod.main(["--reports-root", str(tmp_path / "output" / "reports"), "--apply", "--json"]) == 0

    assert not incomplete.exists()
    assert keep.exists()
    receipts = list((tmp_path / "output" / "audit" / "report_bundle_prune").glob("*.json"))
    assert len(receipts) == 1


def test_prune_generated_report_bundles_legacy_noise_is_opt_in(tmp_path: Path) -> None:
    mod = _load_module()
    mod.REPO_ROOT = tmp_path
    family = tmp_path / "output" / "reports" / "static_exposure_privacy"
    old = family / "20260710T000000Z"
    latest = family / "20260711T000000Z"
    _write_manifest(old, selected_static_runs=1)
    (old / "figures").mkdir()
    (old / "figures" / "permission_profile.pdf").write_text("pdf", encoding="utf-8")
    _write_manifest(latest, selected_static_runs=1)

    assert mod.collect_candidates(reports_root=tmp_path / "output" / "reports") == []
    candidates = mod.collect_candidates(
        reports_root=tmp_path / "output" / "reports",
        include_legacy_noise=True,
    )

    assert [(Path(row.path).name, row.reason) for row in candidates] == [
        ("20260710T000000Z", "legacy_generated_noise")
    ]
