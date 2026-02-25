from __future__ import annotations

import json
import shutil
from pathlib import Path

from scytaledroid.Utils.System.export_manifest import (
    compare_manifest,
    load_manifest,
)

_FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "publication"
_BUNDLE_ROOT = _FIXTURE_ROOT / "publication_bundle"
_MANIFEST_PATH = _FIXTURE_ROOT / "publication_export_manifest.json"


def _load_fixture_manifest() -> dict[str, object]:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def test_export_manifest_comparator_passes_for_matching_bundle():
    baseline = _load_fixture_manifest()
    result = compare_manifest(baseline_manifest=baseline, artifact_root=_BUNDLE_ROOT)
    assert result.passed is True
    assert result.payload["result"]["diff_counts"]["disallowed"] == 0


def test_export_manifest_comparator_ignores_tex_whitespace(tmp_path: Path):
    baseline = load_manifest(_MANIFEST_PATH)
    work_root = tmp_path / "bundle"
    shutil.copytree(_BUNDLE_ROOT, work_root)

    tex_path = work_root / "tables" / "table_4_signature_deltas.tex"
    tex_path.write_text(
        "%    Table 4 fixture\n"
        "\\begin{tabular}{ll}\n"
        "App      & Delta   \\\\\n"
        "Alpha App\t&\t1.00   \\\\\n"
        "\\end{tabular}\n",
        encoding="utf-8",
    )

    result = compare_manifest(baseline_manifest=baseline, artifact_root=work_root)
    assert result.passed is True
    assert result.payload["result"]["diff_counts"]["disallowed"] == 0


def test_export_manifest_comparator_fails_on_csv_drift(tmp_path: Path):
    baseline = load_manifest(_MANIFEST_PATH)
    work_root = tmp_path / "bundle"
    shutil.copytree(_BUNDLE_ROOT, work_root)

    csv_path = work_root / "tables" / "table_7_exposure_deviation_summary.csv"
    csv_path.write_text(
        "app,package_name,rdi_if_interactive\nAlpha App,com.example.alpha,0.777\n",
        encoding="utf-8",
    )

    result = compare_manifest(baseline_manifest=baseline, artifact_root=work_root)
    assert result.passed is False
    assert result.payload["result"]["diff_counts"]["disallowed"] >= 1
    fields = {str(item.get("field")) for item in result.payload.get("diffs", [])}
    assert "sha256" in fields
