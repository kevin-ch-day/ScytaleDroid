from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.static_analysis import report_resource_parse_warnings as subject


def _write_report(path: Path, *, warning: bool) -> None:
    metadata: dict[str, object] = {
        "app_label": "Google Play Store",
        "package_name": "com.android.vending",
        "version_code": "123",
        "version_name": "1.2.3",
        "artifact": "base",
        "canonical_store_path": "data/store/apk/sha256/aa/aa" + "0" * 62 + ".apk",
        "sha256": "aa" + "0" * 62,
        "string_index_resource_strings": 0 if warning else 10,
        "string_index_total_strings": 5 if warning else 15,
        "parser_provenance": {
            "resource_bounds_warning_count": 1 if warning else 0,
            "resource_bounds_warning_severity": "warn" if warning else "none",
            "resource_bounds_warning_kind": "complex_entry" if warning else "none",
            "resource_parse_state": "partial" if warning else "ok",
            "resource_parse_partial": warning,
            "resource_reparse_candidate": warning,
            "resource_fallback_used": False,
        },
    }
    if warning:
        metadata["resource_bounds_warnings"] = [
            "We are out of bound with this complex entry. Count: 2390688778"
        ]
    path.write_text(
        json.dumps(
            {
                "file_name": "base.apk",
                "hashes": {"sha256": "aa" + "0" * 62},
                "metadata": metadata,
            }
        ),
        encoding="utf-8",
    )


def test_build_report_summarizes_partial_resource_parse(tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    _write_report(archive / "warn.json", warning=True)
    _write_report(archive / "clean.json", warning=False)

    report = subject.build_report(archive, session="unit")

    assert report["summary"]["reports_scanned"] == 2
    assert report["summary"]["resource_warning_artifacts"] == 1
    assert report["summary"]["resource_parse_partial_artifacts"] == 1
    assert report["summary"]["resource_reparse_candidate_artifacts"] == 1
    assert report["summary"]["packages_with_resource_warnings"] == 1
    row = report["rows"][0]
    assert row["package_name"] == "com.android.vending"
    assert row["app_label"] == "Google Play Store"
    assert row["count_values"] == "2390688778"


def test_script_help_is_side_effect_free() -> None:
    repo = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "static_analysis" / "report_resource_parse_warnings.py"), "--help"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=8,
    )

    assert proc.returncode == 0
    assert proc.stdout.lower().startswith("usage:")
