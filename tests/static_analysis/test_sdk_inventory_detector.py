from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.core.findings import Badge
from scytaledroid.StaticAnalysis.detectors import sdks
from scytaledroid.StaticAnalysis.detectors.sdks import SdkInventoryDetector
from scytaledroid.StaticAnalysis.modules.string_analysis import IndexedString, StringIndex


def _write_receipt(tmp_path: Path, rows: list[dict[str, object]]) -> Path:
    path = tmp_path / "external_sdk_tracker_intel_refresh_20260615T010101Z.json"
    path.write_text(
        json.dumps(
            {
                "rows": rows,
                "summary": {
                    "snapshot_date": "2026-06-15",
                    "row_count": len(rows),
                    "rows_with_code_signature": sum(1 for row in rows if row.get("code_signature")),
                    "rows_with_network_signature": sum(
                        1 for row in rows if row.get("network_signature")
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def test_sdk_inventory_detector_reports_missing_receipt(monkeypatch) -> None:
    monkeypatch.setattr(sdks, "_latest_tracker_receipt_path", lambda: None)
    detector = SdkInventoryDetector()
    context = SimpleNamespace(
        string_index=StringIndex.empty(),
        libraries=(),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.INFO
    assert result.findings == ()
    assert result.metrics["External tracker intel"]["receipt_available"] is False
    normalization = result.metrics["Observed signals"]["domain_normalization"]
    assert normalization["resolver"] == "publicsuffixlist"
    assert any("No local tracker-intel receipt" in note for note in result.notes)


def test_sdk_inventory_detector_reports_namespace_overlap(monkeypatch, tmp_path: Path) -> None:
    receipt_path = _write_receipt(
        tmp_path,
        [
            {
                "tracker_name": "Example Tracker",
                "code_signature": "com.example.tracker.",
                "network_signature": None,
                "categories": ["Analytics"],
            }
        ],
    )
    monkeypatch.setattr(sdks, "_latest_tracker_receipt_path", lambda: receipt_path)
    detector = SdkInventoryDetector()
    context = SimpleNamespace(
        string_index=StringIndex(
            strings=(
                IndexedString(
                    value="com.example.tracker.sdk.Client",
                    origin="classes.dex",
                    origin_type="code",
                    byte_offset=10,
                ),
            )
        ),
        libraries=(),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.INFO
    assert "Example Tracker" in result.metrics["Matched trackers"]
    assert result.metrics["Overlap counts"]["code_signature_matches"] == 1
    assert {finding.finding_id for finding in result.findings} == {
        "sdk_inventory_tracker_namespace_overlap"
    }
    assert result.subitems
    assert result.subitems[0]["code_overlap"] == "com.example.tracker.sdk.client"


def test_sdk_inventory_detector_reports_network_overlap(monkeypatch, tmp_path: Path) -> None:
    receipt_path = _write_receipt(
        tmp_path,
        [
            {
                "tracker_name": "Telemetry Vendor",
                "code_signature": None,
                "network_signature": "events.sdkvendor.net",
                "categories": ["Advertisement"],
            }
        ],
    )
    monkeypatch.setattr(sdks, "_latest_tracker_receipt_path", lambda: receipt_path)
    detector = SdkInventoryDetector()
    context = SimpleNamespace(
        string_index=StringIndex(
            strings=(
                IndexedString(
                    value="https://cdn.sdkvendor.net/pixel?id=1",
                    origin="res/values/strings.xml",
                    origin_type="resource",
                    byte_offset=22,
                ),
            )
        ),
        libraries=(),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.INFO
    assert result.metrics["Overlap counts"]["network_signature_matches"] == 1
    assert {finding.finding_id for finding in result.findings} == {
        "sdk_inventory_tracker_network_overlap"
    }
    assert result.subitems
    assert result.subitems[0]["network_overlap"] == "sdkvendor.net"
    assert result.metrics["Top categories"] == [{"category": "Advertisement", "match_count": 1}]
    assert result.metrics["External tracker intel"]["source_row_count"] == 1
    assert result.metrics["External tracker intel"]["usable_tracker_rows"] == 1
    assert result.metrics["External tracker intel"]["unusable_tracker_rows"] == 0


def test_sdk_inventory_detector_keeps_private_suffix_tenants_distinct(
    monkeypatch,
    tmp_path: Path,
) -> None:
    receipt_path = _write_receipt(
        tmp_path,
        [
            {
                "tracker_name": "Other Tenant",
                "code_signature": None,
                "network_signature": "other.github.io",
                "categories": ["Analytics"],
            }
        ],
    )
    monkeypatch.setattr(sdks, "_latest_tracker_receipt_path", lambda: receipt_path)
    context = SimpleNamespace(
        string_index=StringIndex(
            strings=(
                IndexedString(
                    value="https://project.github.io/pixel",
                    origin="res/values/strings.xml",
                    origin_type="resource",
                ),
            )
        ),
        libraries=(),
    )

    result = SdkInventoryDetector().run(context)  # type: ignore[arg-type]

    assert result.status is Badge.OK
    assert result.metrics["Overlap counts"]["network_signature_matches"] == 0


def test_sdk_inventory_detector_reports_clean_when_receipt_present_but_no_overlap(
    monkeypatch,
    tmp_path: Path,
) -> None:
    receipt_path = _write_receipt(
        tmp_path,
        [
            {
                "tracker_name": "Example Tracker",
                "code_signature": "com.example.tracker.",
                "network_signature": "events.example.net",
                "categories": ["Analytics"],
            }
        ],
    )
    monkeypatch.setattr(sdks, "_latest_tracker_receipt_path", lambda: receipt_path)
    detector = SdkInventoryDetector()
    context = SimpleNamespace(
        string_index=StringIndex(
            strings=(
                IndexedString(
                    value="https://api.safe-app.test/v1",
                    origin="res/values/strings.xml",
                    origin_type="resource",
                ),
            )
        ),
        libraries=(),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.OK
    assert result.findings == ()
    assert result.metrics["Overlap counts"]["matched_tracker_rows"] == 0
