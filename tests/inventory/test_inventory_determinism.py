from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DeviceAnalysis.inventory.determinism import (
    build_snapshot_payload,
    compare_inventory_payloads,
)


_FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "determinism"


def _fixture(name: str) -> dict[str, object]:
    return json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def test_inventory_comparator_passes_with_reordered_rows():
    left = _fixture("inventory_left.json")
    right = _fixture("inventory_right_same_reordered.json")
    left_payload = build_snapshot_payload(snapshot=left["snapshot"], rows=left["rows"])
    right_payload = build_snapshot_payload(snapshot=right["snapshot"], rows=right["rows"])
    result = compare_inventory_payloads(
        left_payload=left_payload,
        right_payload=right_payload,
        left_meta={"run_id": 1, "source": "fixture", "timestamp_utc": "2026-01-01T00:00:00Z"},
        right_meta={"run_id": 2, "source": "fixture", "timestamp_utc": "2026-01-01T00:01:00Z"},
        tool_semver="2.0.1",
        git_commit="abc123",
    )
    assert result.passed is True
    assert result.payload["result"]["pass"] is True
    assert result.payload["result"]["diff_counts"]["disallowed"] == 0


def test_inventory_comparator_fails_on_secondary_integrity_change():
    left = _fixture("inventory_left.json")
    right = _fixture("inventory_right_signer_changed.json")
    left_payload = build_snapshot_payload(snapshot=left["snapshot"], rows=left["rows"])
    right_payload = build_snapshot_payload(snapshot=right["snapshot"], rows=right["rows"])
    result = compare_inventory_payloads(
        left_payload=left_payload,
        right_payload=right_payload,
        left_meta={"run_id": 1, "source": "fixture", "timestamp_utc": "2026-01-01T00:00:00Z"},
        right_meta={"run_id": 2, "source": "fixture", "timestamp_utc": "2026-01-01T00:01:00Z"},
        tool_semver="2.0.1",
        git_commit="abc123",
    )
    assert result.passed is False
    assert result.payload["result"]["pass"] is False
    assert result.payload["result"]["diff_counts"]["disallowed"] >= 1


def test_inventory_comparator_fails_when_required_row_key_missing():
    left = _fixture("inventory_left.json")
    right = _fixture("inventory_right_same_reordered.json")
    rows = left["rows"]
    rows[0]["version_code"] = ""
    left_payload = build_snapshot_payload(snapshot=left["snapshot"], rows=rows)
    right_payload = build_snapshot_payload(snapshot=right["snapshot"], rows=right["rows"])
    result = compare_inventory_payloads(
        left_payload=left_payload,
        right_payload=right_payload,
        left_meta={"run_id": 1, "source": "fixture", "timestamp_utc": "2026-01-01T00:00:00Z"},
        right_meta={"run_id": 2, "source": "fixture", "timestamp_utc": "2026-01-01T00:01:00Z"},
        tool_semver="2.0.1",
        git_commit="abc123",
    )
    assert result.passed is False
    assert result.payload["result"]["fail_reason"] == "validation_error"
    assert "left.missing_row_keys" in result.payload["result"]["validation_issues"]
