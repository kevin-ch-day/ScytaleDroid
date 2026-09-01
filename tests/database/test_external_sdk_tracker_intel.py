from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scytaledroid.Database.db_utils.external_sdk_tracker_intel import (
    EXODUS_SOURCE_KEY,
    EXODUS_TRACKERS_URL,
    build_refresh_summary,
    ensure_external_tracker_intel_schema,
    load_verified_refresh_receipt,
    normalize_exodus_trackers,
    tracker_rows_content_sha256,
    upsert_external_tracker_rows,
    write_refresh_receipt_bundle,
)


def test_normalize_exodus_trackers_maps_expected_fields() -> None:
    payload = {
        "trackers": {
            "10": {
                "id": 10,
                "name": "Example Tracker",
                "code_signature": "com.example.tracker.",
                "network_signature": "example\\\\.tracker\\\\.com",
                "website": "https://example.test",
                "description": "tracking SDK",
                "categories": ["Analytics", "Ads", "Analytics"],
                "documentation": ["https://docs.example.test", ""],
                "creation_date": "2024-01-15",
            }
        }
    }
    rows = normalize_exodus_trackers(
        payload,
        fetched_at_utc=datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC),
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["intel_source"] == EXODUS_SOURCE_KEY
    assert row["tracker_id_external"] == "10"
    assert row["tracker_name"] == "Example Tracker"
    assert row["code_signature"] == "com.example.tracker."
    assert row["network_signature"] == "example\\\\.tracker\\\\.com"
    assert row["snapshot_date"] == "2026-06-14"
    assert json.loads(row["categories_json"]) == ["Analytics", "Ads"]
    assert json.loads(row["documentation_json"]) == ["https://docs.example.test"]
    assert row["creation_date"] == "2024-01-15"
    assert row["source_url"] == EXODUS_TRACKERS_URL


def test_ensure_schema_and_upsert_use_expected_query_names() -> None:
    calls: list[tuple[str | None, tuple[object, ...]]] = []

    def fake_run_sql(sql, params=(), *, query_name=None, **kwargs):  # noqa: ANN001,ARG001
        calls.append((query_name, tuple(params)))
        return None

    ensure_external_tracker_intel_schema(fake_run_sql)
    upsert_external_tracker_rows(
        fake_run_sql,
        [
            {
                "intel_source": EXODUS_SOURCE_KEY,
                "tracker_id_external": "1",
                "tracker_name": "Teemo",
                "code_signature": "com.databerries.",
                "network_signature": "databerries\\\\.com",
                "website": "https://www.teemo.co",
                "description": "desc",
                "categories_json": '["Analytics"]',
                "documentation_json": "[]",
                "creation_date": "2017-09-24",
                "snapshot_date": "2026-06-14",
                "source_url": EXODUS_TRACKERS_URL,
                "source_terms_note": "note",
                "fetched_at_utc": "2026-06-14 12:00:00",
                "is_active": 1,
            }
        ],
    )
    assert calls[0][0] == "external_sdk_tracker_intel.ensure_schema"
    assert calls[1][0] == "external_sdk_tracker_intel.upsert"
    assert calls[1][1][0] == EXODUS_SOURCE_KEY
    assert calls[1][1][1] == "1"


def test_build_summary_and_write_receipt_bundle(tmp_path: Path) -> None:
    rows = [
        {
            "intel_source": EXODUS_SOURCE_KEY,
            "tracker_id_external": "1",
            "tracker_name": "Teemo",
            "code_signature": "com.databerries.",
            "network_signature": "databerries\\\\.com",
            "website": "https://www.teemo.co",
            "description": "desc",
            "categories_json": '["Analytics"]',
            "documentation_json": "[]",
            "creation_date": "2017-09-24",
            "snapshot_date": "2026-06-14",
            "source_url": EXODUS_TRACKERS_URL,
            "source_terms_note": "note",
            "fetched_at_utc": "2026-06-14 12:00:00",
            "is_active": 1,
        },
        {
            "intel_source": EXODUS_SOURCE_KEY,
            "tracker_id_external": "2",
            "tracker_name": "Second",
            "code_signature": None,
            "network_signature": "second\\\\.example",
            "website": None,
            "description": "desc2",
            "categories_json": '["Ads"]',
            "documentation_json": "[]",
            "creation_date": None,
            "snapshot_date": "2026-06-14",
            "source_url": EXODUS_TRACKERS_URL,
            "source_terms_note": "note",
            "fetched_at_utc": "2026-06-14 12:00:00",
            "is_active": 1,
        },
    ]
    summary = build_refresh_summary(
        rows=rows,
        snapshot_before={"total_rows": 0, "distinct_trackers": 0},
        snapshot_after={"total_rows": 2, "distinct_trackers": 2},
        applied=True,
        source_payload={"trackers": {"1": {"name": "Teemo"}}},
    )
    assert summary["row_count"] == 2
    assert summary["distinct_tracker_ids"] == 2
    assert summary["rows_with_code_signature"] == 1
    assert summary["rows_with_network_signature"] == 2
    assert len(summary["source_payload_canonical_sha256"]) == 64
    assert len(summary["normalized_content_sha256"]) == 64
    assert len(summary["normalized_snapshot_sha256"]) == 64
    assert summary["snapshot_date_semantics"].startswith("UTC retrieval date")
    assert "odbl" in summary["source_database_license"].lower()
    files = write_refresh_receipt_bundle(
        summary=summary,
        rows=rows,
        output_dir=tmp_path,
        stem="external_sdk_tracker_intel_refresh_test",
    )
    payload = json.loads(
        (tmp_path / "external_sdk_tracker_intel_refresh_test.json").read_text(encoding="utf-8")
    )
    assert payload["summary"]["row_count"] == 2
    assert payload["rows"][0]["tracker_name"] == "Teemo"
    assert files["csv"].endswith("external_sdk_tracker_intel_refresh_test.csv")
    assert files["txt"].endswith("external_sdk_tracker_intel_refresh_test.txt")


def test_tracker_content_hash_ignores_retrieval_time_and_snapshot_date() -> None:
    base = {
        "tracker_id_external": "1",
        "tracker_name": "Example",
        "fetched_at_utc": "2026-01-01 00:00:00",
        "snapshot_date": "2026-01-01",
    }
    later = {
        **base,
        "fetched_at_utc": "2026-08-16 23:59:59",
        "snapshot_date": "2026-08-16",
    }

    assert tracker_rows_content_sha256([base]) == tracker_rows_content_sha256([later])


def test_verified_receipt_rejects_normalized_content_tampering(tmp_path: Path) -> None:
    rows = [
        {
            "tracker_id_external": "1",
            "tracker_name": "Example",
            "snapshot_date": "2026-08-17",
            "fetched_at_utc": "2026-08-17 01:00:00",
        }
    ]
    summary = build_refresh_summary(
        rows=rows,
        snapshot_before=None,
        snapshot_after=None,
        applied=False,
    )
    receipt = tmp_path / "receipt.json"
    receipt.write_text(
        json.dumps({"summary": summary, "rows": rows}),
        encoding="utf-8",
    )

    loaded, provenance = load_verified_refresh_receipt(receipt)
    assert loaded == rows
    assert len(provenance["source_receipt_file_sha256"]) == 64

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["rows"][0]["tracker_name"] = "Tampered"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="normalized-content hash mismatch"):
        load_verified_refresh_receipt(receipt)
