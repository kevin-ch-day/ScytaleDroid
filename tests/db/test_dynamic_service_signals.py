from __future__ import annotations

from scytaledroid.Database.db_utils import dynamic_service_signals as catalog
from scytaledroid.DynamicAnalysis import service_signals


def test_backfill_dynamic_service_signals_help_is_safe(assert_safe_script_help) -> None:
    assert_safe_script_help("scripts/db/backfill_dynamic_service_signals.py")


def test_apply_dynamic_service_signal_migration_records_schema_and_seeds(monkeypatch) -> None:
    ddl_statements: list[str] = []
    appended_versions: list[str] = []
    migration_rows: list[dict[str, object]] = []
    seeded_signals: list[tuple[object, ...]] = []
    seeded_maps: list[tuple[object, ...]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return None
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.10-dynamic-service-context"}
        if query_name == f"schema_migrations.apply.{catalog.MIGRATION_ID}":
            ddl_statements.append(sql.strip())
            return None
        if query_name == "dynamic_service_signals.upsert_signal":
            seeded_signals.append(tuple(params))
            return None
        if query_name == "dynamic_service_signals.upsert_map":
            seeded_maps.append(tuple(params))
            return None
        if query_name == "schema_migrations.append_schema_version":
            appended_versions.append(str(params[0]))
            return None
        if query_name == "dynamic_service_signals.signal_count":
            return {"n": len(seeded_signals)}
        if query_name == "dynamic_service_signals.map_count":
            return {"n": len(seeded_maps)}
        if query_name == "dynamic_service_signals.load_signals":
            return [
                {
                    "signal_key": row[0],
                    "display_name": row[1],
                    "signal_family": row[2],
                    "focus_area": row[3],
                    "severity_hint": row[4],
                    "description": row[5],
                    "analyst_guidance": row[6],
                    "source_label": row[7],
                    "source_url": row[8],
                    "notes": row[9],
                }
                for row in seeded_signals
            ]
        if query_name == "dynamic_service_signals.load_maps":
            return [
                {
                    "service_key": row[0],
                    "signal_key": row[1],
                    "signal_strength": row[2],
                    "confidence": row[3],
                    "rationale": row[4],
                    "source_label": row[5],
                    "source_url": row[6],
                    "notes": row[7],
                }
                for row in seeded_maps
            ]
        if query_name == "schema_migrations.insert":
            migration_rows.append(
                {
                    "migration_id": params[0],
                    "schema_version_before": params[4],
                    "schema_version_after": params[5],
                    "status": params[9],
                    "receipt_path": params[11],
                }
            )
            return None
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr(
        catalog,
        "write_dynamic_service_signal_receipt_bundle",
        lambda payload, _output_dir: {  # noqa: ARG005
            "json": "/tmp/dynamic-service-signals.json",
            "signals": "/tmp/dynamic-service-signals-signals.csv",
            "service_signal_maps": "/tmp/dynamic-service-signals-maps.csv",
        },
    )

    payload = catalog.apply_dynamic_service_signal_migration(fake_run_sql)

    assert len(ddl_statements) == 2
    assert appended_versions == ["0.3.11-dynamic-service-signals"]
    assert payload["signals_seeded"] == len(service_signals.default_signal_catalog_seed_rows())
    assert payload["service_signal_maps_seeded"] == len(service_signals.default_service_signal_map_seed_rows())
    assert migration_rows == [
        {
            "migration_id": catalog.MIGRATION_ID,
            "schema_version_before": "0.3.10-dynamic-service-context",
            "schema_version_after": "0.3.11-dynamic-service-signals",
            "status": "applied",
            "receipt_path": "/tmp/dynamic-service-signals.json",
        }
    ]


def test_apply_dynamic_service_signal_migration_reseeds_when_already_applied() -> None:
    seeded_signals: list[tuple[object, ...]] = []
    seeded_maps: list[tuple[object, ...]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return {"migration_entry_id": 1}
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.11-dynamic-service-signals"}
        if query_name == "dynamic_service_signals.upsert_signal":
            seeded_signals.append(tuple(params))
            return None
        if query_name == "dynamic_service_signals.upsert_map":
            seeded_maps.append(tuple(params))
            return None
        if query_name == "dynamic_service_signals.signal_count":
            return {"n": len(seeded_signals)}
        if query_name == "dynamic_service_signals.map_count":
            return {"n": len(seeded_maps)}
        if query_name == "dynamic_service_signals.load_signals":
            return []
        if query_name == "dynamic_service_signals.load_maps":
            return []
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    payload = catalog.apply_dynamic_service_signal_migration(fake_run_sql)

    assert payload["already_applied"] is True
    assert payload["signals_seeded"] == len(service_signals.default_signal_catalog_seed_rows())
    assert payload["service_signal_maps_seeded"] == len(service_signals.default_service_signal_map_seed_rows())


def test_default_service_signal_map_seeds_cover_meta_sdk_and_microsoft_ads_atlas() -> None:
    rows = service_signals.default_service_signal_map_seed_rows()
    by_service: dict[str, set[str]] = {}
    for row in rows:
        service_key = str(row.get("service_key") or "")
        signal_key = str(row.get("signal_key") or "")
        by_service.setdefault(service_key, set()).add(signal_key)

    assert "identity_or_tag_management" in by_service["meta_sdk"]
    assert "third_party_advertising" in by_service["microsoft_ads_atlas"]
    assert "ad_measurement_or_verification" in by_service["microsoft_ads_atlas"]
    assert "first_party_social_platform" in by_service["x_platform"]
    assert "first_party_social_platform" in by_service["x_media_cdn"]
    assert "first_party_social_platform" in by_service["whatsapp_platform"]
    assert "ad_measurement_or_verification" in by_service["x_ads_platform"]
    assert "shared_platform_infrastructure" in by_service["wbd_streaming_platform"]
    assert "shared_platform_infrastructure" in by_service["cloudflare_cdnjs"]
    assert "shared_platform_infrastructure" in by_service["google_amp_cache"]
    assert "shared_platform_infrastructure" in by_service["mapbox_platform"]
    assert "identity_or_tag_management" in by_service["equativ_smartadserver"]
    assert "third_party_advertising" in by_service["equativ_smartadserver"]
    assert "third_party_advertising" in by_service["freewheel"]
    assert "ad_measurement_or_verification" in by_service["freewheel"]
    assert "third_party_analytics_measurement" in by_service["mux_data"]
    assert "third_party_advertising" in by_service["brightline_ctv"]
