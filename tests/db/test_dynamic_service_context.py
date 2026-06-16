from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scytaledroid.Database.db_utils import dynamic_service_context as catalog
from scytaledroid.DynamicAnalysis import service_context


def test_backfill_dynamic_service_context_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_dynamic_service_context.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")


def test_apply_dynamic_service_context_migration_records_schema_and_seeds(monkeypatch) -> None:
    ddl_statements: list[str] = []
    appended_versions: list[str] = []
    migration_rows: list[dict[str, object]] = []
    seeded_services: list[tuple[object, ...]] = []
    seeded_maps: list[tuple[object, ...]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return None
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.9-dynamic-domain-context-collation-hotfix"}
        if query_name == f"schema_migrations.apply.{catalog.MIGRATION_ID}":
            ddl_statements.append(sql.strip())
            return None
        if query_name == "dynamic_service_context.upsert_service":
            seeded_services.append(tuple(params))
            return None
        if query_name == "dynamic_service_context.upsert_domain_map":
            seeded_maps.append(tuple(params))
            return None
        if query_name == "schema_migrations.append_schema_version":
            appended_versions.append(str(params[0]))
            return None
        if query_name == "dynamic_service_context.service_count":
            return {"n": len(seeded_services)}
        if query_name == "dynamic_service_context.domain_map_count":
            return {"n": len(seeded_maps)}
        if query_name == "dynamic_service_context.load_services":
            return [
                {
                    "service_key": row[0],
                    "display_name": row[1],
                    "owner_name": row[2],
                    "owner_class": row[3],
                    "service_category": row[4],
                    "primary_use_case": row[5],
                    "documentation_url": row[6],
                    "privacy_policy_url": row[7],
                    "source_label": row[8],
                    "source_url": row[9],
                    "confidence": row[10],
                    "notes": row[11],
                }
                for row in seeded_services
            ]
        if query_name == "dynamic_service_context.load_domain_maps":
            return [
                {
                    "service_key": row[0],
                    "package_name_scope": row[1],
                    "domain_pattern": row[2],
                    "match_type": row[3],
                    "role_class": row[4],
                    "source_label": row[5],
                    "source_url": row[6],
                    "confidence": row[7],
                    "notes": row[8],
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
        "write_dynamic_service_context_receipt_bundle",
        lambda payload, _output_dir: {  # noqa: ARG005
            "json": "/tmp/dynamic-service-context.json",
            "services_csv": "/tmp/dynamic-service-context-services.csv",
            "domain_maps_csv": "/tmp/dynamic-service-context-domain-maps.csv",
        },
    )

    payload = catalog.apply_dynamic_service_context_migration(fake_run_sql)

    assert len(ddl_statements) == 2
    assert appended_versions == ["0.3.10-dynamic-service-context"]
    assert payload["services_seeded"] == len(service_context.default_service_catalog_seed_rows())
    assert payload["domain_maps_seeded"] == len(service_context.default_service_domain_map_seed_rows())
    assert len(seeded_services) >= 8
    assert len(seeded_maps) >= 10
    assert migration_rows == [
        {
            "migration_id": catalog.MIGRATION_ID,
            "schema_version_before": "0.3.9-dynamic-domain-context-collation-hotfix",
            "schema_version_after": "0.3.10-dynamic-service-context",
            "status": "applied",
            "receipt_path": "/tmp/dynamic-service-context.json",
        }
    ]


def test_apply_dynamic_service_context_migration_reseeds_when_already_applied() -> None:
    seeded_services: list[tuple[object, ...]] = []
    seeded_maps: list[tuple[object, ...]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return {"migration_entry_id": 1}
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.10-dynamic-service-context"}
        if query_name == "dynamic_service_context.upsert_service":
            seeded_services.append(tuple(params))
            return None
        if query_name == "dynamic_service_context.upsert_domain_map":
            seeded_maps.append(tuple(params))
            return None
        if query_name == "dynamic_service_context.service_count":
            return {"n": len(seeded_services)}
        if query_name == "dynamic_service_context.domain_map_count":
            return {"n": len(seeded_maps)}
        if query_name == "dynamic_service_context.load_services":
            return []
        if query_name == "dynamic_service_context.load_domain_maps":
            return []
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    payload = catalog.apply_dynamic_service_context_migration(fake_run_sql)

    assert payload["already_applied"] is True
    assert payload["services_seeded"] == len(service_context.default_service_catalog_seed_rows())
    assert payload["domain_maps_seeded"] == len(service_context.default_service_domain_map_seed_rows())


def test_resolve_service_for_domain_prefers_package_specific_scope() -> None:
    services = tuple(service_context.default_service_catalog_seed_rows())
    maps = tuple(service_context.default_service_domain_map_seed_rows())

    bbc = service_context.resolve_service_for_domain(
        "bbc-global-app.api.bbc.com",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert bbc["service_key"] == "bbc_first_party"
    assert bbc["owner_class"] == "first_party"

    ads = service_context.resolve_service_for_domain(
        "googleads.g.doubleclick.net",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert ads["service_key"] == "google_ads"
    assert ads["service_category"] == "adtech"

    unknown = service_context.resolve_service_for_domain(
        "unknown.example.org",
        package_name="bbc.mobile.news.ww",
        service_rows=services,
        map_rows=maps,
    )
    assert unknown["service_key"] is None
    assert unknown["service_display_name"] is None

    oracle = service_context.resolve_service_for_domain(
        "config.mtp.sag.us-ashburn-1.oci.oraclecloud.com",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert oracle["service_key"] == "oracle_cloud"
    assert oracle["service_category"] == "platform_infrastructure"

    meta_sdk = service_context.resolve_service_for_domain(
        "graph.facebook.com",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_sdk["service_key"] == "meta_sdk"
    assert meta_sdk["owner_class"] == "third_party"

    meta_first_party = service_context.resolve_service_for_domain(
        "graph.facebook.com",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_first_party["service_key"] == "facebook_platform"
    assert meta_first_party["owner_class"] == "first_party"

    meta_infra = service_context.resolve_service_for_domain(
        "star.c10r.facebook.net",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_infra["service_key"] == "facebook_platform"
    assert meta_infra["owner_class"] == "first_party"

    meta_connect = service_context.resolve_service_for_domain(
        "connect.facebook.net",
        package_name="com.zhiliaoapp.musically",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_connect["service_key"] == "meta_sdk"
    assert meta_connect["owner_class"] == "third_party"

    meta_b_graph = service_context.resolve_service_for_domain(
        "b-graph.facebook.com",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert meta_b_graph["service_key"] == "facebook_platform"
    assert meta_b_graph["owner_class"] == "first_party"

    atlas = service_context.resolve_service_for_domain(
        "clk.atdmt.com",
        package_name="com.facebook.katana",
        service_rows=services,
        map_rows=maps,
    )
    assert atlas["service_key"] == "microsoft_ads_atlas"
    assert atlas["service_category"] == "adtech"

    x_api = service_context.resolve_service_for_domain(
        "api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_api["service_key"] == "x_platform"
    assert x_api["owner_class"] == "first_party"

    x_ads = service_context.resolve_service_for_domain(
        "ads-api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_ads["service_key"] == "x_ads_platform"
    assert x_ads["service_category"] == "adtech"

    time_google = service_context.resolve_service_for_domain(
        "time.google.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert time_google["service_key"] == "google_platform"
    assert time_google["owner_name"] == "Google"

    espn = service_context.resolve_service_for_domain(
        "espn.api.edge.bamgrid.com",
        package_name="com.espn.score_center",
        service_rows=services,
        map_rows=maps,
    )
    assert espn["service_key"] == "espn_first_party"
    assert espn["owner_class"] == "first_party"

    new_relic = service_context.resolve_service_for_domain(
        "mobile-collector.newrelic.com",
        package_name="com.espn.score_center",
        service_rows=services,
        map_rows=maps,
    )
    assert new_relic["service_key"] == "new_relic"
    assert new_relic["service_category"] == "analytics"

    nielsen = service_context.resolve_service_for_domain(
        "secure-dcr.vtwenty.com",
        package_name="com.espn.score_center",
        service_rows=services,
        map_rows=maps,
    )
    assert nielsen["service_key"] == "nielsen_dcr"
    assert nielsen["service_category"] == "analytics"

    x_api = service_context.resolve_service_for_domain(
        "api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_api["service_key"] == "x_platform"
    assert x_api["owner_class"] == "first_party"

    x_media = service_context.resolve_service_for_domain(
        "pbs.twimg.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_media["service_key"] == "x_media_cdn"
    assert x_media["service_category"] == "content_delivery"

    x_ads = service_context.resolve_service_for_domain(
        "ads-api.x.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert x_ads["service_key"] == "x_ads_platform"
    assert x_ads["owner_class"] == "first_party"

    google_time = service_context.resolve_service_for_domain(
        "time.google.com",
        package_name="com.twitter.android",
        service_rows=services,
        map_rows=maps,
    )
    assert google_time["service_key"] == "google_platform"
    assert google_time["service_category"] == "platform_infrastructure"
