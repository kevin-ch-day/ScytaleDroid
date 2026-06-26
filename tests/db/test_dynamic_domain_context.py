from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scytaledroid.Database.db_utils import dynamic_domain_context as catalog
from scytaledroid.DynamicAnalysis.domain_context import DomainReference, classify_domain, default_domain_references
from scytaledroid.DynamicAnalysis.storage import domain_context_index


def test_backfill_dynamic_domain_context_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_dynamic_domain_context.py"
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


def test_apply_dynamic_domain_context_migration_records_schema_and_seeds(monkeypatch) -> None:
    ddl_statements: list[str] = []
    appended_versions: list[str] = []
    migration_rows: list[dict[str, object]] = []
    seeded_rows: list[dict[str, object]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return None
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.7-research-cohorts"}
        if query_name == f"schema_migrations.apply.{catalog.MIGRATION_ID}":
            ddl_statements.append(sql.strip())
            return None
        if query_name == "dynamic_domain_context.upsert_reference":
            seeded_rows.append(
                {
                    "package_name_scope": params[0],
                    "domain_pattern": params[1],
                    "match_type": params[2],
                    "owner_class": params[3],
                    "role_class": params[4],
                    "confidence": params[5],
                    "classification_basis": params[6],
                    "source_label": params[7],
                    "source_url": params[8],
                    "notes": params[9],
                }
            )
            return None
        if query_name == "schema_migrations.append_schema_version":
            appended_versions.append(str(params[0]))
            return None
        if query_name == "dynamic_domain_context.reference_count":
            return {"n": len(seeded_rows)}
        if query_name == "dynamic_domain_context.load_references":
            return list(seeded_rows)
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
        "write_dynamic_domain_context_receipt_bundle",
        lambda payload, _output_dir: {  # noqa: ARG005
            "json": "/tmp/dynamic-domain-context.json",
            "references_csv": "/tmp/dynamic-domain-context.csv",
            "summary_txt": "/tmp/dynamic-domain-context.txt",
        },
    )

    payload = catalog.apply_dynamic_domain_context_migration(fake_run_sql)

    assert len(ddl_statements) == 2
    assert appended_versions == ["0.3.8-dynamic-domain-context"]
    assert payload["reference_seed_rows"] == len(seeded_rows)
    assert len(seeded_rows) >= 10
    assert migration_rows == [
        {
            "migration_id": catalog.MIGRATION_ID,
            "schema_version_before": "0.3.7-research-cohorts",
            "schema_version_after": "0.3.8-dynamic-domain-context",
            "status": "applied",
            "receipt_path": "/tmp/dynamic-domain-context.json",
        }
    ]


def test_apply_dynamic_domain_context_migration_reseeds_when_already_applied() -> None:
    seeded_rows: list[dict[str, object]] = []

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return {"migration_entry_id": 1}
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.9-dynamic-domain-context-collation-hotfix"}
        if query_name == "dynamic_domain_context.upsert_reference":
            seeded_rows.append(
                {
                    "package_name_scope": params[0],
                    "domain_pattern": params[1],
                    "match_type": params[2],
                }
            )
            return None
        if query_name == "dynamic_domain_context.load_references":
            return list(seeded_rows)
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    payload = catalog.apply_dynamic_domain_context_migration(fake_run_sql)

    assert payload["already_applied"] is True
    assert int(payload["reference_seed_rows"]) == len(catalog.default_domain_reference_seed_rows())
    assert any(row["domain_pattern"] == "tiktokcdn-us.com" for row in seeded_rows)


def test_build_and_index_domain_observation_rows(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run-1"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps(
            {
                "top_dns": [
                    {"value": "collector.cdp.cnn.com", "count": 6},
                    {"value": "googleads.g.doubleclick.net", "count": 5},
                ],
                "top_sni": [
                    {"value": "combine.urbanairship.com", "count": 4},
                ],
            }
        ),
        encoding="utf-8",
    )

    rows = domain_context_index.build_domain_observation_rows_from_pcap_report(
        {
            "top_dns": [
                {"value": "collector.cdp.cnn.com", "count": 6},
                {"value": "googleads.g.doubleclick.net", "count": 5},
            ],
            "top_sni": [{"value": "combine.urbanairship.com", "count": 4}],
        },
        dynamic_run_id="run-1",
        package_name="com.cnn.mobile.android.phone",
    )
    assert len(rows) == 3
    assert any(row["owner_class"] == "first_party" and row["role_class"] == "publisher_collection" for row in rows)
    assert any(row["role_class"] == "adtech_monetization" for row in rows)
    assert any(row["role_class"] == "engagement_push" for row in rows)

    deleted: list[tuple[object, ...]] = []
    inserted: list[tuple[object, ...]] = []

    monkeypatch.setattr(domain_context_index, "load_domain_references_from_db", lambda: ())
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_write",
        lambda sql, params=(), **_kwargs: deleted.append(tuple(params)),
    )
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_many",
        lambda sql, data, **_kwargs: inserted.extend(tuple(row) for row in data),
    )

    count = domain_context_index.index_dynamic_domain_context_for_run(
        "run-1",
        "com.cnn.mobile.android.phone",
        run_dir,
    )
    assert count == 3
    assert deleted == [("run-1",)]
    assert len(inserted) == 3


def test_classify_domain_prefers_package_scoped_exact_over_global_exact() -> None:
    refs = (
        DomainReference("", "graph.facebook.com", "EXACT", "third_party", "social_graph_api", "medium", "curated_exact"),
        DomainReference(
            "com.facebook.katana",
            "graph.facebook.com",
            "EXACT",
            "first_party",
            "social_graph_api",
            "high",
            "curated_exact",
        ),
    )

    facebook = classify_domain("graph.facebook.com", package_name="com.facebook.katana", references=refs)
    assert facebook["owner_class"] == "first_party"
    assert facebook["package_name_scope"] == "com.facebook.katana"

    tiktok = classify_domain("graph.facebook.com", package_name="com.zhiliaoapp.musically", references=refs)
    assert tiktok["owner_class"] == "third_party"
    assert tiktok["package_name_scope"] == ""


def test_classify_domain_handles_facebook_net_and_atdmt_suffixes() -> None:
    refs = default_domain_references()

    facebook_net = classify_domain("star.c10r.facebook.net", package_name="com.facebook.katana", references=refs)
    assert facebook_net["owner_class"] == "first_party"
    assert facebook_net["role_class"] == "first_party_misc"

    tiktok_meta = classify_domain("star.c10r.facebook.net", package_name="com.zhiliaoapp.musically", references=refs)
    assert tiktok_meta["owner_class"] == "third_party"
    assert tiktok_meta["role_class"] == "social_graph_api"

    atdmt = classify_domain("clk.atdmt.com", package_name="com.facebook.katana", references=refs)
    assert atdmt["owner_class"] == "third_party"
    assert atdmt["role_class"] == "adtech_monetization"

    chat_e2ee = classify_domain("chat-e2ee-mini.facebook.com", package_name="com.facebook.katana", references=refs)
    assert chat_e2ee["owner_class"] == "first_party"
    assert chat_e2ee["role_class"] == "messaging_e2ee"

    connect = classify_domain("connect.facebook.net", package_name="com.zhiliaoapp.musically", references=refs)
    assert connect["owner_class"] == "third_party"
    assert connect["role_class"] == "identity_api"

    b_graph = classify_domain("b-graph.facebook.com", package_name="com.facebook.katana", references=refs)
    assert b_graph["owner_class"] == "first_party"
    assert b_graph["role_class"] == "social_graph_api"

    x_probe = classify_domain("probe.twitter.com", package_name="com.twitter.android", references=refs)
    assert x_probe["owner_class"] == "first_party"
    assert x_probe["role_class"] == "realtime_engagement"

    x_video_s = classify_domain("video-s.twimg.com", package_name="com.twitter.android", references=refs)
    assert x_video_s["owner_class"] == "first_party"
    assert x_video_s["role_class"] == "content_delivery"

    firebase_logging = classify_domain(
        "firebaselogging.googleapis.com",
        package_name="com.twitter.android",
        references=refs,
    )
    assert firebase_logging["owner_class"] == "third_party"
    assert firebase_logging["role_class"] == "google_api_platform"

    firebase_remote_config = classify_domain(
        "firebaseremoteconfig.googleapis.com",
        package_name="com.twitter.android",
        references=refs,
    )
    assert firebase_remote_config["owner_class"] == "third_party"
    assert firebase_remote_config["role_class"] == "google_api_platform"

    google_time = classify_domain("time.google.com", package_name="com.twitter.android", references=refs)
    assert google_time["owner_class"] == "third_party"
    assert google_time["role_class"] == "google_infrastructure"

    cnn_ngtv = classify_domain("freeview.ngtv.io", package_name="com.cnn.mobile.android.phone", references=refs)
    assert cnn_ngtv["owner_class"] == "first_party"
    assert cnn_ngtv["role_class"] == "streaming_delivery"

    cnn_discomax = classify_domain(
        "default.any-any.prd.api.discomax.com",
        package_name="com.cnn.mobile.android.phone",
        references=refs,
    )
    assert cnn_discomax["owner_class"] == "first_party"
    assert cnn_discomax["role_class"] == "streaming_platform_api"

    cnn_warnermedia = classify_domain(
        "top.warnermediacdn.com",
        package_name="com.cnn.mobile.android.phone",
        references=refs,
    )
    assert cnn_warnermedia["owner_class"] == "first_party"
    assert cnn_warnermedia["role_class"] == "content_delivery"

    freewheel = classify_domain("bea4.v.fwmrm.net", package_name="com.cnn.mobile.android.phone", references=refs)
    assert freewheel["owner_class"] == "third_party"
    assert freewheel["role_class"] == "adtech_video_monetization"

    mux = classify_domain(
        "out053a3bejgh7t0phqa0csou.litix.io",
        package_name="com.cnn.mobile.android.phone",
        references=refs,
    )
    assert mux["owner_class"] == "third_party"
    assert mux["role_class"] == "video_analytics_measurement"

    brightline = classify_domain(
        "cdn-media.brightline.tv",
        package_name="com.cnn.mobile.android.phone",
        references=refs,
    )
    assert brightline["owner_class"] == "third_party"
    assert brightline["role_class"] == "interactive_ctv_advertising"

    dianomi_worker = classify_domain(
        "gpp-decoder.dianomi.workers.dev",
        package_name="com.cnn.mobile.android.phone",
        references=refs,
    )
    assert dianomi_worker["owner_class"] == "third_party"
    assert dianomi_worker["role_class"] == "adtech_monetization"


def test_index_dynamic_evidence_pack_to_db_includes_domain_context(monkeypatch, tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    (run_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "dynamic_run_id": "run-1",
                "target": {"package_name": "com.zhiliaoapp.musically"},
                "dataset": {"valid_dataset_run": True, "countable": True},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "analysis" / "pcap_report.json").write_text(
        json.dumps({"top_dns": [{"value": "v45.tiktokcdn-us.com", "count": 5}]}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        domain_context_index,
        "load_domain_references_from_db",
        lambda: domain_context_index.default_domain_references(),
    )

    upserts: list[dict[str, object]] = []
    feature_rows: list[dict[str, object]] = []
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.upsert_dynamic_session_row",
        lambda row: upserts.append(dict(row)),
    )
    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.storage.index_from_evidence.build_dynamic_network_features_row_from_evidence_pack",
        lambda _run_dir: None,
    )
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_write",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        domain_context_index.core_q,
        "run_sql_many",
        lambda _sql, data, **_kwargs: feature_rows.extend(
            {
                "observed_domain": row[3],
                "owner_class": row[7],
                "role_class": row[8],
            }
            for row in data
        ),
    )

    from scytaledroid.DynamicAnalysis.storage import index_from_evidence

    result = index_from_evidence.index_dynamic_evidence_pack_to_db(run_dir)

    assert result["ok"] is True
    assert result["domain_context_indexed"] == 1
    assert upserts and upserts[0]["package_name"] == "com.zhiliaoapp.musically"
    assert feature_rows == [
        {
            "observed_domain": "v45.tiktokcdn-us.com",
            "owner_class": "first_party",
            "role_class": "content_delivery",
        }
    ]
