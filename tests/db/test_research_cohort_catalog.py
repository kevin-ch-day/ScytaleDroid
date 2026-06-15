from __future__ import annotations

from collections.abc import Mapping

from scytaledroid.Database.db_utils import research_cohort_catalog as catalog
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import CANONICAL_PACKAGES


def test_default_seed_payload_defines_alpha_and_beta_without_duplicates() -> None:
    payload = {seed.cohort_key: seed for seed in catalog.default_seed_payload()}

    alpha = payload["research_dataset_alpha"]
    beta = payload["research_dataset_beta"]
    alpha_packages = [member.package_name for member in alpha.members]
    beta_packages = [member.package_name for member in beta.members]

    assert alpha_packages == list(CANONICAL_PACKAGES)
    assert len(beta_packages) == len(set(beta_packages))
    assert beta_packages[: len(alpha_packages)] == alpha_packages
    assert beta_packages[-4:] == [
        "bbc.mobile.news.ww",
        "com.cnn.mobile.android.phone",
        "com.guardian",
        "com.espn.score_center",
    ]


def test_apply_research_cohort_tables_migration_seeds_and_preserves_existing_state(
    monkeypatch,
) -> None:
    before_after_state = {
        "apps_profile_alpha_rows": [
            {"package_name": "com.facebook.katana", "profile_key": "RESEARCH_DATASET_ALPHA"},
            {"package_name": "org.telegram.messenger", "profile_key": "RESEARCH_DATASET_ALPHA"},
        ],
        "analysis_cohorts_rows": [
            {"cohort_id": 1, "name": "legacy-freeze", "selector_type": "static_session"}
        ],
        "analysis_cohort_runs_counts": [{"cohort_id": 1, "row_count": 9}],
    }
    ddl_statements: list[str] = []
    appended_versions: list[str] = []
    migration_rows: list[dict[str, object]] = []
    seeded_members: dict[str, list[dict[str, object]]] = {}
    cohort_ids: dict[str, int] = {}

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return None
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.6-schema-version-width-hotfix"}
        if "FROM apps" in sql:
            return before_after_state["apps_profile_alpha_rows"]
        if "FROM analysis_cohorts" in sql:
            return before_after_state["analysis_cohorts_rows"]
        if "FROM analysis_cohort_runs" in sql:
            return before_after_state["analysis_cohort_runs_counts"]
        if query_name == f"schema_migrations.apply.{catalog.MIGRATION_ID}":
            ddl_statements.append(sql.strip())
            return None
        if query_name == "schema_migrations.append_schema_version":
            appended_versions.append(str(params[0]))
            return None
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

    def fake_upsert(*, cohort_key: str, display_name: str, description: str | None, **_kwargs) -> int:
        cohort_ids[cohort_key] = len(cohort_ids) + 1
        assert display_name
        assert description is not None
        return cohort_ids[cohort_key]

    def fake_replace(*, cohort_id: int, members, **_kwargs) -> int:  # noqa: ANN001
        key = next(name for name, value in cohort_ids.items() if value == cohort_id)
        seeded_members[key] = [
            {
                "package_name": member.package_name,
                "member_source": member.member_source,
                "source_cohort_key": member.source_cohort_key,
                "sort_order": member.sort_order,
            }
            for member in members
        ]
        return len(seeded_members[key])

    def fake_fetch_members(cohort_key: str, **_kwargs) -> list[dict[str, object]]:
        return list(seeded_members.get(cohort_key, []))

    monkeypatch.setattr(catalog, "upsert_research_cohort", fake_upsert)
    monkeypatch.setattr(catalog, "replace_research_cohort_members", fake_replace)
    monkeypatch.setattr(catalog, "fetch_active_research_cohort_members", fake_fetch_members)
    monkeypatch.setattr(
        catalog,
        "write_research_cohort_receipt_bundle",
        lambda payload, _output_dir: {  # noqa: ARG005
            "json": "/tmp/research-cohort.json",
            "members_csv": "/tmp/research-cohort.csv",
            "summary_txt": "/tmp/research-cohort.txt",
        },
    )

    payload = catalog.apply_research_cohort_tables_migration(fake_run_sql)

    assert len(ddl_statements) == 2
    assert appended_versions == ["0.3.7-research-cohorts"]
    assert payload["before"] == payload["after"] == before_after_state
    assert [row["cohort_key"] for row in payload["seeded"]["cohorts"]] == [
        "research_dataset_alpha",
        "research_dataset_beta",
    ]
    assert len(seeded_members["research_dataset_alpha"]) == len(CANONICAL_PACKAGES)
    assert len(seeded_members["research_dataset_beta"]) == len(CANONICAL_PACKAGES) + 4
    assert len({row["package_name"] for row in seeded_members["research_dataset_beta"]}) == len(
        seeded_members["research_dataset_beta"]
    )
    assert migration_rows == [
        {
            "migration_id": catalog.MIGRATION_ID,
            "schema_version_before": "0.3.6-schema-version-width-hotfix",
            "schema_version_after": "0.3.7-research-cohorts",
            "status": "applied",
            "receipt_path": "/tmp/research-cohort.json",
        }
    ]
    assert isinstance(payload["receipt_files"], Mapping)


def test_apply_research_cohort_tables_migration_is_idempotent_when_already_applied(
    monkeypatch,
) -> None:
    state = {
        "apps_profile_alpha_rows": [],
        "analysis_cohorts_rows": [],
        "analysis_cohort_runs_counts": [],
    }

    def fake_run_sql(sql, params=(), *, fetch="one", dictionary=False, query_name=None):  # noqa: ANN001,ARG001
        if "FROM schema_migrations" in sql and "migration_entry_id" in sql:
            return {"migration_entry_id": 99}
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return {"schema_version_after": "0.3.7-research-cohorts"}
        if "FROM apps" in sql:
            return state["apps_profile_alpha_rows"]
        if "FROM analysis_cohorts" in sql:
            return state["analysis_cohorts_rows"]
        if "FROM analysis_cohort_runs" in sql:
            return state["analysis_cohort_runs_counts"]
        raise AssertionError(f"unexpected query_name={query_name!r} sql={sql[:80]!r}")

    monkeypatch.setattr(
        catalog,
        "fetch_active_research_cohort_members",
        lambda cohort_key, **_kwargs: [{"package_name": cohort_key}],
    )

    payload = catalog.apply_research_cohort_tables_migration(fake_run_sql)

    assert payload["already_applied"] is True
    assert payload["schema_version_after"] == "0.3.7-research-cohorts"
    assert payload["seeded"]["cohorts"] == [
        {"cohort_key": "research_dataset_alpha", "member_count": 1},
        {"cohort_key": "research_dataset_beta", "member_count": 1},
    ]
