from __future__ import annotations

from scytaledroid.DynamicAnalysis import profile_loader


def test_load_operational_profiles_excludes_research_cohorts(monkeypatch) -> None:
    sql_calls: list[tuple[str, tuple[object, ...]]] = []

    def fake_run_sql(sql, params=(), *, fetch="all", dictionary=True, **_kwargs):  # noqa: ANN001,ARG001
        sql_calls.append((sql, tuple(params)))
        return [
            {
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "display_name": "Research Dataset Alpha",
                "app_count": 8,
            },
            {
                "profile_key": "NEWS",
                "display_name": "News",
                "app_count": 5,
            },
        ]

    monkeypatch.setattr(profile_loader, "run_sql", fake_run_sql)

    profiles = profile_loader.load_operational_profiles()

    assert profiles == [
        {
            "profile_key": "NEWS",
            "display_name": "News",
            "app_count": 5,
            "source": "android_app_profiles",
        },
    ]
    assert sql_calls


def test_load_research_cohort_profiles_reads_db_backed_cohorts(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.list_active_research_cohorts",
        lambda: [
            {
                "cohort_key": "research_dataset_alpha",
                "display_name": "Research Dataset Alpha",
                "active_member_count": 12,
            },
            {
                "cohort_key": "research_dataset_beta",
                "display_name": "Research Dataset Beta",
                "active_member_count": 15,
            },
        ],
    )

    profiles = profile_loader.load_research_cohort_profiles()

    assert profiles == [
        {
            "profile_key": "RESEARCH_DATASET_ALPHA",
            "display_name": "Research Dataset Alpha",
            "app_count": 12,
            "source": "research_cohorts",
            "cohort_key": "research_dataset_alpha",
        },
        {
            "profile_key": "RESEARCH_DATASET_BETA",
            "display_name": "Research Dataset Beta",
            "app_count": 15,
            "source": "research_cohorts",
            "cohort_key": "research_dataset_beta",
        },
    ]


def test_load_db_profiles_keeps_legacy_merged_view(monkeypatch) -> None:
    monkeypatch.setattr(
        profile_loader,
        "load_operational_profiles",
        lambda: [
            {
                "profile_key": "NEWS",
                "display_name": "News",
                "app_count": 5,
                "source": "android_app_profiles",
            },
        ],
    )
    monkeypatch.setattr(
        profile_loader,
        "load_research_cohort_profiles",
        lambda: [
            {
                "profile_key": "RESEARCH_DATASET_ALPHA",
                "display_name": "Research Dataset Alpha",
                "app_count": 12,
                "source": "research_cohorts",
                "cohort_key": "research_dataset_alpha",
            },
            {
                "profile_key": "RESEARCH_DATASET_BETA",
                "display_name": "Research Dataset Beta",
                "app_count": 15,
                "source": "research_cohorts",
                "cohort_key": "research_dataset_beta",
            },
        ],
    )

    profiles = profile_loader.load_db_profiles()

    by_key = {str(row["profile_key"]): row for row in profiles}
    assert by_key["RESEARCH_DATASET_ALPHA"]["app_count"] == 12
    assert by_key["RESEARCH_DATASET_ALPHA"]["source"] == "research_cohorts"
    assert by_key["RESEARCH_DATASET_ALPHA"]["cohort_key"] == "research_dataset_alpha"
    assert by_key["RESEARCH_DATASET_BETA"]["display_name"] == "Research Dataset Beta"
    assert by_key["RESEARCH_DATASET_BETA"]["app_count"] == 15
    assert by_key["NEWS"]["display_name"] == "News"


def test_load_profile_packages_prefers_research_cohort_members(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.fetch_active_research_cohort_packages",
        lambda cohort_key: ["com.beta.app", "com.alpha.app"] if cohort_key == "research_dataset_beta" else [],
    )

    packages = profile_loader.load_profile_packages("RESEARCH_DATASET_BETA")

    assert packages == {"com.alpha.app", "com.beta.app"}


def test_load_profile_packages_falls_back_to_apps_profile_key(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.fetch_active_research_cohort_packages",
        lambda cohort_key: [],
    )

    def fake_run_sql(sql, params=(), *, fetch="all", dictionary=True, **_kwargs):  # noqa: ANN001,ARG001
        assert params == ("NEWS",)
        return [{"package_name": "com.example.news"}]

    monkeypatch.setattr(profile_loader, "run_sql", fake_run_sql)

    packages = profile_loader.load_profile_packages("NEWS")

    assert packages == {"com.example.news"}
