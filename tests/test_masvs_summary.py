import pytest

from scytaledroid.StaticAnalysis.cli import masvs_summary
from scytaledroid.StaticAnalysis.cli.masvs_summary import _build_summary


def test_build_summary_enriches_cvss_and_counts():
    counts_rows = [
        {"masvs": "NETWORK", "high": 1, "medium": 0, "low": 2, "info": 1},
        {"masvs": "PRIVACY", "high": 0, "medium": 1, "low": 0, "info": 3},
    ]
    top_rows = [
        {"masvs": "NETWORK", "severity": "High", "identifier": "NET-01", "occurrences": 2},
        {"masvs": "PRIVACY", "severity": "Medium", "identifier": "PRIV-01", "occurrences": 1},
    ]
    cvss_rows = [
        {
            "masvs": "NETWORK",
            "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "identifier": "NET-01",
            "severity": "High",
        },
        {
            "masvs": "NETWORK",
            "cvss": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
            "identifier": "NET-02",
            "severity": "Medium",
        },
        {
            "masvs": "PRIVACY",
            "cvss": None,
            "identifier": "PRIV-01",
            "severity": "Medium",
        },
    ]

    summary = _build_summary(counts_rows, top_rows, cvss_rows)
    assert summary
    network = next(item for item in summary if item["area"] == "NETWORK")
    assert network["high"] == 1
    assert network["medium"] == 0
    assert network["low"] == 2
    assert network["info"] == 1
    assert network["control_count"] == 4
    assert network["top_high"]["descriptor"] == "NET-01"
    cvss = network["cvss"]
    assert cvss["worst_identifier"] == "NET-01"
    assert cvss["worst_severity"] == "Critical"
    assert cvss["worst_score"] == 10.0
    worst_basis = cvss["worst_basis"]
    assert worst_basis["band"] == "Critical"
    assert worst_basis["scope_rank"] == 2
    assert worst_basis["impact_high"] == 3
    assert worst_basis["impact_medium"] == 0
    assert cvss["average_score"] == 8.1
    assert cvss["band_counts"] == {"Critical": 1, "Medium": 1}
    assert cvss["band_distribution"] == {"Critical": 0.5, "Medium": 0.5}
    assert cvss["scored_count"] == 2
    assert cvss["missing"] == 0
    assert cvss["total"] == 2
    quality = network["quality"]
    assert quality["risk_index"] == 60.0
    assert quality["cvss_coverage"] == 1.0
    assert quality["severity_pressure"] == 7.0
    assert quality["severity_density_norm"] == 0.35
    components = quality["risk_components"]
    inputs = components["inputs"]
    assert inputs["severity_density_norm"] == 0.35
    assert components["contributions"]["severity"] + components["contributions"]["band"] + components["contributions"]["intensity"] == pytest.approx(quality["risk_index"], abs=0.2)

    privacy = next(item for item in summary if item["area"] == "PRIVACY")
    assert privacy["medium"] == 1
    cvss_priv = privacy["cvss"]
    assert cvss_priv["worst_score"] is None
    assert cvss_priv["missing"] == 1
    assert cvss_priv["total"] == 1
    assert cvss_priv["band_counts"] == {}
    assert "band_distribution" not in cvss_priv
    assert privacy["top_medium"]["descriptor"] == "PRIV-01"
    quality_priv = privacy["quality"]
    assert quality_priv["risk_index"] == 7.5
    assert quality_priv["cvss_coverage"] == 0.0
    assert quality_priv["severity_density_norm"] == 0.15


def test_fetch_db_masvs_summary_handles_missing_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple | None, str | None]] = []

    def fake_run_sql(query: str, params=None, fetch: str | None = None, **kwargs):
        calls.append((query, params, fetch))
        if "MAX(run_id)" in query:
            return (None,)
        return []

    monkeypatch.setattr(masvs_summary.core_q, "run_sql", fake_run_sql)

    result = masvs_summary.fetch_db_masvs_summary()
    assert result is None
    assert any("MAX(run_id)" in call[0] for call in calls)


def test_fetch_db_masvs_summary_merges_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    counts_rows = [
        {"masvs": "NETWORK", "high": 1, "medium": 1, "low": 0, "info": 0},
    ]
    cvss_rows = [
        {
            "masvs": "NETWORK",
            "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "identifier": "NET-01",
            "severity": "High",
        }
    ]
    top_rows = [
        {
            "masvs": "NETWORK",
            "severity": "High",
            "identifier": "NET-01",
            "occurrences": 2,
        }
    ]

    responses = [(7,), counts_rows, cvss_rows, top_rows]

    def fake_run_sql(query: str, params=None, fetch: str | None = None, **kwargs):
        assert responses, "unexpected query call"
        return responses.pop(0)

    monkeypatch.setattr(masvs_summary.core_q, "run_sql", fake_run_sql)

    result = masvs_summary.fetch_db_masvs_summary()
    assert result is not None
    run_id, summary = result
    assert run_id == 7
    assert summary
    network = summary[0]
    assert network["area"] == "NETWORK"
    assert network["high"] == 1
    assert network["medium"] == 1
    cvss_meta = network["cvss"]
    assert cvss_meta["worst_identifier"] == "NET-01"
    assert cvss_meta["worst_severity"] == "Critical"
    quality = network["quality"]
    assert quality["risk_index"] >= 0
    assert quality["cvss_coverage"] == 1.0


def test_cvss_worst_vector_prefers_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    counts_rows: list[dict[str, object]] = []
    top_rows: list[dict[str, object]] = []
    cvss_rows = [
        {"masvs": "NETWORK", "cvss": "vector_high_scope", "identifier": "high-scope", "severity": "High"},
        {"masvs": "NETWORK", "cvss": "vector_low_scope", "identifier": "low-scope", "severity": "High"},
    ]

    def fake_score_vector(_: str) -> float:
        return 8.0

    def fake_parse_vector(vector: str) -> dict[str, str]:
        if vector == "vector_high_scope":
            return {"SC": "H", "SI": "H", "SA": "L", "VC": "H", "VI": "H", "VA": "L"}
        if vector == "vector_low_scope":
            return {"SC": "L", "SI": "N", "SA": "N", "VC": "H", "VI": "H", "VA": "L"}
        return {}

    monkeypatch.setattr(masvs_summary, "score_vector", fake_score_vector)
    monkeypatch.setattr(masvs_summary, "parse_vector", fake_parse_vector)

    summary = _build_summary(counts_rows, top_rows, cvss_rows)
    assert summary
    network = summary[0]
    cvss_meta = network["cvss"]
    assert cvss_meta["worst_identifier"] == "high-scope"
    assert cvss_meta["worst_vector"] == "vector_high_scope"


def test_cvss_worst_vector_prefers_impact_then_length(monkeypatch: pytest.MonkeyPatch) -> None:
    counts_rows: list[dict[str, object]] = []
    top_rows: list[dict[str, object]] = []
    cvss_rows = [
        {"masvs": "NETWORK", "cvss": "vector_high_impact", "identifier": "high-impact", "severity": "High"},
        {"masvs": "NETWORK", "cvss": "vector_lower_impact", "identifier": "lower-impact", "severity": "High"},
        {"masvs": "NETWORK", "cvss": "vector_same", "identifier": "same", "severity": "High"},
    ]

    scores = {row["cvss"]: 7.5 for row in cvss_rows}

    def fake_score_vector(vector: str) -> float:
        return scores[vector]

    def fake_parse_vector(vector: str) -> dict[str, str]:
        if vector == "vector_high_impact":
            return {"SC": "L", "VC": "H", "VI": "H", "VA": "H"}
        if vector == "vector_lower_impact":
            return {"SC": "L", "VC": "H", "VI": "L", "VA": "L"}
        if vector == "vector_same":
            # Same impact counts but shorter identifier to ensure length tie-break works
            return {"SC": "L", "VC": "H", "VI": "H", "VA": "H"}
        return {}

    monkeypatch.setattr(masvs_summary, "score_vector", fake_score_vector)
    monkeypatch.setattr(masvs_summary, "parse_vector", fake_parse_vector)

    summary = _build_summary(counts_rows, top_rows, cvss_rows)
    cvss_meta = summary[0]["cvss"]
    assert cvss_meta["worst_identifier"] == "high-impact"
    assert cvss_meta["worst_vector"] == "vector_high_impact"


def test_cvss_worst_vector_tie_breaks_deterministically(monkeypatch: pytest.MonkeyPatch) -> None:
    counts_rows: list[dict[str, object]] = []
    top_rows: list[dict[str, object]] = []
    cvss_rows = [
        {"masvs": "NETWORK", "cvss": "vector_same_name_a", "identifier": "alpha", "severity": "High"},
        {"masvs": "NETWORK", "cvss": "vector_same_name_b", "identifier": "alpha", "severity": "High"},
    ]

    def fake_score_vector(_: str) -> float:
        return 7.2

    def fake_parse_vector(_: str) -> dict[str, str]:
        return {"SC": "L", "VC": "H", "VI": "H", "VA": "H"}

    monkeypatch.setattr(masvs_summary, "score_vector", fake_score_vector)
    monkeypatch.setattr(masvs_summary, "parse_vector", fake_parse_vector)

    summary = _build_summary(counts_rows, top_rows, cvss_rows)
    cvss_meta = summary[0]["cvss"]
    assert cvss_meta["worst_vector"] == "vector_same_name_b"
    assert cvss_meta["worst_basis"]["vector"] == "vector_same_name_b"

def test_cvss_non_v4_vectors_count_as_missing() -> None:
    counts_rows: list[dict[str, object]] = []
    top_rows: list[dict[str, object]] = []
    cvss_rows = [
        {"masvs": "NETWORK", "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "identifier": "legacy", "severity": "High"},
    ]

    summary = _build_summary(counts_rows, top_rows, cvss_rows)
    cvss_meta = summary[0]["cvss"]
    assert cvss_meta["scored_count"] == 0
    assert cvss_meta["missing"] == 1
    assert cvss_meta["band_counts"] == {}
