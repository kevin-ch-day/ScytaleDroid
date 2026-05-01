from __future__ import annotations


def test_profile_v2_ordering_prefers_publication_and_falls_back(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence import menu as evidence_menu

    responses = {
        "publication": ["com.example.publication"],
        "paper2": ["com.example.legacy"],
    }

    monkeypatch.setattr(
        "scytaledroid.Database.db_func.apps.app_ordering.fetch_ordering",
        lambda key: responses.get(key, []),
    )

    assert evidence_menu._fetch_profile_v2_ordering_db() == ["com.example.publication"]

    responses["publication"] = []
    assert evidence_menu._fetch_profile_v2_ordering_db() == ["com.example.legacy"]
