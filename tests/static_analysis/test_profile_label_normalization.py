from __future__ import annotations

from scytaledroid.StaticAnalysis.core import repository


def test_normalise_profile_label_strips_legacy_paper_suffix() -> None:
    assert (
        repository._normalise_profile_label("Research Dataset Alpha (Paper #12)")
        == "Research Dataset Alpha"
    )


def test_normalise_profile_label_keeps_non_legacy_label() -> None:
    assert repository._normalise_profile_label("Messaging") == "Messaging"
