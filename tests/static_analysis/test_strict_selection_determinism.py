import os


def test_strict_disables_multi_group_latest_selection(monkeypatch):
    # Even if an operator sets the env var, strict/paper mode must force deterministic selection.
    monkeypatch.setenv("SCYTALEDROID_STATIC_ALLOW_MULTI_GROUPS", "1")
    monkeypatch.setenv("SCYTALEDROID_PAPER_STRICT", "1")

    from scytaledroid.StaticAnalysis.cli.flows import selection as sel

    assert sel._allow_multiple_latest() is False

