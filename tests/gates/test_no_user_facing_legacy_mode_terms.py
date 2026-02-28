from __future__ import annotations

from pathlib import Path


def test_no_user_facing_paper_mode_phrase_regression() -> None:
    """Prevent legacy user-facing wording from reappearing in the OSS UI.

    Internal contract keys may retain 'paper*' for backward compatibility.
    This gate only blocks the confusing UI/help/error phrase "paper mode".
    """

    roots = [
        Path("scytaledroid/Reporting"),
        Path("scytaledroid/DynamicAnalysis/controllers"),
        Path("scytaledroid/DynamicAnalysis/pcap"),
        Path("scytaledroid/DynamicAnalysis/run_summary.py"),
    ]
    haystack = ""
    for root in roots:
        if root.is_file():
            haystack += root.read_text(encoding="utf-8", errors="replace").lower() + "\n"
            continue
        if not root.exists():
            continue
        for p in sorted(root.rglob("*.py")):
            haystack += p.read_text(encoding="utf-8", errors="replace").lower() + "\n"

    assert "paper mode" not in haystack

