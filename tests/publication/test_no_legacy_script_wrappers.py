from __future__ import annotations

from pathlib import Path


def test_legacy_script_wrappers_removed() -> None:
    # OSS posture: scripts should be named by function (publication/freeze/profile),
    # not by paper IDs. Legacy wrapper directories should not exist.
    legacy = Path("scripts/paper2")
    if not legacy.exists():
        return
    # CI/dev runs may leave __pycache__ behind; tolerate that, but require no shippable code.
    remaining = [p for p in legacy.rglob("*") if p.is_file() and p.name != ".gitkeep"]
    remaining = [p for p in remaining if "__pycache__" not in p.parts]
    assert not remaining, f"legacy scripts/paper2 contains code files: {remaining}"
