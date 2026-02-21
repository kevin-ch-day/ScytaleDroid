from __future__ import annotations

from pathlib import Path


_ALLOWED_RAW_ANSI_FILES = {
    Path("scytaledroid/Utils/DisplayUtils/colors/ansi.py"),
    Path("scytaledroid/Utils/DisplayUtils/text_blocks.py"),
    Path("scytaledroid/DeviceAnalysis/inventory/progress.py"),
}


def test_raw_ansi_sequences_are_limited_to_allowlist() -> None:
    root = Path(__file__).resolve().parents[2]
    violations: list[str] = []
    for path in root.joinpath("scytaledroid").rglob("*.py"):
        rel = path.relative_to(root)
        content = path.read_text(encoding="utf-8")
        has_raw_ansi = "\\033[" in content or "\\x1b[" in content
        if has_raw_ansi and rel not in _ALLOWED_RAW_ANSI_FILES:
            violations.append(str(rel))
    assert violations == []
