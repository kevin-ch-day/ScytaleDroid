from __future__ import annotations
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "scytaledroid"

BAD_PATTERNS = [
    re.compile(r"\\bscytaledroid\\.StaticAnalysis\\.core\\._androguard\\b"),
    re.compile(r"from\\s+\\.\\s*_androguard\\s+import\\b"),  # wrong when used inside core/*
]

def scan_files():
    for path in SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        yield path, text

def test_no_core_wrapper_references():
    offenders = []
    for path, text in scan_files():
        for pattern in BAD_PATTERNS:
            if pattern.search(text):
                offenders.append((str(path.relative_to(ROOT)), pattern.pattern))
                break

    assert not offenders, (
        "Found references to the wrong _androguard path or relative import.\n"
        + "\n".join(f"- {filename}: {pattern}" for filename, pattern in offenders)
    )
