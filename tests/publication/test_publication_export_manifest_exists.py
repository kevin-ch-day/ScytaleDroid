from __future__ import annotations

import json
from pathlib import Path


def test_paper2_export_manifest_exists_and_has_schema():
    path = Path("tests/baseline/paper2_export_manifest.json")
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload.get("manifest_version") == 1
    assert payload.get("paper") == "paper2"
    artifacts = payload.get("artifacts")
    assert isinstance(artifacts, list)
    assert artifacts, "baseline manifest must lock at least one artifact"
    seen: set[str] = set()
    for entry in artifacts:
        assert isinstance(entry, dict)
        rel = str(entry.get("path") or "").strip()
        assert rel
        assert rel not in seen
        seen.add(rel)
        assert str(entry.get("normalization") or "").strip() in {"none", "tex_whitespace_lf"}
        digest = str(entry.get("sha256") or "").strip().lower()
        assert len(digest) == 64
        assert all(ch in "0123456789abcdef" for ch in digest)
        size = entry.get("size_bytes")
        assert isinstance(size, int) and size >= 0
