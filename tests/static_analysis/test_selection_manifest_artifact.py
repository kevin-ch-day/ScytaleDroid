from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def test_emit_selection_manifest_writes_capture_distribution(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    apk_path = tmp_path / "repo" / "20260217" / "com.example.app" / "base.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_text("apk", encoding="utf-8")
    artifact = RepositoryArtifact(
        path=apk_path,
        display_path="20260217/com.example.app/base.apk",
        metadata={
            "package_name": "com.example.app",
            "session_stamp": "20260217",
            "split_group_id": 1,
            "version_code": "100",
        },
    )
    group = ArtifactGroup(
        group_key="split-com.example.app-1-20260217-100",
        package_name="com.example.app",
        version_display="100",
        session_stamp="20260217",
        capture_id="20260217",
        artifacts=(artifact,),
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=(group,))

    run_dispatch._emit_selection_manifest(selection, "20260216")  # noqa: SLF001 - contract guard

    out = tmp_path / "output" / "audit" / "selection" / "20260216_selected_artifacts.json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["session_stamp"] == "20260216"
    assert payload["artifact_count"] == 1
    assert payload["capture_distribution"] == {"20260217": 1}
    assert len(payload["artifact_manifest_sha256"]) == 64
