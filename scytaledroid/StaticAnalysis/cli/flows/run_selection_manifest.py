"""Selection manifest helpers for static analysis runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..core.models import ScopeSelection


def _emit_selection_manifest(
    selection: ScopeSelection,
    session_stamp: str | None,
    *,
    execution_id: str | None = None,
) -> None:
    stamp = (session_stamp or "").strip() or "unspecified-session"
    groups = tuple(getattr(selection, "groups", ()) or ())

    capture_distribution: dict[str, int] = {}
    app_rows: list[dict[str, object]] = []
    digest_inputs: list[str] = []

    for group in groups:
        artifacts = tuple(getattr(group, "artifacts", ()) or ())
        package = str(getattr(group, "package_name", "") or "")
        group_key = str(getattr(group, "group_key", "") or "")
        capture_id = str(getattr(group, "capture_id", None) or "unknown")

        capture_distribution[capture_id] = capture_distribution.get(capture_id, 0) + len(artifacts)

        artifact_paths = sorted(
            str(getattr(artifact, "display_path", "") or "")
            for artifact in artifacts
        )

        digest_inputs.extend(path for path in artifact_paths if path)

        app_rows.append(
            {
                "package_name": package,
                "group_key": group_key,
                "capture_id": capture_id,
                "artifact_count": len(artifacts),
                "artifacts": artifact_paths,
            }
        )

    digest_payload = "\n".join(sorted(digest_inputs)).encode("utf-8")

    manifest = {
        "session_stamp": stamp,
        "execution_id": execution_id,
        "scope": getattr(selection, "scope", None),
        "scope_label": getattr(selection, "label", None),
        "group_count": len(groups),
        "artifact_count": sum(int(row["artifact_count"]) for row in app_rows),
        "capture_distribution": dict(sorted(capture_distribution.items())),
        "artifact_manifest_sha256": hashlib.sha256(digest_payload).hexdigest(),
        "apps": sorted(
            app_rows,
            key=lambda row: (str(row.get("package_name", "")), str(row.get("group_key", ""))),
        ),
    }

    out_dir = Path("output") / "audit" / "selection"
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / f"{stamp}_selected_artifacts.json"
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


__all__ = [
    "_emit_selection_manifest",
]