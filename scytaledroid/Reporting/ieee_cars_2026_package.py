"""Read-only status assembly for the IEEE-CARS-2026 evidence package."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scytaledroid.Publication.submission_targets import IEEE_CARS_2026

REPO_ROOT = Path(__file__).resolve().parents[2]


def _latest(paths: list[Path]) -> Path | None:
    return max(paths, key=lambda path: path.stat().st_mtime, default=None)


def _read_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def ieee_cars_2026_package_status(*, repo_root: Path) -> dict[str, Any]:
    """Return only paths and readiness metadata; never copy or mutate evidence."""

    paper_root = repo_root / "output" / "paper"
    capsule_root = repo_root / "output" / "audit" / "research_capsules" / IEEE_CARS_2026.identifier
    freeze = _latest(list(paper_root.glob("dynamic_paper_freeze_*/paper_freeze_manifest.json")))
    workspace = _latest(
        [
            *paper_root.glob(f"{IEEE_CARS_2026.identifier}_draft_workspace_*/paper3_source_manifest.json"),
            *paper_root.glob("paper3_draft_workspace_*/paper3_source_manifest.json"),
        ]
    )
    capsule_manifest = _latest(list(capsule_root.glob("manifest_*.json")))
    freeze_payload = _read_json(freeze)
    workspace_payload = _read_json(workspace)
    capsule_payload = _read_json(capsule_manifest)
    workspace_target = workspace_payload.get("publication_target") if isinstance(workspace_payload.get("publication_target"), dict) else {}

    return {
        "target": {
            "identifier": IEEE_CARS_2026.identifier,
            "paper_label": IEEE_CARS_2026.paper_label,
            "generation_label": IEEE_CARS_2026.generation_label,
            "venue": IEEE_CARS_2026.venue,
            "target_format": IEEE_CARS_2026.target_format,
        },
        "freeze_manifest": {
            "path": str(freeze) if freeze else None,
            "readiness_ready": freeze_payload.get("summary", {}).get("ready") if isinstance(freeze_payload.get("summary"), dict) else None,
            "apps_total": freeze_payload.get("summary", {}).get("apps_total") if isinstance(freeze_payload.get("summary"), dict) else None,
        },
        "writing_workspace": {
            "path": str(workspace) if workspace else None,
            "target_identifier": workspace_target.get("submission_id"),
            "target_labeled": workspace_target.get("submission_id") == IEEE_CARS_2026.identifier,
            "manuscript_pdf": workspace_payload.get("manuscript_pdf"),
            "paper_usable_count": workspace_payload.get("paper_usable_count"),
            "apps_total": workspace_payload.get("apps_total"),
        },
        "capsule": {
            "path": str(capsule_manifest) if capsule_manifest else None,
            "ready_to_archive": capsule_payload.get("ready_to_archive") if capsule_manifest else False,
            "missing_required_roles": capsule_payload.get("missing_required_roles", []) if capsule_manifest else ["not generated"],
        },
        "draft_ledgers": sorted(str(path) for path in capsule_root.glob("*_ledger.draft.json")),
        "template_root": str(repo_root / "profiles" / "research_capsules" / IEEE_CARS_2026.identifier),
        "read_only": True,
    }


__all__ = ["ieee_cars_2026_package_status"]
