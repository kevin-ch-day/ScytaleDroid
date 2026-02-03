"""Privacy manifest generation and validation utilities."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PrivacyManifest:
    collected: list[str]
    not_collected: list[str]


DEFAULT_MANIFEST = PrivacyManifest(
    collected=[
        "timestamps",
        "byte_counts",
        "packet_counts",
        "protocol",
        "port",
        "hashed_ip_with_run_salt",
    ],
    not_collected=[
        "payload_content",
        "user_identifiers",
        "full_ip_addresses",
    ],
)


def write_privacy_manifest(output_dir: Path, manifest: PrivacyManifest | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = manifest or DEFAULT_MANIFEST
    path = output_dir / "privacy_manifest.json"
    path.write_text(
        json.dumps(
            {"collected": payload.collected, "not_collected": payload.not_collected},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def validate_privacy_manifest(manifest_path: Path) -> bool:
    if not manifest_path.exists():
        return False
    try:
        payload = json.loads(manifest_path.read_text())
    except json.JSONDecodeError:
        return False
    collected = payload.get("collected")
    not_collected = payload.get("not_collected")
    return isinstance(collected, list) and isinstance(not_collected, list)


__all__ = ["write_privacy_manifest", "validate_privacy_manifest", "PrivacyManifest"]
