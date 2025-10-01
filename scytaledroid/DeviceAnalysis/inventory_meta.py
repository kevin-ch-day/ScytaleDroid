"""Helpers for persisting and comparing inventory metadata snapshots."""

from __future__ import annotations

import json
import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence, Tuple

from scytaledroid.Config import app_config


def _state_root() -> Path:
    return Path(app_config.DATA_DIR) / app_config.DEVICE_STATE_DIR


@dataclass(frozen=True)
class InventoryMeta:
    """Lightweight metadata persisted next to inventory snapshots."""

    serial: str
    captured_at: datetime
    package_count: int
    package_list_hash: Optional[str] = None
    package_signature_hash: Optional[str] = None
    build_fingerprint: Optional[str] = None
    duration_seconds: Optional[float] = None

    def to_payload(self) -> dict:
        payload = asdict(self)
        payload["captured_at"] = self.captured_at.astimezone(timezone.utc).isoformat()
        return payload

    @staticmethod
    def from_payload(payload: dict) -> "InventoryMeta | None":
        serial = payload.get("serial")
        timestamp = payload.get("captured_at")
        count = payload.get("package_count")

        if not isinstance(serial, str) or not isinstance(count, int):
            return None

        captured_at = _parse_timestamp(timestamp)
        if not captured_at:
            return None

        package_list_hash = payload.get("package_list_hash")
        if not isinstance(package_list_hash, str):
            package_list_hash = None

        package_signature_hash = payload.get("package_signature_hash")
        if not isinstance(package_signature_hash, str):
            package_signature_hash = None

        fingerprint = payload.get("build_fingerprint")
        if not isinstance(fingerprint, str):
            fingerprint = None

        duration_seconds = payload.get("duration_seconds")
        if isinstance(duration_seconds, (int, float)):
            duration_value = float(duration_seconds)
        elif isinstance(duration_seconds, str):
            try:
                duration_value = float(duration_seconds)
            except ValueError:
                duration_value = None
        else:
            duration_value = None

        return InventoryMeta(
            serial=serial,
            captured_at=captured_at,
            package_count=count,
            package_list_hash=package_list_hash,
            package_signature_hash=package_signature_hash,
            build_fingerprint=fingerprint,
            duration_seconds=duration_value,
        )

    def write_files(self, timestamp: str) -> None:
        base_dir = _state_root() / self.serial / "inventory"
        base_dir.mkdir(parents=True, exist_ok=True)

        payload = self.to_payload()
        latest_path = base_dir / "latest.meta.json"
        latest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        if timestamp:
            history_path = base_dir / f"inventory_{timestamp}.meta.json"
            history_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_latest(serial: str) -> Optional[InventoryMeta]:
    base_dir = _state_root() / serial / "inventory"
    latest_path = base_dir / "latest.meta.json"
    if not latest_path.exists():
        return None

    try:
        payload = json.loads(latest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    return InventoryMeta.from_payload(payload)


def compute_name_hash(package_names: Iterable[str]) -> Optional[str]:
    tokens = [name for name in package_names if isinstance(name, str) and name]
    if not tokens:
        return None

    digest = hashlib.sha256()
    for name in sorted(tokens):
        digest.update(name.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def compute_signature_hash(
    signatures: Iterable[Tuple[str, Optional[str], Optional[str]]]
) -> Optional[str]:
    tokens = [_signature_token(name, version_code, version_name) for name, version_code, version_name in signatures]
    filtered = [token for token in tokens if token]
    if not filtered:
        return None

    digest = hashlib.sha256()
    for token in sorted(filtered):
        digest.update(token.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def snapshot_signatures(rows: Sequence[dict]) -> Iterator[Tuple[str, Optional[str], Optional[str]]]:
    for row in rows:
        if not isinstance(row, dict):
            continue
        package_name = row.get("package_name")
        if not isinstance(package_name, str) or not package_name:
            continue
        version_code = row.get("version_code")
        version_name = row.get("version_name")
        if not isinstance(version_code, (str, int)):
            version_code = None
        if not isinstance(version_name, str):
            version_name = None
        yield package_name, _stringify(version_code), version_name


def _signature_token(
    package_name: Optional[str],
    version_code: Optional[str],
    version_name: Optional[str],
) -> str:
    if not package_name:
        return ""

    if version_code:
        version_part = version_code
    elif version_name:
        version_part = version_name
    else:
        version_part = ""

    return f"{package_name}:{version_part}" if version_part else package_name


def _stringify(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _parse_timestamp(raw: Optional[str]) -> Optional[datetime]:
    if not isinstance(raw, str):
        return None

    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


__all__ = [
    "InventoryMeta",
    "load_latest",
    "compute_name_hash",
    "compute_signature_hash",
    "snapshot_signatures",
]
