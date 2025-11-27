"""Helpers for persisting and comparing inventory metadata snapshots."""

from __future__ import annotations

import json
import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, Mapping, Optional, Sequence, Tuple

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
    snapshot_type: Optional[str] = None
    scope_hash: Optional[str] = None
    scope_size: Optional[int] = None
    scope_hashes: Optional[Dict[str, str]] = None
    snapshot_id: Optional[int] = None
    # Optional diff metadata (populated by runner)
    delta_new: Optional[int] = None
    delta_removed: Optional[int] = None
    delta_updated: Optional[int] = None
    delta_changed_count: Optional[int] = None
    delta_split_delta: Optional[int] = None

    def to_payload(self) -> dict:
        payload = asdict(self)
        payload["captured_at"] = self.captured_at.astimezone(timezone.utc).isoformat()
        snapshot_type = payload.pop("snapshot_type", None)
        if snapshot_type:
            payload["type"] = snapshot_type
        scope_hash = payload.get("scope_hash")
        if scope_hash is None:
            payload.pop("scope_hash", None)
        scope_size = payload.get("scope_size")
        if scope_size is None:
            payload.pop("scope_size", None)
        if self.scope_hashes is None:
            payload.pop("scope_hashes", None)
        # Drop unset delta fields to avoid bloating meta files
        for field in (
            "delta_new",
            "delta_removed",
            "delta_updated",
            "delta_changed_count",
            "delta_split_delta",
        ):
            if payload.get(field) is None:
                payload.pop(field, None)
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

        scope_hashes_payload = payload.get("scope_hashes")
        scope_hashes: Optional[Dict[str, str]] = None
        if isinstance(scope_hashes_payload, dict):
            filtered: Dict[str, str] = {}
            for key, value in scope_hashes_payload.items():
                if isinstance(key, str) and isinstance(value, str):
                    filtered[key] = value
            if filtered:
                scope_hashes = filtered

        snapshot_type = payload.get("type") or payload.get("snapshot_type")
        if not isinstance(snapshot_type, str):
            snapshot_type = None

        scope_hash = payload.get("scope_hash")
        if not isinstance(scope_hash, str):
            scope_hash = None

        scope_size_value = payload.get("scope_size")
        if isinstance(scope_size_value, int):
            scope_size = scope_size_value
        elif isinstance(scope_size_value, str) and scope_size_value.isdigit():
            scope_size = int(scope_size_value)
        else:
            scope_size = None

        snapshot_identifier = payload.get("snapshot_id")
        if isinstance(snapshot_identifier, (int, float)):
            snapshot_id = int(snapshot_identifier)
        elif isinstance(snapshot_identifier, str) and snapshot_identifier.isdigit():
            snapshot_id = int(snapshot_identifier)
        else:
            snapshot_id = None

        # Optional delta fields (may be absent on older snapshots)
        def _coerce_int(value: object) -> Optional[int]:
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str) and value.isdigit():
                return int(value)
            return None

        delta_new = _coerce_int(payload.get("delta_new"))
        delta_removed = _coerce_int(payload.get("delta_removed"))
        delta_updated = _coerce_int(payload.get("delta_updated"))
        delta_changed_count = _coerce_int(payload.get("delta_changed_count"))
        delta_split_delta = _coerce_int(payload.get("delta_split_delta"))

        return InventoryMeta(
            serial=serial,
            captured_at=captured_at,
            package_count=count,
            package_list_hash=package_list_hash,
            package_signature_hash=package_signature_hash,
            build_fingerprint=fingerprint,
            duration_seconds=duration_value,
            snapshot_type=snapshot_type,
            scope_hash=scope_hash,
            scope_size=scope_size,
            scope_hashes=scope_hashes,
            snapshot_id=snapshot_id,
            delta_new=delta_new,
            delta_removed=delta_removed,
            delta_updated=delta_updated,
            delta_changed_count=delta_changed_count,
            delta_split_delta=delta_split_delta,
        )

    def write_files(self, timestamp: str, *, suffix: Optional[str] = None) -> None:
        base_dir = _state_root() / self.serial / "inventory"
        base_dir.mkdir(parents=True, exist_ok=True)

        payload = self.to_payload()
        latest_path = base_dir / "latest.meta.json"
        latest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        if suffix:
            suffix_path = base_dir / f"latest.{suffix}.meta.json"
            suffix_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

        if timestamp:
            suffix_segment = f".{suffix}" if suffix else ""
            history_path = base_dir / f"inventory_{timestamp}{suffix_segment}.meta.json"
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


def compute_scope_hash(packages: Sequence[Mapping[str, object]]) -> Optional[str]:
    tokens = []
    for entry in packages:
        if not isinstance(entry, Mapping):
            continue
        package_name = entry.get("package_name")
        if not isinstance(package_name, str) or not package_name:
            continue
        version_code = entry.get("version_code")
        if isinstance(version_code, (int, float)):
            version_token = str(int(version_code))
        elif isinstance(version_code, str) and version_code.strip():
            version_token = version_code.strip()
        else:
            version_token = ""
        tokens.append(f"{package_name}:{version_token}" if version_token else package_name)

    if not tokens:
        return None

    digest = hashlib.sha256()
    for token in sorted(tokens):
        digest.update(token.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def update_scope_hash(serial: str, scope_id: str, scope_hash: Optional[str]) -> Optional[Dict[str, str]]:
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

    existing = payload.get("scope_hashes")
    scope_hashes: Dict[str, str] = {}
    if isinstance(existing, dict):
        for key, value in existing.items():
            if isinstance(key, str) and isinstance(value, str):
                scope_hashes[key] = value

    if scope_hash:
        scope_hashes[scope_id] = scope_hash
    elif scope_id in scope_hashes:
        del scope_hashes[scope_id]

    if scope_hashes:
        payload["scope_hashes"] = scope_hashes
    elif "scope_hashes" in payload:
        payload.pop("scope_hashes")

    latest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return scope_hashes or None


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
    "compute_scope_hash",
    "update_scope_hash",
    "snapshot_signatures",
]
