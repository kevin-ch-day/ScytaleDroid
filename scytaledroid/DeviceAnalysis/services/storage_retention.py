"""Audit helpers for APK storage retention planning.

This module is intentionally read-only in its first phase. It scans the current
filesystem layout, groups retained APK payloads by a content-aware identity, and
produces a dry-run retention plan that later prune tooling can consume.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.IO.atomic_write import atomic_write_text


def default_storage_root() -> Path:
    return artifact_store.data_root()


def default_audit_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "audit" / "storage"


def retention_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True)
class PayloadRecord:
    sha256: str
    file_size: int
    artifact_kind: str
    package_name: str | None
    version_code: str | None
    source_kind: str
    device_serial: str | None
    session_label: str | None
    relative_path: str
    absolute_path: str
    receipt_path: str | None
    observed_at_utc: str | None
    discovery_source: str

    @property
    def retention_key(self) -> tuple[str, int, str]:
        return (self.sha256, self.file_size, self.artifact_kind)


def scan_apk_storage(root: Path | None = None) -> tuple[list[PayloadRecord], list[str]]:
    """Return discovered payload records plus non-fatal scan issues."""

    resolved_root = (root or default_storage_root()).resolve()
    records: list[PayloadRecord] = []
    issues: list[str] = []
    claimed_paths: set[str] = set()

    if not resolved_root.exists():
        return records, [f"APK root does not exist: {resolved_root}"]

    manifest_records, manifest_issues, claimed_paths = _scan_harvest_receipts(resolved_root)
    records.extend(manifest_records)
    issues.extend(manifest_issues)

    sidecar_records, sidecar_issues = _scan_standalone_sidecars(resolved_root, claimed_paths)
    records.extend(sidecar_records)
    issues.extend(sidecar_issues)
    return records, issues


def build_retention_audit(
    records: Iterable[PayloadRecord],
    *,
    survivor_policy: str = "oldest",
    issues: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a read-only retention audit for the provided payload records."""

    normalized_policy = _normalize_survivor_policy(survivor_policy)
    records_list = list(records)
    issues_list = list(issues)
    by_identity: dict[tuple[str, int, str], list[PayloadRecord]] = defaultdict(list)
    for record in records_list:
        by_identity[record.retention_key].append(record)

    duplicate_groups: list[dict[str, Any]] = []
    duplicate_payloads = 0
    reclaimable_bytes = 0

    for key, group_records in sorted(by_identity.items()):
        physical_groups: dict[str, list[PayloadRecord]] = defaultdict(list)
        for record in group_records:
            physical_groups[record.absolute_path].append(record)

        if len(physical_groups) <= 1:
            continue

        copies = [rows[0] for rows in physical_groups.values()]
        survivor = _choose_survivor(copies, policy=normalized_policy)
        candidates = [copy for copy in copies if copy.absolute_path != survivor.absolute_path]
        duplicate_payloads += len(candidates)
        reclaimable_bytes += sum(copy.file_size for copy in candidates)

        duplicate_groups.append(
            {
                "retention_key": {
                    "sha256": key[0],
                    "file_size": key[1],
                    "artifact_kind": key[2],
                },
                "payload_copies": len(copies),
                "provenance_receipts": len(group_records),
                "reclaimable_bytes": sum(copy.file_size for copy in candidates),
                "survivor_policy": normalized_policy,
                "retained": _record_to_dict(survivor, provenance_receipts=len(physical_groups[survivor.absolute_path])),
                "candidates": [
                    _record_to_dict(copy, provenance_receipts=len(physical_groups[copy.absolute_path]))
                    for copy in sorted(candidates, key=lambda item: item.absolute_path)
                ],
            }
        )

    sessions = sorted(
        {
            record.session_label
            for record in records_list
            if isinstance(record.session_label, str) and record.session_label.strip()
        }
    )
    packages = sorted(
        {
            record.package_name
            for record in records_list
            if isinstance(record.package_name, str) and record.package_name.strip()
        }
    )

    return {
        "schema_version": "apk_retention_audit_v1",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "policy": {
            "survivor_policy": normalized_policy,
            "retention_identity": ["sha256", "file_size", "artifact_kind"],
        },
        "summary": {
            "records_scanned": len(records_list),
            "unique_retention_keys": len(by_identity),
            "duplicate_groups": len(duplicate_groups),
            "duplicate_payloads": duplicate_payloads,
            "reclaimable_bytes": reclaimable_bytes,
            "sessions_seen": len(sessions),
            "packages_seen": len(packages),
            "issues": len(issues_list),
        },
        "sessions_seen": sessions,
        "packages_seen": packages,
        "issues": issues_list,
        "duplicate_groups": duplicate_groups,
    }


def write_retention_audit(
    audit: Mapping[str, Any],
    *,
    out_dir: Path | None = None,
    stamp: str | None = None,
) -> tuple[Path, Path]:
    """Write JSON and CSV audit outputs and return their paths."""

    resolved_out_dir = (out_dir or default_audit_root()).resolve()
    resolved_out_dir.mkdir(parents=True, exist_ok=True)
    resolved_stamp = stamp or retention_stamp()

    json_path = resolved_out_dir / f"apk_retention_audit_{resolved_stamp}.json"
    csv_path = resolved_out_dir / f"apk_retention_candidates_{resolved_stamp}.csv"

    atomic_write_text(json_path, json.dumps(dict(audit), indent=2, sort_keys=True) + "\n")
    _write_candidate_csv(csv_path, audit)
    return json_path, csv_path


def generate_retention_audit(
    *,
    root: Path | None = None,
    out_dir: Path | None = None,
    survivor_policy: str = "oldest",
    stamp: str | None = None,
) -> tuple[dict[str, Any], Path, Path]:
    """Scan the current APK store and write a dry-run retention audit."""

    records, issues = scan_apk_storage(root)
    audit = build_retention_audit(records, survivor_policy=survivor_policy, issues=issues)
    json_path, csv_path = write_retention_audit(audit, out_dir=out_dir, stamp=stamp)
    return audit, json_path, csv_path


def _scan_harvest_receipts(root: Path) -> tuple[list[PayloadRecord], list[str], set[str]]:
    records: list[PayloadRecord] = []
    issues: list[str] = []
    claimed_paths: set[str] = set()
    receipt_root = root / "receipts" / "harvest"

    for manifest_path in sorted(receipt_root.glob("*/*.json")):
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            issues.append(f"Invalid harvest receipt {manifest_path}: {exc}")
            continue
        if not isinstance(payload, Mapping):
            issues.append(f"Harvest receipt is not an object: {manifest_path}")
            continue

        package = payload.get("package")
        execution = payload.get("execution")
        if not isinstance(package, Mapping) or not isinstance(execution, Mapping):
            issues.append(f"Harvest receipt missing package/execution sections: {manifest_path}")
            continue

        package_name = _maybe_str(package.get("package_name"))
        version_code = _maybe_str(package.get("version_code"))
        session_label = _maybe_str(package.get("session_label"))
        device_serial = _maybe_str(package.get("device_serial"))

        observed = execution.get("observed_artifacts")
        if not isinstance(observed, list):
            continue

        for entry in observed:
            if not isinstance(entry, Mapping):
                continue
            record = _record_from_harvest_entry(
                root=root,
                manifest_path=manifest_path,
                package_name=package_name,
                version_code=version_code,
                session_label=session_label,
                device_serial=device_serial,
                entry=entry,
            )
            if record is None:
                issues.append(f"Incomplete harvest artifact entry in {manifest_path}")
                continue
            claimed_paths.add(record.relative_path)
            records.append(record)

    return records, issues, claimed_paths


def _scan_standalone_sidecars(root: Path, claimed_paths: set[str]) -> tuple[list[PayloadRecord], list[str]]:
    records: list[PayloadRecord] = []
    issues: list[str] = []
    payload_root = root / "store" / "apk"

    for sidecar_path in sorted(payload_root.rglob("*.apk.meta.json")):
        try:
            payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except Exception as exc:
            issues.append(f"Invalid APK sidecar {sidecar_path}: {exc}")
            continue
        if not isinstance(payload, Mapping):
            issues.append(f"APK sidecar is not an object: {sidecar_path}")
            continue

        local_path = _maybe_str(payload.get("local_path"))
        if local_path and local_path in claimed_paths:
            continue

        record = _record_from_sidecar(root=root, sidecar_path=sidecar_path, payload=payload)
        if record is None:
            issues.append(f"Incomplete standalone APK sidecar {sidecar_path}")
            continue
        records.append(record)

    return records, issues


def _record_from_harvest_entry(
    *,
    root: Path,
    manifest_path: Path,
    package_name: str | None,
    version_code: str | None,
    session_label: str | None,
    device_serial: str | None,
    entry: Mapping[str, Any],
) -> PayloadRecord | None:
    sha256 = _maybe_str(entry.get("sha256"))
    local_path = _maybe_str(entry.get("local_artifact_path"))
    canonical_path = _maybe_str(entry.get("canonical_store_path"))
    artifact_kind = _maybe_str(entry.get("split_label")) or _artifact_kind_from_name(_maybe_str(entry.get("file_name")))
    file_size = _coerce_int(entry.get("file_size"))
    observed_at = _maybe_str(entry.get("pulled_at"))
    relative_path = canonical_path or local_path
    if not (sha256 and relative_path and artifact_kind and file_size is not None):
        return None
    absolute_path = (root / relative_path).resolve()
    return PayloadRecord(
        sha256=sha256,
        file_size=file_size,
        artifact_kind=artifact_kind,
        package_name=package_name,
        version_code=version_code,
        source_kind="harvest",
        device_serial=device_serial,
        session_label=session_label,
        relative_path=relative_path,
        absolute_path=str(absolute_path),
        receipt_path=str(manifest_path.resolve()),
        observed_at_utc=observed_at,
        discovery_source="harvest_receipt",
    )


def _record_from_sidecar(
    *,
    root: Path,
    sidecar_path: Path,
    payload: Mapping[str, Any],
) -> PayloadRecord | None:
    sha256 = _maybe_str(payload.get("sha256"))
    local_path = _maybe_str(payload.get("canonical_store_path")) or _maybe_str(payload.get("local_path"))
    file_size = _coerce_int(payload.get("file_size"))
    artifact_kind = _maybe_str(payload.get("artifact")) or _artifact_kind_from_name(sidecar_path.stem)
    if not local_path:
        candidate = sidecar_path.with_name(sidecar_path.name.removesuffix(".meta.json"))
        local_path = _safe_relative(candidate, root)
    if not (sha256 and local_path and artifact_kind):
        return None
    absolute_path = (root / local_path).resolve()
    if file_size is None:
        try:
            file_size = absolute_path.stat().st_size
        except OSError:
            return None
    return PayloadRecord(
        sha256=sha256,
        file_size=file_size,
        artifact_kind=artifact_kind,
        package_name=_maybe_str(payload.get("package_name")),
        version_code=_maybe_str(payload.get("version_code")),
        source_kind=_maybe_str(payload.get("source_kind")) or "unknown",
        device_serial=_maybe_str(payload.get("device_serial")),
        session_label=_maybe_str(payload.get("session_stamp")),
        relative_path=local_path,
        absolute_path=str(absolute_path),
        receipt_path=str(sidecar_path.resolve()),
        observed_at_utc=_maybe_str(payload.get("captured_at")),
        discovery_source="apk_sidecar",
    )


def _choose_survivor(records: list[PayloadRecord], *, policy: str) -> PayloadRecord:
    ordered = sorted(
        records,
        key=lambda record: (
            _sort_timestamp(record.observed_at_utc),
            record.absolute_path,
        ),
    )
    if policy == "newest":
        return ordered[-1]
    return ordered[0]


def _sort_timestamp(value: str | None) -> tuple[int, str]:
    text = (value or "").strip()
    if not text:
        return (1, "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return (0, parsed.astimezone(UTC).isoformat())
    except ValueError:
        return (1, text)


def _normalize_survivor_policy(policy: str) -> str:
    token = (policy or "").strip().lower()
    if token in {"newest", "latest"}:
        return "newest"
    return "oldest"


def _record_to_dict(record: PayloadRecord, *, provenance_receipts: int) -> dict[str, Any]:
    payload = asdict(record)
    payload["provenance_receipts"] = provenance_receipts
    return payload


def _write_candidate_csv(path: Path, audit: Mapping[str, Any]) -> None:
    fieldnames = [
        "sha256",
        "file_size",
        "artifact_kind",
        "retained_path",
        "candidate_path",
        "package_name",
        "version_code",
        "source_kind",
        "device_serial",
        "session_label",
        "receipt_path",
        "observed_at_utc",
        "provenance_receipts",
        "reason",
    ]
    rows: list[dict[str, Any]] = []
    for group in audit.get("duplicate_groups", []):
        if not isinstance(group, Mapping):
            continue
        retained = group.get("retained")
        if not isinstance(retained, Mapping):
            continue
        key = group.get("retention_key")
        if not isinstance(key, Mapping):
            continue
        for candidate in group.get("candidates", []):
            if not isinstance(candidate, Mapping):
                continue
            rows.append(
                {
                    "sha256": key.get("sha256"),
                    "file_size": key.get("file_size"),
                    "artifact_kind": key.get("artifact_kind"),
                    "retained_path": retained.get("relative_path"),
                    "candidate_path": candidate.get("relative_path"),
                    "package_name": candidate.get("package_name"),
                    "version_code": candidate.get("version_code"),
                    "source_kind": candidate.get("source_kind"),
                    "device_serial": candidate.get("device_serial"),
                    "session_label": candidate.get("session_label"),
                    "receipt_path": candidate.get("receipt_path"),
                    "observed_at_utc": candidate.get("observed_at_utc"),
                    "provenance_receipts": candidate.get("provenance_receipts"),
                    "reason": "redundant_payload_copy_same_identity",
                }
            )

    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    tmp_path.replace(path)


def _artifact_kind_from_name(file_name: str | None) -> str:
    token = (file_name or "").strip()
    if not token:
        return "unknown"
    if token.endswith(".apk"):
        token = token[:-4]
    if "__" in token:
        return token.rsplit("__", 1)[-1]
    return token


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _maybe_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


__all__ = [
    "PayloadRecord",
    "build_retention_audit",
    "default_audit_root",
    "default_storage_root",
    "generate_retention_audit",
    "retention_stamp",
    "scan_apk_storage",
    "write_retention_audit",
]
