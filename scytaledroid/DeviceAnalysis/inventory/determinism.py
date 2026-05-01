"""Inventory determinism comparator helpers.

This module compares two inventory snapshots using canonical identity keys:

- snapshot identity key:
  (device_serial, package_list_hash, package_signature_hash, scope_hash)
- package identity key:
  (package_name_lc, version_code_norm)

Secondary integrity fields are compared as non-key fields:
- signer_cert_digest
- split_membership_hash
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from scytaledroid.Database.db_utils.package_utils import normalize_package_name

SNAPSHOT_REQUIRED_FIELDS = (
    "device_serial",
    "package_list_hash",
    "package_signature_hash",
    "scope_hash",
)

ROW_REQUIRED_FIELDS = (
    "package_name_lc",
    "version_code_norm",
)

# Allowed differences for comparator-level payload fields only.
ALLOWED_DIFF_FIELDS = (
    "left.timestamp_utc",
    "right.timestamp_utc",
    "left.run_id",
    "right.run_id",
)


@dataclass(frozen=True)
class CompareResult:
    payload: dict[str, Any]
    passed: bool


def _json_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def _normalize_maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text and text[0] in "{[":
            try:
                return _normalize_maybe_json(json.loads(text))
            except Exception:
                return value
        return value
    if isinstance(value, dict):
        return {str(k): _normalize_maybe_json(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_normalize_maybe_json(item) for item in value]
    return value


def _extract_extra(entry: dict[str, Any], key: str) -> str | None:
    extras_raw = entry.get("extras")
    extras = _normalize_maybe_json(extras_raw)
    if not isinstance(extras, dict):
        return None
    value = extras.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_inventory_row(entry: dict[str, Any]) -> dict[str, Any]:
    package_name = str(entry.get("package_name") or "").strip()
    package_name_lc = normalize_package_name(package_name, context="inventory") or package_name.lower()
    version_code_raw = entry.get("version_code")
    version_code_norm = str(version_code_raw).strip() if version_code_raw is not None else ""

    apk_paths = _normalize_maybe_json(entry.get("apk_paths"))
    if isinstance(apk_paths, list):
        split_membership_hash = _json_hash(sorted(str(path) for path in apk_paths))
    else:
        split_membership_hash = _extract_extra(entry, "split_membership_hash")

    signer_cert_digest = _extract_extra(entry, "signer_cert_digest")

    return {
        "package_name_lc": package_name_lc,
        "version_code_norm": version_code_norm,
        "app_label": entry.get("app_label"),
        "version_name": entry.get("version_name"),
        "installer": entry.get("installer"),
        "primary_path": entry.get("primary_path"),
        "split_count": int(entry.get("split_count") or 1),
        "signer_cert_digest": signer_cert_digest,
        "split_membership_hash": split_membership_hash,
    }


def build_snapshot_payload(*, snapshot: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    missing_snapshot_fields = [name for name in SNAPSHOT_REQUIRED_FIELDS if not str(snapshot.get(name) or "").strip()]
    normalized_rows: list[dict[str, Any]] = [normalize_inventory_row(row) for row in rows]

    missing_row_keys: list[dict[str, Any]] = []
    rows_by_key: dict[str, dict[str, Any]] = {}
    duplicate_keys: list[str] = []

    for row in normalized_rows:
        missing = [name for name in ROW_REQUIRED_FIELDS if not str(row.get(name) or "").strip()]
        if missing:
            missing_row_keys.append({"row": row, "missing": missing})
            continue
        row_key = f"{row['package_name_lc']}|{row['version_code_norm']}"
        if row_key in rows_by_key:
            duplicate_keys.append(row_key)
        rows_by_key[row_key] = row

    return {
        "snapshot_identity": {
            "device_serial": snapshot.get("device_serial"),
            "package_list_hash": snapshot.get("package_list_hash"),
            "package_signature_hash": snapshot.get("package_signature_hash"),
            "scope_hash": snapshot.get("scope_hash"),
        },
        "row_count": len(rows_by_key),
        "rows_by_key": {k: rows_by_key[k] for k in sorted(rows_by_key)},
        "validation": {
            "missing_snapshot_fields": missing_snapshot_fields,
            "missing_row_keys": missing_row_keys,
            "duplicate_keys": sorted(set(duplicate_keys)),
        },
    }


def _is_allowed(path: str, allowed_fields: tuple[str, ...]) -> bool:
    if path in allowed_fields:
        return True
    if path.endswith(".created_at") or path.endswith(".updated_at"):
        return True
    return False


def _collect_diffs(
    left: Any,
    right: Any,
    *,
    path: str = "",
    allowed_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    if isinstance(left, dict) and isinstance(right, dict):
        keys = sorted(set(left.keys()) | set(right.keys()))
        for key in keys:
            child = f"{path}.{key}" if path else str(key)
            if key not in left:
                allowed = _is_allowed(child, allowed_fields)
                diffs.append({"path": child, "left": None, "right": right.get(key), "allowed": allowed})
                continue
            if key not in right:
                allowed = _is_allowed(child, allowed_fields)
                diffs.append({"path": child, "left": left.get(key), "right": None, "allowed": allowed})
                continue
            diffs.extend(
                _collect_diffs(
                    left[key],
                    right[key],
                    path=child,
                    allowed_fields=allowed_fields,
                )
            )
        return diffs
    if isinstance(left, list) and isinstance(right, list):
        max_len = max(len(left), len(right))
        for idx in range(max_len):
            child = f"{path}[{idx}]"
            l_item = left[idx] if idx < len(left) else None
            r_item = right[idx] if idx < len(right) else None
            diffs.extend(
                _collect_diffs(
                    l_item,
                    r_item,
                    path=child,
                    allowed_fields=allowed_fields,
                )
            )
        return diffs
    if left != right:
        allowed = _is_allowed(path, allowed_fields)
        diffs.append({"path": path, "left": left, "right": right, "allowed": allowed})
    return diffs


def compare_inventory_payloads(
    *,
    left_payload: dict[str, Any],
    right_payload: dict[str, Any],
    left_meta: dict[str, Any],
    right_meta: dict[str, Any],
    tool_semver: str,
    git_commit: str,
    compare_type: str = "inventory_guard",
) -> CompareResult:
    validation_issues: list[str] = []
    for side_name, payload in (("left", left_payload), ("right", right_payload)):
        validation = payload.get("validation")
        if not isinstance(validation, dict):
            validation_issues.append(f"{side_name}.validation_missing")
            continue
        for key in ("missing_snapshot_fields", "missing_row_keys", "duplicate_keys"):
            value = validation.get(key)
            if isinstance(value, list) and value:
                validation_issues.append(f"{side_name}.{key}")

    diffs = _collect_diffs(
        left_payload,
        right_payload,
        allowed_fields=ALLOWED_DIFF_FIELDS,
    )
    allowed_count = sum(1 for item in diffs if item["allowed"])
    disallowed_count = sum(1 for item in diffs if not item["allowed"])
    passed = disallowed_count == 0 and not validation_issues

    result = {
        "tool_semver": tool_semver,
        "git_commit": git_commit,
        "compare_type": compare_type,
        "left": left_meta,
        "right": right_meta,
        "allowed_diff_fields": list(ALLOWED_DIFF_FIELDS),
        "result": {
            "pass": passed,
            "degraded": False,
            "degraded_reasons": [],
            "fail_reason": None if passed else ("validation_error" if validation_issues else "disallowed_diffs"),
            "validation_issues": validation_issues,
            "diff_counts": {
                "total": len(diffs),
                "allowed": allowed_count,
                "disallowed": disallowed_count,
            },
        },
        "diffs": diffs,
    }
    return CompareResult(payload=result, passed=passed)


__all__ = [
    "SNAPSHOT_REQUIRED_FIELDS",
    "ROW_REQUIRED_FIELDS",
    "ALLOWED_DIFF_FIELDS",
    "CompareResult",
    "normalize_inventory_row",
    "build_snapshot_payload",
    "compare_inventory_payloads",
]
