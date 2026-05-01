"""Read-only verification of harvested APK evidence using manifests/receipts on disk."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from scytaledroid.DeviceAnalysis.harvest import common as harvest_common


Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class VerifyIssue:
    severity: Severity
    code: str
    manifest: str
    detail: str


def _sha256_bytes(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _resolve_under_repo(*, relative_posix: str, harvest_base: Path, data_root: Path) -> Path:
    raw = Path(relative_posix)
    if raw.is_absolute():
        return raw.resolve()
    posix = relative_posix.replace("\\", "/").strip().lstrip("/")

    cwd_rel = Path.cwd() / posix
    if cwd_rel.exists():
        return cwd_rel.resolve()

    if posix.startswith("data/"):
        rel = posix.removeprefix("data/").lstrip("/")
        candidate = data_root.expanduser().resolve() / rel
        if candidate.exists():
            return candidate.resolve()

    return (harvest_base / posix).resolve()


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _verify_single_manifest(manifest_path: Path, harvest_base: Path, data_root: Path) -> list[VerifyIssue]:
    issues: list[VerifyIssue] = []
    mkey = manifest_path.as_posix()
    try:
        doc = _load_json(manifest_path)
    except Exception as exc:
        issues.append(
            VerifyIssue("error", "manifest_invalid_json", mkey, str(exc)),
        )
        return issues

    schema = str(doc.get("schema") or "")
    if schema != "harvest_package_manifest_v1":
        issues.append(
            VerifyIssue(
                "warning",
                "manifest_schema_unknown",
                mkey,
                f"unexpected schema={schema!r}",
            )
        )

    pkg_block = doc.get("package") if isinstance(doc.get("package"), dict) else {}
    pkg_name = str(pkg_block.get("package_name") or "").strip()

    paths_block = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    legacy_rel = str(paths_block.get("legacy_manifest_path") or "").strip()
    receipt_rel = str(paths_block.get("receipt_path") or "").strip()

    if legacy_rel:
        expected_manifest = _resolve_under_repo(
            relative_posix=legacy_rel, harvest_base=harvest_base, data_root=data_root
        ).resolve()
        if expected_manifest.resolve() != manifest_path.resolve():
            issues.append(
                VerifyIssue(
                    "warning",
                    "manifest_self_path_drift",
                    mkey,
                    f"manifest path_hint {expected_manifest} != loaded {manifest_path}",
                )
            )

    if receipt_rel:
        receipt_abs = _resolve_under_repo(
            relative_posix=receipt_rel, harvest_base=harvest_base, data_root=data_root
        ).resolve()
        if not receipt_abs.exists():
            issues.append(
                VerifyIssue(
                    "error",
                    "receipt_missing",
                    mkey,
                    f"missing receipt: {receipt_abs}",
                )
            )
        else:
            try:
                rec = _load_json(receipt_abs)
                if pkg_name:
                    rp = rec.get("package") if isinstance(rec.get("package"), dict) else {}
                    rname = str(rp.get("package_name") or "").strip()
                    if rname != pkg_name:
                        issues.append(
                            VerifyIssue(
                                "error",
                                "receipt_package_mismatch",
                                mkey,
                                f"receipt pkg {rname!r} vs manifest pkg {pkg_name!r}",
                            )
                        )
            except Exception as exc:
                issues.append(
                    VerifyIssue(
                        "error",
                        "receipt_invalid_json",
                        mkey,
                        str(exc),
                    )
                )

    execution = doc.get("execution") if isinstance(doc.get("execution"), dict) else {}
    observed = execution.get("observed_artifacts")
    if observed is None:
        issues.append(
            VerifyIssue(
                "warning",
                "observed_artifacts_missing",
                mkey,
                "execution.observed_artifacts absent",
            )
        )
    elif isinstance(observed, list):
        for idx, blob in enumerate(observed):
            if not isinstance(blob, dict):
                continue
            outcome = str(blob.get("pull_outcome") or "")
            loc = str(blob.get("local_artifact_path") or "").strip()
            exp_hash = str(blob.get("sha256") or "").strip().lower()

            if not loc:
                continue
            if outcome in {"", "written", None}:
                artifact_abs = _resolve_under_repo(relative_posix=loc, harvest_base=harvest_base, data_root=data_root).resolve()
                if not artifact_abs.exists():
                    issues.append(
                        VerifyIssue(
                            "error",
                            "artifact_missing",
                            mkey,
                            f"[{idx}] missing file {artifact_abs} ({blob.get('file_name')})",
                        )
                    )
                elif exp_hash:
                    digest = _sha256_bytes(artifact_abs)
                    if digest != exp_hash:
                        issues.append(
                            VerifyIssue(
                                "error",
                                "artifact_hash_mismatch",
                                mkey,
                                f"[{idx}] {artifact_abs.name}: stored {exp_hash} actual {digest}",
                            ),
                        )

    cmp = doc.get("comparison") if isinstance(doc.get("comparison"), dict) else {}
    if cmp and not cmp.get("matches_planned_artifacts"):
        issues.append(
            VerifyIssue(
                "warning",
                "comparison_incomplete",
                mkey,
                "planned vs observed mismatch (see manifest comparison block)",
            )
        )

    return issues


def harvest_scan_roots(
    *,
    harvest_root: Path,
    data_root: Path | None,
    serial: str | None,
) -> tuple[Path, Path, list[Path]]:
    """Return ``(normalized_harvest_anchor, data_root Path, harvest_root list to scan)``."""

    root = harvest_root.expanduser().resolve()
    if data_root is None:
        dr = root.parent.resolve() if root.name == "device_apks" else root.resolve()
    else:
        dr = Path(data_root).expanduser().resolve()
    if serial and serial.strip():
        roots = [(root / serial.strip()).resolve()]
    else:
        roots = [root]
    return root, dr, roots


def iter_manifest_written_hashes(
    *,
    harvest_root: Path,
    data_root: Path | None = None,
    serial: str | None = None,
) -> list[tuple[str, str, str]]:
    """Each tuple is ``(manifest_path, package_name, sha256_hex)``.

    Covers ``observed_artifacts`` entries that look materially written with a declared
    hash; skips manifests that fail to parse so filesystem verification can surface
    JSON issues separately.
    """

    _, _dr, roots = harvest_scan_roots(
        harvest_root=harvest_root, data_root=data_root, serial=serial
    )
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    for hr in roots:
        for manifest_path in harvest_common.iter_harvest_package_manifest_paths(hr):
            mkey = manifest_path.as_posix()
            try:
                doc = _load_json(manifest_path)
            except Exception:
                continue
            pkg_block = doc.get("package") if isinstance(doc.get("package"), dict) else {}
            pkg_name = str(pkg_block.get("package_name") or "").strip()

            execution = doc.get("execution") if isinstance(doc.get("execution"), dict) else {}
            observed = execution.get("observed_artifacts")
            if not isinstance(observed, list):
                continue

            for blob in observed:
                if not isinstance(blob, dict):
                    continue
                outcome = str(blob.get("pull_outcome") or "")
                if outcome not in {"", "written"}:
                    continue
                exp_hash = str(blob.get("sha256") or "").strip().lower()
                if len(exp_hash) != 64:
                    continue

                dup_key = (mkey, exp_hash)
                if dup_key in seen:
                    continue
                seen.add(dup_key)
                out.append((mkey, pkg_name, exp_hash))
    return out


def verify_harvest_filesystem(
    *,
    harvest_root: Path,
    data_root: Path | None = None,
    serial: str | None = None,
) -> tuple[list[VerifyIssue], int]:
    """
    Verify manifests under ``harvest_root`` (typically ``DATA_DIR/device_apks``).

    Returns ``(issues, exit_code)`` where ``exit_code`` is 1 if any *error*-severity issue.
    """

    root, dr, roots_list = harvest_scan_roots(
        harvest_root=harvest_root, data_root=data_root, serial=serial
    )
    roots = roots_list

    all_issues: list[VerifyIssue] = []
    for hr in roots:
        for manifest_path in harvest_common.iter_harvest_package_manifest_paths(hr):
            all_issues.extend(_verify_single_manifest(manifest_path, harvest_base=root, data_root=dr))

    if not any(harvest_common.iter_harvest_package_manifest_paths(hr) for hr in roots):
        all_issues.append(
            VerifyIssue(
                "warning",
                "no_harvest_manifests_found",
                str(root),
                f"no harvest_package_manifest.json under {root}" + (f" (serial={serial!r})" if serial else ""),
            ),
        )
    fatal = sum(1 for issue in all_issues if issue.severity == "error")
    return all_issues, 1 if fatal else 0


def format_report(issues: Sequence[VerifyIssue]) -> str:
    lines: list[str] = []
    for issue in sorted(issues, key=lambda item: (item.severity != "error", item.code, item.manifest)):
        prefix = "ERROR " if issue.severity == "error" else "WARN  "
        lines.append(f"{prefix}{issue.code} — {issue.manifest}: {issue.detail}")
    summary = (
        f"Summary: {sum(1 for i in issues if i.severity == 'error')} error(s), "
        f"{sum(1 for i in issues if i.severity == 'warning')} warning(s)"
    )
    return "\n".join(lines + ([] if not lines else [summary]))
