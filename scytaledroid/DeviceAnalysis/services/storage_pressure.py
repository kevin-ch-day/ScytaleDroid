"""Read-only APK storage-pressure and thin-session eligibility audit.

This module complements ``storage_retention``.  Retention answers "which
retained payload copies share the same identity?"; this audit answers "which
run-scoped session APK payloads still consume bytes and can be represented as
thin evidence links to the canonical SHA-256 store?"
"""

from __future__ import annotations

import csv
import json
import stat
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256 as _sha256
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

try:  # The DB read model is optional for pure filesystem unit tests.
    from scytaledroid.Database.db_scripts import package_lineage_read_model
except Exception:  # pragma: no cover - import depends on the operator DB package path.
    package_lineage_read_model = None  # type: ignore[assignment]

SCHEMA_VERSION = "storage_pressure_audit_v1"

STATUS_ELIGIBLE_VERIFIED = "eligible_verified"
STATUS_ELIGIBLE_UNVERIFIED = "eligible_unverified"
STATUS_ALREADY_THIN_SYMLINK = "already_thin_symlink"
STATUS_BLOCKED_CANONICAL_MISSING = "blocked_canonical_missing"
STATUS_BLOCKED_HASH_MISMATCH = "blocked_hash_mismatch"
STATUS_BLOCKED_MISSING_SIDECAR = "blocked_missing_sidecar"
STATUS_BLOCKED_MISSING_MANIFEST = "blocked_missing_manifest"
STATUS_BLOCKED_OLD_ROOT = "blocked_old_root"
STATUS_HISTORICAL_IDENTITY_ONLY = "historical_identity_only"
STATUS_BLOCKED_IDENTITY_UNKNOWN = "blocked_identity_unknown"

_SESSION_STATUSES = {
    STATUS_ELIGIBLE_VERIFIED,
    STATUS_ELIGIBLE_UNVERIFIED,
    STATUS_ALREADY_THIN_SYMLINK,
    STATUS_BLOCKED_CANONICAL_MISSING,
    STATUS_BLOCKED_HASH_MISMATCH,
    STATUS_BLOCKED_MISSING_SIDECAR,
    STATUS_BLOCKED_MISSING_MANIFEST,
    STATUS_BLOCKED_IDENTITY_UNKNOWN,
}


@dataclass(frozen=True)
class DbArtifactIdentity:
    """A read-only APK identity/path row from the core database."""

    row_source: str
    artifact_id: str | None
    package_name: str | None
    version_code: str | None
    version_name: str | None
    file_name: str | None
    file_size: int | None
    sha256: str | None
    is_split_member: bool
    split_group_id: str | None
    device_serial: str | None
    harvested_at: str | None
    storage_root_id: str | None
    data_root: str | None
    local_rel_path: str | None
    recorded_abs_path: str | None
    recorded_root_exists: bool
    recorded_path_exists: bool
    canonical_rel_path: str | None
    canonical_abs_path: str | None
    canonical_exists: bool
    status: str

    @property
    def identity_key(self) -> str:
        if self.artifact_id:
            return f"{self.row_source}:{self.artifact_id}"
        return f"{self.row_source}:{self.package_name or ''}:{self.version_code or ''}:{self.sha256 or ''}:{self.local_rel_path or ''}"


@dataclass(frozen=True)
class SessionCopyRecord:
    """A filesystem observation for one run-scoped APK path."""

    status: str
    session_rel_path: str
    session_abs_path: str
    file_size: int
    reclaimable_bytes: int
    is_symlink: bool
    identity_known: bool
    canonical_bytes_available: bool
    session_copy_bytes_present: bool
    historical_provenance_only: bool
    sha256: str | None
    package_name: str | None
    version_code: str | None
    version_name: str | None
    artifact_kind: str | None
    canonical_rel_path: str | None
    canonical_abs_path: str | None
    sidecar_rel_path: str | None
    manifest_rel_path: str | None
    issue: str | None


def default_storage_root() -> Path:
    return artifact_store.data_root()


def default_audit_root() -> Path:
    return Path(app_config.OUTPUT_DIR) / "audit" / "storage"


def storage_pressure_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def collect_db_artifact_identities(core_q: Any, *, root: Path | None = None) -> tuple[list[DbArtifactIdentity], list[str]]:
    """Read APK identities from the current MariaDB-backed core DB.

    The function performs SELECTs only.  It uses the lineage read model's
    ``table_exists`` helper to avoid hard-failing on partially migrated schemas.
    """

    if core_q is None:
        return [], ["core DB query module was not supplied; DB identity truth unavailable"]
    if package_lineage_read_model is None:
        return [], ["package_lineage_read_model import failed; DB identity truth unavailable"]

    issues: list[str] = []
    try:
        has_repo = package_lineage_read_model.table_exists(core_q, "android_apk_repository")
    except Exception as exc:
        return [], [f"failed to inspect DB schema: {exc}"]
    if not has_repo:
        return [], ["android_apk_repository table is not present"]

    try:
        has_paths = package_lineage_read_model.table_exists(core_q, "harvest_artifact_paths")
        has_roots = package_lineage_read_model.table_exists(core_q, "harvest_storage_roots")
    except Exception as exc:
        issues.append(f"failed to inspect harvest path/root tables: {exc}")
        has_paths = False
        has_roots = False

    joins = ""
    select_path_cols = "NULL AS storage_root_id, NULL AS local_rel_path, NULL AS data_root"
    group_path_cols = ""
    if has_paths and has_roots:
        joins = """
          LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
          LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
        """
        select_path_cols = "h.storage_root_id, h.local_rel_path, sr.data_root"
        group_path_cols = ", h.storage_root_id, h.local_rel_path, sr.data_root"
    elif has_paths:
        joins = "LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id"
        select_path_cols = "h.storage_root_id, h.local_rel_path, NULL AS data_root"
        group_path_cols = ", h.storage_root_id, h.local_rel_path"

    rows = core_q.run_sql(
        f"""
        SELECT
          'android_apk_repository' AS row_source,
          CAST(r.apk_id AS CHAR) AS artifact_id,
          LOWER(TRIM(r.package_name)) AS package_name,
          r.version_code,
          r.version_name,
          r.file_name,
          r.file_size,
          LOWER(TRIM(r.sha256)) AS sha256,
          COALESCE(r.is_split_member, 0) AS is_split_member,
          r.split_group_id,
          r.device_serial,
          r.harvested_at,
          {select_path_cols}
        FROM android_apk_repository r
        {joins}
        WHERE r.sha256 IS NOT NULL
        GROUP BY
          r.apk_id,
          LOWER(TRIM(r.package_name)),
          r.version_code,
          r.version_name,
          r.file_name,
          r.file_size,
          LOWER(TRIM(r.sha256)),
          COALESCE(r.is_split_member, 0),
          r.split_group_id,
          r.device_serial,
          r.harvested_at
          {group_path_cols}
        """,
        fetch="all",
        dictionary=True,
        query_name="storage_pressure.apk_repository_identities",
    ) or []

    data_root = (root or default_storage_root()).expanduser().resolve()
    identities = [_db_identity_from_row(dict(row), root=data_root) for row in rows]
    return identities, issues


def collect_storage_roots(core_q: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Return configured harvest storage roots with existence state."""

    if core_q is None or package_lineage_read_model is None:
        return [], []
    try:
        if not package_lineage_read_model.table_exists(core_q, "harvest_storage_roots"):
            return [], []
        rows = core_q.run_sql(
            """
            SELECT
              sr.root_id,
              sr.data_root,
              COUNT(h.apk_id) AS apk_path_rows
            FROM harvest_storage_roots sr
            LEFT JOIN harvest_artifact_paths h ON h.storage_root_id = sr.root_id
            GROUP BY sr.root_id, sr.data_root
            ORDER BY sr.root_id
            """,
            fetch="all",
            dictionary=True,
            query_name="storage_pressure.harvest_storage_roots",
        ) or []
    except Exception as exc:
        return [], [f"failed to read harvest_storage_roots: {exc}"]

    result: list[dict[str, Any]] = []
    for row in rows:
        path_text = _maybe_str(row.get("data_root"))
        path_exists = bool(path_text and Path(path_text).expanduser().exists())
        result.append(
            {
                "root_id": row.get("root_id"),
                "data_root": path_text,
                "exists": path_exists,
                "apk_path_rows": _coerce_int(row.get("apk_path_rows")) or 0,
            }
        )
    return result, []


def scan_canonical_apk_store(root: Path | None = None) -> dict[str, Any]:
    """Count canonical SHA-256 APK payload files under ``store/apk/sha256``."""

    data_root = (root or default_storage_root()).expanduser().resolve()
    store_root = data_root / "store" / "apk" / "sha256"
    files = 0
    bytes_total = 0
    symlinks = 0
    if not store_root.exists():
        return {
            "root": _safe_relative(store_root, data_root),
            "exists": False,
            "files": 0,
            "bytes": 0,
            "symlinks": 0,
        }
    for path in sorted(store_root.rglob("*.apk")):
        try:
            st = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            symlinks += 1
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        files += 1
        bytes_total += int(st.st_size)
    return {
        "root": _safe_relative(store_root, data_root),
        "exists": True,
        "files": files,
        "bytes": bytes_total,
        "symlinks": symlinks,
    }


def scan_session_copy_pressure(
    *,
    root: Path | None = None,
    db_identities: Iterable[DbArtifactIdentity] = (),
    verify_candidates: bool = False,
) -> tuple[list[SessionCopyRecord], list[str]]:
    """Scan run-scoped session APK paths and classify thin-session eligibility."""

    data_root = (root or default_storage_root()).expanduser().resolve()
    session_root = data_root / "device_apks"
    issues: list[str] = []
    if not session_root.exists():
        return [], [f"session APK root does not exist: {session_root}"]

    identity_index = _IdentityIndex(db_identities)
    records: list[SessionCopyRecord] = []
    for apk_path in sorted(session_root.rglob("*.apk")):
        try:
            records.append(
                _classify_session_apk(
                    apk_path=apk_path,
                    root=data_root,
                    session_root=session_root,
                    identity_index=identity_index,
                    verify_candidates=verify_candidates,
                )
            )
        except Exception as exc:  # Keep the audit best-effort and read-only.
            rel_path = _safe_relative(apk_path, data_root)
            issues.append(f"failed to classify {rel_path}: {exc}")
    return records, issues


def build_storage_pressure_audit(
    *,
    root: Path | None = None,
    db_identities: Iterable[DbArtifactIdentity] = (),
    session_records: Iterable[SessionCopyRecord] = (),
    canonical_summary: Mapping[str, Any] | None = None,
    storage_roots: Iterable[Mapping[str, Any]] = (),
    issues: Iterable[str] = (),
    verify_candidates: bool = False,
) -> dict[str, Any]:
    """Build the read-only storage-pressure report payload."""

    data_root = (root or default_storage_root()).expanduser().resolve()
    db_rows = list(db_identities)
    session_rows = list(session_records)
    canonical = dict(canonical_summary or scan_canonical_apk_store(data_root))
    issue_rows = list(issues)
    roots = [dict(row) for row in storage_roots]

    status_counts = Counter(row.status for row in session_rows)
    db_status_counts = Counter(row.status for row in db_rows)
    regular_session_rows = [row for row in session_rows if row.session_copy_bytes_present]

    unique_db_artifacts = {row.identity_key for row in db_rows}
    unique_db_hashes = {row.sha256 for row in db_rows if row.sha256}
    base_hashes = {row.sha256 for row in db_rows if row.sha256 and not row.is_split_member}
    split_rows = [row for row in db_rows if row.is_split_member]
    packages = {row.package_name for row in db_rows if row.package_name}
    canonical_available_hashes = {row.sha256 for row in db_rows if row.sha256 and row.canonical_exists}

    historical_rows = [row for row in db_rows if row.status == STATUS_HISTORICAL_IDENTITY_ONLY]
    old_root_rows = [row for row in db_rows if row.status == STATUS_BLOCKED_OLD_ROOT]

    eligible_verified = status_counts.get(STATUS_ELIGIBLE_VERIFIED, 0)
    eligible_unverified = status_counts.get(STATUS_ELIGIBLE_UNVERIFIED, 0)
    reclaimable_bytes = sum(
        row.reclaimable_bytes
        for row in session_rows
        if row.status in {STATUS_ELIGIBLE_VERIFIED, STATUS_ELIGIBLE_UNVERIFIED}
    )
    verified_reclaimable_bytes = sum(
        row.reclaimable_bytes for row in session_rows if row.status == STATUS_ELIGIBLE_VERIFIED
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "read_only",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "policy": {
            "identity_authority": "core_db.android_apk_repository",
            "byte_authority": "data/store/apk/sha256/<sha256[:2]>/<sha256>.apk",
            "session_scope": "data/device_apks/<serial>/runs/<run_id>/...",
            "verify_candidates": bool(verify_candidates),
            "reclaimable_statuses": [STATUS_ELIGIBLE_VERIFIED, STATUS_ELIGIBLE_UNVERIFIED],
        },
        "roots": {
            "data_root": str(data_root),
            "session_root": _safe_relative(data_root / "device_apks", data_root),
            "canonical_store": canonical,
            "harvest_storage_roots": roots,
        },
        "truths": {
            "identity_known_in_db": {
                "apk_artifact_rows": len(unique_db_artifacts),
                "apk_path_rows": len(db_rows),
                "packages": len(packages),
                "apk_hash_identities": len(unique_db_hashes),
                "base_apk_identities": len(base_hashes),
                "split_member_rows": len(split_rows),
            },
            "canonical_bytes_available": {
                "canonical_files": int(canonical.get("files") or 0),
                "canonical_bytes": int(canonical.get("bytes") or 0),
                "db_hashes_available_canonical": len(canonical_available_hashes),
                "db_hashes_missing_canonical": max(0, len(unique_db_hashes) - len(canonical_available_hashes)),
            },
            "session_copy_bytes_present": {
                "session_regular_apk_files": len(regular_session_rows),
                "session_regular_apk_bytes": sum(row.file_size for row in regular_session_rows),
                "already_thin_symlinks": status_counts.get(STATUS_ALREADY_THIN_SYMLINK, 0),
            },
            "historical_provenance_only": {
                "rows": len(historical_rows),
                "old_root_blocked_rows": len(old_root_rows),
            },
        },
        "summary": {
            "session_apk_files_seen": len(session_rows),
            "session_regular_apk_files": len(regular_session_rows),
            "session_regular_apk_bytes": sum(row.file_size for row in regular_session_rows),
            "canonical_apk_files": int(canonical.get("files") or 0),
            "canonical_apk_bytes": int(canonical.get("bytes") or 0),
            "eligible_verified_files": eligible_verified,
            "eligible_unverified_files": eligible_unverified,
            "eligible_reclaimable_bytes": reclaimable_bytes,
            "eligible_verified_reclaimable_bytes": verified_reclaimable_bytes,
            "blocked_files": sum(
                count
                for status_name, count in status_counts.items()
                if status_name.startswith("blocked_")
            ),
            "historical_identity_only_rows": len(historical_rows),
            "old_root_blocked_rows": len(old_root_rows),
            "issues": len(issue_rows),
        },
        "status_counts": dict(sorted(status_counts.items())),
        "db_status_counts": dict(sorted(db_status_counts.items())),
        "issues": issue_rows,
        "session_files": [_session_record_to_dict(row) for row in session_rows],
        "historical_identity_rows": [_db_identity_to_dict(row) for row in historical_rows[:500]],
    }


def generate_storage_pressure_audit(
    *,
    root: Path | None = None,
    out_dir: Path | None = None,
    stamp: str | None = None,
    core_q: Any | None = None,
    verify_candidates: bool = False,
) -> tuple[dict[str, Any], Path, Path]:
    """Collect DB/filesystem pressure data, write JSON/CSV, and return paths."""

    data_root = (root or default_storage_root()).expanduser().resolve()
    db_identities, db_issues = collect_db_artifact_identities(core_q, root=data_root) if core_q is not None else ([], [])
    storage_roots, root_issues = collect_storage_roots(core_q) if core_q is not None else ([], [])
    canonical = scan_canonical_apk_store(data_root)
    session_records, scan_issues = scan_session_copy_pressure(
        root=data_root,
        db_identities=db_identities,
        verify_candidates=verify_candidates,
    )
    audit = build_storage_pressure_audit(
        root=data_root,
        db_identities=db_identities,
        session_records=session_records,
        canonical_summary=canonical,
        storage_roots=storage_roots,
        issues=[*db_issues, *root_issues, *scan_issues],
        verify_candidates=verify_candidates,
    )
    json_path, csv_path = write_storage_pressure_audit(audit, out_dir=out_dir, stamp=stamp)
    return audit, json_path, csv_path


def write_storage_pressure_audit(audit: Mapping[str, Any], *, out_dir: Path | None = None, stamp: str | None = None) -> tuple[Path, Path]:
    resolved_out_dir = (out_dir or default_audit_root()).expanduser().resolve()
    resolved_out_dir.mkdir(parents=True, exist_ok=True)
    resolved_stamp = stamp or storage_pressure_stamp()
    json_path = resolved_out_dir / f"storage_pressure_audit_{resolved_stamp}.json"
    csv_path = resolved_out_dir / f"storage_pressure_files_{resolved_stamp}.csv"
    atomic_write_text(json_path, json.dumps(dict(audit), indent=2, sort_keys=True, default=str) + "\n")
    _write_session_csv(csv_path, audit)
    return json_path, csv_path


class _IdentityIndex:
    def __init__(self, identities: Iterable[DbArtifactIdentity]) -> None:
        self.by_sha: dict[str, list[DbArtifactIdentity]] = {}
        self.by_rel_path: dict[str, list[DbArtifactIdentity]] = {}
        for identity in identities:
            if identity.sha256:
                self.by_sha.setdefault(identity.sha256, []).append(identity)
            if identity.local_rel_path:
                self.by_rel_path.setdefault(_norm_rel(identity.local_rel_path), []).append(identity)
            if identity.recorded_abs_path:
                self.by_rel_path.setdefault(_norm_rel(identity.recorded_abs_path), []).append(identity)

    def match(self, *, sha256_digest: str | None, rel_path: str) -> DbArtifactIdentity | None:
        if sha256_digest:
            rows = self.by_sha.get(_norm_sha(sha256_digest)) or []
            if rows:
                return rows[0]
        rows = self.by_rel_path.get(_norm_rel(rel_path)) or []
        return rows[0] if rows else None


def _db_identity_from_row(row: Mapping[str, Any], *, root: Path) -> DbArtifactIdentity:
    sha = _norm_sha(row.get("sha256")) or None
    local_rel_path = _maybe_str(row.get("local_rel_path"))
    data_root_text = _maybe_str(row.get("data_root"))
    recorded_abs = _recorded_abs_path(local_rel_path=local_rel_path, data_root=data_root_text, root=root)
    recorded_root_exists = _recorded_root_exists(data_root_text, root=root, local_rel_path=local_rel_path)
    recorded_path_exists = bool(recorded_abs and recorded_abs.exists())
    canonical_abs = _expected_canonical_path(sha, root=root) if sha else None
    canonical_exists = bool(canonical_abs and canonical_abs.exists())
    canonical_rel = _safe_relative(canonical_abs, root) if canonical_abs else None
    status = _db_identity_status(
        recorded_path_exists=recorded_path_exists,
        recorded_root_exists=recorded_root_exists,
        recorded_location_known=bool(local_rel_path),
        canonical_exists=canonical_exists,
    )
    return DbArtifactIdentity(
        row_source=_maybe_str(row.get("row_source")) or "android_apk_repository",
        artifact_id=_maybe_str(row.get("artifact_id")),
        package_name=_maybe_str(row.get("package_name")),
        version_code=_maybe_str(row.get("version_code")),
        version_name=_maybe_str(row.get("version_name")),
        file_name=_maybe_str(row.get("file_name")),
        file_size=_coerce_int(row.get("file_size")),
        sha256=sha,
        is_split_member=bool(_coerce_int(row.get("is_split_member")) or 0),
        split_group_id=_maybe_str(row.get("split_group_id")),
        device_serial=_maybe_str(row.get("device_serial")),
        harvested_at=_maybe_str(row.get("harvested_at")),
        storage_root_id=_maybe_str(row.get("storage_root_id")),
        data_root=data_root_text,
        local_rel_path=local_rel_path,
        recorded_abs_path=str(recorded_abs) if recorded_abs else None,
        recorded_root_exists=recorded_root_exists,
        recorded_path_exists=recorded_path_exists,
        canonical_rel_path=canonical_rel,
        canonical_abs_path=str(canonical_abs) if canonical_abs else None,
        canonical_exists=canonical_exists,
        status=status,
    )


def _classify_session_apk(
    *,
    apk_path: Path,
    root: Path,
    session_root: Path,
    identity_index: _IdentityIndex,
    verify_candidates: bool,
) -> SessionCopyRecord:
    rel_path = _safe_relative(apk_path, root)
    st = apk_path.lstat()
    is_symlink = stat.S_ISLNK(st.st_mode)
    is_regular = stat.S_ISREG(st.st_mode)
    session_size = int(st.st_size) if is_regular else 0
    session_copy_bytes_present = bool(is_regular and not is_symlink)

    sidecar_path, sidecar_payload = _load_sidecar(apk_path)
    manifest_path, manifest_payload = _load_nearest_manifest(apk_path, session_root=session_root)
    manifest_entry = _manifest_entry_for_apk(manifest_payload, apk_path=apk_path, root=root)

    metadata = _merged_metadata(sidecar_payload, manifest_payload, manifest_entry)
    sha = _norm_sha(metadata.get("sha256")) or None
    db_identity = identity_index.match(sha256_digest=sha, rel_path=rel_path)
    if db_identity and not sha:
        sha = db_identity.sha256

    canonical_abs = _canonical_path_from_metadata(metadata, root=root, sha256_digest=sha)
    canonical_exists = bool(canonical_abs and canonical_abs.exists())
    canonical_rel = _safe_relative(canonical_abs, root) if canonical_abs else None
    identity_known = bool(sha or db_identity)

    package_name = _maybe_str(metadata.get("package_name")) or (db_identity.package_name if db_identity else None)
    version_code = _maybe_str(metadata.get("version_code")) or (db_identity.version_code if db_identity else None)
    version_name = _maybe_str(metadata.get("version_name")) or (db_identity.version_name if db_identity else None)
    artifact_kind = _maybe_str(metadata.get("artifact_kind")) or _artifact_kind_from_name(apk_path.name)

    status_name = STATUS_ELIGIBLE_UNVERIFIED
    issue: str | None = None
    if is_symlink:
        status_name = STATUS_ALREADY_THIN_SYMLINK
    elif not session_copy_bytes_present:
        status_name = STATUS_BLOCKED_IDENTITY_UNKNOWN
        issue = "session APK path is not a regular file"
    elif not identity_known:
        status_name = STATUS_BLOCKED_IDENTITY_UNKNOWN
        issue = "no SHA-256 identity found in sidecar, manifest, or DB index"
    elif sidecar_path is None:
        status_name = STATUS_BLOCKED_MISSING_SIDECAR
        issue = "session APK sidecar is missing"
    elif manifest_path is None:
        status_name = STATUS_BLOCKED_MISSING_MANIFEST
        issue = "harvest_package_manifest.json is missing from the session tree"
    elif not canonical_exists:
        status_name = STATUS_BLOCKED_CANONICAL_MISSING
        issue = "canonical SHA-256 store payload is missing"
    elif verify_candidates:
        mismatch = _verify_hashes(apk_path=apk_path, canonical_path=canonical_abs, expected_sha256=sha)
        if mismatch:
            status_name = STATUS_BLOCKED_HASH_MISMATCH
            issue = mismatch
        else:
            status_name = STATUS_ELIGIBLE_VERIFIED
    else:
        status_name = STATUS_ELIGIBLE_UNVERIFIED

    reclaimable = session_size if status_name in {STATUS_ELIGIBLE_VERIFIED, STATUS_ELIGIBLE_UNVERIFIED} else 0
    return SessionCopyRecord(
        status=status_name,
        session_rel_path=rel_path,
        session_abs_path=str(apk_path.resolve() if not is_symlink else apk_path.absolute()),
        file_size=session_size,
        reclaimable_bytes=reclaimable,
        is_symlink=is_symlink,
        identity_known=identity_known,
        canonical_bytes_available=canonical_exists,
        session_copy_bytes_present=session_copy_bytes_present,
        historical_provenance_only=False,
        sha256=sha,
        package_name=package_name,
        version_code=version_code,
        version_name=version_name,
        artifact_kind=artifact_kind,
        canonical_rel_path=canonical_rel,
        canonical_abs_path=str(canonical_abs) if canonical_abs else None,
        sidecar_rel_path=_safe_relative(sidecar_path, root) if sidecar_path else None,
        manifest_rel_path=_safe_relative(manifest_path, root) if manifest_path else None,
        issue=issue,
    )


def _db_identity_status(
    *,
    recorded_path_exists: bool,
    recorded_root_exists: bool,
    recorded_location_known: bool,
    canonical_exists: bool,
) -> str:
    if canonical_exists or recorded_path_exists:
        return "available"
    if recorded_location_known and not recorded_root_exists:
        return STATUS_HISTORICAL_IDENTITY_ONLY
    if recorded_location_known:
        return STATUS_BLOCKED_OLD_ROOT
    return "missing_bytes"


def _recorded_abs_path(*, local_rel_path: str | None, data_root: str | None, root: Path) -> Path | None:
    if not local_rel_path:
        return None
    local = Path(local_rel_path).expanduser()
    if local.is_absolute():
        return local
    if data_root:
        return Path(data_root).expanduser() / local
    return root / local


def _recorded_root_exists(data_root: str | None, *, root: Path, local_rel_path: str | None) -> bool:
    if data_root:
        return Path(data_root).expanduser().exists()
    if not local_rel_path:
        return True
    return root.exists()


def _expected_canonical_path(sha256_digest: str | None, *, root: Path) -> Path | None:
    sha = _norm_sha(sha256_digest)
    if not sha:
        return None
    try:
        if root.resolve() == artifact_store.data_root().resolve():
            return artifact_store.canonical_apk_path(sha)
    except Exception:
        pass
    return root / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"


def _canonical_path_from_metadata(metadata: Mapping[str, Any], *, root: Path, sha256_digest: str | None) -> Path | None:
    raw = _maybe_str(metadata.get("canonical_store_path")) or _maybe_str(metadata.get("canonical_path"))
    if raw:
        path = Path(raw).expanduser()
        if path.is_absolute():
            return path
        return root / path
    return _expected_canonical_path(sha256_digest, root=root)


def _load_sidecar(apk_path: Path) -> tuple[Path | None, dict[str, Any]]:
    candidates = [apk_path.with_suffix(apk_path.suffix + ".meta.json"), apk_path.with_name(apk_path.name + ".meta.json")]
    for candidate in candidates:
        if not candidate.exists():
            continue
        payload = _read_json_mapping(candidate)
        return candidate, payload
    return None, {}


def _load_nearest_manifest(apk_path: Path, *, session_root: Path) -> tuple[Path | None, dict[str, Any]]:
    for parent in [apk_path.parent, *apk_path.parents]:
        if parent == session_root.parent:
            break
        candidate = parent / "harvest_package_manifest.json"
        if candidate.exists():
            return candidate, _read_json_mapping(candidate)
        if parent == session_root:
            break
    return None, {}


def _manifest_entry_for_apk(manifest: Mapping[str, Any], *, apk_path: Path, root: Path) -> dict[str, Any]:
    execution = manifest.get("execution")
    if not isinstance(execution, Mapping):
        return {}
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return {}
    rel_path = _safe_relative(apk_path, root)
    name = apk_path.name
    for entry in observed:
        if not isinstance(entry, Mapping):
            continue
        local_path = _maybe_str(entry.get("local_artifact_path")) or _maybe_str(entry.get("local_path"))
        file_name = _maybe_str(entry.get("file_name"))
        if local_path and _norm_rel(local_path) == _norm_rel(rel_path):
            return dict(entry)
        if file_name and file_name == name:
            return dict(entry)
    return {}


def _merged_metadata(
    sidecar_payload: Mapping[str, Any],
    manifest_payload: Mapping[str, Any],
    manifest_entry: Mapping[str, Any],
) -> dict[str, Any]:
    package_section = manifest_payload.get("package") if isinstance(manifest_payload, Mapping) else None
    metadata: dict[str, Any] = {}
    if isinstance(package_section, Mapping):
        for key in ("package_name", "version_code", "version_name", "device_serial", "session_label"):
            if package_section.get(key) is not None:
                metadata[key] = package_section.get(key)
    for source in (manifest_entry, sidecar_payload):
        for key, value in source.items():
            if value is not None and value != "":
                metadata[key] = value
    if "artifact_kind" not in metadata:
        metadata["artifact_kind"] = _maybe_str(metadata.get("split_label")) or _maybe_str(metadata.get("artifact"))
    return metadata


def _read_json_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def _verify_hashes(*, apk_path: Path, canonical_path: Path | None, expected_sha256: str | None) -> str | None:
    if canonical_path is None:
        return "canonical path is unknown"
    expected = _norm_sha(expected_sha256)
    if not expected:
        return "expected SHA-256 is unknown"
    session_hash = _hash_file(apk_path)
    if session_hash != expected:
        return f"session hash mismatch: expected {expected}, observed {session_hash}"
    canonical_hash = _hash_file(canonical_path)
    if canonical_hash != expected:
        return f"canonical hash mismatch: expected {expected}, observed {canonical_hash}"
    return None


def _hash_file(path: Path) -> str:
    digest = _sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _session_record_to_dict(record: SessionCopyRecord) -> dict[str, Any]:
    payload = asdict(record)
    payload["status_family"] = "session" if record.status in _SESSION_STATUSES else "other"
    return payload


def _db_identity_to_dict(record: DbArtifactIdentity) -> dict[str, Any]:
    return asdict(record)


def _write_session_csv(path: Path, audit: Mapping[str, Any]) -> None:
    fieldnames = [
        "status",
        "session_rel_path",
        "file_size",
        "reclaimable_bytes",
        "sha256",
        "package_name",
        "version_code",
        "artifact_kind",
        "canonical_rel_path",
        "canonical_bytes_available",
        "identity_known",
        "session_copy_bytes_present",
        "sidecar_rel_path",
        "manifest_rel_path",
        "issue",
    ]
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in audit.get("session_files", []):
            if not isinstance(row, Mapping):
                continue
            writer.writerow({field: row.get(field) for field in fieldnames})
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


def _norm_sha(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if len(text) == 64 else text


def _norm_rel(value: str) -> str:
    return str(value or "").strip().replace("\\", "/").lstrip("./")


def _safe_relative(path: Path, root: Path) -> str:
    # Use absolute() first so session symlinks remain reported at their
    # provenance path instead of resolving to the canonical store target.
    try:
        base = root.expanduser().resolve()
        candidate = path.expanduser()
        if not candidate.is_absolute():
            candidate = candidate.absolute()
        return candidate.relative_to(base).as_posix()
    except Exception:
        try:
            return path.expanduser().resolve().relative_to(root.expanduser().resolve()).as_posix()
        except Exception:
            return path.as_posix()


__all__ = [
    "DbArtifactIdentity",
    "SessionCopyRecord",
    "STATUS_ALREADY_THIN_SYMLINK",
    "STATUS_BLOCKED_CANONICAL_MISSING",
    "STATUS_BLOCKED_HASH_MISMATCH",
    "STATUS_BLOCKED_MISSING_MANIFEST",
    "STATUS_BLOCKED_MISSING_SIDECAR",
    "STATUS_BLOCKED_OLD_ROOT",
    "STATUS_ELIGIBLE_UNVERIFIED",
    "STATUS_ELIGIBLE_VERIFIED",
    "STATUS_HISTORICAL_IDENTITY_ONLY",
    "build_storage_pressure_audit",
    "collect_db_artifact_identities",
    "collect_storage_roots",
    "default_audit_root",
    "default_storage_root",
    "generate_storage_pressure_audit",
    "scan_canonical_apk_store",
    "scan_session_copy_pressure",
    "storage_pressure_stamp",
    "write_storage_pressure_audit",
]
