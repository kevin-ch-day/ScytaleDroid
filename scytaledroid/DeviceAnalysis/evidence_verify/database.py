"""Harvest manifest alignment against ``android_apk_repository`` (optional, read-only).

Database rows rank below on-disk hash truth in ``v1_evidence_catalog_verification``;
misalignment emits **warnings** so CI can tighten with ``--warnings-as-errors``.

Connection/configuration failures emit a single **error** so operators get a terse
CLI report instead of an uncaught stack trace when ``--with-db`` is used without DB.
"""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Database.db_core import DatabaseError
from scytaledroid.Database.db_func.harvest import apk_repository
from scytaledroid.Database.db_utils.package_utils import normalize_package_name

from .filesystem import VerifyIssue, iter_manifest_written_hashes


def verify_harvest_db_alignment(
    *,
    harvest_root: Path,
    data_root: Path | None = None,
    serial: str | None = None,
) -> tuple[list[VerifyIssue], int]:
    """Compare manifest-declared APK hashes against repository rows."""

    triples = iter_manifest_written_hashes(
        harvest_root=harvest_root, data_root=data_root, serial=serial
    )
    issues: list[VerifyIssue] = []
    anchor = harvest_root.expanduser().resolve().as_posix()

    try:
        for manifest, pkg_from_manifest, digest in triples:
            row = apk_repository.get_apk_by_sha256(digest)
            if row is None:
                issues.append(
                    VerifyIssue(
                        "warning",
                        "db_missing_apk_sha256",
                        manifest,
                        f"No android_apk_repository row for sha256={digest[:12]}…"
                        + (
                            f" (manifest package_name={pkg_from_manifest!r})"
                            if pkg_from_manifest
                            else ""
                        ),
                    )
                )
                continue

            if pkg_from_manifest:
                db_pkg_raw = row.get("package_name")
                db_pkg = str(db_pkg_raw).strip() if db_pkg_raw is not None else ""
                norm_manifest = normalize_package_name(pkg_from_manifest, context="database")
                norm_db = normalize_package_name(db_pkg, context="database") if db_pkg else ""
                if norm_db and norm_manifest and norm_manifest != norm_db:
                    issues.append(
                        VerifyIssue(
                            "warning",
                            "db_package_name_mismatch",
                            manifest,
                            f"manifest package_name={norm_manifest!r} vs repo={norm_db!r} "
                            f"for sha256={digest[:12]}…",
                        )
                    )
    except DatabaseError as exc:
        return (
            [
                VerifyIssue(
                    "error",
                    "db_query_failed",
                    anchor,
                    f"{exc}",
                ),
            ],
            1,
        )
    except RuntimeError as exc:
        lowered = str(exc).lower()
        disabled = (
            "database is disabled" in lowered
            or ("sqlite backend" in lowered and "not supported" in lowered)
        )
        if not disabled:
            raise
        detail = (
            str(exc).strip()
            or "Configure MariaDB (SCYTALEDROID_DB_URL or SCYTALEDROID_DB_* ) for --with-db."
        )
        return (
            [
                VerifyIssue(
                    "error",
                    "db_disabled_or_unconfigured",
                    anchor,
                    detail,
                ),
            ],
            1,
        )

    fatal = sum(1 for issue in issues if issue.severity == "error")
    return issues, 1 if fatal else 0
