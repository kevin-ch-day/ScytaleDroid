"""Helpers for creating and verifying run envelopes before persistence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_queries.canonical import schema as canonical_schema
from scytaledroid.Persistence import db_writer as _dw
from scytaledroid.Utils.LoggingUtils import logging_utils as log


@dataclass(slots=True)
class RunEnvelope:
    run_id: int | None
    app_label: str | None
    target_sdk: int | None
    threat_profile: str
    env_profile: str


def first_non_empty_str(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str):
            candidate = value.strip()
        elif value is None:
            candidate = ""
        else:
            candidate = str(value).strip()
        if candidate:
            return candidate
    return None


def _extract_from_sources(
    sources: Sequence[Mapping[str, Any]],
    paths: Sequence[Sequence[str]],
) -> str | None:
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for path in paths:
            current: Any = source
            for key in path:
                if not isinstance(current, Mapping):
                    break
                current = current.get(key)
            else:
                candidate = first_non_empty_str(current)
                if candidate:
                    return candidate
    return None


def extract_run_profiles(
    report: Any,
    baseline_payload: Mapping[str, object],
) -> tuple[str, str]:
    metadata = getattr(report, "metadata", None)
    metadata_map: Mapping[str, Any] = metadata if isinstance(metadata, Mapping) else {}
    baseline_map: Mapping[str, Any] = baseline_payload if isinstance(baseline_payload, Mapping) else {}
    baseline_section_raw = (
        baseline_map.get("baseline") if isinstance(baseline_map.get("baseline"), Mapping) else {}
    )
    baseline_section: Mapping[str, Any] = (
        baseline_section_raw if isinstance(baseline_section_raw, Mapping) else {}
    )

    sources: Sequence[Mapping[str, Any]] = (
        metadata_map,
        baseline_map,
        baseline_section,
    )

    threat_candidate = _extract_from_sources(
        sources,
        (
            ("threat_profile",),
            ("threatProfile",),
            ("threat_profile_code",),
            ("profiles", "threat", "profile"),
            ("profiles", "threat", "code"),
            ("threat", "profile"),
            ("threat", "code"),
            ("risk", "threat_profile"),
            ("risk", "threat", "profile"),
        ),
    )
    env_candidate = _extract_from_sources(
        sources,
        (
            ("env_profile",),
            ("environment_profile",),
            ("envProfile",),
            ("environmentProfile",),
            ("profiles", "env", "profile"),
            ("profiles", "environment", "profile"),
            ("env", "profile"),
            ("environment", "profile"),
        ),
    )

    threat_profile = threat_candidate or "Unknown"
    env_profile = env_candidate or "consumer"
    return threat_profile, env_profile


def prepare_run_envelope(
    *,
    report: Any,
    baseline_payload: Mapping[str, object],
    run_package: str,
    session_stamp: str,
    dry_run: bool,
) -> tuple[RunEnvelope, list[str]]:
    errors: list[str] = []
    baseline_app: Mapping[str, object]
    if isinstance(baseline_payload, Mapping):
        app_section = baseline_payload.get("app")
        baseline_app = app_section if isinstance(app_section, Mapping) else {}
    else:
        baseline_app = {}

    manifest = getattr(report, "manifest", None)
    app_label = first_non_empty_str(
        getattr(manifest, "app_label", None) if manifest else None,
        baseline_app.get("label"),
        baseline_app.get("display_name"),
        baseline_app.get("app_label"),
        run_package,
    )

    try:
        target_sdk = int(getattr(manifest, "target_sdk", None)) if manifest and getattr(manifest, "target_sdk", None) else None
    except Exception:
        target_sdk = None

    threat_profile_value, env_profile_value = extract_run_profiles(report, baseline_payload)

    def _append_diagnostic() -> None:
        diagnostic = _diagnose_database_health()
        if diagnostic and diagnostic not in errors:
            errors.append(diagnostic)

    run_id: int | None = None
    if not dry_run:
        creation_failed = False
        try:
            if not canonical_schema.ensure_all():
                raise RuntimeError("DB schema is outdated; run migrations to use canonical schema.")
        except Exception as exc:
            creation_failed = True
            message = f"Canonical schema guard failed: {exc}"
            log.warning(message, category="static_analysis")
            errors.append(message)
            _append_diagnostic()
        if not creation_failed:
            try:
                run_id = _dw.create_run(
                    package=getattr(manifest, "package_name", None) or run_package,
                    app_label=app_label,
                    version_code=(
                        int(getattr(manifest, "version_code", None))
                        if manifest and getattr(manifest, "version_code", None)
                        else None
                    ),
                    version_name=getattr(manifest, "version_name", None) if manifest else None,
                    target_sdk=target_sdk,
                    session_stamp=session_stamp,
                    threat_profile=threat_profile_value,
                    env_profile=env_profile_value,
                )
            except Exception as exc:  # pragma: no cover - defensive
                run_id = None
                creation_failed = True
                message = f"Failed to create run record for {run_package}: {exc}"
                log.warning(message, category="static_analysis")
                errors.append(message)
                _append_diagnostic()
        if run_id is None and not creation_failed:
            message = f"Failed to create run record for {run_package}"
            log.warning(message, category="static_analysis")
            errors.append(message)
            _append_diagnostic()
        elif run_id:
            try:
                row = core_q.run_sql(
                    "SELECT threat_profile, env_profile FROM runs WHERE run_id=%s",
                    (run_id,),
                    fetch="one",
                    dictionary=True,
                )
                if isinstance(row, Mapping):
                    threat_profile_value = first_non_empty_str(
                        row.get("threat_profile"),
                        threat_profile_value,
                    ) or "Unknown"
                    env_profile_value = first_non_empty_str(
                        row.get("env_profile"),
                        env_profile_value,
                    ) or "consumer"
            except Exception:  # pragma: no cover - defensive
                pass

    envelope = RunEnvelope(
        run_id=int(run_id) if run_id else None,
        app_label=app_label,
        target_sdk=target_sdk,
        threat_profile=threat_profile_value,
        env_profile=env_profile_value,
    )
    return envelope, errors


def _diagnose_database_health() -> str | None:
    try:
        core_q.run_sql("SELECT 1", fetch="one")
    except Exception as exc:  # pragma: no cover - defensive
        detail = f"{exc.__class__.__name__}: {exc}"
        message = (
            "Database connectivity check failed while diagnosing run persistence: "
            f"{detail}"
        )
        log.warning(message, category="static_analysis")
        return message
    return (
        "Database connectivity check succeeded; persistence failure likely stems from "
        "SQL constraints or schema drift."
    )


__all__ = [
    "RunEnvelope",
    "extract_run_profiles",
    "first_non_empty_str",
    "prepare_run_envelope",
]