"""Helpers for persisting baseline/static artefacts and storage surface data."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.persistence import (
    static_findings_writer as sf_writer,  # backwards compat
)
from scytaledroid.StaticAnalysis.cli.persistence import (
    strings_writer as str_writer,  # backwards compat
)
from scytaledroid.StaticAnalysis.cli.persistence.static_findings_writer import (
    persist_static_findings,
)
from scytaledroid.StaticAnalysis.cli.persistence.strings_writer import persist_string_summary
from scytaledroid.StaticAnalysis.modules.string_analysis.selection import select_samples
from scytaledroid.StaticAnalysis.cli.persistence.utils import first_text, require_canonical_schema

# export for existing imports
coerce_severity_counts = sf_writer.coerce_severity_counts  # re-export
normalise_string_counts = str_writer.normalise_string_counts  # re-export


def persist_storage_surface_data(report, session_stamp: str, scope_label: str) -> None:
    try:
        require_canonical_schema()
    except Exception:
        return
    try:
        from scytaledroid.StaticAnalysis.modules.storage_surface import (
            AppModuleContext,
            StorageSurfaceModule,
        )
    except Exception:
        return

    apk_path = getattr(report, "file_path", None)
    package_name = getattr(report.manifest, "package_name", None) or getattr(report, "metadata", {}).get("package")
    if not apk_path or not package_name:
        return

    metadata = dict(getattr(report, "metadata", {}) or {})
    context = AppModuleContext(
        report=report,
        package_name=str(package_name),
        apk_path=Path(apk_path),
        metadata=metadata,
        session_stamp=session_stamp,
        scope_label=scope_label,
    )

    module = StorageSurfaceModule()
    try:
        module_result = module.run(context)
        module.persist(module_result)
    except Exception:
        return


def persist_static_sections(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_section: Mapping[str, object],
    string_payload: Mapping[str, object],
    manifest: object | None,
    app_metadata: Mapping[str, object] | object,
    static_run_id: int | None = None,
) -> tuple[list[str], bool, int]:
    errors: list[str] = []
    baseline_written = False
    try:
        require_canonical_schema()
    except Exception as exc:
        errors.append(str(exc))
        return errors, baseline_written, 0
    metadata_map: Mapping[str, object] = (
        dict(app_metadata)
        if isinstance(app_metadata, Mapping)
        else {}
    )

    severity_counts = sf_writer.coerce_severity_counts(finding_totals)
    details = {
        "app_label": first_text(
            getattr(manifest, "app_label", None) if manifest else None,
            metadata_map.get("label"),
            metadata_map.get("app_label"),
        ),
        "version_name": first_text(
            getattr(manifest, "version_name", None) if manifest else None,
            metadata_map.get("version_name"),
        ),
        "version_code": first_text(
            getattr(manifest, "version_code", None) if manifest else None,
            metadata_map.get("version_code"),
        ),
        "target_sdk": first_text(
            getattr(manifest, "target_sdk", None) if manifest else None,
            metadata_map.get("target_sdk"),
        ),
        "min_sdk": first_text(
            getattr(manifest, "min_sdk", None) if manifest else None,
            metadata_map.get("min_sdk"),
        ),
        "flags": {
            key: value
            for key, value in (
                getattr(getattr(manifest, "flags", None), "__dict__", {}) or metadata_map.get("flags", {}) or {}
            ).items()
            if value not in (None, "")
        },
    }

    findings = baseline_section.get("findings")
    findings_seq: Sequence[object] | None = findings if isinstance(findings, Sequence) else None
    baseline_errors = persist_static_findings(
        package_name=package_name,
        session_stamp=session_stamp,
        scope_label=scope_label,
        severity_counts=severity_counts,
        details=details,
        findings=findings_seq,
        static_run_id=static_run_id,
    )
    if baseline_errors:
        errors.extend(baseline_errors)
    else:
        baseline_written = True

    counts = str_writer.normalise_string_counts(string_payload.get("counts"))
    samples_payload = string_payload.get("samples")
    samples = samples_payload if isinstance(samples_payload, Mapping) else {}
    selected_payload = string_payload.get("selected_samples")
    selected_samples = selected_payload if isinstance(selected_payload, Mapping) else None
    selection_params = string_payload.get("selection_params") if isinstance(string_payload, Mapping) else None
    if selected_samples is None:
        try:
            options = string_payload.get("options") if isinstance(string_payload, Mapping) else {}
            max_samples = int(options.get("max_samples", 2)) if isinstance(options, Mapping) else 2
            min_entropy = float(options.get("min_entropy", 0)) if isinstance(options, Mapping) else None
            selected_samples, selection_params = select_samples(
                samples,
                max_samples=max_samples,
                min_entropy=min_entropy,
            )
        except Exception:
            selected_samples = {}
    elif not isinstance(selection_params, Mapping):
        try:
            options = string_payload.get("options") if isinstance(string_payload, Mapping) else {}
            max_samples = int(options.get("max_samples", 2)) if isinstance(options, Mapping) else 2
            min_entropy = float(options.get("min_entropy", 0)) if isinstance(options, Mapping) else None
            selection_params = {
                "selection_version": "v1",
                "max_samples": max_samples,
                "min_entropy": min_entropy,
                "policy_root": "fallback",
            }
        except Exception:
            selection_params = None
    sample_total = 0
    for values in samples.values():
        if isinstance(values, Sequence):
            sample_total += len(values)
        string_errors = persist_string_summary(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            counts=counts,
            samples=samples,
            selected_samples=selected_samples,
            selection_params=selection_params if isinstance(selection_params, Mapping) else None,
            static_run_id=static_run_id,
        )
    if string_errors:
        errors.extend(string_errors)
        sample_total = 0

    return errors, baseline_written, sample_total


__all__ = [
    "persist_storage_surface_data",
    "persist_static_sections",
    "coerce_severity_counts",
    "normalise_string_counts",
]
