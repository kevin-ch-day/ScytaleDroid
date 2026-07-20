"""Draft reviewed capsule ledgers from explicit Paper-freeze run selections."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .research_capsule import sha256_file

_EVIDENCE_ARTIFACT_TYPES = {
    "pcap_features",
    "pcap_report",
    "analysis_summary_json",
    "static_dynamic_overlap",
}
_EXTRA_RELATIVE_ARTIFACTS = (
    ("run_manifest", "run_manifest.json"),
    ("static_dynamic_plan", "inputs/static_dynamic_plan.json"),
    ("run_events", "notes/run_events.jsonl"),
)


def split_run_ids(value: object) -> list[str]:
    """Normalize the freeze export's comma-separated selected-run representation."""

    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, Iterable):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _record_artifact(run_dir: Path, relative_path: str, role: str, repo_root: Path) -> dict[str, str]:
    path = run_dir / relative_path
    return {
        "role": role,
        "path": _rel(path, repo_root),
        "sha256": sha256_file(path) if path.is_file() else "",
        "draft_status": "present" if path.is_file() else "missing",
    }


def _pcap_record(manifest: Mapping[str, Any], run_dir: Path, repo_root: Path) -> dict[str, str]:
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, Mapping) or str(artifact.get("type") or "") != "pcapdroid_capture":
            continue
        relative_path = str(artifact.get("relative_path") or "")
        pcap = run_dir / relative_path
        return {
            "path": _rel(pcap, repo_root),
            "sha256": str(artifact.get("sha256") or ""),
            "draft_status": "present" if pcap.is_file() else "missing",
        }
    return {"path": "", "sha256": "", "draft_status": "missing"}


def _evidence_artifacts(manifest: Mapping[str, Any], run_dir: Path, repo_root: Path) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for role, relative_path in _EXTRA_RELATIVE_ARTIFACTS:
        artifacts.append(_record_artifact(run_dir, relative_path, role, repo_root))
    for output in manifest.get("outputs") or []:
        if not isinstance(output, Mapping) or str(output.get("type") or "") not in _EVIDENCE_ARTIFACT_TYPES:
            continue
        relative_path = str(output.get("relative_path") or "")
        artifacts.append(
            {
                "role": str(output.get("type")),
                "path": _rel(run_dir / relative_path, repo_root),
                "sha256": str(output.get("sha256") or ""),
                "draft_status": "present" if (run_dir / relative_path).is_file() else "missing",
            }
        )
    return artifacts


def build_paper_freeze_ledger_drafts(
    *,
    freeze_manifest: Mapping[str, Any],
    repo_root: Path | str,
    evidence_root: Path | str,
    display_name_by_package: Mapping[str, str] | None = None,
    apk_store_root: Path | str | None = None,
    paper_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build unreviewed APK/evidence ledgers from the freeze's explicit run IDs.

    The function never walks an evidence root. It resolves only paths named by
    ``selected_dynamic_run_ids`` in the reviewed paper-freeze manifest.
    """

    root = Path(repo_root).resolve()
    dynamic_root = Path(evidence_root).resolve()
    apk_root = Path(apk_store_root).resolve() if apk_store_root else root / "data" / "store" / "apk" / "sha256"
    display_names = dict(display_name_by_package or {})
    resolved_paper_id = str(paper_id or freeze_manifest.get("paper_id") or freeze_manifest.get("cohort_label") or "paper3").strip()
    apk_entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    evidence_entries: list[dict[str, Any]] = []
    selected_run_count = 0
    explicitly_excluded_selected_run_count = 0

    for app in freeze_manifest.get("apps") or []:
        if not isinstance(app, Mapping):
            continue
        for run_id in split_run_ids(app.get("selected_dynamic_run_ids")):
            selected_run_count += 1
            run_dir = dynamic_root / run_id
            manifest_path = run_dir / "run_manifest.json"
            if not manifest_path.is_file():
                evidence_entries.append(
                    {
                        "dynamic_run_id": run_id,
                        "package_name": str(app.get("package_name") or ""),
                        "draft_status": "missing_run_manifest",
                    }
                )
                continue
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
            identity = target.get("run_identity") if isinstance(target.get("run_identity"), Mapping) else {}
            dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
            scenario = manifest.get("scenario") if isinstance(manifest.get("scenario"), Mapping) else {}
            operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
            package = str(target.get("package_name") or app.get("package_name") or "")
            version_code = str(target.get("version_code") or app.get("selected_version_code") or "")
            base_sha = str(identity.get("base_apk_sha256") or app.get("selected_base_apk_sha256") or "").lower()
            if dataset.get("paper_eligible") is False:
                explicitly_excluded_selected_run_count += 1
                reason_codes = dataset.get("paper_exclusion_all_reason_codes")
                if isinstance(reason_codes, (list, tuple)):
                    reason = ",".join(str(value).strip() for value in reason_codes if str(value).strip())
                else:
                    reason = ""
                evidence_entries.append(
                    {
                        "package_name": package,
                        "version_code": version_code,
                        "base_apk_sha256": base_sha,
                        "dynamic_run_id": run_id,
                        "paper_eligibility": "explicit_paper_exclusion",
                        "paper_exclusion_reason": reason
                        or str(dataset.get("paper_exclusion_primary_reason_code") or "unspecified"),
                        "inclusion_disposition": "excluded",
                        "draft_status": "excluded_by_current_policy",
                    }
                )
                continue
            key = (package, version_code, base_sha)
            selected_apk = apk_root / base_sha[:2] / f"{base_sha}.apk" if base_sha else Path()
            apk_entries.setdefault(
                key,
                {
                    "package_name": package,
                    "app_name": str(display_names.get(package) or app.get("app") or package),
                    "version_name": str(target.get("version_name") or app.get("selected_version_name") or ""),
                    "version_code": version_code,
                    "base_apk_sha256": base_sha,
                    "selected_apk_path": _rel(selected_apk, root) if selected_apk.is_file() else "",
                    "static_run_id": str(target.get("static_run_id") or app.get("selected_static_run_id") or ""),
                    "paper_build_relation": str(app.get("selected_relation") or ""),
                    "inclusion_disposition": "included",
                    "source_device_apk_paths": target.get("apk_paths") or [],
                    "draft_status": "requires_reviewer_confirmation" if selected_apk.is_file() else "missing_local_apk",
                },
            )
            evidence_entries.append(
                {
                    "package_name": package,
                    "version_code": version_code,
                    "base_apk_sha256": base_sha,
                    "dynamic_run_id": run_id,
                    "run_profile": str(operator.get("run_profile") or target.get("run_intent") or scenario.get("id") or ""),
                    "capture_started_at_utc": str(scenario.get("started_at") or manifest.get("started_at") or ""),
                    "pcap": _pcap_record(manifest, run_dir, root),
                    "artifacts": _evidence_artifacts(manifest, run_dir, root),
                    "paper_eligibility": "paper_selected" if dataset.get("paper_eligible") else "paper_selected_with_caveat",
                    "validity_state": "VALID" if dataset.get("valid_dataset_run") else "NOT_VALID",
                    "manuscript_dependencies": [],
                    "draft_status": "requires_reviewer_confirmation",
                }
            )

    common = {
        "schema_version": 1,
        "paper_id": resolved_paper_id,
        "review_status": "DRAFT_UNREVIEWED",
        "selection_contract": freeze_manifest.get(
            "selection_contract",
            {
                "requires_valid_dataset_run": True,
                "explicit_paper_ineligible_runs": "excluded",
                "missing_paper_eligibility_field": "retained for legacy compatibility",
            },
        ),
        "selected_run_count": selected_run_count,
        "explicitly_excluded_selected_run_count": explicitly_excluded_selected_run_count,
        "source_freeze_manifest_sha256": hashlib.sha256(
            json.dumps(freeze_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return (
        common | {"entries": sorted(apk_entries.values(), key=lambda entry: (entry["package_name"], entry["version_code"]))},
        common | {"entries": sorted(evidence_entries, key=lambda entry: str(entry.get("dynamic_run_id") or ""))},
    )
