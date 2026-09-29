#!/usr/bin/env python3
"""Report distinct base-APK byte variants for the same package and version."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--package-name", default=None)
    parser.add_argument("--version-code", default=None)
    parser.add_argument("--device-sdk", type=int, default=35)
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def build_report(
    *,
    data_root: Path,
    output_root: Path | None = None,
    stamp: str | None = None,
    package_name: str | None = None,
    version_code: str | None = None,
    device_sdk: int = 35,
    write_outputs: bool = True,
) -> dict[str, Any]:
    """Build a read-only signer comparison for repeated base APK releases."""

    from scytaledroid.DeviceAnalysis.apk_signing import extract_apk_cert_sha256

    data_root = data_root.expanduser()
    repo_root = data_root.parent
    stamp = stamp or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_root = output_root or repo_root / "output" / "audit" / "apk_release_variants" / stamp

    grouped: dict[tuple[str, str], dict[str, dict[str, str]]] = defaultdict(dict)
    invalid_report_count = 0
    for report_path in sorted((data_root / "static_analysis" / "reports" / "latest").glob("*.json")):
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            invalid_report_count += 1
            continue
        metadata = payload.get("metadata") if isinstance(payload, dict) else None
        if not isinstance(metadata, dict):
            continue
        package = str(
            metadata.get("package_name") or metadata.get("normalized_package_name") or ""
        ).strip()
        version = str(metadata.get("version_code") or "").strip()
        artifact = str(metadata.get("artifact") or "base").strip().lower()
        digest = str(metadata.get("sha256") or report_path.stem).strip().lower()
        if (
            not package
            or not version
            or artifact != "base"
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            continue
        if package_name and package != package_name:
            continue
        if version_code is not None and version != str(version_code):
            continue
        canonical = str(metadata.get("canonical_store_path") or "").strip()
        grouped[(package, version)][digest] = {
            "canonical_store_path": canonical,
            "report_path": report_path.as_posix(),
        }

    rows: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    for (package, version), artifacts in sorted(grouped.items()):
        if len(artifacts) < 2:
            continue
        group_rows: list[dict[str, Any]] = []
        for digest, source in sorted(artifacts.items()):
            canonical = _resolve_canonical_path(
                data_root=data_root,
                repo_root=repo_root,
                digest=digest,
                recorded_path=source["canonical_store_path"],
            )
            byte_status = "missing"
            actual_digest = ""
            signer = ""
            if canonical.is_file():
                try:
                    actual_digest = _sha256(canonical)
                    byte_status = "verified" if actual_digest == digest else "hash_mismatch"
                    if byte_status == "verified":
                        signer = extract_apk_cert_sha256(canonical, device_sdk=device_sdk) or ""
                except OSError:
                    byte_status = "unreadable"
            row = {
                "package_name": package,
                "version_code": version,
                "sha256": digest,
                "canonical_path": canonical.as_posix(),
                "byte_status": byte_status,
                "actual_sha256": actual_digest,
                "signer_sha256": signer,
                "report_path": source["report_path"],
            }
            rows.append(row)
            group_rows.append(row)

        signers = {str(row["signer_sha256"]) for row in group_rows if row["signer_sha256"]}
        bytes_verified = all(row["byte_status"] == "verified" for row in group_rows)
        if not bytes_verified:
            disposition = "BYTE_EVIDENCE_INCOMPLETE"
        elif len(signers) == 1 and all(row["signer_sha256"] for row in group_rows):
            disposition = "MULTIPLE_RELEASE_VARIANTS"
        elif len(signers) > 1:
            disposition = "SIGNER_DIVERGENCE_REVIEW"
        else:
            disposition = "SIGNER_EVIDENCE_INCOMPLETE"
        groups.append(
            {
                "package_name": package,
                "version_code": version,
                "distinct_apk_count": len(group_rows),
                "distinct_signer_count": len(signers),
                "disposition": disposition,
                "sha256_values": sorted(row["sha256"] for row in group_rows),
                "signer_sha256_values": sorted(signers),
            }
        )

    disposition_counts: dict[str, int] = defaultdict(int)
    for group in groups:
        disposition_counts[str(group["disposition"])] += 1
    summary = {
        "schema_version": "apk_release_variants_v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "data_root": data_root.as_posix(),
        "device_sdk": int(device_sdk),
        "package_filter": package_name,
        "version_code_filter": str(version_code) if version_code is not None else None,
        "invalid_report_count": invalid_report_count,
        "repeated_release_group_count": len(groups),
        "artifact_count": len(rows),
        "disposition_counts": dict(sorted(disposition_counts.items())),
    }
    outputs = {
        "summary_json": output_root / "summary.json",
        "groups_json": output_root / "release_variant_groups.json",
        "artifacts_csv": output_root / "release_variant_artifacts.csv",
    }
    if write_outputs:
        output_root.mkdir(parents=True, exist_ok=True)
        outputs["summary_json"].write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        outputs["groups_json"].write_text(
            json.dumps(groups, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _write_csv(outputs["artifacts_csv"], rows)
    return {
        "summary": summary,
        "groups": groups,
        "artifacts": rows,
        "outputs": {name: path.as_posix() for name, path in outputs.items()},
    }


def _resolve_canonical_path(
    *,
    data_root: Path,
    repo_root: Path,
    digest: str,
    recorded_path: str,
) -> Path:
    expected = data_root / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    if not recorded_path:
        return expected
    candidate = Path(recorded_path).expanduser()
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate if candidate.is_file() else expected


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "package_name",
        "version_code",
        "sha256",
        "canonical_path",
        "byte_status",
        "actual_sha256",
        "signer_sha256",
        "report_path",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    report = build_report(
        data_root=args.data_root,
        output_root=args.output_root,
        stamp=args.stamp,
        package_name=args.package_name,
        version_code=args.version_code,
        device_sdk=args.device_sdk,
    )
    if args.json:
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(f"Repeated release groups :: {summary['repeated_release_group_count']}")
        print(f"APK artifacts           :: {summary['artifact_count']}")
        for disposition, count in summary["disposition_counts"].items():
            print(f"{disposition:<23} :: {count}")
        print(f"Evidence                :: {report['outputs']['summary_json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
