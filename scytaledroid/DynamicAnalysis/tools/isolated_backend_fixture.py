"""Offline evidence-contract prototype; contains no device/execution backend."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest

OUTCOMES = frozenset(
    {"install_failed", "dormant", "no_network_observed", "collection_failed", "activity_observed"}
)


def render_fixture_pack(run_dir: Path, fixture: dict) -> Path:
    """Seal clearly synthetic evidence in a NEW directory, without executing bytes.

    The fixture's digest identifies JSON input, never an APK. Policy declarations
    validate only this fixture contract; they are not proof of sandbox isolation.
    """
    required = {"contract", "target_kind", "network", "execution_authorized", "outcome", "events"}
    if not isinstance(fixture, dict) or set(fixture) != required:
        raise ValueError("Exact fixture contract required; device fields are forbidden")
    if (
        fixture["contract"] != "scytaledroid.isolated-fixture.v1"
        or fixture["target_kind"] != "controlled_fixture"
        or fixture["network"] != "disabled"
        or fixture["execution_authorized"] is not False
    ):
        raise ValueError("Only offline controlled fixtures are accepted")
    if fixture["outcome"] not in OUTCOMES:
        raise ValueError("Unknown simulated outcome")
    events = fixture["events"]
    if not isinstance(events, list) or len(events) > 1000:
        raise ValueError("At most 1000 synthetic events accepted")
    previous = -1
    for event in events:
        if not isinstance(event, dict) or set(event) != {"offset_ms", "kind", "detail"}:
            raise ValueError("Invalid synthetic event")
        offset = event["offset_ms"]
        if type(offset) is not int or not 0 <= offset <= 3_600_000 or offset < previous:
            raise ValueError("Synthetic offsets must be monotone and bounded")
        if event["kind"] not in {"install", "launch", "network", "process", "logcat", "collector"}:
            raise ValueError("Unknown event kind")
        if not isinstance(event["detail"], str) or len(event["detail"]) > 4096:
            raise ValueError("Bounded synthetic text required")
        previous = offset
    if fixture["outcome"] in {"dormant", "no_network_observed", "install_failed"} and any(
        e["kind"] == "network" for e in events
    ):
        raise ValueError("Synthetic network activity contradicts outcome")
    encoded = json.dumps(fixture, sort_keys=True, ensure_ascii=True, allow_nan=False)
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    # Reject an existing directory or symlink before publishing any artifact.
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=False)
    writer = EvidencePackWriter(run_dir)
    writer.ensure_layout()
    artifact = writer.write_text("artifacts/controlled_fixture.json", encoded + "\n")
    now = datetime.now(UTC).isoformat()
    manifest = RunManifest(
        run_manifest_version=1,
        dynamic_run_id=str(uuid4()),
        created_at=now,
        status="fixture_only",
        target={
            "fixture_sha256": digest,
            "identity_kind": "controlled_json_fixture",
            "base_apk_sha256": None,
            "package_name": None,
        },
        environment={
            "backend": "offline_contract_fixture",
            "device_access": False,
            "execution_performed": False,
            "network_access": False,
            "isolation_validated": False,
        },
        dataset={"countable": False, "valid_dataset_run": False, "tier": "fixture_only"},
        qa={
            "simulated_outcome": fixture["outcome"],
            "observability": "synthetic_only",
            "real_install_outcome": "not_attempted",
            "real_launch_outcome": "not_attempted",
            "restoration": "not_applicable_no_execution",
        },
        notes=[
            "Controlled fixture only. No APK, malware, emulator, or physical device was executed.",
            "No scientific runtime or containment claim can be made from this pack.",
        ],
    )
    manifest.add_artifacts(
        [
            ArtifactRecord(
                relative_path="artifacts/controlled_fixture.json",
                type="controlled_fixture",
                produced_by="offline_contract_fixture",
                origin="synthetic",
                sha256=writer.hash_file(artifact),
                size_bytes=artifact.stat().st_size,
            )
        ]
    )
    manifest.finalize()
    return writer.write_manifest(manifest)
