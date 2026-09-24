"""Offline adversarial tests; fixtures contain synthetic text, never APKs."""

import csv
import hashlib
import json
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.tools.pilot_preflight import (
    PilotVerificationError,
    _digest,
    verify_pilot,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def packet(tmp_path):
    root, source, quarantine = [tmp_path / n for n in ("packet", "source", "quarantine")]
    for p in (root, source, quarantine):
        p.mkdir()

    def write(name, value):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value, sort_keys=True))

    hashes = [sha(f"synthetic-{i}".encode()) for i in range(16)]
    (root / "approved_proposal.tsv").write_text("synthetic-reviewed-proposal")
    proposal = sha((root / "approved_proposal.tsv").read_bytes())
    write("acquisition_plan.json", {"hashes": hashes, "proposal_sha256": proposal})
    write("frozen_assessment_evidence.json", {})
    sources = []
    for i in range(21):
        p = source / f"source{i}.py"
        p.write_text("# frozen synthetic instrument\n")
        sources.append({"path": p.name, "sha256": sha(p.read_bytes())})
    selected, records = [], []
    for i, s in enumerate(hashes[:8]):
        raw = quarantine / "raw" / s / "sample.bin"
        raw.parent.mkdir(parents=True)
        raw.write_text(f"synthetic-{i}")
        body = {
            "artifact": {"sha256": s, "platform": {"value": "unknown"}, "format": {"value": None}},
            "processing": {"status": "unsupported_artifact"},
            "assessment": {"family": {"state": "unresolved", "reason": "No governed assignment"}},
        }
        aid = _digest(
            {
                "artifact_sha256": s,
                "revision": 1,
                "previous_assessment_id": None,
                "input_digest": _digest(body),
            }
        )
        records.append(
            {
                **body,
                "assessment_id": aid,
                "revision": 1,
                "previous_assessment_id": None,
                "assessed_at_utc": "fixture",
            }
        )
        name = f"baselines/{s}.json"
        write(
            name,
            {
                "sha256": s,
                "runtime_evidence_used": False,
                "erebus": {"scytale": {"dynamic": []}},
                "static": {
                    "sha256": s,
                    "extracted_sha256": s,
                    "status": "VALID_APK",
                    "compatibility": "LIKELY_COMPATIBLE",
                    "min_sdk": "21",
                    "signer_verification_returncode": 0,
                    "launchable_activities": ["Main"],
                    "split_required": False,
                    "abis": [],
                },
                "operational_assessment_preview": body,
                "permission_coverage": {
                    "projection_state": "ABSENT",
                    "declared_count": 1,
                    "observed_count": 0,
                    "missing_declared_tokens": ["android.permission.INTERNET"],
                    "unresolved_declared_tokens": [],
                },
            },
        )
        selected.append(
            {
                "sha256": s,
                "pilot_id": f"P{i + 1:02}",
                "baseline_file": name,
                "baseline_sha256": sha((root / name).read_bytes()),
                "compatibility": "LIKELY_COMPATIBLE",
                "assessment_id": aid,
                "assessment_revision": 1,
            }
        )
    (root / "assessments.jsonl").write_text("\n".join(map(json.dumps, records)))
    seed = sha(
        ("MALWARE_DYNAMIC_PILOT_V1\0" + proposal + "\0" + "\n".join(sorted(hashes[:8]))).encode()
    )
    pairs = sorted(
        ((s, i) for s in hashes[:8] for i in range(1, 4)),
        key=lambda p: sha(f"{seed}|pair|{p[0]}|{p[1]}".encode()),
    )
    schedule = []
    for pair_number, (s, repeat) in enumerate(pairs, 1):
        for arm in sorted(
            ["malware", "sham"], key=lambda a: sha(f"{seed}|arm|{s}|{repeat}|{a}".encode())
        ):
            schedule.append(
                dict(
                    sequence=len(schedule) + 1,
                    sha256=s,
                    repeat=repeat,
                    arm=arm,
                    pair_id=f"PAIR{pair_number:02}",
                    pilot_id=f"P{hashes.index(s) + 1:02}",
                    window_seconds=300,
                    seed=seed,
                    state="PLANNED_NOT_AUTHORIZED",
                    fresh_outer_vm=True,
                    fresh_android_userdata=True,
                    install_and_launch_sample=arm == "malware",
                )
            )
    with (root / "future_run_order.tsv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(schedule[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(schedule)
    manifest = dict(
        dataset_id="MALWARE_DYNAMIC_PILOT_V1",
        version=1,
        selected=selected,
        exclusions=[{"sha256": s} for s in hashes[8:]],
        acquisition_plan_identity=proposal,
        instrument_sources=sources,
        execution_authorized=False,
        runtime_observations_used=False,
        replace_samples_after_observing_behavior=False,
        default_countable=False,
        protocol="offline_300s_no_touch_v2",
        window_seconds=300,
        malware_runs=24,
        sham_runs=24,
        hostname_metric="V2",
        evidence_sealing="V2",
        frozen_assessment_evidence_sha256=sha(
            (root / "frozen_assessment_evidence.json").read_bytes()
        ),
        schedule_sha256=sha((root / "future_run_order.tsv").read_bytes()),
        seed=seed,
    )
    write("pilot_dataset_manifest.json", manifest)

    def seal():
        paths = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "checksums.sha256")
        (root / "checksums.sha256").write_text(
            "".join(f"{sha(p.read_bytes())}  {p.relative_to(root)}\n" for p in paths)
        )
        return sha((root / "pilot_dataset_manifest.json").read_bytes())

    pin = seal()
    return root, source, quarantine, pin, seal


def check(packet, *, quarantine=True):
    root, source, raw, pin, _ = packet
    return verify_pilot(
        root,
        expected_manifest_sha256=pin,
        source_root=source,
        quarantine=raw if quarantine else None,
    )


def test_verified_packet_retains_uncertainty_and_no_authorization(packet):
    result = check(packet)
    assert result["packet_integrity"] == result["quarantine_bytes"] == "verified"
    assert result["family_states"] == {"unresolved": 8}
    assert result["processing_states"] == {"unsupported_artifact": 8}
    assert not result["execution_authorized"] and not result["database_checked"]
    assert check(packet, quarantine=False)["quarantine_bytes"] == "not_checked"


@pytest.mark.parametrize("kind", ["baseline", "source", "payload", "pin", "missing"])
def test_drift_refused(packet, kind):
    root, source, raw, pin, seal = packet
    if kind == "baseline":
        next((root / "baselines").iterdir()).write_text("tampered")
    elif kind == "source":
        next(source.iterdir()).write_text("changed instrument")
    elif kind == "payload":
        next(raw.rglob("sample.bin")).write_text("other bytes")
    elif kind == "missing":
        (root / "assessments.jsonl").unlink()
    else:
        packet = root, source, raw, "f" * 64, seal
    with pytest.raises((PilotVerificationError, OSError)):
        check(packet)


@pytest.mark.parametrize(
    "change", ["authorization", "duplicate", "protocol", "traversal", "revision"]
)
def test_coherently_resealed_bad_manifest_refused(packet, change):
    root, source, raw, _, seal = packet
    path = root / "pilot_dataset_manifest.json"
    m = json.loads(path.read_text())
    if change == "authorization":
        m["execution_authorized"] = True
    elif change == "duplicate":
        m["selected"][1] = m["selected"][0]
    elif change == "protocol":
        m["window_seconds"] = 30
    elif change == "traversal":
        m["selected"][0]["baseline_file"] = "../outside.json"
    else:
        m["selected"][0]["assessment_revision"] = 2
    path.write_text(json.dumps(m))
    with pytest.raises(PilotVerificationError):
        check((root, source, raw, seal(), seal))


def test_duplicate_checksum_and_symlink_refused(packet):
    root, _, _, _, _ = packet
    checksum = root / "checksums.sha256"
    content = checksum.read_text()
    checksum.write_text(content + content.splitlines()[0] + "\n")
    with pytest.raises(PilotVerificationError, match="index"):
        check(packet)
    checksum.write_text(content)
    path = root / "approved_proposal.tsv"
    target = root.parent / "outside"
    target.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(PilotVerificationError, match="symlink"):
        check(packet)


def test_resealed_wrong_schedule_order_refused(packet):
    root, source, raw, _, seal = packet
    path = root / "future_run_order.tsv"
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    manifest_path = root / "pilot_dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["schedule_sha256"] = sha(path.read_bytes())
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(PilotVerificationError, match="ordering"):
        check((root, source, raw, seal(), seal))


def test_duplicate_json_key_refused(packet):
    root, source, raw, _, seal = packet
    path = root / "pilot_dataset_manifest.json"
    path.write_text(path.read_text()[:-1] + ', "version": 1}')
    with pytest.raises(PilotVerificationError, match="duplicate JSON"):
        check((root, source, raw, seal(), seal))


@pytest.mark.parametrize("with_bytes,expected_exit", [(True, 0), (False, 3)])
def test_cli_distinguishes_verified_and_unchecked_bytes(packet, with_bytes, expected_exit):
    import subprocess
    import sys

    root, source, raw, pin, _ = packet
    before = {p: sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}
    script = Path(__file__).resolve().parents[2] / "scripts/dynamic/verify_pilot.py"
    args = [
        sys.executable,
        str(script),
        "--packet",
        str(root),
        "--source-root",
        str(source),
        "--expect-manifest-sha256",
        pin,
    ]
    if with_bytes:
        args += ["--quarantine", str(raw)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    assert result.returncode == expected_exit, result.stdout + result.stderr
    assert not json.loads(result.stdout)["execution_authorized"]
    assert before == {p: sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def preruntime_packet(packet, tmp_path):
    root, source, quarantine, _, seal = packet
    for path in (root / "baselines").glob("*.json"):
        value = json.loads(path.read_text())
        value["static"]["permissions"] = []
        path.write_text(json.dumps(value))
    manifest = json.loads((root / "pilot_dataset_manifest.json").read_text())
    for row in manifest["selected"]:
        row["baseline_sha256"] = sha((root / row["baseline_file"]).read_bytes())
    (root / "pilot_dataset_manifest.json").write_text(json.dumps(manifest))
    original_pin = seal()
    v2 = tmp_path / "v2"
    v2.mkdir()
    records = [json.loads(line) for line in (root / "assessments.jsonl").read_text().splitlines()]

    def write(name, value):
        p = v2 / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value))

    write("evidence/assessments_before.json", records)
    write("evidence/assessments_after.json", records)
    rows = []
    for selected, record in zip(manifest["selected"], records, strict=True):
        h = selected["sha256"]
        write(
            "permission_projections/" + h + ".json",
            {
                "sha256": h,
                "baseline_sha256": selected["baseline_sha256"],
                "declared_count": 0,
                "accounted_count": 0,
                "occurrence_complete": True,
                "rows": [],
            },
        )
        rows.append(
            {
                "pilot_id": selected["pilot_id"],
                "sha256": h,
                "baseline_sha256": selected["baseline_sha256"],
                "original_assessment_id": record["assessment_id"],
                "assessment_id": record["assessment_id"],
                "revision": 1,
                "execution_authorized": False,
                "evidence_cutoff_at": "fixture",
            }
        )
    write("pre_runtime_v2.json", rows)
    for name in (
        "17_statistical_analysis_plan.md",
        "18_missingness_and_rerun_policy.md",
        "analysis_variables.tsv",
    ):
        (v2 / name).write_text("synthetic plan")

    def seal_v2():
        files = {
            str(p.relative_to(v2)): sha(p.read_bytes())
            for p in v2.rglob("*")
            if p.is_file() and p.name != "pre_runtime_v2_manifest.json"
        }
        write(
            "pre_runtime_v2_manifest.json",
            {
                "dataset_id": "MALWARE_DYNAMIC_PILOT_PRE_RUNTIME_V2",
                "execution_authorized": False,
                "runtime_evidence_used": False,
                "original_manifest_sha256": original_pin,
                "original_evidence_cutoff_at": "fixture",
                "files": files,
            },
        )
        return sha((v2 / "pre_runtime_v2_manifest.json").read_bytes())

    return v2, root, source, quarantine, seal_v2


def test_preruntime_freeze_validates_and_rejects_resealed_cutoff(preruntime_packet):
    from scytaledroid.DynamicAnalysis.tools.pilot_preruntime_v2 import verify_preruntime_v2

    v2, root, source, quarantine, seal = preruntime_packet

    def verify():
        return verify_preruntime_v2(
            v2,
            expected_manifest_sha256=seal(),
            original_packet=root,
            source_root=source,
            quarantine=quarantine,
        )

    assert verify()["v2_assessment_mappings_verified"] == 8
    rows = json.loads((v2 / "pre_runtime_v2.json").read_text())
    rows[0]["evidence_cutoff_at"] = "changed"
    (v2 / "pre_runtime_v2.json").write_text(json.dumps(rows))
    with pytest.raises(PilotVerificationError, match="cutoff"):
        verify()


def test_preruntime_freeze_rejects_forged_historical_payload(preruntime_packet):
    from scytaledroid.DynamicAnalysis.tools.pilot_preruntime_v2 import verify_preruntime_v2

    v2, root, source, quarantine, seal = preruntime_packet
    records = json.loads((v2 / "evidence/assessments_before.json").read_text())
    records[0]["revision"] = 4
    (v2 / "evidence/assessments_before.json").write_text(json.dumps(records))
    with pytest.raises(PilotVerificationError, match="original assessment"):
        verify_preruntime_v2(
            v2,
            expected_manifest_sha256=seal(),
            original_packet=root,
            source_root=source,
            quarantine=quarantine,
        )
