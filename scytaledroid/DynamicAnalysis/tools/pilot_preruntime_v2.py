"""Verify an additive pre-runtime freeze against the preserved original pilot."""

from pathlib import Path

from .pilot_preflight import _bytes, _digest, _hash, _json, _path, require, verify_pilot


def verify_preruntime_v2(
    packet, *, expected_manifest_sha256, original_packet, source_root, quarantine
):
    packet = Path(packet).absolute()
    require(not packet.is_symlink(), "symlink packet refused")
    raw = _bytes(_path(packet, "pre_runtime_v2_manifest.json"))
    require(_hash(raw) == expected_manifest_sha256, "V2 manifest pin mismatch")
    manifest = _json(raw)
    require(manifest["dataset_id"] == "MALWARE_DYNAMIC_PILOT_PRE_RUNTIME_V2", "wrong V2 dataset")
    require(
        manifest["execution_authorized"] is False and manifest["runtime_evidence_used"] is False,
        "execution boundary changed",
    )
    original = verify_pilot(
        Path(original_packet),
        expected_manifest_sha256=manifest["original_manifest_sha256"],
        source_root=Path(source_root),
        quarantine=Path(quarantine),
    )
    files = manifest["files"]
    require(0 < len(files) <= 1000, "invalid file count")
    for name, sha in files.items():
        require(_hash(_bytes(_path(packet, name))) == sha, "V2 evidence checksum mismatch")

    def read(name):
        require(name in files, "unsealed V2 input")
        return _json(_bytes(_path(packet, name)))

    rows = read("pre_runtime_v2.json")
    old = read("evidence/assessments_before.json")
    current = read("evidence/assessments_after.json")
    old_by = {r["artifact"]["sha256"]: r for r in old}
    new_by = {r["artifact"]["sha256"]: r for r in current}
    v1 = _json(_bytes(_path(Path(original_packet), "pilot_dataset_manifest.json")))
    selected = {r["sha256"]: r for r in v1["selected"]}
    original_records = {
        _json(line)["artifact"]["sha256"]: _json(line)
        for line in _bytes(_path(Path(original_packet), "assessments.jsonl")).splitlines()
        if line
    }
    require(old_by == original_records, "original assessment payload changed")
    require(len(rows) == len(old_by) == len(new_by) == len(selected) == 8, "V2 row count mismatch")
    require(
        len({r["sha256"] for r in rows}) == 8 and set(old_by) == set(new_by) == set(selected),
        "V2 membership mismatch",
    )
    for row in rows:
        sha = row["sha256"]
        initial = old_by[sha]
        latest = new_by[sha]
        body = {
            k: v
            for k, v in latest.items()
            if k not in {"assessment_id", "revision", "previous_assessment_id", "assessed_at_utc"}
        }
        identity = {
            "artifact_sha256": sha,
            "input_digest": _digest(body),
            "revision": latest["revision"],
            "previous_assessment_id": latest["previous_assessment_id"],
        }
        require(
            _digest(identity) == latest["assessment_id"], "assessment content identity mismatch"
        )
        require(row["pilot_id"] == selected[sha]["pilot_id"], "pilot label changed")
        require(
            row["original_assessment_id"] == initial["assessment_id"] and initial["revision"] == 1,
            "historical mapping changed",
        )
        require(
            row["assessment_id"] == latest["assessment_id"]
            and row["revision"] == latest["revision"],
            "current mapping mismatch",
        )
        require(row["execution_authorized"] is False, "execution flag changed")
        require(
            row["baseline_sha256"]
            == _hash(_bytes(_path(Path(original_packet), "baselines/" + sha + ".json"))),
            "baseline drift",
        )
        projection = read("permission_projections/" + sha + ".json")
        require(
            projection["sha256"] == sha and projection["baseline_sha256"] == row["baseline_sha256"],
            "projection identity mismatch",
        )
        require(
            projection["accounted_count"]
            == projection["declared_count"]
            == len(projection["rows"]),
            "declaration accounting mismatch",
        )
        require(projection["occurrence_complete"] is True, "incomplete occurrence ledger")
        baseline = _json(_bytes(_path(Path(original_packet), "baselines/" + sha + ".json")))
        require(
            [r["raw_token"] for r in projection["rows"]] == baseline["static"]["permissions"],
            "declaration token mismatch",
        )
        if latest["revision"] > 1:
            require(
                latest["previous_assessment_id"] == initial["assessment_id"],
                "revision chain mismatch",
            )
            context = latest["provenance"]["batch_context"]
            require(context["evidence_cutoff_at"] == row["evidence_cutoff_at"], "cutoff mismatch")
            ref = context["static_baseline_reference"]["static_declaration_projection"]
            require(
                ref["file_sha256"] == files["permission_projections/" + sha + ".json"],
                "assessment projection mismatch",
            )
        else:
            require(latest == initial, "retained revision changed")
            require(
                row["evidence_cutoff_at"] == manifest["original_evidence_cutoff_at"],
                "original cutoff changed",
            )
    require(
        "17_statistical_analysis_plan.md" in files
        and "analysis_variables.tsv" in files
        and "18_missingness_and_rerun_policy.md" in files,
        "analysis plan missing",
    )
    return {
        "status": "passed",
        "pilot_count": 8,
        "original_verification": original,
        "v2_assessment_mappings_verified": 8,
        "execution_authorized": False,
        "runtime_evidence_used": False,
    }
