"""Read-only verification of the frozen eight-sample pre-execution packet.

This module hashes opaque quarantine bytes; it never parses or executes APKs,
connects to a database, or grants execution authority.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path, PurePosixPath


class PilotVerificationError(ValueError):
    """A bounded input or frozen relationship failed verification."""


def require(condition, reason):
    if not condition:
        raise PilotVerificationError(reason)


def _path(root: Path, relative: str) -> Path:
    require(isinstance(relative, str), "invalid relative path")
    parts = PurePosixPath(relative)
    require(
        bool(relative)
        and not parts.is_absolute()
        and str(parts) == relative
        and ".." not in parts.parts
        and "\\" not in relative
        and not any(ord(c) < 32 for c in relative),
        "unsafe relative path",
    )
    path = root
    for part in parts.parts:
        path /= part
        require(not path.is_symlink(), "symlink refused")
    return path


def _bytes(path: Path, limit: int = 64 * 1024**2) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        metadata = os.fstat(f.fileno())
        require(stat.S_ISREG(metadata.st_mode), "nonregular file refused")
        require(metadata.st_size <= limit, "input exceeds size bound")
        data = f.read(limit + 1)
        require(len(data) <= limit, "input exceeds size bound")
        return data


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), "invalid SHA-256")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _json(data):
    return json.loads(data, object_pairs_hook=_pairs)


def _digest(value):
    return _hash(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    )


def verify_pilot(
    packet: Path,
    *,
    expected_manifest_sha256: str,
    source_root: Path,
    quarantine: Path | None = None,
) -> dict:
    """Verify a pinned V1 packet and return diagnostics without changing inputs.

    The manifest digest must come from outside the packet. A checksum list alone
    cannot authenticate a rewritten manifest. Verification assumes the local
    input directories are not concurrently replaced during the read.
    """
    packet, source_root = Path(packet).absolute(), Path(source_root).absolute()
    require(not packet.is_symlink() and packet.is_dir(), "invalid packet root")
    manifest_bytes = _bytes(_path(packet, "pilot_dataset_manifest.json"))
    require(_hash(manifest_bytes) == _sha(expected_manifest_sha256), "manifest pin mismatch")
    manifest = _json(manifest_bytes)
    seals = {}
    for line in _bytes(_path(packet, "checksums.sha256")).decode().splitlines():
        digest, separator, name = line.partition("  ")
        require(
            separator and name not in seals and name != "checksums.sha256", "invalid checksum index"
        )
        _path(packet, name)
        seals[name] = _sha(digest)
    require(0 < len(seals) <= 5000, "checksum count out of bounds")
    total = 0
    for name, digest in seals.items():
        data = _bytes(_path(packet, name))
        total += len(data)
        require(total <= 512 * 1024**2, "packet exceeds total size bound")
        require(_hash(data) == digest, "packet checksum mismatch")

    def read(name):
        require(name in seals, "required input is not sealed")
        data = _bytes(_path(packet, name))
        require(_hash(data) == seals[name], "input changed during verification")
        return data

    require(
        read("pilot_dataset_manifest.json") == manifest_bytes,
        "manifest changed during verification",
    )
    require(
        manifest["dataset_id"] == "MALWARE_DYNAMIC_PILOT_V1" and manifest["version"] == 1,
        "unsupported pilot contract",
    )
    require(
        manifest["execution_authorized"] is False
        and manifest["runtime_observations_used"] is False
        and manifest["replace_samples_after_observing_behavior"] is False
        and manifest["default_countable"] is False,
        "pre-execution boundary changed",
    )
    require(
        manifest["protocol"] == "offline_300s_no_touch_v2"
        and manifest["window_seconds"] == 300
        and manifest["malware_runs"] == manifest["sham_runs"] == 24
        and manifest["hostname_metric"] == manifest["evidence_sealing"] == "V2",
        "frozen protocol changed",
    )
    plan = _json(read("acquisition_plan.json"))
    approved = [_sha(s) for s in plan["hashes"]]
    require(len(approved) == len(set(approved)) == 16, "approved cohort is not unique sixteen")
    require(
        _hash(read("approved_proposal.tsv"))
        == plan["proposal_sha256"]
        == manifest["acquisition_plan_identity"],
        "proposal identity mismatch",
    )
    selected = manifest["selected"]
    shas = [_sha(r["sha256"]) for r in selected]
    require(
        len(shas) == len(set(shas)) == 8 and set(shas) <= set(approved), "invalid selected eight"
    )
    require(
        [r["pilot_id"] for r in selected] == [f"P{i:02}" for i in range(1, 9)],
        "pilot label mismatch",
    )
    excluded = [r["sha256"] for r in manifest["exclusions"]]
    require(
        len(excluded) == len(set(excluded)) == 8 and set(excluded) == set(approved) - set(shas),
        "exclusion ledger mismatch",
    )
    instrument = manifest["instrument_sources"]
    require(len(instrument) == len({r["path"] for r in instrument}) == 21, "invalid instrument set")
    for entry in instrument:
        require(
            _hash(_bytes(_path(source_root, entry["path"]))) == _sha(entry["sha256"]),
            "instrument source drift",
        )
    sidecar = read("frozen_assessment_evidence.json")
    require(
        _hash(sidecar) == manifest["frozen_assessment_evidence_sha256"], "evidence sidecar mismatch"
    )
    records = [_json(line) for line in read("assessments.jsonl").splitlines() if line]
    by_sha = {r["artifact"]["sha256"]: r for r in records}
    require(
        len(records) == len(by_sha) == 8 and set(by_sha) == set(shas), "assessment scope mismatch"
    )
    gaps = []
    for row in selected:
        sha = row["sha256"]
        baseline_bytes = read(row["baseline_file"])
        require(_hash(baseline_bytes) == row["baseline_sha256"], "baseline digest mismatch")
        baseline = _json(baseline_bytes)
        static = baseline["static"]
        require(
            baseline["sha256"] == static["sha256"] == static["extracted_sha256"] == sha,
            "baseline artifact mismatch",
        )
        require(
            baseline["runtime_evidence_used"] is False
            and not baseline["erebus"]["scytale"]["dynamic"],
            "runtime evidence in baseline",
        )
        require(
            static["status"] == "VALID_APK"
            and static["compatibility"] == row["compatibility"] == "LIKELY_COMPATIBLE"
            and static["signer_verification_returncode"] == 0
            and static["launchable_activities"]
            and not static["split_required"]
            and int(static["min_sdk"]) <= 30
            and (not static["abis"] or bool(set(static["abis"]) & {"x86", "x86_64"})),
            "static eligibility mismatch",
        )
        result = by_sha[sha]
        require(
            result["assessment_id"] == row["assessment_id"]
            and result["revision"] == row["assessment_revision"] == 1
            and result["previous_assessment_id"] is None,
            "frozen revision mismatch",
        )
        body = {
            k: v
            for k, v in result.items()
            if k not in {"assessment_id", "revision", "previous_assessment_id", "assessed_at_utc"}
        }
        require(
            _digest(
                {
                    "artifact_sha256": sha,
                    "revision": 1,
                    "previous_assessment_id": None,
                    "input_digest": _digest(body),
                }
            )
            == result["assessment_id"],
            "assessment identity digest mismatch",
        )
        require(body == baseline["operational_assessment_preview"], "assessment baseline mismatch")
        if quarantine is not None:
            raw = _bytes(_path(Path(quarantine).absolute(), f"raw/{sha}/sample.bin"), 256 * 1024**2)
            require(_hash(raw) == sha, "quarantine payload mismatch")
        pi = baseline["permission_coverage"]
        family = result["assessment"]["family"]
        gaps.append(
            {
                "sha256": sha,
                "assessment_id": result["assessment_id"],
                "revision": 1,
                "processing_status": result["processing"]["status"],
                "catalog_platform": result["artifact"]["platform"]["value"],
                "catalog_format": result["artifact"]["format"]["value"],
                "family_state": family["state"],
                "family_reason": family["reason"],
                "permission_projection": pi["projection_state"],
                "declared_permission_count": pi["declared_count"],
                "observed_permission_count": pi["observed_count"],
                "missing_declared_tokens": pi["missing_declared_tokens"],
                "unresolved_declared_tokens": pi["unresolved_declared_tokens"],
                "historical_observations_rewritten": False,
            }
        )
    schedule_bytes = read("future_run_order.tsv")
    require(_hash(schedule_bytes) == manifest["schedule_sha256"], "schedule digest mismatch")
    schedule = list(csv.DictReader(io.StringIO(schedule_bytes.decode()), delimiter="\t"))
    seed = _hash(
        (
            manifest["dataset_id"] + "\0" + plan["proposal_sha256"] + "\0" + "\n".join(sorted(shas))
        ).encode()
    )
    require(seed == manifest["seed"], "schedule seed mismatch")
    pairs = sorted(
        ((s, i) for s in shas for i in range(1, 4)),
        key=lambda p: _hash(f"{seed}|pair|{p[0]}|{p[1]}".encode()),
    )
    expected = [
        (s, str(i), arm)
        for s, i in pairs
        for arm in sorted(
            ["malware", "sham"], key=lambda a: _hash(f"{seed}|arm|{s}|{i}|{a}".encode())
        )
    ]
    require(
        [(r["sha256"], r["repeat"], r["arm"]) for r in schedule] == expected,
        "schedule ordering or membership mismatch",
    )
    require(
        all(
            r["sequence"] == str(i)
            and r["window_seconds"] == "300"
            and r["pair_id"] == f"PAIR{(i + 1) // 2:02}"
            and r["pilot_id"] == selected[shas.index(r["sha256"])]["pilot_id"]
            and r["seed"] == seed
            and r["state"] == "PLANNED_NOT_AUTHORIZED"
            and r["fresh_outer_vm"] == r["fresh_android_userdata"] == "True"
            and r["install_and_launch_sample"] == str(r["arm"] == "malware")
            for i, r in enumerate(schedule, 1)
        ),
        "schedule boundary mismatch",
    )
    return {
        "contract": "pilot-preflight.v1",
        "dataset_id": manifest["dataset_id"],
        "manifest_sha256": expected_manifest_sha256,
        "packet_integrity": "verified",
        "files_verified": len(seals),
        "instrument_files_verified": 21,
        "quarantine_bytes": "verified" if quarantine is not None else "not_checked",
        "execution_authorized": False,
        "database_checked": False,
        "selected_count": 8,
        "planned_malware_runs": 24,
        "planned_sham_runs": 24,
        "family_states": dict(Counter(r["family_state"] for r in gaps)),
        "permission_projection": dict(Counter(r["permission_projection"] for r in gaps)),
        "processing_states": dict(Counter(r["processing_status"] for r in gaps)),
        "evidence_gaps": gaps,
        "scope": "Frozen evidence only; no live DB freshness, installation or runtime proof",
    }
