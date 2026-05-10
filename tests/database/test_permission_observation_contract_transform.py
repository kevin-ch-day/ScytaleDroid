"""S2-P0: pure transform from static analysis facts → proposed PI observation payload.

No database writes. Contract fields align with
``docs/database/permission_intel_scytaledroid_s2_observation_design.md`` §13.
"""

from __future__ import annotations

from datetime import UTC, datetime


REQUIRED_OBSERVATION_FIELDS: frozenset[str] = frozenset(
    {"permission_string", "artifact_sha256", "static_run_id", "package_name"}
)


def validate_proposed_static_observation_row(row: dict[str, object]) -> tuple[bool, list[str]]:
    """Return (ok, errors) for S2-P1A pre-write contract (no DB)."""
    errs: list[str] = []
    for key in REQUIRED_OBSERVATION_FIELDS:
        val = row.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            errs.append(f"missing_or_empty:{key}")
    ps = row.get("permission_string")
    if isinstance(ps, str) and not ps.strip():
        errs.append("missing_or_empty:permission_string")
    sha = row.get("artifact_sha256")
    if isinstance(sha, str):
        s = sha.strip().lower()
        if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
            errs.append("artifact_sha256_not_64_hex")
    try:
        if int(row.get("static_run_id", 0)) <= 0:
            errs.append("static_run_id_not_positive")
    except (TypeError, ValueError):
        errs.append("static_run_id_invalid")
    return (not errs, errs)


def build_proposed_static_observation_row(
    *,
    permission_string: str,
    artifact_sha256: str,
    static_run_id: int,
    package_name: str,
    apk_id: int | None = None,
    version_code: str | None = None,
    version_name: str | None = None,
    producer: str = "scytaledroid",
    source: str = "apk_manifest",
    source_system: str = "scytaledroid_static",
    observed_at_utc: str | None = None,
    classification: str | None = None,
    bucket: str | None = None,
    rule_fired: str | None = None,
    vendor_id: int | None = None,
    triage_status_note: str | None = None,
) -> dict[str, object]:
    """Return a dict suitable for future ``android_permission_obs_sample`` / registry mapping.

    ``triage_status_note`` is optional parallel context (dict_unknown is a different table).
    """
    stamp = observed_at_utc
    if not stamp:
        stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "permission_string": permission_string,
        "artifact_sha256": artifact_sha256.lower(),
        "static_run_id": int(static_run_id),
        "apk_id": apk_id,
        "package_name": package_name,
        "version_code": version_code,
        "version_name": version_name,
        "producer": producer,
        "source": source,
        "source_system": source_system,
        "observed_at_utc": stamp,
        "classification": classification,
        "bucket": bucket,
        "rule_fired": rule_fired,
        "vendor_id": vendor_id,
        "triage_status_note": triage_status_note,
    }


def propose_queue_action_for_pi(queue_action: str) -> str:
    """S2-P1: normalize Scytale queue verb for Erebus queue-apply compatibility (docs §14)."""
    q = str(queue_action or "").strip().lower()
    if q == "aosp_promote":
        return "aosp"
    return q


def test_build_proposed_row_contains_contract_fields() -> None:
    row = build_proposed_static_observation_row(
        permission_string="android.permission.CAMERA",
        artifact_sha256="A" * 64,
        static_run_id=42,
        package_name="com.example.app",
        apk_id=7,
        version_code="123",
        version_name="1.2.3",
        observed_at_utc="2026-05-09 12:00:00",
        classification="AOSP",
        bucket="AOSP_EXACT",
        rule_fired="aosp_dict",
    )
    assert row["permission_string"] == "android.permission.CAMERA"
    assert row["artifact_sha256"] == "a" * 64
    assert row["static_run_id"] == 42
    assert row["apk_id"] == 7
    assert row["package_name"] == "com.example.app"
    assert row["version_code"] == "123"
    assert row["version_name"] == "1.2.3"
    assert row["producer"] == "scytaledroid"
    assert row["source"] == "apk_manifest"
    assert row["source_system"] == "scytaledroid_static"
    assert row["observed_at_utc"] == "2026-05-09 12:00:00"
    assert row["classification"] == "AOSP"
    assert row["bucket"] == "AOSP_EXACT"
    assert row["rule_fired"] == "aosp_dict"


def test_normalize_aosp_promote_to_aosp() -> None:
    assert propose_queue_action_for_pi("aosp_promote") == "aosp"
    assert propose_queue_action_for_pi("AOSP_PROMOTE") == "aosp"
    assert propose_queue_action_for_pi("defer") == "defer"


def test_validate_rejects_missing_required() -> None:
    ok, err = validate_proposed_static_observation_row({})
    assert not ok
    assert any("permission_string" in e for e in err)

    ok, err = validate_proposed_static_observation_row(
        {
            "permission_string": "android.permission.X",
            "artifact_sha256": "",
            "static_run_id": 1,
            "package_name": "a.b",
        }
    )
    assert not ok

    ok, err = validate_proposed_static_observation_row(
        {
            "permission_string": "android.permission.X",
            "artifact_sha256": "g" * 64,
            "static_run_id": 1,
            "package_name": "a.b",
        }
    )
    assert not ok
    assert any("sha256" in e for e in err)


def test_validate_accepts_minimal_and_multipersm_same_run() -> None:
    base = dict(
        artifact_sha256="a" * 64,
        static_run_id=100,
        package_name="com.example.app",
        source="apk_manifest",
        producer="scytaledroid",
    )
    r1 = build_proposed_static_observation_row(
        permission_string="android.permission.CAMERA", **base
    )
    r2 = build_proposed_static_observation_row(
        permission_string="android.permission.SMS", **base
    )
    assert validate_proposed_static_observation_row(r1)[0]
    assert validate_proposed_static_observation_row(r2)[0]
    assert r1["static_run_id"] == r2["static_run_id"]
    assert r1["artifact_sha256"] == r2["artifact_sha256"]

    r_other_run = build_proposed_static_observation_row(
        permission_string="android.permission.CAMERA",
        artifact_sha256="a" * 64,
        static_run_id=200,
        package_name="com.example.app",
    )
    r_other_hash = build_proposed_static_observation_row(
        permission_string="android.permission.CAMERA",
        artifact_sha256="b" * 64,
        static_run_id=100,
        package_name="com.example.app",
    )
    assert validate_proposed_static_observation_row(r_other_run)[0]
    assert validate_proposed_static_observation_row(r_other_hash)[0]
    assert r_other_run["static_run_id"] != r_other_hash["static_run_id"]


def test_validate_optional_version_device_omitted() -> None:
    row = build_proposed_static_observation_row(
        permission_string="p",
        artifact_sha256="c" * 64,
        static_run_id=1,
        package_name="x",
        version_code=None,
        version_name=None,
    )
    ok, err = validate_proposed_static_observation_row(row)
    assert ok and not err
