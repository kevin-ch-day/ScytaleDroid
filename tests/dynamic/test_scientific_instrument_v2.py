import json
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.core.sealing_v2 import integrity_grade_reasons, verify_inventory
from scytaledroid.DynamicAnalysis.lab.scientific_guest import wait_until
from scytaledroid.DynamicAnalysis.lab.vm_worker import worker_command
from scytaledroid.DynamicAnalysis.pcap.hostname_overlap_v2 import (
    correlate_hosts,
    normalize_host,
    write_hostname_overlap_v2,
)


@pytest.mark.parametrize(
    "value,host,kind",
    [
        ("Example.COM.", "example.com", "DNS_HOST"),
        ("bücher.de", "xn--bcher-kva.de", "DNS_HOST"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de", "DNS_HOST"),
        ("co.uk", "co.uk", "PUBLIC_SUFFIX_ONLY"),
        ("com", "com", "PUBLIC_SUFFIX_ONLY"),
        ("localhost", "localhost", "SYNTHETIC_OR_LOCAL"),
        ("fixture.invalid", "fixture.invalid", "SYNTHETIC_OR_LOCAL"),
        ("127.0.0.1", "127.0.0.1", "IP_ADDRESS"),
        ("[2001:db8::1]", "[2001:db8::1]", "IP_ADDRESS"),
        ("a..com", None, "MALFORMED"),
        ("user@example.com", None, "MALFORMED"),
        ("0.1", None, "MALFORMED"),
    ],
)
def test_normalization(value, host, kind):
    row = normalize_host(value)
    assert row["raw"] == value and row["host"] == host and row["kind"] == kind


def test_relations_and_psl_are_different():
    r = correlate_hosts(
        ["example.com", "example.co.uk", "alice.github.io"],
        ["notexample.com", "x.example.com", "x.example.co.uk", "bob.github.io"],
    )
    assert r["exact_host_overlap_v2"]["count"] == 0
    assert r["subdomain_relation_overlap_v2"]["matched_dynamic_count"] == 2
    assert r["registrable_domain_overlap_v2"]["domains"] == ["example.co.uk", "example.com"]
    assert r["psl"]["unknown_suffix_fallback"] == "none"


def test_case_idna_equality_and_exclusions_retained():
    r = correlate_hosts(
        ["Example.COM.", "bücher.de", "broken..name", "fixture.invalid"],
        ["example.com", "xn--bcher-kva.de"],
    )
    assert r["exact_host_overlap_v2"]["count"] == 2
    assert len(r["inputs"]["static"]) == 4
    assert r["inputs"]["static"][2]["kind"] == "MALFORMED"


def make_pack(tmp_path):
    w = EvidencePackWriter(tmp_path)
    w.ensure_layout()
    w.write_text("artifacts/logcat.txt", "evidence\n")
    m = RunManifest(
        1,
        "id",
        "2026-09-20",
        dataset={"countable": False, "valid_dataset_run": False, "tier": "exploration"},
        artifacts=[
            ArtifactRecord(
                "artifacts/logcat.txt",
                "system_log_capture",
                "observer",
                origin="device",
                pull_status="pulled",
            )
        ],
    )
    return w, m


def test_seal_hashes_and_accounts_unregistered_without_fabricating_provenance(tmp_path):
    w, m = make_pack(tmp_path)
    w.write_text("notes/unregistered.txt", "retained")
    w.write_manifest(m)
    assert len(m.evidence_integrity["files"]) == 2
    assert m.artifacts[0].sha256
    assert verify_inventory(tmp_path, m.evidence_integrity)["valid"]
    assert integrity_grade_reasons(tmp_path, m.evidence_integrity) == [
        {"code": "evidence_provenance_v2_incomplete"}
    ]
    assert m.dataset == {"countable": False, "valid_dataset_run": False, "tier": "exploration"}


def test_seal_is_immutable_and_detects_modified_missing_and_extra_files(tmp_path):
    w, m = make_pack(tmp_path)
    w.write_manifest(m)
    before = (tmp_path / "run_manifest.json").read_bytes()
    with pytest.raises(RuntimeError):
        w.write_manifest(m)
    with pytest.raises(RuntimeError):
        w.write_text("artifacts/new.txt", "bad")
    assert (tmp_path / "run_manifest.json").read_bytes() == before
    (tmp_path / "artifacts/logcat.txt").write_text("changed")
    assert not verify_inventory(tmp_path, m.evidence_integrity)["valid"]
    (tmp_path / "artifacts/logcat.txt").unlink()
    (tmp_path / "extra").write_text("x")
    result = verify_inventory(tmp_path, m.evidence_integrity)
    assert (
        "unaccounted_file:extra" in result["issues"]
        and "missing_or_unreadable:artifacts/logcat.txt" in result["issues"]
    )


def test_symlink_never_reads_outside_and_missing_is_explicit(tmp_path):
    root = tmp_path / "pack"
    root.mkdir()
    outside = tmp_path / "private"
    outside.write_text("secret")
    w, m = make_pack(root)
    (root / "artifacts/link").symlink_to(outside)
    m.artifacts.append(ArtifactRecord("../private", "bad", "test"))
    w.write_manifest(m)
    assert m.evidence_integrity["status"] == "INCOMPLETE"
    assert all(
        r["sha256"] is None for r in m.evidence_integrity["files"] if r["status"] == "EXEMPT"
    )
    assert not verify_inventory(root, m.evidence_integrity)["valid"]


def test_grade_consumes_integrity_contract(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.storage import persistence

    w, m = make_pack(tmp_path)
    w.write_manifest(m)
    monkeypatch.setattr(persistence, "_load_artifact_registry", lambda _: [])
    monkeypatch.setattr(persistence, "resolve_evidence_path", lambda _: tmp_path)
    payload = {
        "status": "success",
        "dynamic_run_id": "id",
        "evidence_path": str(tmp_path),
        "telemetry_process": [{}],
        "telemetry_network": [{}],
        "telemetry_stats": {"expected_samples": 1, "captured_samples": 1},
    }
    assert persistence._evaluate_grade(payload, {})[0] == "PAPER_GRADE"
    # Evidence grade alone has NOT changed the manifest's dataset eligibility.
    assert not m.dataset["countable"]
    (tmp_path / "artifacts/logcat.txt").write_text("tampered")
    grade, reasons = persistence._evaluate_grade(payload, {})
    assert grade == "EXPERIMENTAL" and any(
        r["code"] == "evidence_integrity_v2_failed" for r in reasons
    )


def test_events_after_seal_go_to_separate_sidecar(tmp_path):
    from scytaledroid.DynamicAnalysis.core.event_logger import append_run_event

    w, m = make_pack(tmp_path / "pack")
    w.write_manifest(m)
    append_run_event(tmp_path / "pack", "late_event", {})
    assert not (tmp_path / "pack/notes/run_events.jsonl").exists()
    assert (tmp_path / "pack.postseal/notes/run_events.jsonl").exists()
    assert verify_inventory(tmp_path / "pack", m.evidence_integrity)["valid"]


def test_window_wait_uses_deadline_not_accumulated_sleeps():
    tick = [0]
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        tick[0] += int(s * 1e9) + 100

    wait_until(300_000_000_000, clock=lambda: tick[0], sleep=sleep)
    assert sleeps == [300.0]


def test_worker_has_no_network_personal_mount_or_external_monitor(tmp_path):
    paths = {k: tmp_path / k for k in ["boot", "sdk", "control", "export", "scratch"]}
    for p in paths.values():
        p.mkdir()
    cmd = worker_command(**paths)
    assert cmd[cmd.index("-nic") + 1] == "none" and cmd[cmd.index("-monitor") + 1] == "none"
    assert "--unshare-all" in cmd and "--clearenv" in cmd
    assert "/home/systemadmin" not in cmd and "/dev/bus/usb" not in cmd
    assert cmd.count("--dev-bind") == 1
    assert any("path=/usr" in x and "readonly=on" in x for x in cmd)


def test_v2_never_changes_sealed_pack(tmp_path):
    w, m = make_pack(tmp_path)
    w.write_manifest(m)
    with pytest.raises(RuntimeError):
        write_hostname_overlap_v2(m, tmp_path)


def test_tiktok_exact_regression_preserves_three_distinct_metrics():
    fixture = json.loads(
        (Path(__file__).parents[1] / "fixtures/android_lab/tiktok_hostname_v2.json").read_text()
    )
    assert fixture["run_id"] == "b25ad0a2-94a0-40a2-a552-f98b50d1a2eb"
    r = correlate_hosts(fixture["static"], fixture["dynamic"])
    assert len(fixture["static"]) == 26 and len(fixture["dynamic"]) == 48
    assert r["exact_host_overlap_v2"]["count"] == 0
    assert r["subdomain_relation_overlap_v2"]["matched_static_count"] == 3
    assert r["subdomain_relation_overlap_v2"]["matched_dynamic_count"] == 43
    assert r["registrable_domain_overlap_v2"]["domains"] == [
        "tiktokcdn-us.com",
        "tiktokv.com",
        "tiktokv.us",
    ]
    assert "tiktokcdn.com" in fixture["static"]
    assert not any(
        p["static_host"] == "tiktokcdn.com" for p in r["subdomain_relation_overlap_v2"]["pairs"]
    )
    assert any(x["raw"] == "0.1" and x["kind"] == "MALFORMED" for x in r["inputs"]["static"])


@pytest.mark.parametrize("kind", ["boot", "benign"])
def test_measurement_clock_and_sham_observer_order(monkeypatch, tmp_path, kind):
    from scytaledroid.DynamicAnalysis.lab import scientific_guest as g

    tick = [1_000_000_000_000]
    calls = []
    monkeypatch.setattr(g, "WORK", tmp_path)
    monkeypatch.setattr(g.time, "monotonic_ns", lambda: tick[0])
    monkeypatch.setattr(g.time, "time_ns", lambda: tick[0] + 1_000_000_000_000_000_000)
    monkeypatch.setattr(
        g.time, "sleep", lambda seconds: tick.__setitem__(0, tick[0] + int(seconds * 1e9))
    )
    # wait_until's default callables are bound at definition; inject the simulated clock explicitly.
    original = g.wait_until
    monkeypatch.setattr(
        g,
        "wait_until",
        lambda deadline: original(deadline, clock=g.time.monotonic_ns, sleep=g.time.sleep),
    )

    class Child:
        def poll(self):
            return None

        def terminate(self):
            calls.append(["observer_stop"])

        def wait(self, timeout):
            return 0

    def popen(*a, **k):
        calls.append(["observer_start"])
        return Child()

    monkeypatch.setattr(g.subprocess, "Popen", popen)

    def call(args, **kwargs):
        calls.append(args)
        if args[0] == "install":
            return "Success"
        if args[:3] == ["shell", "pm", "path"]:
            return "package:/x.apk"
        if args[:2] == ["shell", "sha256sum"]:
            return g.SHA + " /x.apk"
        if args[:3] == ["shell", "am", "start"]:
            return "Status: ok"
        if args[:2] == ["shell", "run-as"]:
            return "launches=1"
        return "snapshot"

    result = {}
    g.measure(["adb"], call, {"kind": kind, "measurement_seconds": 300}, result)
    m = result["measurement"]
    assert m["actual_observation_seconds"] == 300 and m["missing_snapshots"] == 0
    assert m["window_end_epoch_ns"] - m["t0_epoch_ns"] == 300_000_000_000
    assert [r["scheduled_offset_seconds"] for r in m["snapshots"]] == [0, 150, 299]
    assert calls.index(["logcat", "-c"]) < calls.index(["observer_start"])
    if kind == "boot":
        assert not any(c[0] == "install" or c[:3] == ["shell", "am", "start"] for c in calls)
    else:
        assert m["apk_launch_finished_ns"] <= m["t0_epoch_ns"]


@pytest.mark.parametrize(
    "damage", ["rows_missing", "bad_row", "duplicate", "metadata", "exclusions"]
)
def test_malformed_seal_fails_closed(tmp_path, damage):
    w, m = make_pack(tmp_path)
    w.write_manifest(m)
    seal = json.loads(json.dumps(m.evidence_integrity))
    if damage == "rows_missing":
        seal["files"] = None
    elif damage == "bad_row":
        seal["files"] = [None]
    elif damage == "duplicate":
        seal["files"].append(seal["files"][0].copy())
    elif damage == "metadata":
        seal["files"][0]["origin"] = []
    else:
        seal["scope_exclusions"] = {}
    result = verify_inventory(tmp_path, seal)
    assert result["valid"] is False and result["issues"]
    assert integrity_grade_reasons(tmp_path, seal)


def test_operational_sidecar_does_not_change_canonical_inventory(tmp_path):
    w, m = make_pack(tmp_path / "pack")
    w.write_manifest(m)
    sidecar = w.derived_writer()
    sidecar.write_json("notes/db_persist_receipt.json", {"status": "not_requested"})
    assert sidecar.run_dir == tmp_path / "pack.postseal"
    assert verify_inventory(w.run_dir, m.evidence_integrity)["valid"]


def test_unknown_suffix_has_no_registrable_fallback():
    r = correlate_hosts(["example.thissuffixdoesnotexist"], ["x.example.thissuffixdoesnotexist"])
    assert r["inputs"]["static"][0]["kind"] == "UNKNOWN_SUFFIX"
    assert r["subdomain_relation_overlap_v2"]["matched_dynamic_count"] == 1
    assert r["registrable_domain_overlap_v2"]["count"] == 0


def test_legacy_automatic_ml_does_not_parse_train_or_mutate_v2_pack(monkeypatch, tmp_path):
    from scytaledroid.DynamicAnalysis.ml import profile_v3_ml_derive as derive

    w, m = make_pack(tmp_path / "baseline")
    w.write_manifest(m)
    monkeypatch.setattr(derive, "_find_latest_runs_for_package", lambda **kw: ("baseline", None))

    def forbidden(**kw):
        pytest.fail("Sealed V2 pack reached legacy parser/trainer")

    monkeypatch.setattr(derive, "_window_rows_for_run", forbidden)
    result = derive.derive_profile_v3_ml_for_package(package="test", evidence_root=tmp_path)
    assert result.errors == ("sealed_v2_requires_external_derivation",)
    assert not result.trained and not result.wrote_baseline
    assert verify_inventory(w.run_dir, m.evidence_integrity)["valid"]


def test_prospective_hostname_writer_preserves_raw_exclusions_and_legacy_bytes(tmp_path):
    w, m = make_pack(tmp_path)
    m.target["static_plan_path"] = "inputs/static_dynamic_plan.json"
    w.write_json(
        m.target["static_plan_path"], {"network_targets": {"domains": ["example.com", "bücher.de"]}}
    )
    w.write_json(
        "analysis/pcap_report.json",
        {
            "top_dns": [
                {"value": "X.Example.COM."},
                {"value": ""},
                {"value": None},
                {"value": "broken..host"},
            ],
            "top_sni": [{"value": "xn--bcher-kva.de"}],
        },
    )
    legacy = w.write_json("analysis/static_dynamic_overlap.json", {"original": True})
    before = legacy.read_bytes()
    record = write_hostname_overlap_v2(m, tmp_path)
    payload = json.loads((tmp_path / record.relative_path).read_text())
    assert [row["raw"] for row in payload["inputs"]["dynamic"]] == [
        "X.Example.COM.",
        "",
        None,
        "broken..host",
        "xn--bcher-kva.de",
    ]
    assert sum(row["kind"] == "MALFORMED" for row in payload["inputs"]["dynamic"]) == 3
    assert payload["exact_host_overlap_v2"]["count"] == 1
    assert payload["subdomain_relation_overlap_v2"]["matched_dynamic_count"] == 2
    assert legacy.read_bytes() == before
    m.outputs.append(record)
    w.write_manifest(m)
    assert verify_inventory(tmp_path, m.evidence_integrity)["valid"]
