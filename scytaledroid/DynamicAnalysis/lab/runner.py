"""One fresh, pinned benign Android acceptance run; never schedules malware."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.DynamicAnalysis.core.evidence_pack import EvidencePackWriter
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest

from .sandbox import BACKEND, FIXTURE_PACKAGE, NETWORK_PROFILE, sandbox_command, verify_fixture


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def execution_failures(payload: dict, *, returncode: int, image_unchanged: bool) -> list[str]:
    """Require successful execution and cleanup, not just a successful fixture."""
    checks = {
        "harness_failed": payload.get("status") == "passed",
        "sandbox_failed": returncode == 0,
        "image_changed": image_unchanged,
        "emulator_not_stopped": payload.get("emulator_stopped") is True,
        "emulator_exit_failed": payload.get("emulator_returncode") == 0,
        "emulator_exited_early": payload.get("natural_emulator_exit") is None,
        "cleanup_failed_or_unverified": payload.get("cleanup_errors") == [],
    }
    return [reason for reason, ok in checks.items() if not ok]


def fixture_dns_canary_observed(report: dict) -> bool:
    """Background traffic alone cannot establish fixture capture coverage."""
    return any(
        row.get("value") == "fixture.invalid" and row.get("count", 0) > 0
        for row in report.get("top_dns", [])
    )


def _run_trial(
    *,
    lab_root: Path,
    apk: Path,
    output: Path,
    kind: str,
    gpu_mode: str,
    full_controls: bool,
    controls: tuple[str, ...] | None = None,
) -> dict:
    """Execute one acceptance trial in a fresh namespace and fresh AVD filesystem."""
    if kind not in {"boot", "benign"} or gpu_mode not in {
        "software",
        "swiftshader",
        "lavapipe",
        "swangle",
    }:
        raise ValueError("Unsupported bounded trial")
    if controls is None:
        controls = ("wipe", "grpc", "dns", "pcap") if full_controls else ()
    if set(controls) - {"wipe", "grpc", "dns", "pcap"}:
        raise ValueError("Unknown research control")
    sha = verify_fixture(apk)
    lab_root = Path(lab_root).resolve(strict=True)
    sdk = lab_root / "sdk"
    golden = lab_root / "golden.avd"
    if output.exists():
        raise FileExistsError("Evidence destination already exists")
    ident = str(uuid.uuid4())
    workspace = lab_root / "runtime" / ident
    workspace.mkdir(parents=True)
    try:
        (workspace / "trial.json").write_text(
            json.dumps(
                {
                    "kind": kind,
                    "gpu_mode": gpu_mode,
                    "full_controls": full_controls,
                    "controls": list(controls),
                }
            )
        )
        avd = workspace / "avds/phase1.avd"
        avd.mkdir(parents=True)
        values = {}
        for line in (golden / "config.ini").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                values[k] = v
        values.update(
            {
                "AvdId": "phase1",
                "avd.id": "phase1",
                "avd.name": "phase1",
                "image.sysdir.1": "/sdk/system-images/android-30/default/x86_64/",
                "hw.ramSize": "1536",
                "hw.cpu.ncore": "2",
                "hw.lcd.width": "540",
                "hw.lcd.height": "960",
                "hw.lcd.density": "240",
                "hw.camera.back": "none",
                "hw.camera.front": "none",
                "hw.audioInput": "no",
                "hw.audioOutput": "no",
                "hw.sdCard": "no",
                "disk.dataPartition.size": "2G",
                "fastboot.forceColdBoot": "yes",
                "fastboot.forceFastBoot": "no",
                "firstboot.bootFromDownloadableSnapshot": "no",
                "firstboot.bootFromLocalSnapshot": "no",
                "firstboot.saveToLocalSnapshot": "no",
            }
        )
        for k in ["disk.dataPartition.path", "sdcard.path", "sdcard.size"]:
            values.pop(k, None)
        (avd / "config.ini").write_text("".join(f"{k}={v}\n" for k, v in sorted(values.items())))
        (workspace / "avds/phase1.ini").write_text(
            "avd.ini.encoding=UTF-8\npath=/work/avds/phase1.avd\ntarget=android-30\n"
        )
        (workspace / "home").mkdir()
        image_root = sdk / "system-images/android-30/default/x86_64"
        image_files = [
            image_root / n
            for n in ["system.img", "vendor.img", "ramdisk.img", "kernel-ranchu", "userdata.img"]
        ]
        # Missing images must fail preflight; two empty hash maps are not identity proof.
        image_before = {p.name: file_hash(p) for p in image_files}
        command = sandbox_command(
            sdk=sdk,
            workspace=workspace,
            fixture=apk,
            guest_script=Path(__file__).with_name("guest.py"),
        )
        started = datetime.now(UTC).isoformat()
        timed_out = False
        with (workspace / "sandbox.log").open("w") as log:
            try:
                proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=420)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = -1
        image_after = {p.name: file_hash(p) for p in image_files}
        payload = (
            json.loads((workspace / "result.json").read_text())
            if (workspace / "result.json").is_file()
            else {"status": "failed", "error": "No harness receipt"}
        )
        payload.update(
            {
                "sandbox_returncode": returncode,
                "sandbox_timeout": timed_out,
                "image_unchanged": image_before == image_after,
                "workspace_id": ident,
            }
        )
        # A successful receipt alone cannot override a process or image-identity failure.
        payload["execution_failure_reasons"] = execution_failures(
            payload, returncode=returncode, image_unchanged=image_before == image_after
        )
        passed = not payload["execution_failure_reasons"]
        payload["acceptance_passed"] = passed
        writer = EvidencePackWriter(output)
        writer.ensure_layout()
        records = []
        for name in [
            "result.json",
            "containment.json",
            "commands.json",
            "emulator_command.json",
            "emulator.log",
            "sandbox.log",
            "logcat.txt",
            "capture.pcap",
            "processes.txt",
            "ui.xml",
            "package.txt",
            "activity.txt",
            "appops.txt",
            "files.txt",
            "trial.json",
        ]:
            source = workspace / name
            if source.is_file():
                dest = writer._output_path("artifacts/" + name)
                shutil.copyfile(source, dest)
                records.append(
                    ArtifactRecord(
                        "artifacts/" + name,
                        "emulator_pcap" if name.endswith(".pcap") else "lab_telemetry",
                        BACKEND,
                        writer.hash_file(dest),
                        dest.stat().st_size,
                        origin="isolated_benign_acceptance",
                    )
                )
        for name in ["config.ini", "hardware-qemu.ini"]:
            source = avd / name
            if source.is_file():
                dest = writer._output_path("artifacts/" + name)
                shutil.copyfile(source, dest)
                records.append(
                    ArtifactRecord(
                        "artifacts/" + name,
                        "lab_configuration",
                        BACKEND,
                        writer.hash_file(dest),
                        dest.stat().st_size,
                        origin="host",
                    )
                )
        # Namespace teardown on process exit kills its child processes. Delete only this UUID workspace.
        if workspace.parent != lab_root / "runtime" or workspace.name != ident:
            raise RuntimeError("Teardown boundary violated")
        shutil.rmtree(workspace)
        payload["workspace_removed"] = not workspace.exists()
        writer.write_json("analysis/acceptance.json", payload)
        manifest = RunManifest(
            1,
            ident,
            started,
            started_at=started,
            ended_at=datetime.now(UTC).isoformat(),
            status="success" if passed else "failed",
            target={
                "package_name": FIXTURE_PACKAGE,
                "base_apk_sha256": sha,
                "identity_kind": "exact_single_apk",
                "artifact_set_hash_version": None,
                "artifact_set_hash": None,
            },
            environment={
                "execution_backend": BACKEND,
                "graphics_mode": gpu_mode,
                "api_level": 30,
                "containment_profile": NETWORK_PROFILE,
                "malware_lab_identity": str(lab_root),
                "environment_snapshot": image_before,
                "backend_source_sha256": {
                    name: file_hash(Path(__file__).with_name(name))
                    for name in ("runner.py", "guest.py", "sandbox.py")
                },
                "restore_method": "fresh_userdata_from_pinned_sdk_image",
                "apk_execution": "benign_only",
                "known_malware_executed": False,
            },
            scenario={
                "id": "benign_acceptance_v1",
                "idle_seconds": 15,
                "interaction": "one UI button press",
                "post_interaction_seconds": 5,
                "persistence_positive_control": "second launch after force-stop",
            },
            dataset={"countable": False, "valid_dataset_run": False, "tier": "lab_acceptance"},
            qa=payload,
            notes=[
                "Benign acceptance only; no malware execution authorized.",
                "Network and filesystem namespace tests do not prove immunity to hypervisor/kernel vulnerabilities.",
            ],
        )
        manifest.target["display_name"] = "Scytale Lab Fixture"
        manifest.add_artifacts(records)
        from scytaledroid.DynamicAnalysis.analysis.summarizer import DynamicRunSummarizer
        from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features
        from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report

        try:
            report = write_pcap_report(manifest, writer.run_dir)
            features = write_pcap_features(manifest, writer.run_dir)
            for artifact in [report, features]:
                if artifact is not None:
                    manifest.add_outputs([artifact])
            manifest.add_outputs(DynamicRunSummarizer(writer).summarize(manifest))
            payload["analysis_pipeline_accepted"] = report is not None and features is not None
            parsed_report = json.loads((writer.run_dir / "analysis/pcap_report.json").read_text())
            payload["pcap_valid_with_packets"] = (
                parsed_report.get("report_status") == "ok"
                and (parsed_report.get("packet_count") or 0) > 0
            )
            payload["packet_count"] = parsed_report.get("packet_count")
            payload["fixture_dns_canary_observed"] = fixture_dns_canary_observed(parsed_report)
        except Exception as exc:
            payload["analysis_pipeline_accepted"] = False
            payload["analysis_error"] = type(exc).__name__ + ": " + str(exc)
        payload["acceptance_passed"] = bool(
            passed
            and (
                kind == "boot"
                or (
                    payload["analysis_pipeline_accepted"]
                    and payload.get("pcap_valid_with_packets", False)
                    and payload.get("fixture_dns_canary_observed", False)
                )
            )
        )
        if not payload["acceptance_passed"]:
            manifest.status = "failed"
        writer.write_json("analysis/acceptance.json", payload)
        acceptance = writer.run_dir / "analysis/acceptance.json"
        manifest.add_outputs(
            [
                ArtifactRecord(
                    "analysis/acceptance.json",
                    "lab_acceptance",
                    BACKEND,
                    writer.hash_file(acceptance),
                    acceptance.stat().st_size,
                    origin="host",
                )
            ]
        )
        manifest.finalize()
        writer.write_manifest(manifest)
        return payload
    finally:
        if (
            workspace.exists()
            and workspace.parent == lab_root / "runtime"
            and workspace.name == ident
        ):
            shutil.rmtree(workspace)


def run_boot_probe(
    *,
    lab_root: Path,
    apk: Path,
    output: Path,
    gpu_mode="lavapipe",
    full_controls=False,
    controls=None,
) -> dict:
    """Bounded boot-only probe; no APK installation or launch."""
    return _run_trial(
        lab_root=lab_root,
        apk=apk,
        output=output,
        kind="boot",
        gpu_mode=gpu_mode,
        full_controls=full_controls,
        controls=controls,
    )


def run_benign(*, lab_root: Path, apk: Path, output: Path, gpu_mode="lavapipe") -> dict:
    """Pinned benign fixture only, with all research capture controls enabled."""
    return _run_trial(
        lab_root=lab_root,
        apk=apk,
        output=output,
        kind="benign",
        gpu_mode=gpu_mode,
        full_controls=True,
    )
