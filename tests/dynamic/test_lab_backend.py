"""Safety boundaries of the real benign-only lab backend."""

import hashlib
import subprocess

import pytest
from scytaledroid.DynamicAnalysis.lab import runner, sandbox


def test_unapproved_apk_never_starts_or_creates_workspace(tmp_path, monkeypatch):
    apk = tmp_path / "unknown.apk"
    apk.write_bytes(b"not authorized")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: pytest.fail("execution before identity gate")
    )
    with pytest.raises(ValueError, match="pinned benign"):
        runner.run_benign(lab_root=tmp_path, apk=apk, output=tmp_path / "output")
    assert not (tmp_path / "runtime").exists()


def setup(tmp_path, monkeypatch):
    sdk = tmp_path / "sdk"
    (sdk / "emulator").mkdir(parents=True)
    (sdk / "platform-tools").mkdir()
    (sdk / "emulator/emulator").touch()
    (sdk / "platform-tools/adb").touch()
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"test-only")
    monkeypatch.setattr(sandbox, "FIXTURE_SHA256", hashlib.sha256(apk.read_bytes()).hexdigest())
    work = tmp_path / "work"
    work.mkdir()
    guest = tmp_path / "guest.py"
    guest.touch()
    return sdk, work, apk, guest


def test_command_has_no_host_network_usb_home_or_credentials(tmp_path, monkeypatch):
    sdk, work, apk, guest = setup(tmp_path, monkeypatch)
    command = sandbox.sandbox_command(sdk=sdk, workspace=work, fixture=apk, guest_script=guest)
    for flag in [
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--clearenv",
        "--die-with-parent",
        "--new-session",
    ]:
        assert flag in command
    assert "--share-net" not in command and "/dev/bus/usb" not in command
    assert "/home/systemadmin" not in command and "/run" not in command
    assert (
        command.count("--dev-bind") == 1 and command[command.index("--dev-bind") + 1] == "/dev/kvm"
    )
    assert "ZY22JK89DR" not in command
    socket_index = command.index("ADB_SERVER_SOCKET")
    assert command[socket_index + 1] == "localfilesystem:/work/adb-server.sock"
    assert "tcp:5038" not in command
    assert "--cap-drop" in command and "ALL" in command


def test_sdk_workspace_overlap_rejected(tmp_path, monkeypatch):
    sdk, work, apk, guest = setup(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="separate"):
        sandbox.sandbox_command(sdk=sdk, workspace=sdk, fixture=apk, guest_script=guest)


def test_configuration_failure_removes_private_workspace(tmp_path, monkeypatch):
    sdk, work, apk, guest = setup(tmp_path, monkeypatch)
    with pytest.raises(FileNotFoundError):
        runner.run_benign(lab_root=tmp_path, apk=apk, output=tmp_path / "output")
    assert list((tmp_path / "runtime").iterdir()) == []


def test_existing_output_is_never_overwritten(tmp_path, monkeypatch):
    sdk, work, apk, guest = setup(tmp_path, monkeypatch)
    out = tmp_path / "output"
    out.mkdir()
    (out / "evidence").write_text("preserve")
    with pytest.raises(FileExistsError):
        runner.run_benign(lab_root=tmp_path, apk=apk, output=out)
    assert (out / "evidence").read_text() == "preserve"
    assert not (tmp_path / "runtime").exists()


def test_deprecated_or_host_gpu_modes_are_rejected_before_execution(tmp_path):
    for mode in ["off", "swiftshader_indirect", "host"]:
        with pytest.raises(ValueError, match="Unsupported"):
            runner.run_boot_probe(
                lab_root=tmp_path, apk=tmp_path / "absent", output=tmp_path / "out", gpu_mode=mode
            )


def test_outer_timeout_seals_failure_and_removes_workspace(tmp_path, monkeypatch):
    sdk, work, apk, guest = setup(tmp_path, monkeypatch)
    golden = tmp_path / "golden.avd"
    golden.mkdir()
    (golden / "config.ini").write_text("hw.gpu.mode=auto\n")

    images = sdk / "system-images/android-30/default/x86_64"
    images.mkdir(parents=True)
    for name in ["system.img", "vendor.img", "ramdisk.img", "kernel-ranchu", "userdata.img"]:
        (images / name).write_bytes(b"test image")

    def timeout(command, **kwargs):
        if command[0] == "/usr/bin/bwrap":
            raise subprocess.TimeoutExpired(command, 420)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", timeout)
    result = runner.run_boot_probe(lab_root=tmp_path, apk=apk, output=tmp_path / "output")
    assert result["sandbox_timeout"] is True and result["acceptance_passed"] is False
    assert result["workspace_removed"] is True
    assert list((tmp_path / "runtime").iterdir()) == []
    assert (tmp_path / "output/run_manifest.json").is_file()


def test_emulator_pcap_is_read_without_misrepresenting_capture_origin(tmp_path):
    from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
    from scytaledroid.DynamicAnalysis.pcap.report import _find_pcap_artifact

    capture = ArtifactRecord("artifacts/capture.pcap", "emulator_pcap", sandbox.BACKEND)
    manifest = RunManifest(1, "lab-test", "2026-09-20T00:00:00Z")
    manifest.add_artifacts([capture])
    assert _find_pcap_artifact(manifest, tmp_path) is capture
    assert capture.produced_by == sandbox.BACKEND
    legacy = ArtifactRecord("artifacts/legacy.pcap", "pcapdroid_capture", "pcapdroid_capture")
    manifest.add_artifacts([legacy])
    assert _find_pcap_artifact(manifest, tmp_path) is legacy


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"emulator_returncode": -11}, "emulator_exit_failed"),
        ({"cleanup_errors": ["adb:TimeoutExpired"]}, "cleanup_failed_or_unverified"),
        ({"cleanup_errors": None}, "cleanup_failed_or_unverified"),
        ({"emulator_stopped": False}, "emulator_not_stopped"),
        ({"natural_emulator_exit": 0}, "emulator_exited_early"),
        ({"status": "failed"}, "harness_failed"),
    ],
)
def test_fixture_success_cannot_hide_execution_or_cleanup_failure(changes, reason):
    receipt = dict(
        status="passed",
        emulator_returncode=0,
        cleanup_errors=[],
        emulator_stopped=True,
        natural_emulator_exit=None,
    )
    assert runner.execution_failures(receipt, returncode=0, image_unchanged=True) == []
    receipt.update(changes)
    assert reason in runner.execution_failures(receipt, returncode=0, image_unchanged=True)


def test_missing_sdk_images_fail_before_execution(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    golden = tmp_path / "golden.avd"
    golden.mkdir()
    (golden / "config.ini").write_text("hw.gpu.mode=auto\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("missing image launched"))
    with pytest.raises(FileNotFoundError):
        runner.run_benign(lab_root=tmp_path, apk=tmp_path / "fixture.apk", output=tmp_path / "out")
    assert list((tmp_path / "runtime").iterdir()) == []


@pytest.mark.parametrize(
    "names,expected",
    [
        ([], False),
        ([{"value": "connectivitycheck.gstatic.com", "count": 100}], False),
        ([{"value": "fixture.invalid", "count": 0}], False),
        ([{"value": "fixture.invalid", "count": 2}], True),
    ],
)
def test_background_packets_do_not_satisfy_fixture_capture(names, expected):
    assert runner.fixture_dns_canary_observed({"packet_count": 100, "top_dns": names}) is expected
