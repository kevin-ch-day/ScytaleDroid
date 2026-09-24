"""Benign acceptance harness, executed ONLY inside the isolated launcher."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

WORK = Path("/work")
PACKAGE = "org.scytaledroid.labfixture"
SHA = "f9d7ffa39c5eaa8ca36bd32b41230946d12ed58651e5b048bab675e502206dbd"


def main():
    if not WORK.is_dir() or Path("/home/systemadmin").exists() or Path("/run/dbus").exists():
        raise RuntimeError("Required isolated filesystem missing")
    assert hashlib.sha256(Path("/fixture.apk").read_bytes()).hexdigest() == SHA
    interfaces = socket.if_nameindex()
    assert [name for _, name in interfaces] == ["lo"], "External interface present"
    checks = {
        "interfaces": interfaces,
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "pid_namespace": os.readlink("/proc/self/ns/pid"),
        "forbidden_paths": {
            p: Path(p).exists()
            for p in [
                "/home/systemadmin",
                "/var/lib/mysql",
                "/run/user/1000",
                "/dev/bus/usb",
                "/root/.ssh",
            ]
        },
        "environment_keys": sorted(os.environ),
        "routes": Path("/proc/net/route").read_text(),
        "probes": [],
    }
    for family, address in [(socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")]:
        for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
            with socket.socket(family, kind) as s:
                s.settimeout(1)
                try:
                    s.connect((address, 443))
                    s.send(b"benign-containment-canary")
                    result = "unexpected_success"
                except OSError as exc:
                    result = type(exc).__name__ + ":" + str(exc.errno)
                checks["probes"].append({"address": address, "type": kind.name, "result": result})
                assert result != "unexpected_success", "Network escape detected"
    (WORK / "containment.json").write_text(json.dumps(checks, indent=2))
    (WORK / "home").mkdir(exist_ok=True)
    trial = json.loads((WORK / "trial.json").read_text())
    if trial["gpu_mode"] not in {"software", "swiftshader", "lavapipe", "swangle"} or trial[
        "kind"
    ] not in {"boot", "benign"}:
        raise ValueError("Unsupported diagnostic trial")
    adb = ["/sdk/platform-tools/adb", "-s", "127.0.0.1:5555"]
    commands = []

    def call(args, timeout=30, check=True):
        result = subprocess.run(adb + args, capture_output=True, text=True, timeout=timeout)
        commands.append(
            {
                "args": args,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        (WORK / "commands.json").write_text(json.dumps(commands, indent=2))
        if check and result.returncode:
            raise RuntimeError("ADB operation failed: " + str(args[:2]))
        return result.stdout.strip()

    subprocess.run(
        ["/sdk/platform-tools/adb", "-L", "localfilesystem:/work/adb-server.sock", "start-server"],
        check=True,
        capture_output=True,
    )
    emu_cmd = [
        "/sdk/emulator/emulator",
        "-avd",
        "phase1",
        "-no-window",
        "-no-audio",
        "-no-boot-anim",
        "-gpu",
        trial["gpu_mode"],
        "-feature",
        "-Vulkan",
        "-show-kernel",
        "-memory",
        "1536",
        "-cores",
        "2",
        "-accel",
        "on",
        "-port",
        "5554",
        "-no-snapshot",
        "-no-metrics",
    ]
    controls = trial.get("controls", [])
    if set(controls) - {"wipe", "grpc", "dns", "pcap"}:
        raise ValueError("Unknown research control")
    if "wipe" in controls:
        emu_cmd += ["-wipe-data"]
    if "grpc" in controls:
        emu_cmd += ["-grpc", "8554", "-grpc-use-jwt"]
    if "dns" in controls:
        # Intentionally disabled resolver in the no-external-network profile.
        # This is not a running sinkhole or a successful DNS service.
        emu_cmd += ["-dns-server", "127.0.0.1"]
    if "pcap" in controls:
        emu_cmd += ["-tcpdump", "/work/capture.pcap"]
    (WORK / "emulator_command.json").write_text(json.dumps(emu_cmd))
    result = {
        "status": "failed",
        "package": PACKAGE,
        "expected_apk_sha256": SHA,
        "reset_method": "fresh_avd_from_read_only_sdk_image",
        "phases": [],
        "trial": trial,
    }
    emulator = None
    logcat = None
    with (WORK / "emulator.log").open("w") as emulog, (WORK / "logcat.txt").open("w") as log:
        try:
            launch_time = time.monotonic()
            result["emulator_launch_utc"] = datetime.now(UTC).isoformat()
            emulator = subprocess.Popen(emu_cmd, stdout=emulog, stderr=subprocess.STDOUT)
            result["emulator_namespace_pid"] = emulator.pid
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if emulator.poll() is not None:
                    raise RuntimeError("Emulator exited before boot")
                try:
                    call(["connect", "127.0.0.1:5555"], timeout=5, check=False)
                except subprocess.TimeoutExpired:
                    time.sleep(2)
                    continue
                if call(["shell", "getprop", "sys.boot_completed"], timeout=5, check=False) == "1":
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Boot timeout")
            result["boot_duration_seconds"] = time.monotonic() - launch_time
            result["guest_routes"] = call(["shell", "ip route show"], check=False)
            result["guest_addresses"] = call(["shell", "ip address show"], check=False)
            # Validate the guest's probe tool independently of guest-to-host routing.
            result["guest_loopback_canary"] = call(
                [
                    "shell",
                    "{ printf 'SCYTALE_GUEST_LOOPBACK_CANARY\\n'; sleep 3; } | toybox nc -l -p 49200 & probe_pid=$!; sleep 1; sleep 2 | toybox nc -w 1 127.0.0.1 49200; kill $probe_pid 2>/dev/null; wait $probe_pid 2>/dev/null",
                ],
                timeout=5,
                check=False,
            )
            if "SCYTALE_GUEST_LOOPBACK_CANARY" not in result["guest_loopback_canary"]:
                raise RuntimeError("Guest network probe positive control failed")
            # Positive control for the same guest-to-namespace path used below.
            # sys.boot_completed can precede stable Android policy routing.
            # Bounded readiness retries occur BEFORE either arm's observers/window.
            result["guest_namespace_canary_attempts"] = []
            for _readiness_attempt in range(5):
                with socket.socket() as canary:
                    canary.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    canary.bind(("127.0.0.1", 49199))
                    canary.listen(1)
                    canary.settimeout(8)

                    def reply():
                        try:
                            client, _ = canary.accept()
                            with client:
                                client.sendall(b"SCYTALE_NAMESPACE_CANARY\n")
                        except OSError:
                            pass

                    responder = threading.Thread(target=reply, daemon=True)
                    responder.start()
                    result["guest_namespace_canary"] = call(
                        ["shell", "sleep 2 | toybox nc -w 1 10.0.2.2 49199"],
                        timeout=4,
                        check=False,
                    )
                    responder.join(timeout=9)
                result["guest_namespace_canary_attempts"].append(result["guest_namespace_canary"])
                if "SCYTALE_NAMESPACE_CANARY" in result["guest_namespace_canary"]:
                    break
                time.sleep(2)
            if "SCYTALE_NAMESPACE_CANARY" not in result["guest_namespace_canary"]:
                raise RuntimeError("Guest-to-namespace positive control failed")
            result["adb_unix_socket_present"] = (WORK / "adb-server.sock").is_socket()
            result["namespace_tcp_listeners"] = sorted(
                {
                    int(line.split()[1].rsplit(":", 1)[1], 16)
                    for name in ("tcp", "tcp6")
                    for line in Path("/proc/net", name).read_text().splitlines()[1:]
                    if line.split()[3] == "0A"
                }
            )
            if not result["adb_unix_socket_present"] or 5038 in result["namespace_tcp_listeners"]:
                raise RuntimeError("ADB control socket isolation failed")
            result["guest_host_service_probes"] = {}
            for port in (22, 80, 443, 3306, 49198):
                result["guest_host_service_probes"][str(port)] = call(
                    [
                        "shell",
                        f"toybox nc -w 1 10.0.2.2 {port} </dev/null; echo NC_EXIT:$?",
                    ],
                    timeout=4,
                    check=False,
                )
            result["guest_adb_management_probe"] = call(
                ["shell", "{ printf '000chost:version'; sleep 2; } | toybox nc -w 1 10.0.2.2 5038"],
                timeout=4,
                check=False,
            )
            if "OKAY" in result["guest_adb_management_probe"]:
                raise RuntimeError("Guest can access ADB control server")
            if any(value != "NC_EXIT:1" for value in result["guest_host_service_probes"].values()):
                raise RuntimeError("Unexpected host service access")
            result["accounts"] = call(["shell", "dumpsys", "account"])
            assert "Account {name=" not in result["accounts"], "Nonempty Android accounts"
            result["boot_fingerprint"] = call(["shell", "getprop", "ro.build.fingerprint"])
            result["devices"] = subprocess.run(
                ["/sdk/platform-tools/adb", "devices", "-l"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            assert "ZY22JK89DR" not in result["devices"]
            result["preinstall_package"] = call(["shell", "pm", "path", PACKAGE], check=False)
            assert not result["preinstall_package"], "State leaked from previous run"
            result["boot_uptime"] = call(["shell", "cat", "/proc/uptime"])
            if trial.get("measurement_seconds") is not None:
                from scientific_guest import measure

                measure(adb, call, trial, result)
            elif trial["kind"] == "boot":
                time.sleep(10)
                assert call(["shell", "getprop", "sys.boot_completed"]) == "1"
                result["stable_uptime"] = call(["shell", "cat", "/proc/uptime"])
            else:
                call(["shell", "settings", "put", "global", "window_animation_scale", "0"])
                call(["shell", "input", "keyevent", "82"])
                call(["logcat", "-c"])
                logcat = subprocess.Popen(
                    adb + ["logcat", "-v", "epoch"], stdout=log, stderr=subprocess.STDOUT
                )
                result["install"] = call(["install", "--no-streaming", "/fixture.apk"], timeout=60)
                assert "Success" in result["install"]
                package_path = call(["shell", "pm", "path", PACKAGE]).removeprefix("package:")
                result["installed_apk_sha256"] = call(["shell", "sha256sum", package_path]).split()[
                    0
                ]
                assert result["installed_apk_sha256"] == SHA
                result["phases"].append({"name": "launch", "monotonic": time.monotonic()})
                result["launch"] = call(
                    ["shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity"]
                )
                result["phases"].append({"name": "idle_15_seconds", "monotonic": time.monotonic()})
                time.sleep(15)
                (WORK / "processes.txt").write_text(
                    call(["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME"])
                )
                call(["shell", "uiautomator", "dump", "/sdcard/window.xml"])
                xml = call(["shell", "cat", "/sdcard/window.xml"])
                (WORK / "ui.xml").write_text(xml)
                buttons = [
                    e
                    for e in ET.fromstring(xml).iter()
                    if e.attrib.get("text") == "CONTROLLED INTERACTION"
                ]
                assert len(buttons) == 1, "Fixture button unavailable"
                x1, y1, x2, y2 = map(int, re.findall(r"\d+", buttons[0].attrib["bounds"]))
                result["phases"].append(
                    {"name": "controlled_button_press", "monotonic": time.monotonic()}
                )
                call(["shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2)])
                time.sleep(5)
                result["marker"] = call(["shell", "run-as", PACKAGE, "cat", "files/run_marker"])
                assert result["marker"] == "launches=1"
                for name, args in [
                    ("package.txt", ["shell", "dumpsys", "package", PACKAGE]),
                    ("activity.txt", ["shell", "dumpsys", "activity", "activities"]),
                    ("appops.txt", ["shell", "cmd", "appops", "get", PACKAGE]),
                    ("files.txt", ["shell", "run-as", PACKAGE, "find", ".", "-type", "f"]),
                ]:
                    (WORK / name).write_text(call(args, check=False))
                # Positive persistence control: state changes within the run, then must disappear at reset.
                call(["shell", "am", "force-stop", PACKAGE])
                call(["shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity"])
                time.sleep(3)
                result["second_launch_marker"] = call(
                    ["shell", "run-as", PACKAGE, "cat", "files/run_marker"]
                )
                assert result["second_launch_marker"] == "launches=2"
                log.flush()
                text = (WORK / "logcat.txt").read_text(errors="replace")
                assert (
                    "RESET_PROBE previous=0" in text and "CONTROLLED_INTERACTION observed" in text
                )
                assert "UNEXPECTED_CONNECT" not in text
            result["status"] = "passed"
        except Exception as exc:
            result["error"] = type(exc).__name__ + ": " + str(exc)
        finally:
            result["cleanup_errors"] = []
            result["natural_emulator_exit"] = emulator.poll() if emulator is not None else None
            for label, child in [("logcat", logcat), ("emulator", emulator)]:
                if child is None or child.poll() is not None:
                    continue
                if label == "emulator":
                    try:
                        call(["emu", "kill"], timeout=5, check=False)
                    except (subprocess.TimeoutExpired, OSError) as exc:
                        result["cleanup_errors"].append(label + ":" + type(exc).__name__)
                try:
                    child.terminate()
                    child.wait(timeout=10)
                except (subprocess.TimeoutExpired, OSError):
                    child.kill()
                    child.wait(timeout=5)
            try:
                subprocess.run(
                    ["/sdk/platform-tools/adb", "kill-server"],
                    capture_output=True,
                    timeout=5,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                result["cleanup_errors"].append("adb:" + type(exc).__name__)
            result["emulator_stopped"] = emulator is None or emulator.poll() is not None
            result["emulator_returncode"] = emulator.poll() if emulator is not None else None
            (WORK / "result.json").write_text(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
