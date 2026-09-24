"""Trusted outer-VM supervisor: emulator, unprivileged parser, bounded export."""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

WORK = Path("/work")
EXPORT = Path("/export")


def main():
    checks = {
        "kernel": os.uname().release,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "interfaces": socket.if_nameindex(),
        "uid": os.getuid(),
        "kvm_present": Path("/dev/kvm").exists(),
        "forbidden_paths": {
            p: Path(p).exists()
            for p in [
                "/home/systemadmin",
                "/var/lib/mysql",
                "/root/.ssh",
                "/dev/bus/usb",
                "/run/dbus",
            ]
        },
        "mounts": Path("/proc/mounts").read_text(),
        "started_ns": time.time_ns(),
    }
    assert [n for _, n in checks["interfaces"]] == ["lo"] and not any(
        checks["forbidden_paths"].values()
    )
    try:
        with (WORK / "harness.log").open("w") as f:
            r = subprocess.run(
                ["/usr/bin/python3", "/control/guest.py"],
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=650,
            )
        checks["harness_returncode"] = r.returncode
        trial = json.loads((WORK / "trial.json").read_text())
        if r.returncode == 0 and trial.get("measurement_seconds"):
            inputs = WORK / "parser_input"
            inputs.mkdir()
            outputs = WORK / "parser_output"
            outputs.mkdir()
            outputs.chmod(0o777)
            for name in ["measurement.json", "capture.pcap", "logcat.txt"]:
                shutil.copyfile(WORK / name, inputs / name)
            shutil.copyfile("/fixture.apk", inputs / "fixture.apk")
            for p in inputs.iterdir():
                p.chmod(0o444)
            inputs.chmod(0o555)
            cmd = [
                "/usr/bin/bwrap",
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--clearenv",
                "--cap-drop",
                "ALL",
                "--uid",
                "65534",
                "--gid",
                "65534",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/bin",
                "/bin",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                str(inputs),
                "/input",
                "--bind",
                str(outputs),
                "/output",
                "--ro-bind",
                "/control/isolated_parser.py",
                "/parser.py",
                "--setenv",
                "HOME",
                "/tmp",
                "--setenv",
                "PATH",
                "/usr/bin",
                "/usr/bin/python3",
                "/parser.py",
            ]
            checks["parser_command"] = cmd
            parsed = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            checks["parser_returncode"] = parsed.returncode
            checks["parser_stderr"] = parsed.stderr
            checks["parser_stdout"] = parsed.stdout
            if parsed.returncode == 0:
                shutil.copyfile(outputs / "window_metrics.json", WORK / "window_metrics.json")
        checks["finished_ns"] = time.time_ns()
    except Exception as exc:
        checks["error"] = type(exc).__name__ + ":" + str(exc)
    finally:
        (WORK / "worker_checks.json").write_text(json.dumps(checks, indent=2) + "\n")
        exports = []
        # Only regular, bounded top-level telemetry files; never export userdata or symlinks.
        for src in sorted(WORK.iterdir()):
            if (
                src.is_symlink()
                or not src.is_file()
                or src.suffix not in {".json", ".txt", ".log", ".pcap"}
            ):
                continue
            if src.stat().st_size > 128 * 1024 * 1024:
                raise RuntimeError("Telemetry export size exceeded")
            dst = EXPORT / src.name
            shutil.copyfile(src, dst)
            exports.append(
                {
                    "file": src.name,
                    "sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
                    "size": dst.stat().st_size,
                }
            )
        (EXPORT / "export_receipt.json").write_text(json.dumps(exports, indent=2) + "\n")


if __name__ == "__main__":
    main()
