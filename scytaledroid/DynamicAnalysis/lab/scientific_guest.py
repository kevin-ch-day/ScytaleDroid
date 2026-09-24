"""Fixed 300-second no-touch measurement inside the disposable Linux worker."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

WORK = Path("/work")
PACKAGE = "org.scytaledroid.labfixture"
SHA = "f9d7ffa39c5eaa8ca36bd32b41230946d12ed58651e5b048bab675e502206dbd"
DURATION_NS = 300_000_000_000


def wait_until(deadline_ns, *, clock=time.monotonic_ns, sleep=time.sleep):
    while True:
        remaining = deadline_ns - clock()
        if remaining <= 0:
            return
        sleep(remaining / 1e9)


def clock_bracket(call):
    before = time.time_ns()
    value = call(["shell", "date +%s.%N"])
    after = time.time_ns()
    return {
        "worker_before_ns": before,
        "android_realtime": value,
        "worker_after_ns": after,
        "round_trip_ns": after - before,
    }


def measure(adb, call, trial, result):
    if trial.get("measurement_seconds") != 300:
        raise ValueError("Scientific duration is fixed at 300 seconds")
    launched = trial["kind"] == "benign"
    if launched:
        assert "Success" in call(["install", "--no-streaming", "/fixture.apk"], timeout=90)
        package_path = call(["shell", "pm", "path", PACKAGE]).removeprefix("package:")
        result["installed_apk_sha256"] = call(["shell", "sha256sum", package_path]).split()[0]
        assert result["installed_apk_sha256"] == SHA
    # Identical observer setup/order and settling interval in both arms.
    call(["logcat", "-c"])
    log = (WORK / "logcat.txt").open("w")
    observer_started_ns = time.time_ns()
    observer = subprocess.Popen(
        adb + ["logcat", "-v", "epoch"], stdout=log, stderr=subprocess.STDOUT
    )
    receipt = {
        "contract": "offline_300s_no_touch_v2",
        "arm": "launch" if launched else "sham",
        "requested_duration_seconds": 300,
        "observer_started_ns": observer_started_ns,
        "pcap_observer_start": "emulator_start; exact command and launch receipt retained",
        "clock_before": clock_bracket(call),
        "snapshots": [],
        "dropped_pcap_packets": "NOT_AVAILABLE_FROM_EMULATOR_CAPTURE",
        "logcat_drop_completeness": "NOT_PROVEN; raw log retained",
        "apk_launch_started_ns": None,
        "apk_launch_finished_ns": None,
    }
    try:
        time.sleep(10)
        receipt["launch_slot_started_ns"] = time.time_ns()
        if launched:
            receipt["apk_launch_started_ns"] = receipt["launch_slot_started_ns"]
            result["launch"] = call(
                ["shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity"]
            )
            if "Status: ok" not in result["launch"]:
                raise RuntimeError("Launch did not report success")
            receipt["apk_launch_finished_ns"] = time.time_ns()
        else:
            call(["shell", "true"])
        # t0 is worker monotonic/realtime bracket immediately after launch acknowledgement (or sham no-op).
        before = time.monotonic_ns()
        start_wall = time.time_ns()
        start_mono = time.monotonic_ns()
        receipt.update(
            t0_epoch_ns=start_wall,
            t0_monotonic_ns=start_mono,
            t0_bracket_ns=start_mono - before,
            window_end_epoch_ns=start_wall + DURATION_NS,
        )
        for i, offset in enumerate((0, 150, 299)):
            wait_until(start_mono + offset * 1_000_000_000)
            stamp = time.time_ns()
            process = call(["shell", "ps -A -o USER,PID,PPID,NAME"], timeout=10)
            activity = call(["shell", "dumpsys activity activities"], timeout=10)
            (WORK / f"processes_{i}.txt").write_text(process)
            (WORK / f"activity_{i}.txt").write_text(activity)
            receipt["snapshots"].append(
                {
                    "index": i,
                    "scheduled_offset_seconds": offset,
                    "started_epoch_ns": stamp,
                    "finished_epoch_ns": time.time_ns(),
                    "process_available": bool(process),
                    "activity_available": bool(activity),
                }
            )
        wait_until(start_mono + DURATION_NS)
        receipt["observation_finished_monotonic_ns"] = time.monotonic_ns()
        receipt["observation_finished_epoch_ns"] = time.time_ns()
        receipt["actual_observation_seconds"] = (
            receipt["observation_finished_monotonic_ns"] - start_mono
        ) / 1e9
        receipt["clock_mapping_residual_ns"] = (
            receipt["observation_finished_epoch_ns"] - start_wall
        ) - (receipt["observation_finished_monotonic_ns"] - start_mono)
        receipt["clock_after"] = clock_bracket(call)
        receipt["scheduled_snapshots"] = 3
        receipt["captured_snapshots"] = len(receipt["snapshots"])
        receipt["missing_snapshots"] = 3 - len(receipt["snapshots"])
        receipt["logcat_alive_through_window"] = observer.poll() is None
        if not receipt["logcat_alive_through_window"]:
            raise RuntimeError("Logcat exited during window")
        if abs(receipt["clock_mapping_residual_ns"]) > 50_000_000:
            raise RuntimeError("Worker clock mapping drift exceeds 50ms")
        if (
            receipt["actual_observation_seconds"] < 300
            or receipt["actual_observation_seconds"] > 302
        ):
            raise RuntimeError("Window controller deadline missed")
        if launched:
            result["marker"] = call(["shell", "run-as", PACKAGE, "cat", "files/run_marker"])
            assert result["marker"] == "launches=1"
        receipt["status"] = "passed"
    finally:
        receipt["teardown_started_ns"] = time.time_ns()
        observer.terminate()
        observer.wait(timeout=10)
        log.close()
        (WORK / "measurement.json").write_text(json.dumps(receipt, indent=2) + "\n")
    result["measurement"] = receipt
