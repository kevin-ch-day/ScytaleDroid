"""Telemetry collection helpers for behavior sessions."""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.DeviceAnalysis.adb_errors import AdbError
JITTER_MULTIPLIER = 1.5


def _shell(serial: str, cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        proc = adb_shell.run_shell_command(serial, cmd, timeout=timeout)
    except AdbError as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def resolve_package_info(serial: str, package: str) -> Dict[str, Optional[str]]:
    rc, out, _ = _shell(serial, ["dumpsys", "package", package])
    info: Dict[str, Optional[str]] = {
        "package": package,
        "versionCode": None,
        "versionName": None,
        "device_model": None,
        "device_manufacturer": None,
        "android_version": None,
        "android_sdk": None,
        "build_fingerprint": None,
        "apk_path": None,
        "apk_hashes": {"md5": None, "sha1": None, "sha256": None},
        "target_package_installed": False,
    }
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if "versionCode" in line:
                match = re.search(r"versionCode=(\d+)", line)
                if match:
                    info["versionCode"] = match.group(1)
            if "versionName" in line:
                parts = line.split("versionName=")
                if len(parts) > 1:
                    info["versionName"] = parts[1].strip()
        info["target_package_installed"] = True
    # Basic device props
    rc2, props, _ = _shell(serial, ["getprop"])
    if rc2 == 0:
        def _get(prop: str) -> Optional[str]:
            for line in props.splitlines():
                if line.startswith(f"[{prop}]"):
                    return line.split("]: [", 1)[-1].rstrip("]")
            return None
        info["device_model"] = _get("ro.product.model")
        info["device_manufacturer"] = _get("ro.product.manufacturer")
        info["android_version"] = _get("ro.build.version.release")
        info["android_sdk"] = _get("ro.build.version.sdk")
        info["build_fingerprint"] = _get("ro.build.fingerprint")
    # APK path + hashes (best effort)
    rc3, out3, _ = _shell(serial, ["pm", "path", package])
    if rc3 == 0:
        for line in out3.splitlines():
            if line.startswith("package:"):
                path = line.split("package:", 1)[-1].strip()
                if path:
                    info["apk_path"] = path
                    info["apk_hashes"] = {
                        "md5": _device_hash(serial, path, "md5sum"),
                        "sha1": _device_hash(serial, path, "sha1sum"),
                        "sha256": _device_hash(serial, path, "sha256sum"),
                    }
                    break
    return info


def _device_hash(serial: str, path: str, tool: str) -> Optional[str]:
    rc, out, _ = _shell(serial, [tool, path])
    if rc != 0:
        return None
    token = out.strip().split()
    return token[0] if token else None


def resolve_pid_uid(serial: str, package: str) -> Tuple[Optional[str], Optional[str]]:
    uid = None
    rc, out, _ = _shell(serial, ["dumpsys", "package", package])
    if rc == 0:
        match = re.search(r"userId=(\d+)", out)
        if match:
            uid = match.group(1)
    if uid is None:
        rc_u, out_u, _ = _shell(serial, ["cmd", "package", "list", "packages", "-U", package])
        if rc_u == 0:
            m2 = re.search(r"uid:(\d+)", out_u)
            if m2:
                uid = m2.group(1)
    pid = None
    rc2, out2, _ = _shell(serial, ["pidof", "-s", package])
    if rc2 == 0:
        pid = out2.strip() or None
    return uid, pid


def parse_top_output(output: str, target_pid: str) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0] == target_pid:
            try:
                result["cpu_pct"] = float(parts[1].rstrip("%"))
            except Exception:
                pass
            try:
                result["rss_kb"] = _parse_mem(parts[2])
            except Exception:
                pass
            result["proc_name"] = " ".join(parts[3:])
            break
    return result


def parse_meminfo_total(output: str) -> Optional[int]:
    match = re.search(r"TOTAL\s+(\d+)", output)
    if match:
        try:
            return int(match.group(1))
        except Exception:
            return None
    return None


def parse_netstats_detail(output: str, uid: str) -> Tuple[int, int]:
    bytes_in = 0
    bytes_out = 0
    for line in output.splitlines():
        if f"uid={uid}" not in line:
            continue
        m_in = re.search(r"rxBytes=(\d+)", line)
        m_out = re.search(r"txBytes=(\d+)", line)
        if m_in:
            bytes_in += int(m_in.group(1))
        if m_out:
            bytes_out += int(m_out.group(1))
    return bytes_in, bytes_out


def parse_proc_net_dev(output: str) -> Tuple[int, int]:
    bytes_in = 0
    bytes_out = 0
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 10:
            try:
                bytes_in += int(parts[1])
                bytes_out += int(parts[9])
            except Exception:
                continue
    return bytes_in, bytes_out


def should_mark_missed_sample(start_time: float, sample_rate: float) -> bool:
    elapsed = time.time() - start_time
    return elapsed > sample_rate * JITTER_MULTIPLIER


def _resolve_pid_only(serial: str, package: str) -> Optional[str]:
    rc, out, _ = _shell(serial, ["pidof", "-s", package])
    if rc == 0:
        return out.strip() or None
    return None


def collect_process_sample(
    serial: str,
    package: str,
    uid: Optional[str],
    pid: Optional[str],
    ts: datetime,
    *,
    strict: bool = False,
) -> Dict[str, object]:
    row: Dict[str, object] = {
        "ts_utc": ts.isoformat(),
        "uid": uid or "",
        "pid": pid or "",
        "cpu_pct": "",
        "rss_kb": "",
        "pss_kb": "",
        "threads": "",
        "proc_name": package,
        "best_effort": 1,
        "collector_status": "unavailable",
    }
    if uid is None:
        row["collector_status"] = "unavailable_uid"
        return row
    pid = pid or _resolve_pid_only(serial, package)
    row["pid"] = pid or ""
    rc, out, _ = _shell(serial, ["top", "-b", "-n", "1", "-o", "PID,CPU,RES,NAME"])
    if rc == 0 and pid:
        parsed = parse_top_output(out, pid)
        if parsed:
            row["cpu_pct"] = parsed.get("cpu_pct", "")
            row["rss_kb"] = parsed.get("rss_kb", "")
            row["proc_name"] = parsed.get("proc_name", package)
            row["best_effort"] = 0
            row["collector_status"] = "ok"
    if rc == 0 and not pid:
        # PID missing but uid known: emit row with pid_missing
        row["collector_status"] = "pid_missing"
    # Memory detail
    rc2, out2, _ = _shell(serial, ["dumpsys", "meminfo", "--package", package])
    if rc2 == 0:
        mem_total = parse_meminfo_total(out2)
        if mem_total is not None:
            row["pss_kb"] = mem_total
    return row


def _parse_mem(token: str) -> int:
    # top RES may show K or M
    token = token.upper()
    if token.endswith("M"):
        return int(float(token.rstrip("M")) * 1024)
    if token.endswith("K"):
        return int(float(token.rstrip("K")))
    return int(float(token))


def collect_network_sample(serial: str, uid: str, ts: datetime) -> Dict[str, object]:
    row: Dict[str, object] = {
        "ts_utc": ts.isoformat(),
        "uid": uid,
        "bytes_in": "",
        "bytes_out": "",
        "conn_count": "",
        "source": "best_effort",
        "best_effort": 1,
        "collector_status": "unavailable",
    }
    if not uid:
        row["collector_status"] = "unavailable_uid"
        row["source"] = "unavailable"
        return row
    rc, out, _ = _shell(serial, ["dumpsys", "netstats", "detail"])
    if rc == 0:
        bytes_in, bytes_out = parse_netstats_detail(out, uid)
        if bytes_in or bytes_out:
            row["bytes_in"] = bytes_in
            row["bytes_out"] = bytes_out
            row["conn_count"] = ""  # unknown from netstats detail
            row["source"] = "netstats"
            row["best_effort"] = 0
            row["collector_status"] = "ok"
            return row
    # Fallback: /proc/net/dev aggregate
    rc2, out2, _ = _shell(serial, ["cat", "/proc/net/dev"])
    if rc2 == 0:
        bytes_in, bytes_out = parse_proc_net_dev(out2)
        row["bytes_in"] = bytes_in
        row["bytes_out"] = bytes_out
        row["conn_count"] = ""
        row["source"] = "fallback_iface"
        row["best_effort"] = 1
        row["collector_status"] = "best_effort"
    return row
