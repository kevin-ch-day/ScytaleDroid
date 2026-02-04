"""Process parsing helpers shared across telemetry collectors."""

from __future__ import annotations

import re

from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.DeviceAnalysis.adb_errors import AdbError


def _shell(serial: str, cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        proc = adb_shell.run_shell_command(serial, cmd, timeout=timeout)
    except AdbError as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def resolve_pid_uid(serial: str, package: str) -> tuple[str | None, str | None]:
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


def parse_top_output(output: str, target_pid: str) -> dict[str, object]:
    result: dict[str, object] = {}
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


def parse_meminfo_total(output: str) -> int | None:
    match = re.search(r"TOTAL\s+(\d+)", output)
    if match:
        try:
            return int(match.group(1))
        except Exception:
            return None
    return None


def _parse_mem(token: str) -> int:
    token = token.upper()
    if token.endswith("M"):
        return int(float(token.rstrip("M")) * 1024)
    if token.endswith("K"):
        return int(float(token.rstrip("K")))
    return int(float(token))


__all__ = ["resolve_pid_uid", "parse_top_output", "parse_meminfo_total"]
