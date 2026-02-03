"""ADB helpers for collecting raw netstats output."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.DeviceAnalysis import adb_shell
from scytaledroid.DeviceAnalysis.adb_errors import AdbError


@dataclass(frozen=True)
class NetstatsRaw:
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool


class NetstatsCollector:
    """Collect raw dumpsys netstats output for a device."""

    def collect_detail(self, serial: str, *, timeout: float = 5.0) -> NetstatsRaw:
        return self._run(serial, ["dumpsys", "netstats", "detail"], timeout=timeout)

    def collect_uid(self, serial: str, uid: str, *, timeout: float = 5.0) -> NetstatsRaw:
        return self._run(serial, ["dumpsys", "netstats", "--uid", uid], timeout=timeout)

    def _run(self, serial: str, command: list[str], *, timeout: float) -> NetstatsRaw:
        try:
            completed = adb_shell.run_shell_command(serial, command, timeout=timeout)
            return NetstatsRaw(
                command=command,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                returncode=completed.returncode,
                timed_out=False,
            )
        except AdbError as exc:
            return NetstatsRaw(command=command, stdout="", stderr=str(exc), returncode=1, timed_out=False)
        except RuntimeError as exc:
            message = str(exc).lower()
            return NetstatsRaw(
                command=command,
                stdout="",
                stderr=str(exc),
                returncode=1,
                timed_out="timed out" in message,
            )


__all__ = ["NetstatsCollector", "NetstatsRaw"]
